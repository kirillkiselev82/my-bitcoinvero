#!/root/mybot/.venv/bin/python3
"""MyBot V51 independent superset auditor for the V50 dense-state lineage.

Read-only auditor for the dense V50 state.  It intentionally does NOT import or
execute utxo_pipeline_v50.py or the V50 dense core.  The auditor combines the
expensive lessons of n30/R67 (false-green, coverage, provenance, fail-closed
reporting) and n41 (Stage/source/lifecycle/Core anchors), plus V50-specific
physical-state invariants.

Authoritative inputs are read only.  Writes are restricted to audit-owned evidence:
  * audit-private temporary DuckDB/scanner artifacts under --tmp;
  * resumable Bitcoin-Core->Stage exact progress contract/ledger/dirty evidence under
    --core-stage-progress-dir (default: <output-dir>/core_stage_progress);
  * optional legacy AWS RAW diagnostics under --raw-progress-dir when explicitly enabled;
  * resumable bounded-memory Stage->UTXO work/evidence under --stage-rebuild-work-dir;
  * immutable JSON/Markdown/SHA256 final audit evidence under --output-dir.

Certification rule: NOT_EVALUATED is never GREEN.

V51.1 adds one mandatory pre-scan `quick_invariants` phase.  It fails closed
before the expensive full state scan on: physical frontier mismatch, impossible
checkpoint arithmetic/subsidy bounds, apply-ledger counter regression, BIP30
pointer mismatch, Bitcoin Core tip mismatch, or Parquet footer row-count drift.
These are deterministic tripwires; they do not replace any existing full proof.

V51.2 fixes baseline-only provenance semantics: after a certified anchor adoption,
`provenance_r12/runs` is allowed to be absent until the first R12 APPLY run.
If the directory exists it must still be a real non-symlink directory; once any
post-baseline run record exists (or an explicit run contract is requested), the
directory is mandatory.

V51.5.1 hardens the V51.5 bounded-memory Stage semantic proof for production.
Each canonical Stage window is checked in an isolated DuckDB connection, committed
to a resumable hash-chained progress ledger, and released before the next window.
The old monolithic Stage semantic query remains available only as a regression
oracle. Global duplicate-txid exactness is proved in the existing 256-prefix
bounded Stage->UTXO engine, avoiding an O(total Stage) global GROUP BY.

V51.5.2 is a production bug-fix release only. It removes two late-path
NameError hazards found by static integration review: the bounded Stage stream
summary no longer references duplicate-TXID variables owned by the bucketed
caller, and the optional legacy RAW chunk path now records the DuckDB settings
returned by configure_duckdb(). No audit semantics or UTXO math are changed.

V51.5.3 fixes the late-path legacy V40 reference contract for targets beyond the
certified 456028 prefix and adds fail-closed reuse of expensive V51.5.2 proof
phases from an operator-SHA-pinned immutable FATAL report that failed only at
reference_v40. Fresh state/Stage/provenance/Core/stability checks still execute.

V51.5.4 adds an independent mandatory read-only Core chain revalidation guard.
The existing Core->Stage exact proof, Stage semantics, Stage->UTXO rebuild,
provenance, and snapshot guards are unchanged.  The new guard performs a fresh
height-by-height active-chain hash comparison against immutable Stage block
hashes in bounded RPC batches, commits expected/observed chain digests, checks
that the final range-end anchor did not move during the sweep, and blocks
maximum certification on any mismatch or incomplete coverage.

V51.5.5 is a production parser-compatibility and evidence-reuse hotfix. It makes
window-function aliases explicit for DuckDB 1.4.4, fixes source_catalog prev-hash
validation without changing audit semantics, and permits strictly revalidated
Core->Stage evidence produced by the certified V51.5.4 auditor. No UTXO, Stage,
Core->Stage digest, Merkle, provenance, or certification semantics are changed.
"""
from __future__ import annotations

import argparse
import ast
import base64
import csv
import fcntl
import gzip
import hashlib
import http.client
import json
import os
import re
import resource
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PRODUCT_VERSION = "V51"
COMPONENT_VERSION = "V51.5.5"
VERSION = "v51.5.5-independent-auditor-r12.9-core-chain-guard-source-catalog-hotfix-prod"
V51_5_2_AUDITOR_SHA256 = "934639d464d715dad6f77903761875e26766cd57148c6f6b2ca175b4c4b0f5a4"
V51_5_2_VERSION = "v51.5.2-independent-auditor-r12.9-bounded-stage-semantics-bugfix-prod"
V51_5_3_AUDITOR_SHA256 = "4127d9dfbd9a2813a2a200b4bfab998f2dfdce5e1f0e87d3cc6aa3623189527b"
V51_5_3_VERSION = "v51.5.3-independent-auditor-r12.9-reference-prefix-proof-reuse-prod"
V51_5_4_AUDITOR_SHA256 = "2a8b601961affd78efc90b3cc9c6042e29565a2de765d5c94edadf94f9f30d39"
V51_5_4_VERSION = "v51.5.4-independent-auditor-r12.9-core-chain-guard-prod"
REPORT_SCHEMA = "mybot-v51-independent-audit-v1.5.4"
DUCKDB_VERSION = "1.4.4"

DEFAULT_STATE = Path("/opt/mybot_data/etl/utxo_v50/state")
DEFAULT_STAGE_BASE = Path("/opt/mybot_data/etl/utxo_core_v1/stage2")
DEFAULT_DRIVER = Path("/opt/mybot_data/etl/utxo_v50/runtime/utxo_pipeline_v50_r11_certified.py")
DEFAULT_SUPERVISOR = Path("/root/mybot/utxo_pipeline_v50_r12_9.py")
DEFAULT_CORE = Path("/opt/mybot_data/etl/utxo_v50/runtime/utxo_v50_dense_core")
DEFAULT_REFERENCE_DB = Path("/opt/mybot_data/etl/utxo_core_v1/output/utxo_core_v40_0_617698.duckdb")
DEFAULT_TMP = Path("/opt/mybot_tmp/utxo_v50_audit")
DEFAULT_OUTPUT = Path("/opt/mybot_data/etl/utxo_v50/audit")
DEFAULT_RAW_BASE = Path("/opt/mybot_data/raw/aws-btc/transactions")
DEFAULT_SOURCE_CATALOG = Path("/opt/mybot_data/etl/utxo_core_v2/source/source_catalog.duckdb")
DEFAULT_CONTROL = Path("/opt/mybot_data/etl/utxo_v50/control")
DEFAULT_RECOVERY_LEDGER = Path("/opt/mybot_data/etl/utxo_v50/state/provenance_r12/recovery_ledger_v2.jsonl")
DEFAULT_APPLY_LEDGER = Path("/opt/mybot_data/etl/utxo_v50/state/provenance_r12/apply_ledger_v2.jsonl")
DEFAULT_SOURCE_LINEAGE = Path("/opt/mybot_data/etl/utxo_v50/state/provenance_r12/source_lineage_v1.jsonl")
DEFAULT_RUNS_DIR = Path("/opt/mybot_data/etl/utxo_v50/state/provenance_r12/runs")
SOURCE_LEDGER_CONTRACT = "utxo-source-catalog-ledger-v2"
V50_RUN_CONTRACT_SCHEMA = "mybot-v50-run-contract-v2"
V50_RECOVERY_LEDGER_SCHEMA = "mybot-v50-recovery-ledger-v2"
V50_APPLY_LEDGER_SCHEMA = "mybot-v50-apply-ledger-v2"
V50_SOURCE_LINEAGE_SCHEMA = "mybot-v50-source-lineage-v1"
V50_WINDOW_FINGERPRINT_SCHEMA = "mybot-v50-r12-window-fingerprint-v2"
V50_ACTIVE_RUN_SCHEMA = "mybot-v50-r12-active-run-v2"
V50_RUN_RESULT_SCHEMA = "mybot-v50-run-result-v1"
V50_PROVENANCE_EPOCH_ACTION = "PROVENANCE_EPOCH_OPEN"
RAW_PROGRESS_SCHEMA = "mybot-v50-raw-audit-progress-v2"
RAW_CHUNK_RECORD_SCHEMA = "mybot-v50-raw-audit-chunk-v2"
CORE_STAGE_PROGRESS_SCHEMA = "mybot-v50-core-stage-progress-v1"
CORE_STAGE_CHUNK_RECORD_SCHEMA = "mybot-v50-core-stage-chunk-v1"
STAGE_SEMANTICS_PROGRESS_SCHEMA = "mybot-v51-stage-semantics-progress-v1"
STAGE_SEMANTICS_RECORD_SCHEMA = "mybot-v51-stage-semantics-window-v1"
STAGE_SEMANTICS_ENGINE = "WINDOW_ISOLATED_V1"
SEGWIT_HEIGHT = 481824
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

LEGACY_GLOBAL_SHA = "3dc4e285947651d0c36bf5564c6f424d620947d29f36154ffa1cbb1dbe94860a"
LEGACY_END = 617698
LEGACY_END_HASH = "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
LEGACY_TOTALS = {"blocks": 617699, "transactions": 503813853, "inputs": 1231768826, "outputs": 1337956664}
FROZEN_LIVE_COUNT = 65419258
FROZEN_LIVE_VALUE = 1822105482121089
MAX_MONEY_SATS = 21_000_000 * 100_000_000
MAX_SCRIPT_SIZE = 10_000
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

BIP30 = (
    {"txid": "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599", "early": 91812, "later": 91842},
    {"txid": "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468", "early": 91722, "later": 91880},
)

# Packed V50 R11 state contracts, independently restated here rather than imported.
META = struct.Struct("<8sIIQQQQIIII32s32s32s32s")
CHECKPOINT = struct.Struct("<8sIq32sQQQQQqQQ32s32s")
DIRTY = struct.Struct("<8sIqqQQQQQQQQQQQQ32s32s")
TX_RECORD_SIZE = 56
OUT_RECORD_SIZE = 32
CLOSE_RECORD_SIZE = 24
HASH_SLOT_SIZE = 40
TX_RECORD = struct.Struct("<32sQIIII")
OUT_RECORD = struct.Struct("<QqQII")
CLOSE_RECORD = struct.Struct("<QQII")
TX_FLAG_COINBASE = 1
HALVING_INTERVAL = 210000
INITIAL_SUBSIDY_SATS = 50 * 100_000_000
V50_STATE_VERSION = 3
EXPECTED_V50_DRIVER_VERSION = "v50-dense-r11-buffered-script-append-singlefile-prod"
EXPECTED_V50_CORE_ID = "v50-dense-core-r11-buffered-script-append"
EXPECTED_V50_EMBEDDED_CORE_SOURCE_SHA256 = "cb689d72992419378568d11617c8203115a7af8105adaf6dcdfbf5e972211dbf"
EXPECTED_R11_SHA256 = "c735fb8cc7a63d992f0dbb4ce56cd9b4745304711d71f05b7a8db9390bc6911f"
EXPECTED_R12_SUPERVISOR_VERSION = "v50-dense-r12.9-certified-r11-supervisor-provenance-prod"
EXPECTED_R12_SUPERVISOR_SHA256 = "572f382257c797d1475a27f7e08388da120c5f88eaf00de7673608150cc8b19e"
CERTIFIED_R225_ANCHOR = {
    "height": 456028,
    "block_hash": "0000000000000000017a6703bddac846115c36e551392cd24398b66c2f386ab4",
    "tx_count": 202389264,
    "out_count": 558432085,
    "close_count": 510025682,
    "script_bytes": 13930769818,
    "live_count": 46425999,
    "live_value_sats": 1620019859866423,
    "fingerprint_sha256": "52fad5d79597d86313edd7b5617e86a15c6aad2ecc5053eb08f38694b052442a",
    "source_sha256": LEGACY_GLOBAL_SHA,
    "audit_report_sha256": "31b8025dfd0ee48ab14660c5467f69cc63358b5c43d24b0919c4aebc282c37f4",
    "auditor_sha256": "12a6cfbfeb9b9adecebac16a154ab2cb9b0bc8739b2d6778b02d24f7e63bfb51",
}

AUDIT_HELPER_SOURCE_SHA256 = "4f89c1536f4c36597eb0de233eace7b869afc3e35769d77277617b60ef9f4556"
AUDIT_HELPER_GZIP_B64 = "H4sIAPxkoWoC/50773PbNrLf/Vco6oxOjGiVpCiKMkXduInb87w0zthup/cSnwYEQYtXiVRIylHs+P72twuAICjJ6c3LB4tc7G8sFrsA80Oa0dU2Zp0ZWd3nRVot1/OTHxpgUZCvOoCyosjyFqSs4jSr9kBFmt3roIRm1Wq4bIEAi5GWuDQ/hK3SdVqVOgQEsh1lm6oN3BdZfi1/XK9J1paK0LIiVRu6zVLg2oY9MFrlxfzkBNFT2qF5VlZstyk6W7B35Cyqzu9ja/H7xfXN5dX7cBR8B/H2j8XP785/Wby5unz/0/nNRWhvv4d+9dutwL94d/nL5U/v/gr/zburm4vFzYeL92//K8yfLj+MrND5Lub7q8Xvl+9Da5fIfy9hey5g/3r+x+LXq/cX/1zcnN/ehI5t8X/b1eq1fOQv3xOILG7eXF9+uF3cXP4vmMxpXqDw0UsfFtcXt79do5IeCdREPeRp3ElIuupzmg7M7NmZiI9eaTxVyyL/IoDFNqvSNVtAUOdFvzSC506LCV0y+mc/yvNV58E8yixN+q8eDC6sRa6hdZZsJzWRmr/emGX6yMCEzHjSzQOBpHi9DLuW7YzcsTfxpySiMUu6gc6wDMphwZBFP3vtGEGCyguGaWgF6SwL0sEAWH90Xqd34fLj5mN6N5+7dwGHDOwa1rPHd8FzwaptkQHX51p7bvEjK/KRs6+58YTS4E2KGjlcFvgBGRqSV0JWJQvkS1Vs2R5v9vmAMzHb75HxVCuGpq/Zmq43fWJG5sgxQpD9fHLy44+dyyxmGwZ/QKObf5yfOmOvk643K7YGCAjMQZm86JBtnFYd9pACImXDE7oiZYkEiP900oF/KhCXH/278Aljypoyz5tsTWsXRd6EMH+MzyPqsWQ0cfCZjN0kGY8IPo9ti42dSYLP08gae75P8dlO/FEME8lxImbR2J5unwMllC+gCJIcGKWCO9omHz337uk56Mip3ZYsBgxOJn2pVC7yquirt52J85MpB/Z383lmfOvvZrP+yDnNDIhUzoYHebTKIcgPppkjaLIaBC7jT9QubLCsnev4xEmmPpo5sUcT153a3HVjaiUR5W5h02gcR0S4cTr2qDMWbpkmtm0nHH/qjBLfIS53b2TTMYsBXxMU+9aEECHIdvzROLI4oeOObB8czBmOLTqJ6Ygr40RsHE84Q9+KWWQnTMxRTC2P8Pml9jRKbMTRBDF3GnlTypmzJGLuxPfw2UoAPaaeEGpRYlM+0U7Mpg71uKUumbi+S0Rg0MgiQMCV8cBFfkxagqb+iI3tsYgof2RTz4u56yxr5EwotzRKxtNJQoW2HrOsKOHWxWMymdouh1seJd5ozBW2XWfqTDF6NUHOJJpYRISxw+zIsUecuRuD3nHCNRyPRuAlmzP3xhaZjMau0BwWBIn4fPk2dejUEW50Jo5D/fYcESdKmE9sYZFNPM/lhNRxIx904M8Tj45tIqywgZsP6wKfvenU8hwuNHEtNhoLhW2YLGIhrSbInhKX2jafC5uNgKXFLXLA/ZOJyy0auZEV0UhGnU0tGnGhLot9QlwxR9GUUuLyufN8h3kJulcTBPwgLBk3eeKTsTcSE+271J/4toguSieWIxSYWhGDXZMzJ+4YpoZxDwB0SkaJnMeJPfETp84GrTT0BVdY0M62tsez7RdItaFa75B5XcjzxmzmuLDK22BI9jBge4cDDg74xjfxNrprVGhkoryZ54rtRGlWWiFPOKDGKewg5sT4V+vd9o1/1S/z+cgIGkq7oXQAUafE96kkdIDOtoyAG8o5eXeD0hrg4wSebJnAWg4jsKtZd2YEP/adSeEHWMbwM7ozGfy4d2YCP6DgPfx4d+Yj/EyO2m0dM/tGKs9MT6rNTNtWj87YMOky7LNeAlb0/8OM3r1hVnb4OLixB3Q5+BOMQQvuzBvpQGI6kpyY9kg9Oo5hrsm/wz7pRcCK9Cj8jeCvWTnhjTWAseAxvA/uwyRIQhawMB5UdhCHNKBhFEQhCUhY2YPK0dyEvhnACDpnAFjonQFQoHsGYRygfwbADB00AMbooQEIQRcNwkfhpeeTzTZapfSs2T62m5hUTO4fCGlVN+1t5XO4t88YmwA3vkFY74P9zHjtB1+W6QpqG6hgBKMqFDVAmvUz03NPcSs0AlUXbL72YbscINT8bFYQb/A0CKvgM/7JTuEP1Cd8/ww913gSOx6QCEysJZ6f5b4KLHnTM5MqQrUx7yRpRlZ9EQp8t4ZO6T5EzYN6v84zFuL2Ekh/9ABg2oYax2oKBAnLUOqrcOwZNTKO6tgrlkERsrf4fR6PODQ5rdc/IBt91GY+76evfdjZJUtAM33powODcigrjvF+ynkmgWWB9aLjBrlMIRIC6SCXuUNCfAkYCYAqJnOIPEhqJz9sCnK/Jp0NAY9vtuUSrIRKsNhSKPhZRTpPWPJ21uQ+pWixWmwPrCiheDOhtEtJFijPV7sFJcAtrb6a+bZqXugqL1nzuiTlUr01bIG8YDQv4gWGFuegvwsmOoTzKVd5xV/VBJX5tqBsUS7JxxFkGcBvXuIiBe2bMWwiyu0aX4LnoLb+DYI3OU7BX/ggqG1fsvR+WSkdeBgvUEHOuuWiHDob4R/+JJ3Dn0tapJtqEX2tWGmuQFUBV1I46IGstizQqtPNyFqU7PNis9qW9kcp7pgnjlt7u7vmTu081XTVLo3beidpUVYLULrxgLDYBItSKPF35kNjUrIi96Um4WpbbbaVLqV2BqitjON2LUoiVy6HSYfkSVIyTbYE40Lal/UG3XkgKucaLNJYuLtYSNnNfKaZWX3dMOTUXhj5xpD90QL6ElZUvJ/Lk37tN+h4IF0ER3F0ywEP2qPjeJrWgAa1AqzPikGvBPliJhqi27ms9m87BSPxYpPHR5roDXat8JrKI5wONH+mgOTl2VkE2bL4agSie+bts5GY3RzatE53sDGC284OE9AQRfT7vOc1ejtTqrkzFKlI/0YyvOdz3ge1FZLZLZd5UQmOfAFRSfZKcu5RSDZmtyqgO8e2mUe8wJdZagdZ6iUP8D61ZGS1yOvu6La3M55kz4g9eJ29leq3xil6n2yrvBOH5VDuG8GRRjYeAi3pG+ZuWC+ZprHV2juxMrgjNqRavjQbPCyRDP6Ab4UjEIVAuTekC8AAWb2yQgngOsSUnkPMm8XlzfXFL/2yGsISXOcxA8dlOTSW7H67At/qXuvXehkCnSfGZ9lS/0o2nSdZJGBuS+Lw1G7WWgb27bWaYbZdrTZVEQDpMfPAarNJRDiHxlnWFw9PwB7jqo9YysyrxfXbq/fv/vntavHm3dXFHxdvajuTeI7m16EIRGqkcTEHh6FIkF2Ed9ZpuSYVXSoiqCegPOHlzudwvQbNpRVmZn64vrpdXF+cvzV/Pf+wgHi5vnhrJrFp1bI+vwpx5Ofzy3cw0kVyxXhzUCJ9hurkP+gbftq0MdbbDOX1uXBjY2ZcG26ZwRMPPEODfxDXdQxDRCh3pgaHqoOCOtCBr8G38+egfW6zSu/TCCuYvQzd1rmkpkLIuNoCDWLv27dsvnfSd/TQKOO4JYWq9VWoTvr2jpGgl4KNt1ZapspefZKkAM1REhkKRWaRfPj2rV/DYMblU69HhvWWA5j1o9FIb5nb4cepi9s/Lt/Cxoh7Wvh08oSdOTazDvaLU2wOJ/UrGeFTwltgfoSA5wsjfgxS41kU+1APm1QcjfCPxfAVUSYRMkAUC2X4CCMWdrfIxXH4GQUytZEp0jqIEvuIjBTT6bOJKnKpEaKOYiTiKnKBnBu+jlGJkW9KexJkGaP8scPPWRDGatqIoCxUzKU1Fw8HaMxPDRDm886bHwahKVwayhjjwDiprfV8Lfj2Dp+Ewy/Or9/98yN6e2r7tmNO7YnjPAffI3l3fntxXZO4SOL7ViMGE5YoddJ491cnn+rgU0/rG1MLBuj0REqvIzyto/vUbmJJP9klxT2XQKjJt8XX5Ni5c6arYoMa9ozQWhvygD1zmNUy8R0q+ICfUXchkZUoqDvI6nwO28XzyQkyWxNosPbEG09V8fWpaY6kokWeVyFqC6igY/f0FK1hXSPo4JE4Dg8hAVVf+0avx98iLHTAGX/78W8GB0DRsxBA0VvydmAd1nXHDN/nfUQddPmVDRuuAQQitNKZbhqCBqzIqAINoSrpSkkiC+vTth7y6tvs/j62fr24Pbe70DzBxPV666GswsNQu+1BuOhMAGln2ZZjjSwXUjnaABMGNQetunW+r6uItVFjyB3/ZYXoRtPozQerUQhGjmlkdqnmlZc0oBujjdgoIhD5wfx62BT1Jshr3rDq4i8dPEivoLVqm7AethssrFrRV3t9FhapCD5ot7AsxYF21xWGLmzaAo2fhpdtqaCiSNxzqDVa9gmwsg4Q6+ZoFnJd6w6R+1U1FzioN5d8VOuhcHyv32x5VQDTRk+siqrdug5L5aSSh6XZUuX12INSwjBzhS4aC4Wra/Z65HBkqpC5Xgq3reVrx+XYpcIWTY5Ex6nWmkMjaJa9uAytzxDmHc4Xi3fNa4OJ8aOPVQ6vf9NS4IQfe3dNwbFrLiXE8MfdfD66m8/7u97EMHqQFwU5tGIv0Ot030KpUd/ezmaCR3B4tbLhNDzvw470bJZ4Y8RhkMllQS88hYEnyDHDNnUSz/jtIBAnJup8TaRp1L1HQ7oekmqmNVzzfqqCcKgaxZnuPgghxJdtZOfq6icVt69qZ+rEsBbj7QbqbMiMHZ0UyJT3WgRKgVZ/OtNWhdShgGBtKUCH2LeGoXbR/O1bG8j3vdoGHKhjf885eZhz5+hd6/yYmvnwRf06FJI+xKOmpub9KoSlhiLqAnCueLUQH48g7vmm1qUuNCvzseKdUXZKybYkK+F43VTY/o44BsJWOvIhhcQtLtfNLh/DcwHgIIqPUKs/qiEekigdUt67CJJt9meWf8n4KUozS5UqZfUKKUrvIIFVqo7l2wgi82ON3v63CUYtI1/FnXuWsYJfoyopj/tSRFHFpTzuS3l8UUqvJy6BhZHmozS2Fp6xL23hahWDoMEgeGbQLOhOfaWcylc3OhXquQey4g5qVjzSNnGpFr1q5rVIxAPUoxitGHkRC4973BfGMEBwUJ6qt/IVPwfDhCPfNwV7WCzrNppXsxxUpU32AlX+KnXVa+jlvHVkPais9Up+DqCmCd/b4QdTXZ/ghSF/NLuwQBWwAyVDKUqGmqA5z5uHNsfmbOWGp3PGIOItoXrejyghDMf2lmOKFfhTzUl1or1eK1g5uTzPwsAr07KzyUFfEX483pBbvz78aFiJCWpENFzlPA24bQLYuSebmp+keJHlwD5QUiD8uM+tmU7Bsf/iunsFzgjDlpYWFoVQuUQETNRsfkG7WagKLu60iH3NM/mxDC+AWv7fz2p1UgNX8oxm7E/MXurCGX8h35hdkQRFxkC2nS9Fzr+4kWWfUkOuj3oFyqSDh3V7I71aGq7OwzF1En10VDuedpvLHBqFajps4+/2mXVASiO8/WkuInHJDEKdYX1MhSN8ArS6AeZAFg0JmA91ZwGmy6xRmxPUKaOxQU8+GvfwgLssQKGuLWI80RRrGDe6JqvIaZRS9yJELquKFWuk35ufupeNMFVF2FhH7RQlJMng24sBQ1X2+3cUEbbBsGJApTWBkpPJONEK9dYGo8TpO8tRtnPRhh0Z4TPTFCvfEXhYtxyrRo4KObVb3ZqMZe3cAd3S631nm97fpZvo/L7O9TGoyjh7O1dzmwSOZ7sNNA0MGjveUwAkzerzQ213a66bmt2Mw3CBmGS1wlDke5sSQ7dFAd0n7L/AFCxBjJIxPFtu3fts1/X3Uq0dMU/xyjffK78R8NLGeLxmzf+qVpXLRgz9VxPe1Kl7CR1kzUNtg+31UH8NMGhln1o0/JTQqWOdXJDsnnUbhVu3XmG4N1tQRfHfjhjv4F0Abt8vchio9xXL+DJo3TPW7CJQLy6VH5oD41Cn/3u5Hm4GexLO6nsC5Rp5JB2qU2mVu0tq6vzUelnBzgeai2g/+MqW741mV7BLMc3xekIP+9r2ph5Rzwfs1CzURUlN3FxCzvnyU/cp+tAsbH9Tq7hxFDWdepLEwBYqiSh6FTYrhZ/CA8KrZsfVFs6R1NNQtgKr2Ws4QKZ2NK5ZlLX8oL021ZJ8bi+aUFNTWzQdGNri15pdQ2cE9btgNAiPOy5Q5gHSoRcr8FxJKM9ntay8gk3pwKMqYTzknhuC70619Sal4NBM/0h6tTK76K9O/sCKZJV/6WqfPz3kzVdbBpKa5aoV+GazYZvtvfo7xYRSWEuWRwqdI6O9hxwLlWMjukexwzmGU66QGk/AV8aRcViEMHCUcvmS2Cp9aUSUSLUbcI1GsPC5A46hc4RWUYXn0mxlNJsQRFJd1DcHLJjUjadmIwMkMdPNPjUTXyNl2zUrUroQ/0FhJoNlfna2Jru+cdpyYBep5crVAqPhOQhbIaw2wCPzeDAmZ/EQvj+Hhxj6DB6Myvk7pFoeFyfm7hAuZq5pUfa2mkFrBehFqaj7VPJRDdb/K3GtSMmzyvHspVfB+4XLi5uZqme1slvjo1VDyKJ5FeEgnvVKS9tn9tmIAkmx4a+SjYiq77Dh56mrZdjMjPwuwawg3ezaoHwZ6supBtNlqJ1j1N81NOfDYEs1m3WfPvFPC7blp+7Zp+7V/3zqmp9kywqQ7mzW1PEzHGo+YeIEgMD/swSUvWoAYx6QOafmIgKqxD0K7cpCo6g/zNrDXw/rAR25+XDrAL0Z0gnqUk/Zpm4XuHUq+tR4c8PAEbTTZIWiXzNwJD30FJYOFGhNSAmk5l0bb/KBhiSSGkdqkuNCnsEIvAYudcLjtIW4ahAYzQGbnFnetyiMj4CiTvCsO8TRITZC7hSZanck5ZE+SPE4Mqa4cfMgWO9ZsSlgaRyZ2tWy/hCnPa8iMxwhqI4RwJKpHXaEJD9GIub5RTH0gOb5U9YVK07eoMDO/0xxoetfzYj/GQfFTY/Jr7Twv+wBA7wrPP/t7eXt4h8X7z5cXC9+Pr89f3fWAXls+GVJqj4XAzIkeyd4fj75P5fN92sgOAAA"

CORE_STAGE_RANGE_COMPACT_PROGRESS = False

PHASE_ORDER = [
    "safety", "resource_preflight", "state_contract", "supervisor_contract",
    "stage_release", "quick_invariants", "state_scan", "stage_sha", "recovery_provenance", "run_provenance", "stage_semantics",
    "core_stage_exact", "legacy_aws", "source_catalog", "stage_rebuild", "false_green_guard",
    "reference_v40", "core_chain_guard", "bitcoin_core", "stage_stable_snapshot",
    "stable_snapshot", "report",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def log(msg: str) -> None:
    if CORE_STAGE_RANGE_COMPACT_PROGRESS and msg.startswith("Core->Stage chunk heights=") and "raw_blocks=" in msg:
        return
    print(f"{utc_now()} V51_AUDIT {msg}", flush=True)


def sha256_file(path: Path, chunk: int = 16 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def canonical_json_hash(payload: Dict[str, Any], exclude: Sequence[str] = ()) -> str:
    skip = set(exclude)
    body = {str(k): v for k, v in payload.items() if str(k) not in skip}
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def regular(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"missing/not-regular/symlink: {path}")
    return path.resolve(strict=True)


def load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(regular(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"JSON object required: {path}")
    return obj


def read_sidecar(path: Path) -> str:
    path = regular(path)
    parts = path.read_text(encoding="ascii").strip().split()
    if not parts or HASH_RE.fullmatch(parts[0].lower()) is None:
        raise RuntimeError(f"invalid SHA256 sidecar: {path}")
    return parts[0].lower()


def verify_with_sidecar(path: Path, expected: Optional[str] = None, full: bool = True) -> str:
    p = regular(path)
    recorded = read_sidecar(Path(str(p) + ".sha256"))
    if expected and recorded != expected.lower():
        raise RuntimeError(f"recorded SHA mismatch path={p} recorded={recorded} expected={expected}")
    if full:
        actual = sha256_file(p)
        if actual != recorded:
            raise RuntimeError(f"content SHA mismatch path={p} actual={actual} expected={recorded}")
    return recorded


def file_token(path: Path) -> Dict[str, Any]:
    p = regular(path)
    st = p.stat()
    return {
        "path": str(p), "dev": int(st.st_dev), "ino": int(st.st_ino),
        "size": int(st.st_size), "mtime_ns": int(st.st_mtime_ns), "ctime_ns": int(st.st_ctime_ns),
    }


def same_token(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return all(a.get(k) == b.get(k) for k in ("path", "dev", "ino", "size", "mtime_ns", "ctime_ns"))


def atomic_immutable_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}")
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError as exc:
            raise RuntimeError(f"immutable audit artifact already exists: {path}") from exc
        tmp.unlink()
        dfd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def write_evidence(path: Path, payload: Dict[str, Any]) -> str:
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_immutable_write(path, data)
    digest = hashlib.sha256(data).hexdigest()
    atomic_immutable_write(Path(str(path) + ".sha256"), f"{digest}  {path.name}\n".encode("ascii"))
    return digest


def fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_replace_json(path: Path, payload: Dict[str, Any]) -> None:
    """Durably replace a mutable audit-progress marker."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}")
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise

def append_jsonl_fsync(path: Path, payload: Dict[str, Any]) -> None:
    """Append one durable JSONL record. Hash chaining is validated separately."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
    try:
        with os.fdopen(fd, "ab", buffering=0) as f:
            fd = -1
            f.write(line)
            os.fsync(f.fileno())
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)


class RawProgressLease:
    """Exclusive lock for one deterministic RAW-audit progress contract."""
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self.root / "LOCK"
        self.fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o640)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            self.fd = -1
            raise RuntimeError(f"RAW audit progress is already in use: {lock}") from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1


def phase(report: Dict[str, Any], name: str, fn):
    if name not in PHASE_ORDER:
        raise RuntimeError(f"unknown phase: {name}")
    started = time.monotonic()
    log(f"PHASE START {name}")
    try:
        result = fn()
        if not isinstance(result, dict):
            result = {"status": "OK", "value": result}
        result.setdefault("status", "OK")
        result["elapsed_sec"] = round(time.monotonic() - started, 3)
        report["phases"][name] = result
        log(f"PHASE {result['status']} {name} elapsed={result['elapsed_sec']}s")
        return result
    except Exception as exc:
        result = {
            "status": "BAD", "error_type": type(exc).__name__, "error": str(exc),
            "elapsed_sec": round(time.monotonic() - started, 3),
        }
        report["phases"][name] = result
        log(f"PHASE BAD {name}: {type(exc).__name__}: {exc}")
        raise


class AuditFreezeLease:
    """Hold shared supervisor, driver and state locks for the entire audit.

    Lock order matches the production mutation hierarchy: R12 supervisor -> exact-R11
    driver -> dense-core State.  Every acquisition is non-blocking and failure releases
    already-held locks.  With all three shared leases held, neither R12 mutation, a
    direct R11 writer, nor a dense-core State writer can begin while evidence is read.
    """
    def __init__(self, state: Path):
        self.state = state
        self._fds: List[Tuple[str, Path, int]] = []

    @staticmethod
    def _acquire_shared(path: Path, label: str) -> Tuple[str, Path, int]:
        p = regular(path)
        st = p.stat()
        if int(st.st_nlink) != 1:
            raise RuntimeError(f"{label} lock must be single-link regular file: {p}")
        fd = os.open(str(p), os.O_RDONLY | os.O_CLOEXEC)
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or int(fst.st_nlink) != 1:
                raise RuntimeError(f"{label} lock identity invalid after open: {p}")
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError(f"{label} lock is busy; mutation is active: {p}") from exc
            return (label, p, fd)
        except BaseException:
            os.close(fd)
            raise

    def __enter__(self):
        parent = self.state.parent
        paths = (
            (parent / ".v50-r12-supervisor.lock", "R12 supervisor"),
            (parent / ".v50-driver.lock", "R11 driver"),
            (self.state / "LOCK", "V50 state"),
        )
        try:
            for path, label in paths:
                self._fds.append(self._acquire_shared(path, label))
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def summary(self) -> Dict[str, Any]:
        return {label: {"path": str(path), "shared_lock_held": True} for label, path, _ in self._fds}

    def __exit__(self, exc_type, exc, tb):
        while self._fds:
            _, _, fd = self._fds.pop()
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

def _try_driver_lock(state: Path) -> Dict[str, Any]:
    p = state.parent / ".v50-driver.lock"
    if not p.exists():
        return {"status": "OK", "path": str(p), "exists": False, "busy": False}
    if p.is_symlink() or not p.is_file():
        return {"status": "BAD", "path": str(p), "exists": True, "busy": None, "error": "not_regular_or_symlink"}
    fd = os.open(str(p), os.O_RDONLY | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            busy = False
        except OSError:
            busy = True
        if not busy:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return {"status": "BAD" if busy else "OK", "path": str(p), "exists": True, "busy": busy}


def _try_supervisor_lock(state: Path) -> Dict[str, Any]:
    p = state.parent / ".v50-r12-supervisor.lock"
    if not p.exists():
        return {"status": "OK", "path": str(p), "exists": False, "busy": False}
    if p.is_symlink() or not p.is_file():
        return {"status": "BAD", "path": str(p), "exists": True, "busy": None, "error": "not_regular_or_symlink"}
    fd = os.open(str(p), os.O_RDONLY | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            busy = False
        except OSError:
            busy = True
        if not busy:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return {"status": "BAD" if busy else "OK", "path": str(p), "exists": True, "busy": busy}


def inspect_v50_driver(path: Path) -> Dict[str, Any]:
    p = regular(path)
    text = p.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(p))
    values: Dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except Exception:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    observed = {
        "VERSION": values.get("VERSION"),
        "EXPECTED_CORE_ID": values.get("EXPECTED_CORE_ID"),
        "EMBEDDED_CORE_SOURCE_SHA256": values.get("EMBEDDED_CORE_SOURCE_SHA256"),
    }
    expected = {
        "VERSION": EXPECTED_V50_DRIVER_VERSION,
        "EXPECTED_CORE_ID": EXPECTED_V50_CORE_ID,
        "EMBEDDED_CORE_SOURCE_SHA256": EXPECTED_V50_EMBEDDED_CORE_SOURCE_SHA256,
    }
    bad = {k: (observed.get(k), v) for k, v in expected.items() if observed.get(k) != v}
    if bad:
        raise RuntimeError(f"unsupported/unknown V50 driver contract: {bad}")
    observed_sha = sha256_file(p)
    if observed_sha != EXPECTED_R11_SHA256:
        raise RuntimeError(f"exact certified R11 driver SHA mismatch actual={observed_sha} expected={EXPECTED_R11_SHA256}")
    return {"status": "OK", "path": str(p), "sha256": observed_sha, "observed": observed}


def inspect_v50_supervisor(path: Path) -> Dict[str, Any]:
    p = regular(path)
    raw = p.read_bytes()
    observed_sha = hashlib.sha256(raw).hexdigest()
    if observed_sha != EXPECTED_R12_SUPERVISOR_SHA256:
        raise RuntimeError(f"unsupported R12 supervisor SHA256 actual={observed_sha} expected={EXPECTED_R12_SUPERVISOR_SHA256}")
    text = raw.decode("utf-8")
    tree = ast.parse(text, filename=str(p))
    values: Dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except Exception:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    expected = {
        "VERSION": EXPECTED_R12_SUPERVISOR_VERSION,
        "R11_VERSION": EXPECTED_V50_DRIVER_VERSION,
        "R11_SHA256": EXPECTED_R11_SHA256,
        "R11_CORE_ID": EXPECTED_V50_CORE_ID,
        "APPLY_LEDGER_SCHEMA": V50_APPLY_LEDGER_SCHEMA,
        "RECOVERY_LEDGER_SCHEMA": V50_RECOVERY_LEDGER_SCHEMA,
        "RUN_CONTRACT_SCHEMA": V50_RUN_CONTRACT_SCHEMA,
        "SOURCE_LINEAGE_SCHEMA": V50_SOURCE_LINEAGE_SCHEMA,
        "WINDOW_FINGERPRINT_SCHEMA": V50_WINDOW_FINGERPRINT_SCHEMA,
        "ACTIVE_RUN_SCHEMA": V50_ACTIVE_RUN_SCHEMA,
    }
    bad = {k: (values.get(k), v) for k, v in expected.items() if values.get(k) != v}
    if bad:
        raise RuntimeError(f"R12 supervisor contract mismatch: {bad}")
    embedded_b64 = values.get("R11_ENGINE_GZIP_B64")
    if not isinstance(embedded_b64, str) or not embedded_b64:
        raise RuntimeError("R12 supervisor embedded R11 payload missing")
    try:
        embedded = gzip.decompress(base64.b64decode(embedded_b64.encode("ascii")))
    except Exception as exc:
        raise RuntimeError(f"R12 embedded R11 payload decode failed: {exc}") from exc
    embedded_sha = hashlib.sha256(embedded).hexdigest()
    if embedded_sha != EXPECTED_R11_SHA256:
        raise RuntimeError(f"R12 embedded R11 SHA mismatch actual={embedded_sha} expected={EXPECTED_R11_SHA256}")
    etree = ast.parse(embedded.decode("utf-8"), filename="<embedded-r11>")
    ev: Dict[str, Any] = {}
    for node in etree.body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except Exception:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    ev[target.id] = value
    eexpected = {
        "VERSION": EXPECTED_V50_DRIVER_VERSION,
        "EXPECTED_CORE_ID": EXPECTED_V50_CORE_ID,
        "EMBEDDED_CORE_SOURCE_SHA256": EXPECTED_V50_EMBEDDED_CORE_SOURCE_SHA256,
    }
    ebad = {k: (ev.get(k), v) for k, v in eexpected.items() if ev.get(k) != v}
    if ebad:
        raise RuntimeError(f"R12 embedded R11 contract mismatch: {ebad}")
    return {
        "status": "OK",
        "path": str(p),
        "sha256": observed_sha,
        "version": values.get("VERSION"),
        "embedded_r11_sha256": embedded_sha,
        "embedded_r11_version": ev.get("VERSION"),
        "embedded_core_id": ev.get("EXPECTED_CORE_ID"),
        "embedded_core_source_sha256": ev.get("EMBEDDED_CORE_SOURCE_SHA256"),
    }


def parse_state_contract(state: Path, driver: Path, core: Path) -> Dict[str, Any]:
    state = state.resolve(strict=True)
    names = ["state.meta", "checkpoint.bin", "tx_records.bin", "outputs.bin", "closes.bin", "scripts.bin", "LOCK"]
    for n in names:
        regular(state / n)
    dirty = state / "dirty.bin"
    temp_artifacts = sorted(str(p) for p in state.glob("*.tmp.*") if p.exists())
    if dirty.exists():
        raise RuntimeError(f"dirty.bin present: read-only audit refuses implicit recovery: {dirty}")
    if temp_artifacts:
        raise RuntimeError(f"stale/unknown state temp artifacts present: {temp_artifacts[:20]}")

    meta_raw = (state / "state.meta").read_bytes()
    cp_raw = (state / "checkpoint.bin").read_bytes()
    if len(meta_raw) != META.size:
        raise RuntimeError(f"state.meta size={len(meta_raw)} expected={META.size}")
    if len(cp_raw) != CHECKPOINT.size:
        raise RuntimeError(f"checkpoint.bin size={len(cp_raw)} expected={CHECKPOINT.size}")
    mv = META.unpack(meta_raw)
    cv = CHECKPOINT.unpack(cp_raw)
    (mmagic, mver, endian, txcap, outcap, closecap, hashcap, txsz, outsz, closesz, hashsz,
     source_sha, core_sha, driver_sha, meta_checksum) = mv
    (cmagic, cver, height, block_hash, txc, outc, closec, script_bytes, live_count, live_value,
     bip0, bip1, cp_source_sha, cp_checksum) = cv
    if mmagic != b"V50META1" or mver != V50_STATE_VERSION or endian != 0x01020304:
        raise RuntimeError("V50 state.meta magic/version/endian mismatch")
    if cmagic != b"V50CP01\x00" or cver != V50_STATE_VERSION:
        raise RuntimeError("V50 checkpoint magic/version mismatch")
    if hashlib.sha256(meta_raw[:-32]).digest() != meta_checksum:
        raise RuntimeError("state.meta checksum mismatch")
    if hashlib.sha256(cp_raw[:-32]).digest() != cp_checksum:
        raise RuntimeError("checkpoint checksum mismatch")
    if source_sha != cp_source_sha:
        raise RuntimeError("state.meta/checkpoint source SHA mismatch")
    if (txsz, outsz, closesz, hashsz) != (TX_RECORD_SIZE, OUT_RECORD_SIZE, CLOSE_RECORD_SIZE, HASH_SLOT_SIZE):
        raise RuntimeError(f"V50 record-size contract mismatch: {(txsz,outsz,closesz,hashsz)}")
    if txc > txcap or outc > outcap or closec > closecap:
        raise RuntimeError("checkpoint counters exceed capacities")
    expected_sizes = {
        "tx_records.bin": txcap * TX_RECORD_SIZE,
        "outputs.bin": outcap * OUT_RECORD_SIZE,
        "closes.bin": closecap * CLOSE_RECORD_SIZE,
        "scripts.bin": script_bytes,
    }
    size_errors = {}
    for n, expected in expected_sizes.items():
        actual = (state / n).stat().st_size
        if actual != expected:
            size_errors[n] = {"actual": actual, "expected": expected}
    if size_errors:
        raise RuntimeError(f"V50 physical file size mismatch: {size_errors}")

    driver_contract = inspect_v50_driver(driver)
    driver = regular(driver)
    core = regular(core)
    actual_driver_sha = driver_contract["sha256"]
    actual_core_sha = sha256_file(core)
    if actual_driver_sha != driver_sha.hex():
        raise RuntimeError(f"driver SHA mismatch state={driver_sha.hex()} actual={actual_driver_sha}")
    if actual_core_sha != core_sha.hex():
        raise RuntimeError(f"core SHA mismatch state={core_sha.hex()} actual={actual_core_sha}")

    return {
        "status": "OK", "state": str(state), "height": int(height), "block_hash": block_hash.hex(),
        "source_sha256": source_sha.hex(), "core_sha256": core_sha.hex(), "driver_sha256": driver_sha.hex(),
        "tx_count": int(txc), "out_count": int(outc), "close_count": int(closec), "script_bytes": int(script_bytes),
        "live_count": int(live_count), "live_value_sats": int(live_value),
        "bip30_seq_plus1": [int(bip0), int(bip1)],
        "capacities": {"tx": int(txcap), "out": int(outcap), "close": int(closecap), "hash": int(hashcap)},
        "record_sizes": {"tx": int(txsz), "out": int(outsz), "close": int(closesz), "hash_slot": int(hashsz)},
        "driver": str(driver), "core": str(core), "driver_contract": driver_contract,
    }


def state_snapshot_tokens(state: Path) -> Dict[str, Dict[str, Any]]:
    """Freeze authoritative state + R12 provenance namespace identity.

    Shared locks prevent supported writers; this token map additionally detects any
    out-of-band/manual replacement, addition or removal while the audit is running.
    """
    result: Dict[str, Dict[str, Any]] = {}
    for n in ("state.meta", "checkpoint.bin", "tx_records.bin", "outputs.bin", "closes.bin", "scripts.bin", "LOCK"):
        result[n] = file_token(state / n)
    for n in (".v50-r12-supervisor.lock", ".v50-driver.lock"):
        result[f"parent/{n}"] = file_token(state.parent / n)
    dirty = state / "dirty.bin"
    result["dirty.bin"] = {"path": str(dirty), "exists": dirty.exists() or dirty.is_symlink()}
    prov = state / "provenance_r12"
    if prov.exists() or prov.is_symlink():
        if prov.is_symlink() or not prov.is_dir():
            raise RuntimeError(f"unsafe R12 provenance root: {prov}")
        for child in sorted(prov.rglob("*"), key=lambda x: str(x)):
            if child.is_symlink():
                raise RuntimeError(f"symlink forbidden in R12 provenance snapshot: {child}")
            if child.is_file():
                rel = child.relative_to(prov)
                result[f"provenance/{rel}"] = file_token(child)
            elif not child.is_dir():
                raise RuntimeError(f"unsupported artifact in R12 provenance snapshot: {child}")
    return result


def compile_audit_helper(runtime: Path) -> Path:
    runtime.mkdir(parents=True, exist_ok=True)
    src = gzip.decompress(base64.b64decode(AUDIT_HELPER_GZIP_B64.encode("ascii"), validate=True))
    if hashlib.sha256(src).hexdigest() != AUDIT_HELPER_SOURCE_SHA256:
        raise RuntimeError("embedded independent audit helper source SHA mismatch")
    src_path = runtime / f"v50_audit_state_scanner_{AUDIT_HELPER_SOURCE_SHA256[:16]}.cpp"
    bin_path = runtime / f"v50_audit_state_scanner_{AUDIT_HELPER_SOURCE_SHA256[:16]}"
    if not src_path.exists():
        atomic_immutable_write(src_path, src)
    elif sha256_file(src_path) != AUDIT_HELPER_SOURCE_SHA256:
        raise RuntimeError(f"existing audit helper source mismatch: {src_path}")
    if bin_path.exists():
        regular(bin_path)
        return bin_path
    cxx = shutil.which("g++")
    if not cxx:
        raise RuntimeError("g++ is required to build independent V50 audit scanner")
    tmp = runtime / f".{bin_path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    cp = subprocess.run([cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", str(src_path), "-o", str(tmp)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if cp.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"audit helper compile failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    os.chmod(tmp, 0o700)
    os.replace(tmp, bin_path)
    dfd = os.open(str(runtime), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return regular(bin_path)


def run_state_scanner(state: Path, runtime: Path) -> Dict[str, Any]:
    helper = compile_audit_helper(runtime)
    cp = subprocess.run([str(helper), "--state", str(state)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if cp.returncode != 0:
        raise RuntimeError(f"independent state scanner failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    lines = [x for x in cp.stdout.splitlines() if x.strip()]
    if not lines:
        raise RuntimeError("independent state scanner produced no JSON")
    obj = json.loads(lines[-1])
    if obj.get("status") != "OK":
        raise RuntimeError(f"independent state scanner not OK: {obj}")
    obj["helper_path"] = str(helper)
    obj["helper_binary_sha256"] = sha256_file(helper)
    obj["helper_source_sha256"] = AUDIT_HELPER_SOURCE_SHA256
    return obj


def file_ref(path: Path, expected_sha: str, rows: int) -> Dict[str, Any]:
    p = regular(path)
    s = read_sidecar(Path(str(p) + ".sha256"))
    if s != expected_sha.lower():
        raise RuntimeError(f"Stage sidecar mismatch path={p} recorded={s} expected={expected_sha}")
    return {"path": str(p), "sha256": s, "rows": int(rows)}


def load_legacy_stage(base: Path) -> Dict[str, Any]:
    base = base.resolve(strict=True)
    gm = base / "manifests" / "canonical_transactions_0_617698.json"
    gsha = verify_with_sidecar(gm, LEGACY_GLOBAL_SHA, True)
    obj = load_json(gm)
    if obj.get("schema") != "mybot_stage2_canonical_transactions_v1" or obj.get("release_complete") is not True:
        raise RuntimeError("legacy Stage global contract mismatch")
    if int(obj.get("start_height", -1)) != 0 or int(obj.get("end_height", -1)) != LEGACY_END:
        raise RuntimeError("legacy Stage range mismatch")
    if str(obj.get("end_hash") or LEGACY_END_HASH).lower() != LEGACY_END_HASH:
        raise RuntimeError("legacy Stage end hash mismatch")
    totals = obj.get("totals") or {}
    for k, v in LEGACY_TOTALS.items():
        if int(totals.get(k, -1)) != v:
            raise RuntimeError(f"legacy Stage total mismatch {k}: {totals.get(k)} != {v}")
    required = {
        "all_windows_release_complete", "all_window_file_sha256_verified", "height_coverage_contiguous",
        "canonical_block_hash_all", "canonical_prevhash_all", "exact_block_boundary_all",
        "context_free_tx_checks_all", "txid_wtxid_all", "merkle_root_all", "witness_commitment_all",
        "parquet_cross_table_counts_all",
    }
    val = obj.get("validation") or {}
    bad = sorted(k for k in required if val.get(k) is not True)
    if bad:
        raise RuntimeError(f"legacy Stage validation not GREEN: {bad}")
    w = base / "manifests" / "canonical_transactions_0_617698.windows.tsv"
    wsha = verify_with_sidecar(w, str((obj.get("windows_tsv") or {}).get("sha256") or ""), True)
    with w.open("r", encoding="ascii", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        rows = list(reader)
        fields = list(reader.fieldnames or [])
    expect = ["window_start", "window_end", "window_manifest_sha256", "blocks_sha256", "transactions_sha256", "inputs_sha256", "outputs_sha256", "blocks", "transactions", "inputs", "outputs"]
    if fields != expect:
        raise RuntimeError(f"legacy Stage windows.tsv schema mismatch: {fields}")
    entries: List[Dict[str, Any]] = []
    nxt = 0
    agg = {k: 0 for k in LEGACY_TOTALS}
    for row in rows:
        h1, h2 = int(row["window_start"]), int(row["window_end"])
        if h1 != nxt or h2 < h1:
            raise RuntimeError(f"legacy Stage continuity failure expected={nxt} actual={h1}..{h2}")
        nxt = h2 + 1
        wd = base / "windows" / f"window_{h1:06d}_{h2:06d}"
        mp = wd / "manifest.json"
        msha = verify_with_sidecar(mp, row["window_manifest_sha256"], True)
        mo = load_json(mp)
        if mo.get("schema") != "mybot_stage2_window_v1" or mo.get("release_complete") is not True:
            raise RuntimeError(f"legacy Stage window contract mismatch: {mp}")
        if int(mo.get("start_height", -1)) != h1 or int(mo.get("end_height", -1)) != h2:
            raise RuntimeError(f"legacy Stage window range mismatch: {mp}")
        e: Dict[str, Any] = {"h1": h1, "h2": h2, "producer": "legacy_stage2_v1", "manifest_path": str(mp.resolve()), "manifest_sha256": msha}
        for role in ("blocks", "transactions", "inputs", "outputs"):
            n = int(row[role]); agg[role] += n
            e[role] = file_ref(wd / f"{role}.parquet", row[f"{role}_sha256"], n)
        entries.append(e)
    if nxt != LEGACY_END + 1 or agg != LEGACY_TOTALS:
        raise RuntimeError("legacy Stage aggregate/coverage mismatch")
    return {"kind": "legacy", "sha256": gsha, "path": str(gm.resolve()), "start_height": 0, "end_height": LEGACY_END, "end_hash": LEGACY_END_HASH, "totals": agg, "entries": entries, "windows_sha256": wsha, "windows_path": str(w.resolve()), "validation": val}


def load_v41_stage_release(path: Path) -> Dict[str, Any]:
    path = regular(path)
    gsha = verify_with_sidecar(path, None, True)
    obj = load_json(path)
    if obj.get("schema") != "mybot-stage2-release-v2" or obj.get("release_complete") is not True:
        raise RuntimeError("V41 Stage release contract mismatch")
    start, end = int(obj.get("start_height", -1)), int(obj.get("end_height", -1))
    if start != 0 or end < LEGACY_END:
        raise RuntimeError("V41 Stage release range invalid")
    end_hash = str(obj.get("end_hash") or "").lower()
    if HASH_RE.fullmatch(end_hash) is None:
        raise RuntimeError("V41 Stage end_hash invalid")
    wobj = obj.get("windows_tsv") or {}
    wp = Path(str(wobj.get("path") or ""))
    if not wp.is_absolute():
        raise RuntimeError("V41 Stage windows_tsv path must be absolute")
    wsha = verify_with_sidecar(wp, str(wobj.get("sha256") or ""), True)
    with wp.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        rows = list(reader)
        fields = list(reader.fieldnames or [])
    expect = ["window_start", "window_end", "producer_contract", "window_manifest_path", "window_manifest_sha256", "blocks_path", "blocks_sha256", "transactions_path", "transactions_sha256", "inputs_path", "inputs_sha256", "outputs_path", "outputs_sha256", "blocks", "transactions", "inputs", "outputs"]
    if fields != expect:
        raise RuntimeError(f"V41 Stage TSV schema mismatch: {fields}")
    required_v2 = {"canonical_block_hash_all", "canonical_prevhash_all", "exact_block_boundary_all", "context_free_tx_checks_all", "txid_wtxid_all", "merkle_root_all", "witness_commitment_all", "parquet_cross_table_counts", "parquet_output_script_blob_lengths"}
    entries: List[Dict[str, Any]] = []
    nxt = 0
    agg = {k: 0 for k in LEGACY_TOTALS}
    for row in rows:
        h1, h2 = int(row["window_start"]), int(row["window_end"])
        if h1 != nxt or h2 < h1 or h2 > end:
            raise RuntimeError(f"V41 Stage continuity failure expected={nxt} actual={h1}..{h2}")
        nxt = h2 + 1
        prod = row["producer_contract"]
        mp = Path(row["window_manifest_path"])
        msha = verify_with_sidecar(mp, row["window_manifest_sha256"], True)
        mo = load_json(mp)
        if prod == "legacy_stage2_v1":
            if mo.get("schema") != "mybot_stage2_window_v1" or mo.get("release_complete") is not True:
                raise RuntimeError(f"bad legacy window under V41 release: {mp}")
        elif prod == "utxo-stage-window-v2":
            if mo.get("schema") != "utxo-stage-window-v2" or mo.get("release_complete") is not True:
                raise RuntimeError(f"bad V41 window: {mp}")
            bad = sorted(k for k in required_v2 if (mo.get("validation") or {}).get(k) is not True)
            if bad:
                raise RuntimeError(f"V41 window validation not GREEN path={mp}: {bad}")
        else:
            raise RuntimeError(f"unknown V41 Stage producer: {prod}")
        e: Dict[str, Any] = {"h1": h1, "h2": h2, "producer": prod, "manifest_path": str(mp.resolve()), "manifest_sha256": msha}
        for role in ("blocks", "transactions", "inputs", "outputs"):
            n = int(row[role]); agg[role] += n
            e[role] = file_ref(Path(row[f"{role}_path"]), row[f"{role}_sha256"], n)
        entries.append(e)
    if nxt != end + 1:
        raise RuntimeError("V41 Stage terminal coverage mismatch")
    declared = obj.get("totals") or {}
    for k, v in agg.items():
        if int(declared.get(k, -1)) != v:
            raise RuntimeError(f"V41 Stage total mismatch {k}")
    return {"kind": "v41_release", "sha256": gsha, "path": str(path), "start_height": 0, "end_height": end, "end_hash": end_hash, "totals": agg, "entries": entries, "windows_sha256": wsha, "windows_path": str(wp.resolve()), "object": obj}


def load_stage(args) -> Dict[str, Any]:
    return load_v41_stage_release(Path(args.stage_release)) if args.stage_release else load_legacy_stage(Path(args.stage_base))


def selected_entries(stage: Dict[str, Any], target: int) -> List[Dict[str, Any]]:
    out = [e for e in stage["entries"] if int(e["h1"]) <= target]
    if not out or out[0]["h1"] != 0 or int(out[-1]["h2"]) < target:
        raise RuntimeError(f"Stage does not cover 0..{target}")
    return out


def r12_source_fingerprint(stage: Dict[str, Any]) -> str:
    entries: List[Dict[str, Any]] = []
    for e in stage["entries"]:
        eo: Dict[str, Any] = {
            "h1": int(e["h1"]), "h2": int(e["h2"]), "producer": str(e["producer"]),
            "manifest_sha256": str(e["manifest_sha256"]),
        }
        for role in ("blocks", "transactions", "inputs", "outputs"):
            ref = e[role]
            eo[role] = {
                "sha256": str(ref["sha256"]), "rows": int(ref["rows"]),
                "path": str(Path(ref["path"]).resolve(strict=True)),
            }
        entries.append(eo)
    return canonical_json_hash({
        "schema": "mybot-v50-r12-source-fingerprint-v1",
        "global_manifest_sha256": str(stage["sha256"]),
        "windows_tsv_sha256": str(stage["windows_sha256"]),
        "entries": entries,
    })


def r12_window_fingerprint(stage: Dict[str, Any], h1: int, h2: int) -> str:
    selected: List[Dict[str, Any]] = []
    for e in stage["entries"]:
        if int(e["h2"]) < int(h1) or int(e["h1"]) > int(h2):
            continue
        eo: Dict[str, Any] = {"h1": int(e["h1"]), "h2": int(e["h2"])}
        for role in ("blocks", "transactions", "inputs", "outputs"):
            eo[role] = {"sha256": str(e[role]["sha256"]), "rows": int(e[role]["rows"])}
        selected.append(eo)
    if not selected:
        raise RuntimeError(f"no Stage entries for R12 window fingerprint {h1}..{h2}")
    return canonical_json_hash({
        "schema": V50_WINDOW_FINGERPRINT_SCHEMA,
        "h1": int(h1), "h2": int(h2), "entries": selected,
    })


def stage_hashes_at(stage: Dict[str, Any], heights: Sequence[int]) -> Dict[int, str]:
    wanted = sorted(set(int(x) for x in heights))
    if not wanted:
        return {}
    paths = [str(e["blocks"]["path"]) for e in stage["entries"] if int(e["h1"]) <= wanted[-1] and int(e["h2"]) >= wanted[0]]
    if not paths:
        raise RuntimeError("no Stage block payloads for requested provenance heights")
    duckdb = require_duckdb()
    con = duckdb.connect(":memory:")
    try:
        ilist = ",".join(str(x) for x in wanted)
        rows = con.execute(f"SELECT height,lower(block_hash) FROM read_parquet({sql_list(paths)},union_by_name=true) WHERE height IN ({ilist}) ORDER BY height").fetchall()
    finally:
        con.close()
    out: Dict[int, str] = {}
    for h, bh in rows:
        ih = int(h); sbh = str(bh).lower()
        if ih in out and out[ih] != sbh:
            raise RuntimeError(f"multiple Stage block hashes at provenance height={ih}")
        out[ih] = sbh
    missing = [h for h in wanted if h not in out]
    if missing:
        raise RuntimeError(f"Stage block hash lookup missing heights: {missing[:20]}")
    return out


def audit_stage_sha(stage: Dict[str, Any], target: int, mode: str) -> Dict[str, Any]:
    entries = selected_entries(stage, target)
    if mode == "manifest":
        return {"status": "WARN", "mode": "MANIFEST_SIDECAR_ONLY", "files_checked": 0, "windows_selected": len(entries), "warning": "Parquet payload SHA not rehashed; certification blocked"}
    checked = 0
    bytes_hashed = 0
    for idx, e in enumerate(entries, 1):
        for role in ("blocks", "transactions", "inputs", "outputs"):
            p = regular(Path(e[role]["path"]))
            before = file_token(p)
            actual = sha256_file(p)
            after = file_token(p)
            if not same_token(before, after):
                raise RuntimeError(f"Stage file changed during SHA read: {p}")
            if actual != e[role]["sha256"]:
                raise RuntimeError(f"Stage payload SHA mismatch role={role} path={p} actual={actual} expected={e[role]['sha256']}")
            checked += 1
            bytes_hashed += int(before["size"])
        if idx == 1 or idx % 50 == 0 or idx == len(entries):
            log(f"Stage SHA windows={idx}/{len(entries)} files={checked}")
    return {"status": "OK", "mode": "FULL_SELECTED_WINDOWS", "files_checked": checked, "windows_selected": len(entries), "bytes_hashed": bytes_hashed}


def require_duckdb():
    try:
        import duckdb
    except Exception as exc:
        raise RuntimeError("duckdb Python package is required") from exc
    if getattr(duckdb, "__version__", None) != DUCKDB_VERSION:
        raise RuntimeError(f"DuckDB version mismatch expected={DUCKDB_VERSION} actual={getattr(duckdb,'__version__',None)}")
    return duckdb



def _read_record_at(path: Path, record: struct.Struct, index: int) -> Tuple[Any, ...]:
    p = regular(path)
    if index < 0:
        raise RuntimeError(f"negative record index path={p} index={index}")
    offset = int(index) * record.size
    with p.open("rb", buffering=0) as f:
        f.seek(offset)
        data = f.read(record.size)
    if len(data) != record.size:
        raise RuntimeError(f"short record read path={p} index={index} got={len(data)} expected={record.size}")
    return record.unpack(data)


def bitcoin_subsidy_issued_sats(height: int) -> int:
    """Consensus subsidy upper bound through height, inclusive (fees do not mint coins)."""
    h = int(height)
    if h < 0:
        return 0
    blocks = h + 1
    subsidy = INITIAL_SUBSIDY_SATS
    total = 0
    while blocks > 0 and subsidy > 0:
        n = min(blocks, HALVING_INTERVAL)
        total += int(n) * int(subsidy)
        blocks -= n
        subsidy >>= 1
    return total


def quick_state_frontier(state: Path, sc: Dict[str, Any]) -> Dict[str, Any]:
    failed: List[str] = []
    tx_count = int(sc["tx_count"]); out_count = int(sc["out_count"]); close_count = int(sc["close_count"])
    if tx_count <= 0 or out_count <= 0:
        return {"status": "BAD", "failed_checks": ["nonempty_frontier_required"]}

    ftx = _read_record_at(state / "tx_records.bin", TX_RECORD, 0)
    ltx = _read_record_at(state / "tx_records.bin", TX_RECORD, tx_count - 1)
    # TxRecord: txid, first_out, height, tx_index, vout_count, flags
    if ftx[0].hex() != GENESIS_TXID:
        failed.append("first_txid_not_genesis")
    if int(ftx[2]) != 0 or int(ftx[3]) != 0:
        failed.append("first_tx_position_not_0_0")
    if int(ltx[2]) != int(sc["height"]):
        failed.append(f"last_tx_height:{ltx[2]}!={sc['height']}")
    if int(ltx[4]) < 1:
        failed.append("last_tx_zero_outputs")
    if int(ltx[1]) + int(ltx[4]) != out_count:
        failed.append("last_tx_output_frontier_mismatch")

    lo = _read_record_at(state / "outputs.bin", OUT_RECORD, out_count - 1)
    # OutputRecord: tx_seq, value_sats, script_offset, script_len, flags
    if int(lo[0]) != tx_count - 1:
        failed.append(f"last_output_owner:{lo[0]}!={tx_count - 1}")
    if int(lo[2]) + int(lo[3]) != int(sc["script_bytes"]):
        failed.append("last_output_script_frontier_mismatch")
    if int(lo[1]) < 0 or int(lo[1]) > MAX_MONEY_SATS:
        failed.append("last_output_value_out_of_range")

    last_close = None
    if close_count:
        lc = _read_record_at(state / "closes.bin", CLOSE_RECORD, close_count - 1)
        # CloseRecord: output_id, closer_tx_seq, vin, type
        last_close = {"output_id": int(lc[0]), "closer_tx_seq": int(lc[1]), "vin": int(lc[2]), "type": int(lc[3])}
        if int(lc[0]) >= out_count:
            failed.append("last_close_output_oob")
        if int(lc[1]) >= tx_count:
            failed.append("last_close_closer_tx_oob")
        if int(lc[3]) not in (1, 2):
            failed.append("last_close_type_invalid")

    return {
        "status": "BAD" if failed else "OK",
        "failed_checks": failed,
        "first_tx": {"txid": ftx[0].hex(), "height": int(ftx[2]), "tx_index": int(ftx[3])},
        "last_tx": {"txid": ltx[0].hex(), "first_out": int(ltx[1]), "height": int(ltx[2]), "tx_index": int(ltx[3]), "vout_count": int(ltx[4]), "flags": int(ltx[5])},
        "last_output": {"tx_seq": int(lo[0]), "value_sats": int(lo[1]), "script_offset": int(lo[2]), "script_len": int(lo[3]), "flags": int(lo[4])},
        "last_close": last_close,
    }


def quick_checkpoint_arithmetic(sc: Dict[str, Any]) -> Dict[str, Any]:
    failed: List[str] = []
    h = int(sc["height"]); txc = int(sc["tx_count"]); outc = int(sc["out_count"]); closec = int(sc["close_count"])
    livec = int(sc["live_count"]); livev = int(sc["live_value_sats"]); scripts = int(sc["script_bytes"])
    if txc < h + 1: failed.append("tx_count_below_block_minimum")
    if outc < txc: failed.append("out_count_below_tx_count")
    if closec > outc: failed.append("close_count_above_out_count")
    if livec > outc: failed.append("live_count_above_out_count")
    if livec + closec > outc: failed.append("eligible_partition_above_out_count")
    if min(txc, outc, closec, livec, scripts) < 0: failed.append("negative_counter")
    if livev < 0 or livev > MAX_MONEY_SATS: failed.append("live_value_out_of_money_range")
    issued = bitcoin_subsidy_issued_sats(h)
    if livev > issued: failed.append(f"live_value_above_issued_subsidy:{livev}>{issued}")
    return {
        "status": "BAD" if failed else "OK", "failed_checks": failed,
        "height": h, "tx_count": txc, "out_count": outc, "close_count": closec,
        "live_count": livec, "live_value_sats": livev, "issued_subsidy_upper_bound_sats": issued,
    }


def quick_apply_ledger_lengths(path: Path, sc: Dict[str, Any]) -> Dict[str, Any]:
    led = _validate_r12_ledger(path, V50_APPLY_LEDGER_SCHEMA, require_nonempty=True)
    rows = list(led.pop("_rows", []) or [])
    failed = list(led.get("failed_checks") or [])
    if led.get("status") != "OK":
        failed.append("apply_ledger_hash_chain_not_ok")
    if not rows:
        failed.append("apply_ledger_empty")
        return {"status": "BAD", "failed_checks": failed, "records": 0, "ledger": led}
    fields = ("state_tx_count", "state_out_count", "state_close_count", "state_script_bytes")
    prev: Optional[Dict[str, int]] = None
    summary: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows, 1):
        cur: Dict[str, int] = {}
        for k in fields:
            try:
                cur[k] = int(row.get(k))
            except Exception:
                failed.append(f"row_{idx}:{k}:invalid")
                cur[k] = -1
            if cur[k] < 0:
                failed.append(f"row_{idx}:{k}:negative")
        if prev is not None:
            for k in fields:
                if cur[k] < prev[k]:
                    failed.append(f"row_{idx}:{k}:regression:{cur[k]}<{prev[k]}")
            if row.get("record_type") in ("APPLY_COMMIT", "RECOVERED_COMMITTED_PREFIX"):
                if cur["state_tx_count"] <= prev["state_tx_count"]:
                    failed.append(f"row_{idx}:state_tx_count:not_strictly_advancing")
                if cur["state_out_count"] <= prev["state_out_count"]:
                    failed.append(f"row_{idx}:state_out_count:not_strictly_advancing")
        prev = cur
        summary.append({"record_no": row.get("record_no"), "record_type": row.get("record_type"), **cur})
    final_expected = {
        "state_tx_count": int(sc["tx_count"]), "state_out_count": int(sc["out_count"]),
        "state_close_count": int(sc["close_count"]), "state_script_bytes": int(sc["script_bytes"]),
    }
    if prev is not None:
        for k, v in final_expected.items():
            if prev[k] != v:
                failed.append(f"terminal:{k}:{prev[k]}!={v}")
    return {
        "status": "BAD" if failed else "OK", "failed_checks": failed,
        "records": len(rows), "first": summary[0] if summary else None, "last": summary[-1] if summary else None,
        "ledger": led,
    }


def quick_bip30(state: Path, sc: Dict[str, Any]) -> Dict[str, Any]:
    failed: List[str] = []
    target = int(sc["height"]); tx_count = int(sc["tx_count"])
    seqs = [int(x) for x in sc.get("bip30_seq_plus1", [])]
    if len(seqs) != len(BIP30):
        return {"status": "BAD", "failed_checks": ["bip30_checkpoint_cardinality"]}
    checks: List[Dict[str, Any]] = []
    for idx, b in enumerate(BIP30):
        seqp1 = seqs[idx]
        if target < int(b["later"]):
            if seqp1 != 0:
                failed.append(f"bip30_{idx}:premature_seq_plus1:{seqp1}")
            checks.append({"index": idx, "target_before_later": True, "seq_plus1": seqp1})
            continue
        if seqp1 <= 0 or seqp1 > tx_count:
            failed.append(f"bip30_{idx}:seq_plus1_oob:{seqp1}")
            checks.append({"index": idx, "seq_plus1": seqp1})
            continue
        tr = _read_record_at(state / "tx_records.bin", TX_RECORD, seqp1 - 1)
        got = {"txid": tr[0].hex(), "height": int(tr[2]), "tx_index": int(tr[3]), "flags": int(tr[5]), "seq_plus1": seqp1}
        if got["txid"] != str(b["txid"]): failed.append(f"bip30_{idx}:txid")
        if got["height"] != int(b["later"]): failed.append(f"bip30_{idx}:height")
        if got["tx_index"] != 0: failed.append(f"bip30_{idx}:tx_index")
        if (got["flags"] & TX_FLAG_COINBASE) == 0: failed.append(f"bip30_{idx}:not_coinbase")
        checks.append({"index": idx, **got})
    return {"status": "BAD" if failed else "OK", "failed_checks": failed, "checks": checks}


def _bitcoin_cli_json(cli: Path, method: str, datadir: Optional[str]) -> Dict[str, Any]:
    cmd = [str(cli)]
    if datadir: cmd.append(f"-datadir={datadir}")
    cmd.append(method)
    cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if cp.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {method} failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    obj = json.loads(cp.stdout)
    if not isinstance(obj, dict):
        raise RuntimeError(f"bitcoin-cli {method} did not return JSON object")
    return obj


def quick_core_tip_anchor(sc: Dict[str, Any], explicit_cli: Optional[str], datadir: Optional[str], rpc_url: str, rpc_cookie: Optional[str], rpc_timeout: int) -> Dict[str, Any]:
    """Cheap independent Core anchor.

    Prefer bitcoin-cli when it is usable, but do not treat mere presence of the
    binary as proof that its authentication context is configured.  If CLI
    access fails, fall back to the same cookie-authenticated local RPC transport
    used by the full Core->Stage proof.  A semantic mismatch observed through a
    working transport is never hidden by fallback; only transport/auth failure
    triggers the alternate access path.
    """
    target = int(sc["height"]); expected = str(sc["block_hash"]).lower()
    cli = bitcoin_cli_path(explicit_cli)
    transport = None
    access_notes: List[str] = []
    info: Dict[str, Any]
    genesis: str
    observed: str

    cli_ok = False
    if cli is not None:
        try:
            info = _bitcoin_cli_json(cli, "getblockchaininfo", datadir)
            genesis = core_hash(cli, 0, datadir)
            observed = core_hash(cli, target, datadir)
            transport = f"bitcoin-cli:{cli}"
            cli_ok = True
        except Exception as exc:
            access_notes.append(f"bitcoin_cli_unavailable:{type(exc).__name__}:{exc}")

    if not cli_ok:
        cookie = _rpc_cookie(rpc_cookie, datadir)
        if cookie is None:
            return {
                "status": "BAD",
                "failed_checks": ["bitcoin_core_access_unavailable"],
                "access_notes": access_notes,
                "certification_blocking": True,
            }
        rpc = BitcoinRPC(rpc_url, cookie, timeout=max(5, int(rpc_timeout)))
        try:
            info = rpc.call("getblockchaininfo")
            genesis, observed = rpc.batch([("getblockhash", [0]), ("getblockhash", [target])])
            genesis = str(genesis).lower(); observed = str(observed).lower()
            transport = f"rpc:{rpc_url}"
        except Exception as exc:
            access_notes.append(f"rpc_unavailable:{type(exc).__name__}:{exc}")
            return {
                "status": "BAD",
                "failed_checks": ["bitcoin_core_access_unavailable"],
                "access_notes": access_notes,
                "certification_blocking": True,
            }
        finally:
            rpc.close()

    failed: List[str] = []
    if str(info.get("chain") or "") != "main": failed.append(f"chain:{info.get('chain')}!=main")
    try: blocks = int(info.get("blocks", -1))
    except Exception: blocks = -1
    if blocks < target: failed.append(f"core_blocks:{blocks}<{target}")
    if genesis != GENESIS_HASH: failed.append("genesis_hash")
    if observed != expected: failed.append(f"target_hash:{observed}!={expected}")
    return {
        "status": "BAD" if failed else "OK", "failed_checks": failed, "transport": transport,
        "access_notes": access_notes,
        "chain": info.get("chain"), "core_blocks": blocks, "target_height": target,
        "target_hash": observed, "expected_target_hash": expected, "genesis_hash": genesis,
    }


def quick_stage_footer_lengths(stage: Dict[str, Any], target: int) -> Dict[str, Any]:
    entries = selected_entries(stage, target)
    duckdb = require_duckdb()
    con = duckdb.connect(":memory:")
    failed: List[str] = []
    checked = 0
    try:
        for role in ("blocks", "transactions", "inputs", "outputs"):
            refs = [(str(Path(e[role]["path"]).resolve(strict=True)), int(e[role]["rows"])) for e in entries]
            declared = {p: n for p, n in refs}
            if len(declared) != len(refs):
                failed.append(f"{role}:duplicate_payload_path")
                continue
            observed: Dict[str, int] = {}
            paths = list(declared)
            # File-level Parquet metadata only: no payload columns/pages are scanned.
            # Use exact paths (not globs) so an unrelated parquet in the same directory cannot influence the proof.
            for pos in range(0, len(paths), 64):
                chunk = paths[pos:pos + 64]
                q = " UNION ALL ".join(
                    f"SELECT file_name,num_rows::BIGINT FROM parquet_file_metadata({sql_quote(x)})" for x in chunk
                )
                for fn, n in con.execute(q).fetchall():
                    rp = str(Path(str(fn)).resolve(strict=True))
                    if rp in observed:
                        failed.append(f"{role}:duplicate_metadata_row:{rp}")
                    observed[rp] = int(n)
            for path, expected_rows in declared.items():
                got = observed.get(path)
                if got is None:
                    failed.append(f"{role}:missing_footer_count:{path}")
                elif int(got) != int(expected_rows):
                    failed.append(f"{role}:row_count:{path}:{got}!={expected_rows}")
                checked += 1
            extras = sorted(set(observed) - set(declared))
            if extras:
                failed.append(f"{role}:unexpected_paths:{extras[:5]}")
    finally:
        con.close()
    return {
        "status": "BAD" if failed else "OK", "failed_checks": failed,
        "windows_checked": len(entries), "files_checked": checked,
        "method": "DUCKDB_PARQUET_FILE_METADATA_NUM_ROWS",
    }


def quick_invariants(state: Path, sc: Dict[str, Any], stage: Dict[str, Any], apply_ledger: Path, explicit_cli: Optional[str], datadir: Optional[str], rpc_url: str, rpc_cookie: Optional[str], rpc_timeout: int) -> Dict[str, Any]:
    checks: Dict[str, Dict[str, Any]] = {}
    specs = (
        ("state_frontier", lambda: quick_state_frontier(state, sc)),
        ("checkpoint_arithmetic", lambda: quick_checkpoint_arithmetic(sc)),
        ("ledger_no_length_regression", lambda: quick_apply_ledger_lengths(apply_ledger, sc)),
        ("bip30_fast", lambda: quick_bip30(state, sc)),
        ("core_tip_anchor", lambda: quick_core_tip_anchor(sc, explicit_cli, datadir, rpc_url, rpc_cookie, rpc_timeout)),
        ("parquet_footer_lengths", lambda: quick_stage_footer_lengths(stage, int(sc["height"]))),
    )
    failed: List[str] = []
    for name, fn in specs:
        started = time.monotonic()
        try:
            result = fn()
            if not isinstance(result, dict): result = {"status": "BAD", "failed_checks": ["invalid_result_type"]}
        except Exception as exc:
            result = {"status": "BAD", "failed_checks": [f"exception:{type(exc).__name__}:{exc}"]}
        result["elapsed_sec"] = round(time.monotonic() - started, 3)
        checks[name] = result
        if result.get("status") != "OK":
            failed.extend([f"{name}:{x}" for x in (result.get("failed_checks") or [result.get("status")])])
        log(f"quick invariant {name} status={result.get('status')} elapsed={result['elapsed_sec']}s")
    return {
        "status": "BAD" if failed else "OK",
        "failed_checks": failed,
        "checks": checks,
        "policy": "all six fail-fast invariants mandatory before full state scan",
    }


def current_runtime_epoch() -> Dict[str, Any]:
    """Independently recompute the immutable R12.9 runtime epoch."""
    if sys.platform != "linux":
        raise RuntimeError("R12.9 production provenance requires Linux")
    expected_python = Path("/root/mybot/.venv/bin/python3").resolve(strict=True)
    actual_python = Path(sys.executable).resolve(strict=True)
    if actual_python != expected_python:
        raise RuntimeError(f"production Python mismatch expected={expected_python} actual={actual_python}")
    duckdb = require_duckdb()
    try:
        import _duckdb
    except Exception as exc:
        raise RuntimeError("native _duckdb module is required for runtime-epoch proof") from exc
    fields = {
        "python_runtime_sha256": sha256_file(regular(actual_python)),
        "duckdb_python_sha256": sha256_file(regular(Path(duckdb.__file__).resolve(strict=True))),
        "duckdb_native_sha256": sha256_file(regular(Path(_duckdb.__file__).resolve(strict=True))),
        "duckdb_version": DUCKDB_VERSION,
    }
    fields["runtime_contract_sha256"] = canonical_json_hash({"schema": "mybot-v50-r12-runtime-epoch-v1", **fields})
    return fields


def sql_quote(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def sql_list(paths: Sequence[str]) -> str:
    return "[" + ",".join(sql_quote(x) for x in paths) + "]"


_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b)\s*$", re.IGNORECASE)


def parse_size_bytes(value: str) -> int:
    text = str(value or "").strip()
    m = _SIZE_RE.fullmatch(text)
    if not m:
        raise RuntimeError(f"invalid size value: {value!r}")
    number = float(m.group(1))
    unit = m.group(2).lower()
    factors = {
        "b": 1,
        "kb": 1000, "mb": 1000**2, "gb": 1000**3, "tb": 1000**4,
        "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4,
    }
    if unit not in factors:
        raise RuntimeError(f"unsupported size unit: {value!r}")
    return int(number * factors[unit])


def resource_preflight(tmp: Path, temp_max: str, min_free_tmp: str) -> Dict[str, Any]:
    tmp.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(tmp)
    temp_max_bytes = parse_size_bytes(temp_max)
    reserve_bytes = parse_size_bytes(min_free_tmp)
    required_free = temp_max_bytes + reserve_bytes
    failed: List[str] = []
    if int(usage.free) < required_free:
        failed.append(
            f"tmp_free_below_configured_spill_plus_reserve:{usage.free}<{required_free}"
        )
    return {
        "status": "BAD" if failed else "OK",
        "tmp_path": str(tmp.resolve(strict=False)),
        "free_bytes": int(usage.free),
        "total_bytes": int(usage.total),
        "temp_max": str(temp_max),
        "temp_max_bytes": temp_max_bytes,
        "min_free_tmp": str(min_free_tmp),
        "reserve_bytes": reserve_bytes,
        "required_free_bytes": required_free,
        "failed_checks": failed,
    }


def _duckdb_setting(con, name: str) -> str:
    row = con.execute(
        "SELECT value FROM duckdb_settings() WHERE name=?", [str(name)]
    ).fetchone()
    if row is None:
        raise RuntimeError(f"DuckDB setting not exposed after SET: {name}")
    return str(row[0])


def _size_readback_slack_bytes(text: str) -> int:
    """Return one display quantum for a DuckDB human-readable size setting."""
    rendered = str(text).strip()
    match = _SIZE_RE.fullmatch(rendered)
    if not match:
        raise RuntimeError(f"DuckDB size readback invalid: {rendered!r}")
    number = match.group(1)
    unit = match.group(2).lower()
    factors = {
        "b": 1,
        "kb": 1000, "mb": 1000**2, "gb": 1000**3, "tb": 1000**4,
        "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4,
    }
    decimals = len(number.split(".", 1)[1]) if "." in number else 0
    quantum = max(1, factors[unit] // (10**decimals))
    return max(1 << 20, quantum)


def _verify_duckdb_size_setting(name: str, observed_text: str, requested_text: str) -> None:
    observed_bytes = parse_size_bytes(observed_text)
    requested_bytes = parse_size_bytes(requested_text)
    slack = _size_readback_slack_bytes(observed_text)
    if abs(observed_bytes - requested_bytes) > slack:
        raise RuntimeError(
            f"DuckDB {name} readback mismatch beyond display precision: "
            f"observed={observed_text} requested={requested_text} slack_bytes={slack}"
        )


def configure_duckdb(con, memory: str, tmp: Path, temp_max: str, threads: int) -> Dict[str, Any]:
    tmp.mkdir(parents=True, exist_ok=True)
    requested_threads = max(1, int(threads))
    con.execute(f"SET memory_limit={sql_quote(memory)}")
    con.execute(f"SET threads={requested_threads}")
    con.execute(f"SET temp_directory={sql_quote(str(tmp))}")
    con.execute(f"SET max_temp_directory_size={sql_quote(temp_max)}")
    con.execute("SET preserve_insertion_order=false")

    observed = {
        "memory_limit": _duckdb_setting(con, "memory_limit"),
        "threads": _duckdb_setting(con, "threads"),
        "temp_directory": _duckdb_setting(con, "temp_directory"),
        "max_temp_directory_size": _duckdb_setting(con, "max_temp_directory_size"),
        "preserve_insertion_order": _duckdb_setting(con, "preserve_insertion_order"),
    }
    # Fail closed if DuckDB did not retain the requested resource envelope.
    # Human-readable size settings are rounded on readback, so compare within
    # one displayed unit rather than requiring byte-for-byte equality.
    _verify_duckdb_size_setting("memory_limit", observed["memory_limit"], str(memory))
    _verify_duckdb_size_setting("max_temp_directory_size", observed["max_temp_directory_size"], str(temp_max))

    requested_temp_dir = Path(tmp).resolve(strict=False)
    observed_temp_dir = Path(str(observed["temp_directory"])).resolve(strict=False)
    if observed_temp_dir != requested_temp_dir:
        raise RuntimeError(
            f"DuckDB temp_directory readback mismatch: observed={observed_temp_dir} requested={requested_temp_dir}"
        )
    try:
        observed_threads = int(observed["threads"])
    except Exception as exc:
        raise RuntimeError(f"DuckDB threads readback invalid: {observed['threads']!r}") from exc
    if observed_threads != requested_threads:
        raise RuntimeError(
            f"DuckDB threads readback mismatch observed={observed_threads} requested={requested_threads}"
        )
    if observed["preserve_insertion_order"].strip().lower() not in {"false", "0"}:
        raise RuntimeError(
            f"DuckDB preserve_insertion_order readback is not false: {observed['preserve_insertion_order']!r}"
        )
    observed["requested"] = {
        "memory_limit": str(memory),
        "threads": requested_threads,
        "temp_directory": str(tmp),
        "max_temp_directory_size": str(temp_max),
        "preserve_insertion_order": False,
    }
    return observed


def bind_stage_views(con, stage: Dict[str, Any], target: int) -> Dict[str, Any]:
    entries = selected_entries(stage, target)
    paths = {role: [str(e[role]["path"]) for e in entries] for role in ("blocks", "transactions", "inputs", "outputs")}
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_block AS
        SELECT height::BIGINT height, lower(block_hash::VARCHAR) block_hash,
               lower(prev_hash::VARCHAR) prev_hash, block_time::BIGINT block_time,
               tx_count::BIGINT tx_count
        FROM read_parquet({sql_list(paths['blocks'])}, union_by_name=true)
        WHERE height BETWEEN 0 AND {int(target)}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_tx AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, is_coinbase::BOOLEAN is_coinbase,
               vin_count::BIGINT vin_count, vout_count::BIGINT vout_count
        FROM read_parquet({sql_list(paths['transactions'])}, union_by_name=true)
        WHERE height BETWEEN 0 AND {int(target)}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_in AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vin_index::BIGINT vin_index,
               lower(prev_txid::VARCHAR) prev_txid, prev_vout::UBIGINT prev_vout
        FROM read_parquet({sql_list(paths['inputs'])}, union_by_name=true)
        WHERE height BETWEEN 0 AND {int(target)}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_out AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vout::BIGINT vout,
               value_sats::BIGINT value_sats, script_pubkey::BLOB script_pubkey,
               script_pubkey_size::BIGINT script_pubkey_size
        FROM read_parquet({sql_list(paths['outputs'])}, union_by_name=true)
        WHERE height BETWEEN 0 AND {int(target)}
    """)
    return {"windows": len(entries), "paths": {k: len(v) for k, v in paths.items()}}


def stage_semantics_global(con, target: int, state_contract: Dict[str, Any]) -> Dict[str, Any]:
    failed: List[str] = []
    warnings: List[str] = []
    block = con.execute("""
        SELECT count(*),min(height),max(height),count(DISTINCT height),count(DISTINCT block_hash),
               count(*) FILTER (WHERE height IS NULL OR block_hash IS NULL OR prev_hash IS NULL OR tx_count<1),
               count(*) FILTER (WHERE NOT regexp_full_match(block_hash,'[0-9a-f]{64}') OR NOT regexp_full_match(prev_hash,'[0-9a-f]{64}'))
        FROM stage_block
    """).fetchone()
    block_rows, bmin, bmax, bdh, bdb, bbad, bhashbad = [int(x or 0) for x in block]
    if (block_rows, bmin, bmax, bdh, bdb) != (target + 1, 0, target, target + 1, target + 1):
        failed.append(f"block_prefix:{block_rows},{bmin},{bmax},{bdh},{bdb}:target={target}")
    if bbad or bhashbad:
        failed.append(f"block_bad_fields:{bbad}:hash_format={bhashbad}")
    chain_bad = int(con.execute("""
        WITH x AS (
          SELECT height,block_hash,prev_hash,lag(block_hash) OVER (ORDER BY height) AS prior_hash
          FROM stage_block
        )
        SELECT count(*) FROM x
        WHERE (height=0 AND prev_hash<>repeat('0',64))
           OR (height>0 AND (prior_hash IS NULL OR prev_hash<>prior_hash))
    """).fetchone()[0] or 0)
    if chain_bad:
        failed.append(f"prevhash_chain_bad:{chain_bad}")
    tip = con.execute("SELECT block_hash FROM stage_block WHERE height=?", [target]).fetchone()
    tip_hash = str(tip[0]) if tip else None
    if tip_hash != state_contract["block_hash"]:
        failed.append(f"stage_state_tip_hash:{tip_hash}!={state_contract['block_hash']}")

    tx = con.execute("""
        SELECT count(*),
          count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR length(txid)<>64 OR vin_count<1 OR vout_count<1),
          count(*) FILTER (WHERE txid=repeat('0',64) OR NOT regexp_full_match(txid,'[0-9a-f]{64}'))
        FROM stage_tx
    """).fetchone()
    tx_rows, tx_bad, tx_zero = [int(x or 0) for x in tx]
    if tx_bad or tx_zero:
        failed.append(f"tx_bad_fields:{tx_bad}:zero_txid={tx_zero}")
    tx_groups_bad = int(con.execute("""
        SELECT count(*) FROM (
          SELECT height,count(*) n,min(tx_index) mn,max(tx_index) mx,count(DISTINCT tx_index) di,
                 sum(CASE WHEN is_coinbase THEN 1 ELSE 0 END) cb,
                 max(CASE WHEN tx_index=0 AND is_coinbase THEN 1 ELSE 0 END) cb0,
                 max(CASE WHEN tx_index<>0 AND is_coinbase THEN 1 ELSE 0 END) cb_nonzero
          FROM stage_tx GROUP BY height
        ) q
        WHERE mn<>0 OR mx<>n-1 OR di<>n OR cb<>1 OR cb0<>1 OR cb_nonzero<>0
    """).fetchone()[0] or 0)
    if tx_groups_bad:
        failed.append(f"tx_index_or_coinbase_groups_bad:{tx_groups_bad}")
    block_tx_mismatch = int(con.execute("""
        WITH t AS (SELECT height,count(*) n FROM stage_tx GROUP BY height)
        SELECT count(*) FROM stage_block b LEFT JOIN t USING(height)
        WHERE coalesce(t.n,-1)<>b.tx_count
    """).fetchone()[0] or 0)
    if block_tx_mismatch:
        failed.append(f"block_tx_count_mismatch:{block_tx_mismatch}")

    inp = con.execute("""
        SELECT count(*),
          count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR vin_index IS NULL OR prev_txid IS NULL OR prev_vout IS NULL),
          count(*) FILTER (WHERE NOT regexp_full_match(txid,'[0-9a-f]{64}') OR NOT regexp_full_match(prev_txid,'[0-9a-f]{64}'))
        FROM stage_in
    """).fetchone()
    in_rows, in_bad, in_hashbad = [int(x or 0) for x in inp]
    if in_bad or in_hashbad:
        failed.append(f"input_bad_fields:{in_bad}:hash_format={in_hashbad}")
    in_groups_bad = int(con.execute("""
        WITH g AS (
          SELECT i.height,i.tx_index,count(*) n,min(i.vin_index) mn,max(i.vin_index) mx,count(DISTINCT i.vin_index) di,
                 max(t.vin_count) expected,max(CASE WHEN t.is_coinbase THEN 1 ELSE 0 END) cb,
                 sum(CASE WHEN i.prev_txid=repeat('0',64) AND i.prev_vout=4294967295 THEN 1 ELSE 0 END) nullprev
          FROM stage_in i JOIN stage_tx t USING(height,tx_index,txid)
          GROUP BY i.height,i.tx_index
        )
        SELECT count(*) FROM g
        WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>expected OR (cb=1 AND (n<>1 OR nullprev<>1)) OR (cb=0 AND nullprev<>0)
    """).fetchone()[0] or 0)
    if in_groups_bad:
        failed.append(f"input_dense_or_coinbase_prevout_bad_groups:{in_groups_bad}")
    input_orphan_tx = int(con.execute("""
        SELECT count(*)
        FROM stage_in i
        LEFT JOIN stage_tx t USING(height,tx_index,txid)
        WHERE t.txid IS NULL
    """).fetchone()[0] or 0)
    if input_orphan_tx:
        failed.append(f"input_rows_without_exact_owner_tx:{input_orphan_tx}")
    missing_input_tx = int(con.execute("""
        SELECT count(*) FROM stage_tx t LEFT JOIN (SELECT height,tx_index,txid,count(*) n FROM stage_in GROUP BY 1,2,3) i USING(height,tx_index,txid)
        WHERE coalesce(i.n,-1)<>t.vin_count
    """).fetchone()[0] or 0)
    if missing_input_tx:
        failed.append(f"tx_input_cardinality_mismatch:{missing_input_tx}")

    out = con.execute("""
        SELECT count(*),coalesce(sum(script_pubkey_size),0),
          count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR vout IS NULL OR value_sats IS NULL OR script_pubkey IS NULL OR script_pubkey_size IS NULL),
          count(*) FILTER (WHERE NOT regexp_full_match(txid,'[0-9a-f]{64}') OR vout<0 OR value_sats<0 OR value_sats>? OR script_pubkey_size<0 OR octet_length(script_pubkey)<>script_pubkey_size)
        FROM stage_out
    """, [MAX_MONEY_SATS]).fetchone()
    out_rows, script_bytes, out_bad, out_sem_bad = [int(x or 0) for x in out]
    if out_bad or out_sem_bad:
        failed.append(f"output_bad_fields:{out_bad}:semantic={out_sem_bad}")
    out_groups_bad = int(con.execute("""
        WITH g AS (
          SELECT o.height,o.tx_index,count(*) n,min(o.vout) mn,max(o.vout) mx,count(DISTINCT o.vout) di,max(t.vout_count) expected
          FROM stage_out o JOIN stage_tx t USING(height,tx_index,txid)
          GROUP BY o.height,o.tx_index
        )
        SELECT count(*) FROM g WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>expected
    """).fetchone()[0] or 0)
    if out_groups_bad:
        failed.append(f"output_dense_groups_bad:{out_groups_bad}")
    output_orphan_tx = int(con.execute("""
        SELECT count(*)
        FROM stage_out o
        LEFT JOIN stage_tx t USING(height,tx_index,txid)
        WHERE t.txid IS NULL
    """).fetchone()[0] or 0)
    if output_orphan_tx:
        failed.append(f"output_rows_without_exact_owner_tx:{output_orphan_tx}")
    missing_output_tx = int(con.execute("""
        SELECT count(*) FROM stage_tx t LEFT JOIN (SELECT height,tx_index,txid,count(*) n FROM stage_out GROUP BY 1,2,3) o USING(height,tx_index,txid)
        WHERE coalesce(o.n,-1)<>t.vout_count
    """).fetchone()[0] or 0)
    if missing_output_tx:
        failed.append(f"tx_output_cardinality_mismatch:{missing_output_tx}")
    tx_value_bad = int(con.execute("""
        SELECT count(*) FROM (
          SELECT height,tx_index,sum(value_sats) total FROM stage_out GROUP BY height,tx_index
        ) q WHERE total<0 OR total>?
    """, [MAX_MONEY_SATS]).fetchone()[0] or 0)
    if tx_value_bad:
        failed.append(f"transaction_output_total_out_of_range:{tx_value_bad}")

    if tx_rows != int(state_contract["tx_count"]):
        failed.append(f"stage_state_tx_count:{tx_rows}!={state_contract['tx_count']}")
    if out_rows != int(state_contract["out_count"]):
        failed.append(f"stage_state_out_count:{out_rows}!={state_contract['out_count']}")
    if script_bytes != int(state_contract["script_bytes"]):
        failed.append(f"stage_state_script_bytes:{script_bytes}!={state_contract['script_bytes']}")

    duplicate_groups = con.execute("""
        SELECT txid,list(height ORDER BY height),list(tx_index ORDER BY height,tx_index),count(*)
        FROM stage_tx GROUP BY txid HAVING count(*)>1 ORDER BY txid
    """).fetchall()
    expected_dups = []
    for b in BIP30:
        heights = [x for x in (b["early"], b["later"]) if x <= target]
        if len(heights) == 2:
            expected_dups.append((b["txid"], heights, [0, 0], 2))
    normalized_dups = [(str(r[0]), [int(x) for x in r[1]], [int(x) for x in r[2]], int(r[3])) for r in duplicate_groups]
    if normalized_dups != expected_dups:
        failed.append(f"duplicate_txid_contract:{normalized_dups}!={expected_dups}")

    bip30_payload_bad = 0
    for b in BIP30:
        if b["later"] > target:
            continue
        row = con.execute("""
            WITH a AS (SELECT vout,value_sats,script_pubkey,script_pubkey_size FROM stage_out WHERE txid=? AND height=?),
                 z AS (SELECT vout,value_sats,script_pubkey,script_pubkey_size FROM stage_out WHERE txid=? AND height=?)
            SELECT
              (SELECT count(*) FROM a),(SELECT count(*) FROM z),
              (SELECT count(*) FROM a FULL OUTER JOIN z USING(vout)
               WHERE a.vout IS NULL OR z.vout IS NULL OR a.value_sats<>z.value_sats OR a.script_pubkey_size<>z.script_pubkey_size OR a.script_pubkey<>z.script_pubkey)
        """, [b["txid"], b["early"], b["txid"], b["later"]]).fetchone()
        if int(row[0] or 0) <= 0 or int(row[0] or 0) != int(row[1] or 0) or int(row[2] or 0) != 0:
            bip30_payload_bad += 1
    if bip30_payload_bad:
        failed.append(f"BIP30_payload_mismatch_pairs:{bip30_payload_bad}")

    false_green: List[str] = []
    if block_rows > 0 and tx_rows > block_rows and in_rows == 0:
        false_green.append("FALSE_GREEN_EMPTY_INPUTS_WITH_NONTRIVIAL_TX_SOURCE")
    if tx_rows > 0 and out_rows == 0:
        false_green.append("FALSE_GREEN_EMPTY_OUTPUTS_WITH_NONEMPTY_TX_SOURCE")
    if missing_input_tx or input_orphan_tx:
        false_green.append("FALSE_GREEN_INPUT_COVERAGE_INCOMPLETE")
    if missing_output_tx or output_orphan_tx:
        false_green.append("FALSE_GREEN_OUTPUT_COVERAGE_INCOMPLETE")
    if false_green:
        failed.extend(false_green)

    return {
        "status": "OK" if not failed else "BAD", "failed_checks": failed, "warnings": warnings,
        "target": target, "tip_hash": tip_hash,
        "block_rows": block_rows, "tx_rows": tx_rows, "input_rows": in_rows, "output_rows": out_rows,
        "input_rows_without_exact_owner_tx": input_orphan_tx, "output_rows_without_exact_owner_tx": output_orphan_tx,
        "script_bytes": script_bytes, "duplicate_txid_groups": normalized_dups,
        "false_green_guard_status": "OK" if not false_green else "BAD_FALSE_GREEN_RISK",
        "false_green_failed_checks": false_green,
        "coverage_status": "OK" if not missing_input_tx and not missing_output_tx and not input_orphan_tx and not output_orphan_tx else "GAP",
    }



class StageSemanticsProgressLease:
    """Exclusive lease for one deterministic bounded Stage-semantics contract."""
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self.root / "LOCK"
        self.fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o640)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd); self.fd = -1
            raise RuntimeError(f"Stage semantics progress is already in use: {lock}") from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd); self.fd = -1


def _process_rss_bytes() -> int:
    try:
        with open("/proc/self/status", "r", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


def _tree_size_bytes(path: Path) -> int:
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for name in files:
                try:
                    total += int(os.stat(os.path.join(root, name), follow_symlinks=False).st_size)
                except OSError:
                    pass
    except Exception:
        pass
    return total


class _ResourceSampler:
    """Low-overhead peak RSS/temp sampler for one isolated semantic window."""
    def __init__(self, temp_path: Path, interval: float = 1.0):
        self.temp_path = temp_path
        self.interval = max(0.05, float(interval))
        self.peak_rss = 0
        self.peak_temp = 0
        self.samples = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _sample(self) -> None:
        self.peak_rss = max(self.peak_rss, _process_rss_bytes())
        self.peak_temp = max(self.peak_temp, _tree_size_bytes(self.temp_path))
        self.samples += 1

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample()

    def __enter__(self):
        self._sample()
        self._thread = threading.Thread(target=self._run, name="v51-stage-semantics-resource-sampler", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._sample()


def _stage_semantics_plan(stage: Dict[str, Any], target: int) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    expected = 0
    for e in selected_entries(stage, target):
        h1 = max(0, int(e["h1"])); h2 = min(target, int(e["h2"]))
        if h1 != expected or h2 < h1:
            raise RuntimeError(f"Stage semantics plan continuity failure expected={expected} actual={h1}..{h2}")
        plan.append({"window_no": len(plan), "h1": h1, "h2": h2, "entry": e})
        expected = h2 + 1
        if h2 == target:
            break
    if not plan or expected != target + 1:
        raise RuntimeError(f"Stage semantics plan terminal mismatch next={expected} target={target}")
    return plan


def _stage_semantics_contract(*, auditor_sha256: str, stage: Dict[str, Any], target: int,
                              state_contract: Dict[str, Any], plan: Sequence[Dict[str, Any]],
                              stage_token_digest: Optional[str] = None) -> Dict[str, Any]:
    body = {
        "schema": STAGE_SEMANTICS_PROGRESS_SCHEMA,
        "engine": STAGE_SEMANTICS_ENGINE,
        "auditor_sha256": str(auditor_sha256),
        "stage_manifest_sha256": str(stage["sha256"]),
        "stage_windows_sha256": str(stage["windows_sha256"]),
        "target": int(target),
        "state_block_hash": str(state_contract["block_hash"]),
        "state_source_sha256": str(state_contract["source_sha256"]),
        "state_tx_count": int(state_contract["tx_count"]),
        "state_out_count": int(state_contract["out_count"]),
        "state_script_bytes": int(state_contract["script_bytes"]),
        "stage_snapshot_token_digest": str(stage_token_digest or "NOT_SUPPLIED"),
        "windows": [
            {"window_no": int(x["window_no"]), "h1": int(x["h1"]), "h2": int(x["h2"]),
             "manifest_sha256": str(x["entry"]["manifest_sha256"])} for x in plan
        ],
    }
    body["contract_id"] = canonical_json_hash(body)
    return body


def _load_stage_semantics_records(path: Path, contract: Dict[str, Any], plan: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    prev = None
    with regular(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict) or obj.get("schema") != STAGE_SEMANTICS_RECORD_SCHEMA:
                raise RuntimeError(f"Stage semantics progress schema mismatch line={line_no}")
            idx = len(records)
            if idx >= len(plan):
                raise RuntimeError("Stage semantics progress has more records than current plan")
            item = plan[idx]
            if str(obj.get("contract_id")) != str(contract["contract_id"]):
                raise RuntimeError(f"Stage semantics progress contract mismatch line={line_no}")
            if int(obj.get("record_no", -1)) != idx + 1 or int(obj.get("window_no", -1)) != idx:
                raise RuntimeError(f"Stage semantics progress sequence mismatch line={line_no}")
            if int(obj.get("h1", -1)) != int(item["h1"]) or int(obj.get("h2", -1)) != int(item["h2"]):
                raise RuntimeError(f"Stage semantics progress range mismatch line={line_no}")
            if str(obj.get("stage_manifest_sha256")) != str(item["entry"]["manifest_sha256"]):
                raise RuntimeError(f"Stage semantics progress Stage manifest mismatch line={line_no}")
            if obj.get("previous_record_sha256") != prev:
                raise RuntimeError(f"Stage semantics progress hash chain mismatch line={line_no}")
            actual = canonical_json_hash(obj, exclude=("record_sha256",))
            if str(obj.get("record_sha256")) != actual:
                raise RuntimeError(f"Stage semantics progress record SHA mismatch line={line_no}")
            result = obj.get("result") or {}
            if result.get("status") != "OK":
                raise RuntimeError(f"Stage semantics committed non-OK record line={line_no}")
            prev = actual
            records.append(obj)
    return records


def _stage_semantics_prepare_progress(progress_base: Path, contract: Dict[str, Any], plan: Sequence[Dict[str, Any]],
                                      allow_resume: bool) -> Tuple[Path, Path, List[Dict[str, Any]]]:
    root = progress_base / str(contract["contract_id"])
    root.mkdir(parents=True, exist_ok=True)
    contract_path = root / "contract.json"
    ledger = root / "windows.jsonl"
    if contract_path.exists():
        existing = load_json(contract_path)
        side = read_sidecar(Path(str(contract_path) + ".sha256"))
        actual = sha256_file(contract_path)
        if side != actual or existing != contract:
            raise RuntimeError(f"Stage semantics progress contract drift: {contract_path}")
        if not allow_resume and ledger.exists() and ledger.stat().st_size:
            raise RuntimeError(f"Stage semantics matching progress exists but resume disabled: {ledger}")
    else:
        digest = write_evidence(contract_path, contract)
        if digest != sha256_file(contract_path):
            raise RuntimeError("Stage semantics progress contract write verification failed")
    records = _load_stage_semantics_records(ledger, contract, plan)
    return root, ledger, records


def _expected_duplicate_groups(target: int, *, h1: Optional[int] = None, h2: Optional[int] = None,
                               bucket: Optional[str] = None) -> List[Tuple[str, List[int], List[int], int]]:
    out: List[Tuple[str, List[int], List[int], int]] = []
    for b in BIP30:
        heights = [int(x) for x in (b["early"], b["later"]) if int(x) <= int(target)]
        if len(heights) != 2:
            continue
        if bucket is not None and str(b["txid"])[:2] != str(bucket):
            continue
        if h1 is not None and h2 is not None and not all(int(h1) <= x <= int(h2) for x in heights):
            continue
        out.append([str(b["txid"]), heights, [0, 0], 2])
    return sorted(out, key=lambda x: x[0])


def _stage_semantics_window_item(*, duckdb_module, item: Dict[str, Any], target: int,
                                 state_contract: Dict[str, Any], expected_prev_hash: Optional[str],
                                 memory: str, temp_max: str, threads: int, scratch_root: Path) -> Dict[str, Any]:
    idx, h1, h2 = int(item["window_no"]), int(item["h1"]), int(item["h2"])
    entry = item["entry"]
    scratch = scratch_root / f"w{idx:05d}_{h1:06d}_{h2:06d}_{uuid.uuid4().hex[:8]}"
    scratch.mkdir(parents=True, exist_ok=False)
    con = duckdb_module.connect()
    failed: List[str] = []
    warnings: List[str] = []
    try:
        settings = configure_duckdb(con, memory, scratch / "duckdb_tmp", temp_max, max(1, threads))
        bp = sql_quote(str(entry["blocks"]["path"])); tp = sql_quote(str(entry["transactions"]["path"]))
        ip = sql_quote(str(entry["inputs"]["path"])); op = sql_quote(str(entry["outputs"]["path"]))
        con.execute(f"""
            CREATE TEMP VIEW w_block AS
            SELECT height::BIGINT height, lower(block_hash::VARCHAR) block_hash,
                   lower(prev_hash::VARCHAR) prev_hash, tx_count::BIGINT tx_count
            FROM read_parquet({bp}) WHERE height BETWEEN {h1} AND {h2}
        """)
        con.execute(f"""
            CREATE TEMP VIEW w_tx AS
            SELECT height::BIGINT height, tx_index::BIGINT tx_index,
                   lower(txid::VARCHAR) txid, is_coinbase::BOOLEAN is_coinbase,
                   vin_count::BIGINT vin_count, vout_count::BIGINT vout_count
            FROM read_parquet({tp}) WHERE height BETWEEN {h1} AND {h2}
        """)
        con.execute(f"""
            CREATE TEMP VIEW w_in AS
            SELECT height::BIGINT height, tx_index::BIGINT tx_index,
                   lower(txid::VARCHAR) txid, vin_index::BIGINT vin_index,
                   lower(prev_txid::VARCHAR) prev_txid, prev_vout::UBIGINT prev_vout
            FROM read_parquet({ip}) WHERE height BETWEEN {h1} AND {h2}
        """)
        con.execute(f"""
            CREATE TEMP VIEW w_out AS
            SELECT height::BIGINT height, tx_index::BIGINT tx_index,
                   lower(txid::VARCHAR) txid, vout::BIGINT vout,
                   value_sats::BIGINT value_sats, script_pubkey::BLOB script_pubkey,
                   script_pubkey_size::BIGINT script_pubkey_size
            FROM read_parquet({op}) WHERE height BETWEEN {h1} AND {h2}
        """)
        with _ResourceSampler(scratch) as sampler:
            block = con.execute("""
                SELECT count(*),min(height),max(height),count(DISTINCT height),count(DISTINCT block_hash),
                       count(*) FILTER (WHERE height IS NULL OR block_hash IS NULL OR prev_hash IS NULL OR tx_count<1),
                       count(*) FILTER (WHERE NOT regexp_full_match(block_hash,'[0-9a-f]{64}') OR NOT regexp_full_match(prev_hash,'[0-9a-f]{64}'))
                FROM w_block
            """).fetchone()
            block_rows, bmin, bmax, bdh, bdb, bbad, bhashbad = [int(x or 0) for x in block]
            expected_blocks = h2 - h1 + 1
            if (block_rows, bmin, bmax, bdh, bdb) != (expected_blocks, h1, h2, expected_blocks, expected_blocks):
                failed.append(f"block_window:{block_rows},{bmin},{bmax},{bdh},{bdb}:expected={h1}..{h2}")
            if bbad or bhashbad:
                failed.append(f"block_bad_fields:{bbad}:hash_format={bhashbad}")
            boundary = con.execute("SELECT height,block_hash,prev_hash FROM w_block WHERE height IN (?,?) ORDER BY height", [h1,h2]).fetchall()
            if not boundary:
                failed.append("block_boundary_missing")
                first_prev = None; last_hash = None
            else:
                first = boundary[0]; last = boundary[-1]
                first_prev = str(first[2]); last_hash = str(last[1])
                wanted_prev = ("0" * 64) if h1 == 0 else str(expected_prev_hash or "")
                if first_prev != wanted_prev:
                    failed.append(f"window_prevhash_boundary:{first_prev}!={wanted_prev}")
            chain_bad = int(con.execute("""
                WITH x AS (SELECT height,block_hash,prev_hash,lag(block_hash) OVER (ORDER BY height) AS prior_hash FROM w_block)
                SELECT count(*) FROM x WHERE height>? AND (prior_hash IS NULL OR prev_hash<>prior_hash)
            """, [h1]).fetchone()[0] or 0)
            if chain_bad:
                failed.append(f"prevhash_chain_bad:{chain_bad}")

            tx = con.execute("""
                SELECT count(*),
                  count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR length(txid)<>64 OR vin_count<1 OR vout_count<1),
                  count(*) FILTER (WHERE txid=repeat('0',64) OR NOT regexp_full_match(txid,'[0-9a-f]{64}'))
                FROM w_tx
            """).fetchone()
            tx_rows, tx_bad, tx_zero = [int(x or 0) for x in tx]
            if tx_bad or tx_zero: failed.append(f"tx_bad_fields:{tx_bad}:zero_txid={tx_zero}")
            tx_groups_bad = int(con.execute("""
                SELECT count(*) FROM (
                  SELECT height,count(*) n,min(tx_index) mn,max(tx_index) mx,count(DISTINCT tx_index) di,
                         sum(CASE WHEN is_coinbase THEN 1 ELSE 0 END) cb,
                         max(CASE WHEN tx_index=0 AND is_coinbase THEN 1 ELSE 0 END) cb0,
                         max(CASE WHEN tx_index<>0 AND is_coinbase THEN 1 ELSE 0 END) cb_nonzero
                  FROM w_tx GROUP BY height
                ) q WHERE mn<>0 OR mx<>n-1 OR di<>n OR cb<>1 OR cb0<>1 OR cb_nonzero<>0
            """).fetchone()[0] or 0)
            if tx_groups_bad: failed.append(f"tx_index_or_coinbase_groups_bad:{tx_groups_bad}")
            block_tx_mismatch = int(con.execute("""
                WITH t AS (SELECT height,count(*) n FROM w_tx GROUP BY height)
                SELECT count(*) FROM w_block b LEFT JOIN t USING(height) WHERE coalesce(t.n,-1)<>b.tx_count
            """).fetchone()[0] or 0)
            if block_tx_mismatch: failed.append(f"block_tx_count_mismatch:{block_tx_mismatch}")

            inp = con.execute("""
                SELECT count(*),
                  count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR vin_index IS NULL OR prev_txid IS NULL OR prev_vout IS NULL),
                  count(*) FILTER (WHERE NOT regexp_full_match(txid,'[0-9a-f]{64}') OR NOT regexp_full_match(prev_txid,'[0-9a-f]{64}'))
                FROM w_in
            """).fetchone()
            in_rows, in_bad, in_hashbad = [int(x or 0) for x in inp]
            if in_bad or in_hashbad: failed.append(f"input_bad_fields:{in_bad}:hash_format={in_hashbad}")
            in_groups_bad = int(con.execute("""
                WITH g AS (
                  SELECT i.height,i.tx_index,count(*) n,min(i.vin_index) mn,max(i.vin_index) mx,count(DISTINCT i.vin_index) di,
                         max(t.vin_count) expected,max(CASE WHEN t.is_coinbase THEN 1 ELSE 0 END) cb,
                         sum(CASE WHEN i.prev_txid=repeat('0',64) AND i.prev_vout=4294967295 THEN 1 ELSE 0 END) nullprev
                  FROM w_in i JOIN w_tx t USING(height,tx_index,txid) GROUP BY i.height,i.tx_index
                ) SELECT count(*) FROM g
                WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>expected OR (cb=1 AND (n<>1 OR nullprev<>1)) OR (cb=0 AND nullprev<>0)
            """).fetchone()[0] or 0)
            if in_groups_bad: failed.append(f"input_dense_or_coinbase_prevout_bad_groups:{in_groups_bad}")
            input_orphan_tx = int(con.execute("SELECT count(*) FROM w_in i LEFT JOIN w_tx t USING(height,tx_index,txid) WHERE t.txid IS NULL").fetchone()[0] or 0)
            if input_orphan_tx: failed.append(f"input_rows_without_exact_owner_tx:{input_orphan_tx}")
            missing_input_tx = int(con.execute("""
                SELECT count(*) FROM w_tx t LEFT JOIN (SELECT height,tx_index,txid,count(*) n FROM w_in GROUP BY 1,2,3) i USING(height,tx_index,txid)
                WHERE coalesce(i.n,-1)<>t.vin_count
            """).fetchone()[0] or 0)
            if missing_input_tx: failed.append(f"tx_input_cardinality_mismatch:{missing_input_tx}")

            out = con.execute("""
                SELECT count(*),coalesce(sum(script_pubkey_size),0),
                  count(*) FILTER (WHERE height IS NULL OR tx_index IS NULL OR txid IS NULL OR vout IS NULL OR value_sats IS NULL OR script_pubkey IS NULL OR script_pubkey_size IS NULL),
                  count(*) FILTER (WHERE NOT regexp_full_match(txid,'[0-9a-f]{64}') OR vout<0 OR value_sats<0 OR value_sats>? OR script_pubkey_size<0 OR octet_length(script_pubkey)<>script_pubkey_size)
                FROM w_out
            """, [MAX_MONEY_SATS]).fetchone()
            out_rows, script_bytes, out_bad, out_sem_bad = [int(x or 0) for x in out]
            if out_bad or out_sem_bad: failed.append(f"output_bad_fields:{out_bad}:semantic={out_sem_bad}")
            out_groups_bad = int(con.execute("""
                WITH g AS (
                  SELECT o.height,o.tx_index,count(*) n,min(o.vout) mn,max(o.vout) mx,count(DISTINCT o.vout) di,max(t.vout_count) expected
                  FROM w_out o JOIN w_tx t USING(height,tx_index,txid) GROUP BY o.height,o.tx_index
                ) SELECT count(*) FROM g WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>expected
            """).fetchone()[0] or 0)
            if out_groups_bad: failed.append(f"output_dense_groups_bad:{out_groups_bad}")
            output_orphan_tx = int(con.execute("SELECT count(*) FROM w_out o LEFT JOIN w_tx t USING(height,tx_index,txid) WHERE t.txid IS NULL").fetchone()[0] or 0)
            if output_orphan_tx: failed.append(f"output_rows_without_exact_owner_tx:{output_orphan_tx}")
            missing_output_tx = int(con.execute("""
                SELECT count(*) FROM w_tx t LEFT JOIN (SELECT height,tx_index,txid,count(*) n FROM w_out GROUP BY 1,2,3) o USING(height,tx_index,txid)
                WHERE coalesce(o.n,-1)<>t.vout_count
            """).fetchone()[0] or 0)
            if missing_output_tx: failed.append(f"tx_output_cardinality_mismatch:{missing_output_tx}")
            tx_value_bad = int(con.execute("""
                SELECT count(*) FROM (SELECT height,tx_index,sum(value_sats) total FROM w_out GROUP BY height,tx_index) q
                WHERE total<0 OR total>?
            """, [MAX_MONEY_SATS]).fetchone()[0] or 0)
            if tx_value_bad: failed.append(f"transaction_output_total_out_of_range:{tx_value_bad}")

            dup_rows = con.execute("""
                SELECT txid,list(height ORDER BY height),list(tx_index ORDER BY height,tx_index),count(*)
                FROM w_tx GROUP BY txid HAVING count(*)>1 ORDER BY txid
            """).fetchall()
            normalized_dups = [[str(r[0]), [int(x) for x in r[1]], [int(x) for x in r[2]], int(r[3])] for r in dup_rows]
            expected_local_dups = _expected_duplicate_groups(target, h1=h1, h2=h2)
            if normalized_dups != expected_local_dups:
                failed.append(f"window_duplicate_txid_contract:{normalized_dups}!={expected_local_dups}")

            bip30_payload_bad = 0
            for b in BIP30:
                if int(b["later"]) > target or not (h1 <= int(b["early"]) <= h2 and h1 <= int(b["later"]) <= h2):
                    continue
                row = con.execute("""
                    WITH a AS (SELECT vout,value_sats,script_pubkey,script_pubkey_size FROM w_out WHERE txid=? AND height=?),
                         z AS (SELECT vout,value_sats,script_pubkey,script_pubkey_size FROM w_out WHERE txid=? AND height=?)
                    SELECT (SELECT count(*) FROM a),(SELECT count(*) FROM z),
                           (SELECT count(*) FROM a FULL OUTER JOIN z USING(vout)
                            WHERE a.vout IS NULL OR z.vout IS NULL OR a.value_sats<>z.value_sats OR a.script_pubkey_size<>z.script_pubkey_size OR a.script_pubkey<>z.script_pubkey)
                """, [b["txid"], b["early"], b["txid"], b["later"]]).fetchone()
                if int(row[0] or 0) <= 0 or int(row[0] or 0) != int(row[1] or 0) or int(row[2] or 0) != 0:
                    bip30_payload_bad += 1
            if bip30_payload_bad: failed.append(f"BIP30_payload_mismatch_pairs:{bip30_payload_bad}")

        return {
            "status": "OK" if not failed else "BAD", "failed_checks": failed, "warnings": warnings,
            "engine": STAGE_SEMANTICS_ENGINE, "window_no": idx, "h1": h1, "h2": h2,
            "first_prev_hash": first_prev, "last_block_hash": last_hash,
            "block_rows": block_rows, "tx_rows": tx_rows, "input_rows": in_rows, "output_rows": out_rows,
            "script_bytes": script_bytes,
            "input_rows_without_exact_owner_tx": input_orphan_tx,
            "output_rows_without_exact_owner_tx": output_orphan_tx,
            "tx_input_cardinality_mismatch": missing_input_tx,
            "tx_output_cardinality_mismatch": missing_output_tx,
            "duplicate_txid_groups_local": normalized_dups,
            "bip30_payload_bad_pairs": bip30_payload_bad,
            "duckdb_settings": settings,
            "resource_telemetry": {"peak_rss_bytes": int(sampler.peak_rss), "peak_temp_bytes": int(sampler.peak_temp), "samples": int(sampler.samples)},
        }
    finally:
        try:
            con.close()
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


def stage_semantics_windowed(*, duckdb_module, stage: Dict[str, Any], target: int,
                             state_contract: Dict[str, Any], auditor_sha256: str,
                             progress_base: Path, allow_resume: bool, memory: str,
                             temp_max: str, threads: int, scratch_root: Path,
                             min_free_tmp: str, stage_token_digest: Optional[str] = None) -> Dict[str, Any]:
    plan = _stage_semantics_plan(stage, target)
    contract = _stage_semantics_contract(
        auditor_sha256=auditor_sha256, stage=stage, target=target,
        state_contract=state_contract, plan=plan, stage_token_digest=stage_token_digest,
    )
    root = progress_base / str(contract["contract_id"])
    with StageSemanticsProgressLease(root):
        root, ledger, records = _stage_semantics_prepare_progress(progress_base, contract, plan, allow_resume)
        if records:
            log(f"stage_semantics resume windows={len(records)}/{len(plan)}")
        expected_prev = None
        if records:
            expected_prev = str((records[-1].get("result") or {}).get("last_block_hash") or "")
        for idx in range(len(records), len(plan)):
            item = plan[idx]
            resources = resource_preflight(scratch_root, temp_max, min_free_tmp)
            if resources["status"] != "OK":
                raise RuntimeError(f"Stage semantics temp preflight failed before window {idx}: {resources.get('failed_checks')}")
            log(f"stage_semantics window START {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
            result = _stage_semantics_window_item(
                duckdb_module=duckdb_module, item=item, target=target, state_contract=state_contract,
                expected_prev_hash=expected_prev, memory=memory, temp_max=temp_max,
                threads=max(1, threads), scratch_root=scratch_root,
            )
            if result.get("status") != "OK":
                return {
                    "status": "BAD", "failed_checks": result.get("failed_checks") or [f"window_{idx}_bad"],
                    "failed_window": result, "engine": STAGE_SEMANTICS_ENGINE,
                    "bounded_memory": True, "progress_root": str(root),
                    "windows_total": len(plan), "windows_completed": len(records),
                }
            rec = {
                "schema": STAGE_SEMANTICS_RECORD_SCHEMA,
                "contract_id": contract["contract_id"], "record_no": idx + 1, "window_no": idx,
                "h1": int(item["h1"]), "h2": int(item["h2"]),
                "stage_manifest_sha256": str(item["entry"]["manifest_sha256"]),
                "status": "OK", "result": result, "finished_utc": utc_now(),
                "previous_record_sha256": records[-1]["record_sha256"] if records else None,
            }
            rec["record_sha256"] = canonical_json_hash(rec, exclude=("record_sha256",))
            append_jsonl_fsync(ledger, rec); records.append(rec)
            expected_prev = str(result["last_block_hash"])
            log(f"stage_semantics window OK {idx+1}/{len(plan)} tx={result['tx_rows']:,} in={result['input_rows']:,} out={result['output_rows']:,} peak_rss={result['resource_telemetry']['peak_rss_bytes']/(1<<30):.2f}GiB peak_temp={result['resource_telemetry']['peak_temp_bytes']/(1<<30):.2f}GiB")

        results = [r["result"] for r in records]
        block_rows = sum(int(r["block_rows"]) for r in results)
        tx_rows = sum(int(r["tx_rows"]) for r in results)
        in_rows = sum(int(r["input_rows"]) for r in results)
        out_rows = sum(int(r["output_rows"]) for r in results)
        script_bytes = sum(int(r["script_bytes"]) for r in results)
        input_orphan_tx = sum(int(r["input_rows_without_exact_owner_tx"]) for r in results)
        output_orphan_tx = sum(int(r["output_rows_without_exact_owner_tx"]) for r in results)
        missing_input_tx = sum(int(r["tx_input_cardinality_mismatch"]) for r in results)
        missing_output_tx = sum(int(r["tx_output_cardinality_mismatch"]) for r in results)
        failed: List[str] = []
        if block_rows != target + 1: failed.append(f"block_prefix:{block_rows}:target={target}")
        if tx_rows != int(state_contract["tx_count"]): failed.append(f"stage_state_tx_count:{tx_rows}!={state_contract['tx_count']}")
        if out_rows != int(state_contract["out_count"]): failed.append(f"stage_state_out_count:{out_rows}!={state_contract['out_count']}")
        if script_bytes != int(state_contract["script_bytes"]): failed.append(f"stage_state_script_bytes:{script_bytes}!={state_contract['script_bytes']}")
        tip_hash = str(results[-1]["last_block_hash"]) if results else None
        if tip_hash != str(state_contract["block_hash"]): failed.append(f"stage_state_tip_hash:{tip_hash}!={state_contract['block_hash']}")
        local_dups = sorted([x for r in results for x in (r.get("duplicate_txid_groups_local") or [])], key=lambda x: x[0])
        # Only duplicates whose complete known BIP30 pair co-resides inside one
        # Stage window are expected here. Cross-window duplicate exactness is
        # proved later by the mandatory 256-prefix bounded Stage->UTXO engine.
        expected_local = sorted(
            [g for item in plan for g in _expected_duplicate_groups(target, h1=int(item["h1"]), h2=int(item["h2"]))],
            key=lambda x: x[0],
        )
        if local_dups != expected_local:
            failed.append(f"local_duplicate_txid_contract:{local_dups}!={expected_local}")
        false_green: List[str] = []
        if block_rows > 0 and tx_rows > block_rows and in_rows == 0: false_green.append("FALSE_GREEN_EMPTY_INPUTS_WITH_NONTRIVIAL_TX_SOURCE")
        if tx_rows > 0 and out_rows == 0: false_green.append("FALSE_GREEN_EMPTY_OUTPUTS_WITH_NONEMPTY_TX_SOURCE")
        if missing_input_tx or input_orphan_tx: false_green.append("FALSE_GREEN_INPUT_COVERAGE_INCOMPLETE")
        if missing_output_tx or output_orphan_tx: false_green.append("FALSE_GREEN_OUTPUT_COVERAGE_INCOMPLETE")
        failed.extend(false_green)
        return {
            "status": "OK" if not failed else "BAD", "failed_checks": sorted(set(failed)), "warnings": [],
            "engine": STAGE_SEMANTICS_ENGINE, "bounded_memory": True,
            "target": target, "tip_hash": tip_hash, "block_rows": block_rows, "tx_rows": tx_rows,
            "input_rows": in_rows, "output_rows": out_rows, "script_bytes": script_bytes,
            "input_rows_without_exact_owner_tx": input_orphan_tx,
            "output_rows_without_exact_owner_tx": output_orphan_tx,
            "duplicate_txid_groups": local_dups,
            "duplicate_txid_scope": "WITHIN_STAGE_WINDOW_EXACT; GLOBAL_EXACT_DEFERRED_TO_BUCKETED_STAGE_REBUILD",
            "false_green_guard_status": "OK" if not false_green else "BAD_FALSE_GREEN_RISK",
            "false_green_failed_checks": false_green,
            "coverage_status": "OK" if not missing_input_tx and not missing_output_tx and not input_orphan_tx and not output_orphan_tx else "GAP",
            "windows_total": len(plan), "windows_completed": len(records), "progress_root": str(root),
            "progress_ledger": str(ledger), "contract_id": contract["contract_id"],
            "peak_window_rss_bytes": max((int(r.get("resource_telemetry", {}).get("peak_rss_bytes", 0)) for r in results), default=0),
            "peak_window_temp_bytes": max((int(r.get("resource_telemetry", {}).get("peak_temp_bytes", 0)) for r in results), default=0),
        }

def fp_update(h, txid: str, vout: int, value: int, script: bytes, height: int, tx_index: int, coinbase: bool) -> None:
    h.update(bytes.fromhex(txid.lower()))
    h.update(struct.pack("<I", int(vout)))
    h.update(struct.pack("<q", int(value)))
    h.update(struct.pack("<I", len(script)))
    h.update(script)
    h.update(struct.pack("<I", int(height)))
    h.update(struct.pack("<I", int(tx_index)))
    h.update(bytes([1 if coinbase else 0]))


def stage_independent_rebuild_global(con, target: int, state_scan: Dict[str, Any], full_stream_hashes: bool) -> Dict[str, Any]:
    failed: List[str] = []
    duplicate_rows = con.execute("""
        SELECT txid,list(height ORDER BY height),list(tx_index ORDER BY height,tx_index),count(*)
        FROM stage_tx GROUP BY txid HAVING count(*)>1 ORDER BY txid
    """).fetchall()
    duplicate_txid_groups = [[str(r[0]), [int(x) for x in r[1]], [int(x) for x in r[2]], int(r[3])] for r in duplicate_rows]
    expected_duplicate_txid_groups = _expected_duplicate_groups(target)
    duplicate_txid_contract_status = "OK" if duplicate_txid_groups == expected_duplicate_txid_groups else "BAD"
    if duplicate_txid_contract_status != "OK":
        failed.append(f"duplicate_txid_contract:{duplicate_txid_groups}!={expected_duplicate_txid_groups}")
    log("independent rebuild materialize dense tx/output/input relations")
    con.execute("DROP TABLE IF EXISTS audit_tx")
    con.execute("DROP TABLE IF EXISTS audit_out")
    con.execute("DROP TABLE IF EXISTS audit_in")
    con.execute("DROP TABLE IF EXISTS resolved_spends")
    con.execute("DROP TABLE IF EXISTS bip30_closes")
    con.execute("DROP TABLE IF EXISTS expected_closes")
    con.execute("""
        CREATE TEMP TABLE audit_tx AS
        SELECT row_number() OVER (ORDER BY height,tx_index)-1 AS tx_seq,
               height,tx_index,txid,is_coinbase,vin_count,vout_count
        FROM stage_tx ORDER BY height,tx_index
    """)
    con.execute("""
        CREATE TEMP TABLE audit_out AS
        SELECT row_number() OVER (ORDER BY o.height,o.tx_index,o.vout)-1 AS output_id,
               t.tx_seq,o.height,o.tx_index,o.txid,o.vout,o.value_sats,o.script_pubkey,o.script_pubkey_size,
               t.is_coinbase,
               CASE WHEN o.height<>0 AND o.script_pubkey_size<=10000
                          AND NOT (o.script_pubkey_size>0 AND substr(hex(o.script_pubkey),1,2)='6A')
                    THEN TRUE ELSE FALSE END AS eligible
        FROM stage_out o JOIN audit_tx t USING(height,tx_index,txid)
        ORDER BY o.height,o.tx_index,o.vout
    """)
    con.execute("""
        CREATE TEMP TABLE audit_in AS
        SELECT t.tx_seq AS closer_tx_seq,i.height,i.tx_index,i.vin_index,i.prev_txid,i.prev_vout,t.is_coinbase
        FROM stage_in i JOIN audit_tx t USING(height,tx_index,txid)
    """)
    log("independent rebuild resolve every non-coinbase prevout causally")
    con.execute("""
        CREATE TEMP TABLE resolved_spends AS
        SELECT closer_tx_seq,vin_index,output_id,eligible
        FROM (
          SELECT i.closer_tx_seq,i.vin_index,o.output_id,o.eligible,
                 row_number() OVER (
                   PARTITION BY i.closer_tx_seq,i.vin_index
                   ORDER BY o.height DESC,o.tx_index DESC
                 ) AS rn
          FROM audit_in i
          JOIN audit_out o ON o.txid=i.prev_txid AND o.vout=CAST(i.prev_vout AS BIGINT)
          WHERE NOT i.is_coinbase
            AND (o.height<i.height OR (o.height=i.height AND o.tx_index<i.tx_index))
        ) q WHERE rn=1
    """)
    noncb_inputs = int(con.execute("SELECT count(*) FROM audit_in WHERE NOT is_coinbase").fetchone()[0] or 0)
    resolved = int(con.execute("SELECT count(*) FROM resolved_spends").fetchone()[0] or 0)
    unresolved = noncb_inputs - resolved
    if unresolved:
        failed.append(f"coverage_orphan_prevouts:{unresolved}/{noncb_inputs}")
    spend_ineligible = int(con.execute("SELECT count(*) FROM resolved_spends WHERE NOT eligible").fetchone()[0] or 0)
    if spend_ineligible:
        failed.append(f"spend_of_ineligible_output:{spend_ineligible}")
    double_spends = int(con.execute("SELECT count(*) FROM (SELECT output_id,count(*) c FROM resolved_spends GROUP BY output_id HAVING c<>1)").fetchone()[0] or 0)
    if double_spends:
        failed.append(f"double_spend_resolved_outputs:{double_spends}")

    orphan_samples: List[Dict[str, Any]] = []
    if unresolved:
        rows = con.execute("""
            SELECT i.height,i.tx_index,t.txid,i.vin_index,i.prev_txid,i.prev_vout
            FROM audit_in i
            JOIN audit_tx t ON t.tx_seq=i.closer_tx_seq
            LEFT JOIN resolved_spends r ON r.closer_tx_seq=i.closer_tx_seq AND r.vin_index=i.vin_index
            WHERE NOT i.is_coinbase AND r.output_id IS NULL LIMIT 20
        """).fetchall()
        orphan_samples = [{"spent_height": int(r[0]), "spent_tx_index": int(r[1]), "spent_txid": str(r[2]), "vin_index": int(r[3]), "prev_txid": str(r[4]), "prev_vout": int(r[5])} for r in rows]

    log("independent rebuild materialize exact BIP30 overwrite closes")
    unions = []
    for b in BIP30:
        if b["later"] <= target:
            unions.append(f"""
              SELECT old_out.output_id,new_tx.tx_seq AS closer_tx_seq,4294967295::UBIGINT AS vin,2::INTEGER AS close_type
              FROM audit_out old_out
              JOIN audit_out new_out ON new_out.txid=old_out.txid AND new_out.vout=old_out.vout AND new_out.height={b['later']}
              JOIN audit_tx new_tx ON new_tx.height=new_out.height AND new_tx.tx_index=new_out.tx_index AND new_tx.txid=new_out.txid
              WHERE old_out.txid='{b['txid']}' AND old_out.height={b['early']} AND old_out.eligible
                AND NOT EXISTS (
                  SELECT 1 FROM resolved_spends r WHERE r.output_id=old_out.output_id AND r.closer_tx_seq<new_tx.tx_seq
                )
            """)
    bip_sql = " UNION ALL ".join(unions) if unions else "SELECT NULL::UBIGINT output_id,NULL::UBIGINT closer_tx_seq,NULL::UBIGINT vin,NULL::INTEGER close_type WHERE FALSE"
    con.execute(f"CREATE TEMP TABLE bip30_closes AS {bip_sql}")
    con.execute("""
        CREATE TEMP TABLE expected_closes AS
        SELECT output_id,closer_tx_seq,vin_index::UBIGINT vin,1::INTEGER close_type FROM resolved_spends
        UNION ALL
        SELECT output_id,closer_tx_seq,vin,close_type FROM bip30_closes
    """)
    close_duplicate = int(con.execute("SELECT count(*) FROM (SELECT output_id,count(*) c FROM expected_closes GROUP BY output_id HAVING c<>1)").fetchone()[0] or 0)
    if close_duplicate:
        failed.append(f"expected_close_not_bijective:{close_duplicate}")
    expected_close_count = int(con.execute("SELECT count(*) FROM expected_closes").fetchone()[0] or 0)
    if expected_close_count != int(state_scan["close_count"]):
        failed.append(f"close_count:{expected_close_count}!={state_scan['close_count']}")

    live = con.execute("""
        SELECT count(*),coalesce(sum(o.value_sats),0)
        FROM audit_out o LEFT JOIN expected_closes c USING(output_id)
        WHERE o.eligible AND c.output_id IS NULL
    """).fetchone()
    live_count, live_value = int(live[0] or 0), int(live[1] or 0)
    if live_count != int(state_scan["live_count"]):
        failed.append(f"live_count:{live_count}!={state_scan['live_count']}")
    if live_value != int(state_scan["live_value_sats"]):
        failed.append(f"live_value:{live_value}!={state_scan['live_value_sats']}")

    log(f"independent rebuild fingerprint expected live UTXO rows={live_count:,}")
    h = hashlib.sha256(); count = 0; value = 0
    cur = con.execute("""
        SELECT o.txid,o.vout,o.value_sats,o.script_pubkey,o.height,o.tx_index,o.is_coinbase
        FROM audit_out o LEFT JOIN expected_closes c USING(output_id)
        WHERE o.eligible AND c.output_id IS NULL
        ORDER BY o.height,o.tx_index,o.vout
    """)
    while True:
        rows = cur.fetchmany(32768)
        if not rows:
            break
        for txid, vout, val, script, ch, ti, cb in rows:
            sb = bytes(script)
            fp_update(h, str(txid), int(vout), int(val), sb, int(ch), int(ti), bool(cb))
            count += 1; value += int(val)
        if count and count % 5_000_000 < 32768:
            log(f"expected live fingerprint rows={count:,}/{live_count:,}")
    expected_live_fp = h.hexdigest()
    if count != live_count or value != live_value:
        failed.append("expected_live_fingerprint_stream_aggregate_mismatch")
    if expected_live_fp != state_scan["live_fingerprint_sha256"]:
        failed.append(f"live_fingerprint:{expected_live_fp}!={state_scan['live_fingerprint_sha256']}")

    all_out_fp = None; tx_fp = None; close_fp = None
    if full_stream_hashes:
        log("independent rebuild full historical tx stream fingerprint")
        htx = hashlib.sha256(); n = 0
        cur = con.execute("SELECT txid,height,tx_index,vout_count,is_coinbase FROM audit_tx ORDER BY tx_seq")
        while True:
            rows = cur.fetchmany(65536)
            if not rows: break
            for txid, height, ti, vc, cb in rows:
                htx.update(bytes.fromhex(str(txid))); htx.update(struct.pack("<I", int(height))); htx.update(struct.pack("<I", int(ti))); htx.update(struct.pack("<I", int(vc))); htx.update(bytes([1 if cb else 0])); n += 1
            if n and n % 10_000_000 < 65536: log(f"tx stream hash rows={n:,}")
        tx_fp = htx.hexdigest()
        if tx_fp != state_scan["tx_stream_sha256"]:
            failed.append(f"tx_stream_sha256:{tx_fp}!={state_scan['tx_stream_sha256']}")

        log("independent rebuild full historical output stream fingerprint")
        hout = hashlib.sha256(); n = 0
        cur = con.execute("SELECT txid,vout,value_sats,script_pubkey,height,tx_index,is_coinbase,eligible FROM audit_out ORDER BY output_id")
        while True:
            rows = cur.fetchmany(32768)
            if not rows: break
            for txid, vout, val, script, height, ti, cb, elig in rows:
                sb = bytes(script); fp_update(hout, str(txid), int(vout), int(val), sb, int(height), int(ti), bool(cb)); hout.update(bytes([1 if elig else 0])); n += 1
            if n and n % 5_000_000 < 32768: log(f"output stream hash rows={n:,}")
        all_out_fp = hout.hexdigest()
        if all_out_fp != state_scan["all_outputs_sha256"]:
            failed.append(f"all_outputs_sha256:{all_out_fp}!={state_scan['all_outputs_sha256']}")

        log("independent rebuild exact close-log fingerprint")
        hc = hashlib.sha256(); n = 0
        cur = con.execute("SELECT output_id,closer_tx_seq,vin,close_type FROM expected_closes ORDER BY closer_tx_seq,CASE WHEN close_type=2 THEN output_id ELSE vin END,output_id")
        while True:
            rows = cur.fetchmany(65536)
            if not rows: break
            for oid, closer, vin, typ in rows:
                hc.update(struct.pack("<Q", int(oid))); hc.update(struct.pack("<Q", int(closer))); hc.update(struct.pack("<I", int(vin))); hc.update(struct.pack("<I", int(typ))); n += 1
        close_fp = hc.hexdigest()
        if close_fp != state_scan["close_stream_sha256"]:
            failed.append(f"close_stream_sha256:{close_fp}!={state_scan['close_stream_sha256']}")

    return {
        "status": "OK" if not failed else "BAD", "failed_checks": failed,
        "coverage_status": "OK" if unresolved == 0 else "GAP",
        "noncoinbase_inputs": noncb_inputs, "resolved_spends": resolved, "unresolved_prevouts": unresolved,
        "orphan_samples": orphan_samples, "spend_ineligible": spend_ineligible, "double_spends": double_spends,
        "bip30_close_rows": int(con.execute("SELECT count(*) FROM bip30_closes").fetchone()[0] or 0),
        "expected_close_count": expected_close_count,
        "expected_live_count": live_count, "expected_live_value_sats": live_value,
        "expected_live_fingerprint_sha256": expected_live_fp,
        "full_stream_hashes": bool(full_stream_hashes),
        "tx_stream_sha256": tx_fp, "all_outputs_sha256": all_out_fp, "close_stream_sha256": close_fp,
    }


# --- R2.2 bounded-memory Stage->UTXO rebuild ---------------------------------
STAGE_REBUILD_PROGRESS_SCHEMA = "mybot-v50-stage-rebuild-progress-v1"
STAGE_REBUILD_PARTITION_RECORD_SCHEMA = "mybot-v50-stage-rebuild-partition-v1"
STAGE_REBUILD_BUCKET_RECORD_SCHEMA = "mybot-v50-stage-rebuild-bucket-v1"
STAGE_REBUILD_BUCKET_PREFIX_CHARS = 2
STAGE_REBUILD_BUCKETS = tuple(f"{i:02x}" for i in range(256))
NO_VIN = 0xFFFFFFFF
STAGE_REBUILD_PARTITION_OPEN_FILES = 256


class StageRebuildProgressLease:
    """Exclusive lock for one deterministic bounded Stage-rebuild work contract."""
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1

    def __enter__(self):
        # Fail closed on a pre-created symlink/special-object contract root.
        # pathlib.mkdir(exist_ok=True) follows a symlink-to-directory, which would
        # otherwise allow LOCK/evidence writes to escape --stage-rebuild-work-dir.
        self.root.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(self.root):
            st = os.lstat(self.root)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise RuntimeError(f"Stage rebuild progress root is symlink/non-directory: {self.root}")
        else:
            os.mkdir(self.root, 0o750)
        before = os.lstat(self.root)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise RuntimeError(f"Stage rebuild progress root became unsafe: {self.root}")
        lock = self.root / "LOCK"
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(str(lock), flags, 0o640)
        except OSError as exc:
            raise RuntimeError(f"cannot safely open Stage rebuild progress lock: {lock}: {exc}") from exc
        after = os.lstat(self.root)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            os.close(self.fd); self.fd = -1
            raise RuntimeError(f"Stage rebuild progress root changed during lock acquisition: {self.root}")
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            self.fd = -1
            raise RuntimeError(f"Stage rebuild progress is already in use: {lock}") from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1


def _stage_rebuild_plan(stage: Dict[str, Any], target: int) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    expected = 0
    for idx, e in enumerate(selected_entries(stage, target)):
        h1 = max(0, int(e["h1"]))
        h2 = min(int(target), int(e["h2"]))
        if h1 != expected or h2 < h1:
            raise RuntimeError(f"Stage rebuild plan discontinuity expected={expected} actual={h1}..{h2}")
        plan.append({
            "window_no": idx,
            "h1": h1,
            "h2": h2,
            "stage_manifest_sha256": str(e["manifest_sha256"]),
            "transactions_path": str(e["transactions"]["path"]),
            "inputs_path": str(e["inputs"]["path"]),
            "outputs_path": str(e["outputs"]["path"]),
        })
        expected = h2 + 1
    if expected != int(target) + 1:
        raise RuntimeError(f"Stage rebuild plan terminal coverage {expected}!={target+1}")
    return plan


def _stage_rebuild_plan_digest(plan: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash({
        "schema": "mybot-v50-stage-rebuild-plan-v1",
        "windows": [
            {
                "window_no": int(x["window_no"]), "h1": int(x["h1"]), "h2": int(x["h2"]),
                "stage_manifest_sha256": str(x["stage_manifest_sha256"]),
            }
            for x in plan
        ],
    })


def _stage_rebuild_contract(
    *, auditor_sha256: str, state: Path, state_contract: Dict[str, Any], stage: Dict[str, Any],
    target: int, plan: Sequence[Dict[str, Any]], close_tx_span: int,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema": STAGE_REBUILD_PROGRESS_SCHEMA,
        "auditor_version": VERSION,
        "auditor_sha256": str(auditor_sha256),
        "target_height": int(target),
        "target_hash": str(state_contract["block_hash"]),
        "state": {
            "path": str(state.resolve(strict=True)),
            "checkpoint_sha256": sha256_file(regular(state / "checkpoint.bin")),
            "meta_sha256": sha256_file(regular(state / "state.meta")),
            "source_sha256": str(state_contract["source_sha256"]),
            "core_sha256": str(state_contract["core_sha256"]),
            "driver_sha256": str(state_contract["driver_sha256"]),
        },
        "stage": {
            "kind": str(stage["kind"]),
            "release_path": str(stage["path"]),
            "release_sha256": str(stage["sha256"]),
            "window_plan_sha256": _stage_rebuild_plan_digest(plan),
            "windows_total": len(plan),
        },
        "engine": {
            "name": "txid-prefix-bucketed-causal-v1",
            "bucket_contract": "first-two-lowercase-hex-chars-of-canonical-txid",
            "bucket_prefix_chars": STAGE_REBUILD_BUCKET_PREFIX_CHARS,
            "buckets": len(STAGE_REBUILD_BUCKETS),
            "close_partition_contract": "floor(closer_tx_seq/close_tx_span)",
            "close_tx_span": int(close_tx_span),
            "causal_winner": "max(created_height,created_tx_index) strictly before spender",
            "bip30": "exact historical duplicate txids only",
        },
    }
    payload["contract_id"] = canonical_json_hash(payload)
    return payload


def _tree_digest(root: Path) -> Dict[str, Any]:
    """Strong digest of audit-generated files for crash-safe reuse.

    Generated evidence trees are fail-closed: symlinks and special filesystem
    objects are forbidden.  This prevents an added symlink from being invisible
    to the evidence digest while later being followed by a parquet file scan.
    """
    h = hashlib.sha256()
    files = 0
    total = 0
    if not root.exists():
        return {"sha256": h.hexdigest(), "files": 0, "bytes": 0}
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"Stage rebuild evidence root is not a regular directory: {root}")
    entries = sorted(root.rglob("*"), key=lambda x: str(x.relative_to(root)))
    for p in entries:
        if p.is_symlink():
            raise RuntimeError(f"Symlink forbidden in Stage rebuild evidence tree: {p}")
        if p.is_dir():
            continue
        if not p.is_file():
            raise RuntimeError(f"Special/non-regular object forbidden in Stage rebuild evidence tree: {p}")
        rel = str(p.relative_to(root)).replace(os.sep, "/")
        before = file_token(p)
        if int(os.lstat(p).st_nlink) != 1:
            raise RuntimeError(f"Hardlinked Stage rebuild evidence file forbidden: {p}")
        digest = sha256_file(p)
        after = file_token(p)
        if int(os.lstat(p).st_nlink) != 1:
            raise RuntimeError(f"Hardlinked Stage rebuild evidence file forbidden after hashing: {p}")
        if not same_token(before, after):
            raise RuntimeError(f"Stage rebuild evidence file changed while hashing: {p}")
        h.update(rel.encode("utf-8")); h.update(b"\0")
        h.update(struct.pack("<Q", int(after["size"])))
        h.update(bytes.fromhex(digest))
        files += 1; total += int(after["size"])
    return {"sha256": h.hexdigest(), "files": files, "bytes": total}


def _generated_regular_files(paths: Sequence[Path], root: Path) -> List[str]:
    """Validate audit-generated parquet paths without following symlinks."""
    root_real = root.resolve(strict=True)
    out: List[str] = []
    for p in sorted(paths, key=lambda x: str(x)):
        if p.is_symlink() or not p.is_file():
            raise RuntimeError(f"Generated parquet is missing/not-regular/symlink: {p}")
        if int(os.lstat(p).st_nlink) != 1:
            raise RuntimeError(f"Generated parquet hardlink forbidden: {p}")
        resolved = p.resolve(strict=True)
        if resolved != root_real and root_real not in resolved.parents:
            raise RuntimeError(f"Generated parquet escaped evidence root: {p} -> {resolved}")
        out.append(str(resolved))
    return out




def _owned_dir(path: Path, root: Path, *, create: bool = False) -> Path:
    """Return a verified audit-owned directory contained by root, never via symlink."""
    root_real = root.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"Audit evidence root is symlink/non-directory: {root}")
    if create and not os.path.lexists(path):
        path.mkdir(parents=True, exist_ok=False)
    if not os.path.lexists(path):
        raise RuntimeError(f"Audit-owned directory missing: {path}")
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"Audit-owned directory is symlink/non-directory: {path}")
    resolved = path.resolve(strict=True)
    if resolved != root_real and root_real not in resolved.parents:
        raise RuntimeError(f"Audit-owned directory escaped root: {path} -> {resolved} root={root_real}")
    return resolved


def _remove_uncommitted_owned(path: Path, root: Path) -> None:
    """Remove only an uncommitted entry directly inside a verified audit-owned tree."""
    _owned_dir(path.parent, root)
    if not os.path.lexists(path):
        return
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        path.unlink()
        return
    if stat.S_ISDIR(st.st_mode):
        resolved = path.resolve(strict=True)
        root_real = root.resolve(strict=True)
        if root_real not in resolved.parents:
            raise RuntimeError(f"Refusing to remove directory outside audit root: {path} -> {resolved}")
        shutil.rmtree(path)
        return
    path.unlink()

def _read_stage_rebuild_ledger(
    path: Path, *, schema: str, contract_id: str, expected_count: int,
    index_field: str, expected_items: Sequence[Any], validate_item,
) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    regular(path)
    before = file_token(path); raw = path.read_bytes(); after = file_token(path)
    if not same_token(before, after):
        raise RuntimeError(f"Stage rebuild ledger changed during read: {path}")
    out: List[Dict[str, Any]] = []
    previous: Optional[str] = None
    for line_no, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        idx = len(out)
        if idx >= expected_count:
            raise RuntimeError(f"Stage rebuild ledger has excess records: {path}")
        if obj.get("schema") != schema:
            raise RuntimeError(f"Stage rebuild ledger schema mismatch line={line_no}: {path}")
        if str(obj.get("contract_id") or "") != contract_id:
            raise RuntimeError(f"Stage rebuild contract mismatch line={line_no}: {path}")
        if int(obj.get("record_no", -1)) != idx + 1 or int(obj.get(index_field, -1)) != idx:
            raise RuntimeError(f"Stage rebuild sequence mismatch line={line_no}: {path}")
        validate_item(obj, expected_items[idx])
        if obj.get("previous_record_sha256") != previous:
            raise RuntimeError(f"Stage rebuild previous SHA mismatch line={line_no}: {path}")
        sha = canonical_json_hash(obj, exclude=("record_sha256",))
        if str(obj.get("record_sha256") or "") != sha:
            raise RuntimeError(f"Stage rebuild record SHA mismatch line={line_no}: {path}")
        if str(obj.get("status") or "") not in {"OK", "BAD"}:
            raise RuntimeError(f"Stage rebuild invalid committed status line={line_no}: {path}")
        previous = sha
        out.append(obj)
    return out


def _stage_rebuild_prepare_root(
    work_base: Path, contract: Dict[str, Any], plan: Sequence[Dict[str, Any]], allow_resume: bool,
) -> Tuple[Path, List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    contract_id = str(contract["contract_id"])
    root = work_base / contract_id
    if not os.path.lexists(root):
        root.mkdir(parents=True, exist_ok=False)
    _owned_dir(root, root)
    contract_path = root / "contract.json"
    if contract_path.exists():
        observed = load_json(contract_path)
        if canonical_json_hash(observed) != canonical_json_hash(contract):
            raise RuntimeError(f"Stage rebuild progress contract mismatch: {contract_path}")
        if read_sidecar(Path(str(contract_path) + ".sha256")) != sha256_file(contract_path):
            raise RuntimeError(f"Stage rebuild contract sidecar mismatch: {contract_path}")
    else:
        write_evidence(contract_path, contract)

    partition_ledger = root / "partition_windows.jsonl"
    bucket_ledger = root / "buckets.jsonl"

    def check_window(obj, item):
        if int(obj.get("h1", -1)) != int(item["h1"]) or int(obj.get("h2", -1)) != int(item["h2"]):
            raise RuntimeError("Stage rebuild window range mismatch")
        if str(obj.get("stage_manifest_sha256") or "") != str(item["stage_manifest_sha256"]):
            raise RuntimeError("Stage rebuild window manifest mismatch")

    def check_bucket(obj, expected_bucket):
        if str(obj.get("bucket") or "") != str(expected_bucket):
            raise RuntimeError("Stage rebuild bucket mismatch")

    windows = _read_stage_rebuild_ledger(
        partition_ledger, schema=STAGE_REBUILD_PARTITION_RECORD_SCHEMA, contract_id=contract_id,
        expected_count=len(plan), index_field="window_no", expected_items=plan, validate_item=check_window,
    )
    buckets = _read_stage_rebuild_ledger(
        bucket_ledger, schema=STAGE_REBUILD_BUCKET_RECORD_SCHEMA, contract_id=contract_id,
        expected_count=len(STAGE_REBUILD_BUCKETS), index_field="bucket_no", expected_items=STAGE_REBUILD_BUCKETS,
        validate_item=check_bucket,
    )
    if (windows or buckets) and not allow_resume:
        raise RuntimeError(f"Stage rebuild progress exists but resume disabled: {root}")

    # Ledger is authoritative.  A crash can happen after atomic directory promotion
    # but before the corresponding ledger append/fsync.  Such final-looking data is
    # uncommitted scratch and must never block or silently authorize resume.
    committed_windows = {
        f"w{int(r['window_no']):05d}_{int(r['h1']):06d}_{int(r['h2']):06d}" for r in windows
    }
    windows_dir = root / "windows"
    if os.path.lexists(windows_dir):
        _owned_dir(windows_dir, root)
        for d in windows_dir.iterdir():
            if d.name.startswith("w") and d.name not in committed_windows:
                _remove_uncommitted_owned(d, root)
    committed_buckets = {f"bucket_{str(r['bucket'])}" for r in buckets}
    buckets_dir = root / "buckets"
    if os.path.lexists(buckets_dir):
        _owned_dir(buckets_dir, root)
        for d in buckets_dir.iterdir():
            if d.name.startswith("bucket_") and d.name not in committed_buckets:
                _remove_uncommitted_owned(d, root)

    # Validate cumulative ID bases in committed window records before trusting resume.
    expected_tx_base = 0
    expected_out_base = 0
    for rec in windows:
        if str(rec.get("status")) != "OK":
            raise RuntimeError(f"Stage rebuild committed partition is not OK: window={rec.get('window_no')}")
        rr = rec.get("result") or {}
        if rec.get("tree") != rr.get("tree"):
            raise RuntimeError(f"Stage rebuild partition tree binding mismatch: window={rec.get('window_no')}")
        if int(rr.get("tx_base", -1)) != expected_tx_base or int(rr.get("out_base", -1)) != expected_out_base:
            raise RuntimeError(f"Stage rebuild partition base discontinuity: window={rec.get('window_no')}")
        tx_count = int(rr.get("tx_count", -1)); out_count = int(rr.get("out_count", -1))
        if tx_count < 0 or out_count < 0:
            raise RuntimeError(f"Stage rebuild partition negative counts: window={rec.get('window_no')}")
        expected_tx_base += tx_count; expected_out_base += out_count
        if int(rr.get("next_tx_base", -1)) != expected_tx_base or int(rr.get("next_out_base", -1)) != expected_out_base:
            raise RuntimeError(f"Stage rebuild partition terminal base mismatch: window={rec.get('window_no')}")

    for rec in buckets:
        rr = rec.get("result") or {}
        if rec.get("tree") != rr.get("tree"):
            raise RuntimeError(f"Stage rebuild bucket tree binding mismatch: bucket={rec.get('bucket')}")

    # Revalidate committed generated artifacts before reuse.
    for rec in windows:
        d = root / "windows" / f"w{int(rec['window_no']):05d}_{int(rec['h1']):06d}_{int(rec['h2']):06d}"
        if not d.is_dir():
            raise RuntimeError(f"Committed Stage rebuild window data missing: {d}")
        got = _tree_digest(d)
        want = rec.get("tree") or {}
        if got != want:
            raise RuntimeError(f"Committed Stage rebuild window data changed: {d}")
    for rec in buckets:
        d = root / "buckets" / f"bucket_{str(rec['bucket'])}"
        if not d.is_dir():
            raise RuntimeError(f"Committed Stage rebuild bucket data missing: {d}")
        got = _tree_digest(d)
        want = rec.get("tree") or {}
        if got != want:
            raise RuntimeError(f"Committed Stage rebuild bucket data changed: {d}")

    # Clean only uncommitted scratch directories. Never mutate committed evidence.
    for pattern in (".tmp_window_*", ".tmp_bucket_*"):
        for p in root.glob(pattern):
            _remove_uncommitted_owned(p, root)

    return root, windows, buckets, {
        "contract_path": str(contract_path),
        "partition_ledger": str(partition_ledger),
        "bucket_ledger": str(bucket_ledger),
    }


def _copy_partitioned(con, query: str, dest: Path, partition_col: str = "bucket") -> None:
    if dest.exists():
        raise RuntimeError(f"partitioned COPY destination already exists: {dest}")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(partition_col)) is None:
        raise RuntimeError(f"invalid partition column: {partition_col!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    soft_nofile, _hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_nofile != resource.RLIM_INFINITY and int(soft_nofile) < STAGE_REBUILD_PARTITION_OPEN_FILES + 96:
        raise RuntimeError(
            f"RLIMIT_NOFILE too low for bounded partition writer: soft={soft_nofile} "
            f"required>={STAGE_REBUILD_PARTITION_OPEN_FILES + 96}"
        )
    con.execute(f"SET partitioned_write_max_open_files={STAGE_REBUILD_PARTITION_OPEN_FILES}")
    con.execute(
        f"COPY ({query}) TO {sql_quote(str(dest))} "
        f"(FORMAT PARQUET, COMPRESSION ZSTD, PARTITION_BY ({partition_col}), FILENAME_PATTERN 'data_{{uuid}}')"
    )


def _count_generated_parquet_in_con(con, root: Path, partition_col: str = "bucket") -> int:
    files = _generated_regular_files(list(root.glob(f"{partition_col}=*/*.parquet")), root)
    if not files:
        return 0
    return int(con.execute(
        f"SELECT count(*) FROM read_parquet({sql_list(files)}, hive_partitioning=false)"
    ).fetchone()[0] or 0)


def _stage_rebuild_partition_window(
    *, duckdb_module, root: Path, item: Dict[str, Any], tx_base: int, out_base: int,
    memory: str, temp_max: str, threads: int,
) -> Dict[str, Any]:
    idx, h1, h2 = int(item["window_no"]), int(item["h1"]), int(item["h2"])
    final = root / "windows" / f"w{idx:05d}_{h1:06d}_{h2:06d}"
    tmp = root / f".tmp_window_{idx:05d}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    scratch = root / f".duck_window_{idx:05d}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    tmp.mkdir(parents=True, exist_ok=False)
    con = duckdb_module.connect()
    try:
        settings = configure_duckdb(con, memory, scratch, temp_max, max(1, threads))
        txp = sql_quote(str(item["transactions_path"])); inp = sql_quote(str(item["inputs_path"])); outp = sql_quote(str(item["outputs_path"]))
        con.execute(f"""
            CREATE TEMP TABLE w_tx AS
            SELECT {int(tx_base)}::UBIGINT + row_number() OVER (ORDER BY height,tx_index)-1 AS tx_seq,
                   {int(out_base)}::UBIGINT + coalesce(sum(vout_count) OVER (
                       ORDER BY height,tx_index ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
                   ),0)::UBIGINT AS first_out,
                   height::BIGINT height, tx_index::BIGINT tx_index,
                   lower(txid::VARCHAR) txid, is_coinbase::BOOLEAN is_coinbase,
                   vin_count::BIGINT vin_count, vout_count::BIGINT vout_count
            FROM read_parquet({txp})
            WHERE height BETWEEN {h1} AND {h2}
        """)
        counts = con.execute("""
            SELECT count(*),coalesce(sum(vout_count),0),
                   coalesce(sum(CASE WHEN NOT is_coinbase THEN vin_count ELSE 0 END),0)
            FROM w_tx
        """).fetchone()
        tx_count, out_count, noncb_inputs = [int(x or 0) for x in counts]
        if tx_count <= 0 or out_count <= 0:
            raise RuntimeError(f"Stage rebuild empty window {h1}..{h2}")

        out_query = f"""
            SELECT substr(t.txid,1,2) AS bucket,
                   from_hex(t.txid) AS txid,
                   (t.first_out + o.vout::UBIGINT)::UBIGINT AS output_id,
                   t.tx_seq::UBIGINT AS tx_seq,
                   o.height::BIGINT AS height,o.tx_index::BIGINT AS tx_index,o.vout::UBIGINT AS vout,
                   CASE WHEN o.height<>0 AND o.script_pubkey_size<=10000
                              AND NOT (o.script_pubkey_size>0 AND substr(hex(o.script_pubkey),1,2)='6A')
                        THEN TRUE ELSE FALSE END AS eligible
            FROM read_parquet({outp}) o
            JOIN w_tx t ON t.height=o.height AND t.tx_index=o.tx_index AND t.txid=lower(o.txid::VARCHAR)
            WHERE o.height BETWEEN {h1} AND {h2}
        """
        in_query = f"""
            SELECT substr(lower(i.prev_txid::VARCHAR),1,2) AS bucket,
                   from_hex(lower(i.prev_txid::VARCHAR)) AS prev_txid,
                   i.prev_vout::UBIGINT AS prev_vout,
                   t.tx_seq::UBIGINT AS closer_tx_seq,
                   i.height::BIGINT AS height,i.tx_index::BIGINT AS tx_index,i.vin_index::UBIGINT AS vin_index
            FROM read_parquet({inp}) i
            JOIN w_tx t ON t.height=i.height AND t.tx_index=i.tx_index AND t.txid=lower(i.txid::VARCHAR)
            WHERE i.height BETWEEN {h1} AND {h2} AND NOT t.is_coinbase
        """
        _copy_partitioned(con, out_query, tmp / "outputs")
        if noncb_inputs:
            _copy_partitioned(con, in_query, tmp / "inputs")

        generated_out = _count_generated_parquet_in_con(con, tmp / "outputs")
        generated_in = _count_generated_parquet_in_con(con, tmp / "inputs") if noncb_inputs else 0
        if generated_out != out_count:
            raise RuntimeError(f"Stage rebuild partition output count {generated_out}!={out_count} window={h1}..{h2}")
        if generated_in != noncb_inputs:
            raise RuntimeError(f"Stage rebuild partition input count {generated_in}!={noncb_inputs} window={h1}..{h2}")
    finally:
        con.close(); shutil.rmtree(scratch, ignore_errors=True)

    tree = _tree_digest(tmp)
    if not os.path.lexists(final.parent):
        final.parent.mkdir(parents=True, exist_ok=False)
    _owned_dir(final.parent, root)
    if os.path.lexists(final):
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"uncommitted/final Stage rebuild window collision: {final}")
    os.replace(tmp, final); fsync_dir(final.parent)
    return {
        "status": "OK", "window_no": idx, "h1": h1, "h2": h2,
        "tx_base": int(tx_base), "out_base": int(out_base),
        "tx_count": tx_count, "out_count": out_count, "noncoinbase_inputs": noncb_inputs,
        "next_tx_base": int(tx_base + tx_count), "next_out_base": int(out_base + out_count),
        "tree": tree, "duckdb_settings": settings,
    }


def _bucket_file_lists(root: Path, bucket: str) -> Tuple[List[str], List[str]]:
    windows_root = root / "windows"
    _owned_dir(windows_root, root)
    outs = _generated_regular_files(list(windows_root.glob(f"w*/outputs/bucket={bucket}/*.parquet")), windows_root)
    ins = _generated_regular_files(list(windows_root.glob(f"w*/inputs/bucket={bucket}/*.parquet")), windows_root)
    return outs, ins


def _stage_rebuild_resolve_bucket(
    *, duckdb_module, root: Path, bucket_no: int, bucket: str, target: int,
    close_tx_span: int, memory: str, temp_max: str, threads: int,
) -> Dict[str, Any]:
    final = root / "buckets" / f"bucket_{bucket}"
    tmp = root / f".tmp_bucket_{bucket}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    scratch = root / f".duck_bucket_{bucket}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    tmp.mkdir(parents=True, exist_ok=False)
    outs, ins = _bucket_file_lists(root, bucket)
    if not outs:
        if ins:
            raise RuntimeError(f"Stage rebuild bucket {bucket} has inputs but no outputs")
        if not os.path.lexists(final.parent):
            final.parent.mkdir(parents=True, exist_ok=False)
        _owned_dir(final.parent, root)
        if os.path.lexists(final):
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"uncommitted/final Stage rebuild empty-bucket collision: {final}")
        os.replace(tmp, final); fsync_dir(final.parent)
        return {
            "status": "OK", "bucket_no": bucket_no, "bucket": bucket,
            "outputs": 0, "noncoinbase_inputs": 0, "resolved_spends": 0,
            "unresolved_prevouts": 0, "spend_ineligible": 0, "double_spends": 0,
            "bucket_integrity": {"bad_output_membership_or_txid_size":0,"bad_input_membership_or_txid_size":0,"duplicate_output_ids":0,"duplicate_input_keys":0},
            "duplicate_txid_groups": [], "duplicate_txid_contract_status": "OK",
            "bip30_close_rows": 0, "bip30_counts": {}, "expected_close_count": 0,
            "tree": _tree_digest(final),
        }
    con = duckdb_module.connect()
    failed: List[str] = []
    orphan_samples: List[Dict[str, Any]] = []
    try:
        settings = configure_duckdb(con, memory, scratch, temp_max, max(1, threads))
        con.execute(f"CREATE TEMP VIEW b_out AS SELECT * FROM read_parquet({sql_list(outs)}, hive_partitioning=false)")
        if ins:
            con.execute(f"CREATE TEMP VIEW b_in AS SELECT * FROM read_parquet({sql_list(ins)}, hive_partitioning=false)")
        else:
            con.execute("""
                CREATE TEMP TABLE b_in(prev_txid BLOB,prev_vout UBIGINT,closer_tx_seq UBIGINT,
                                       height BIGINT,tx_index BIGINT,vin_index UBIGINT)
            """)
        output_rows = int(con.execute("SELECT count(*) FROM b_out").fetchone()[0] or 0)
        noncb_inputs = int(con.execute("SELECT count(*) FROM b_in").fetchone()[0] or 0)
        duplicate_rows = con.execute("""
            WITH txs AS (
              SELECT txid,tx_seq,min(height) height,min(tx_index) tx_index
              FROM b_out GROUP BY txid,tx_seq
            )
            SELECT lower(hex(txid)),list(height ORDER BY height,tx_index),list(tx_index ORDER BY height,tx_index),count(*)
            FROM txs GROUP BY txid HAVING count(*)>1 ORDER BY 1
        """).fetchall()
        duplicate_txid_groups = [[str(r[0]), [int(x) for x in r[1]], [int(x) for x in r[2]], int(r[3])] for r in duplicate_rows]
        expected_duplicate_txid_groups = _expected_duplicate_groups(target, bucket=bucket)
        if duplicate_txid_groups != expected_duplicate_txid_groups:
            failed.append(f"duplicate_txid_contract:{duplicate_txid_groups}!={expected_duplicate_txid_groups}")
        bucket_integrity = con.execute("""
            SELECT
              (SELECT count(*) FROM b_out WHERE octet_length(txid)<>32 OR lower(substr(hex(txid),1,2))<>?),
              (SELECT count(*) FROM b_in WHERE octet_length(prev_txid)<>32 OR lower(substr(hex(prev_txid),1,2))<>?),
              (SELECT count(*) FROM (SELECT output_id,count(*) c FROM b_out GROUP BY output_id HAVING c<>1)),
              (SELECT count(*) FROM (SELECT closer_tx_seq,vin_index,count(*) c FROM b_in GROUP BY closer_tx_seq,vin_index HAVING c<>1))
        """, [bucket, bucket]).fetchone()
        bad_out_bucket, bad_in_bucket, duplicate_output_ids, duplicate_input_keys = [int(x or 0) for x in bucket_integrity]
        if bad_out_bucket:
            failed.append(f"bucket_output_membership_or_txid_size:{bad_out_bucket}")
        if bad_in_bucket:
            failed.append(f"bucket_input_membership_or_txid_size:{bad_in_bucket}")
        if duplicate_output_ids:
            failed.append(f"bucket_duplicate_output_id:{duplicate_output_ids}")
        if duplicate_input_keys:
            failed.append(f"bucket_duplicate_input_key:{duplicate_input_keys}")
        log(f"stage_rebuild bucket {bucket} resolve outputs={output_rows:,} inputs={noncb_inputs:,}")
        con.execute("""
            CREATE TEMP TABLE resolved_spends AS
            SELECT closer_tx_seq,vin_index,output_id,eligible
            FROM (
              SELECT i.closer_tx_seq,i.vin_index,o.output_id,o.eligible,
                     row_number() OVER (
                       PARTITION BY i.closer_tx_seq,i.vin_index
                       ORDER BY o.height DESC,o.tx_index DESC
                     ) AS rn
              FROM b_in i
              JOIN b_out o ON o.txid=i.prev_txid AND o.vout=i.prev_vout
              WHERE o.height<i.height OR (o.height=i.height AND o.tx_index<i.tx_index)
            ) q WHERE rn=1
        """)
        resolved = int(con.execute("SELECT count(*) FROM resolved_spends").fetchone()[0] or 0)
        unresolved = noncb_inputs - resolved
        if unresolved:
            failed.append(f"coverage_orphan_prevouts:{unresolved}/{noncb_inputs}")
            rows = con.execute("""
                SELECT i.height,i.tx_index,i.vin_index,hex(i.prev_txid),i.prev_vout,i.closer_tx_seq
                FROM b_in i LEFT JOIN resolved_spends r
                  ON r.closer_tx_seq=i.closer_tx_seq AND r.vin_index=i.vin_index
                WHERE r.output_id IS NULL LIMIT 20
            """).fetchall()
            orphan_samples = [
                {"spent_height": int(r[0]), "spent_tx_index": int(r[1]), "vin_index": int(r[2]),
                 "prev_txid": str(r[3]).lower(), "prev_vout": int(r[4]), "closer_tx_seq": int(r[5])}
                for r in rows
            ]
        spend_ineligible = int(con.execute("SELECT count(*) FROM resolved_spends WHERE NOT eligible").fetchone()[0] or 0)
        if spend_ineligible:
            failed.append(f"spend_of_ineligible_output:{spend_ineligible}")
        double_spends = int(con.execute("SELECT count(*) FROM (SELECT output_id,count(*) c FROM resolved_spends GROUP BY output_id HAVING c<>1)").fetchone()[0] or 0)
        if double_spends:
            failed.append(f"double_spend_resolved_outputs:{double_spends}")

        unions: List[str] = []
        bip30_counts: Dict[str, int] = {}
        for bi, b in enumerate(BIP30):
            if b["later"] <= target and b["txid"][:2] == bucket:
                unions.append(f"""
                  SELECT old_out.output_id,new_out.tx_seq AS closer_tx_seq,{NO_VIN}::UBIGINT AS vin,2::INTEGER AS close_type,{bi}::INTEGER AS bip30_index
                  FROM b_out old_out
                  JOIN b_out new_out ON new_out.txid=old_out.txid AND new_out.vout=old_out.vout AND new_out.height={int(b['later'])}
                  WHERE old_out.txid=from_hex('{b['txid']}') AND old_out.height={int(b['early'])} AND old_out.eligible
                    AND NOT EXISTS (
                      SELECT 1 FROM resolved_spends r WHERE r.output_id=old_out.output_id AND r.closer_tx_seq<new_out.tx_seq
                    )
                """)
        bip_sql = " UNION ALL ".join(unions) if unions else (
            "SELECT NULL::UBIGINT output_id,NULL::UBIGINT closer_tx_seq,NULL::UBIGINT vin,NULL::INTEGER close_type,NULL::INTEGER bip30_index WHERE FALSE"
        )
        con.execute(f"CREATE TEMP TABLE bip30_closes AS {bip_sql}")
        for bi, b in enumerate(BIP30):
            n = int(con.execute("SELECT count(*) FROM bip30_closes WHERE bip30_index=?", [bi]).fetchone()[0] or 0)
            if n:
                bip30_counts[str(b["txid"])] = n
        con.execute("""
            CREATE TEMP TABLE expected_closes AS
            SELECT output_id,closer_tx_seq,vin_index::UBIGINT vin,1::INTEGER close_type FROM resolved_spends
            UNION ALL
            SELECT output_id,closer_tx_seq,vin,close_type FROM bip30_closes
        """)
        close_duplicate = int(con.execute("SELECT count(*) FROM (SELECT output_id,count(*) c FROM expected_closes GROUP BY output_id HAVING c<>1)").fetchone()[0] or 0)
        if close_duplicate:
            failed.append(f"expected_close_not_bijective:{close_duplicate}")
        expected_close_count = int(con.execute("SELECT count(*) FROM expected_closes").fetchone()[0] or 0)

        if expected_close_count:
            close_dest = tmp / "closes"
            close_query = f"""
                SELECT floor(closer_tx_seq/{int(close_tx_span)})::UBIGINT AS close_part,
                       output_id::UBIGINT AS output_id,closer_tx_seq::UBIGINT AS closer_tx_seq,
                       vin::UBIGINT AS vin,close_type::INTEGER AS close_type
                FROM expected_closes
            """
            _copy_partitioned(con, close_query, close_dest, partition_col="close_part")
            generated = sorted(str(p) for p in close_dest.glob("close_part=*/*.parquet") if p.is_file())
            if generated:
                actual_close_count = int(con.execute(f"SELECT count(*) FROM read_parquet({sql_list(generated)}, hive_partitioning=false)").fetchone()[0] or 0)
                if actual_close_count != expected_close_count:
                    raise RuntimeError(f"bucket close COPY count {actual_close_count}!={expected_close_count} bucket={bucket}")
        else:
            (tmp / "closes").mkdir(parents=True, exist_ok=True)
    finally:
        con.close(); shutil.rmtree(scratch, ignore_errors=True)

    tree = _tree_digest(tmp)
    if not os.path.lexists(final.parent):
        final.parent.mkdir(parents=True, exist_ok=False)
    _owned_dir(final.parent, root)
    if os.path.lexists(final):
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"uncommitted/final Stage rebuild bucket collision: {final}")
    os.replace(tmp, final); fsync_dir(final.parent)
    return {
        "status": "OK" if not failed else "BAD", "failed_checks": failed,
        "bucket_no": bucket_no, "bucket": bucket, "outputs": output_rows,
        "noncoinbase_inputs": noncb_inputs, "resolved_spends": resolved,
        "unresolved_prevouts": unresolved, "orphan_samples": orphan_samples,
        "spend_ineligible": spend_ineligible, "double_spends": double_spends,
        "bucket_integrity": {
            "bad_output_membership_or_txid_size": bad_out_bucket,
            "bad_input_membership_or_txid_size": bad_in_bucket,
            "duplicate_output_ids": duplicate_output_ids,
            "duplicate_input_keys": duplicate_input_keys,
        },
        "duplicate_txid_groups": duplicate_txid_groups,
        "duplicate_txid_contract_status": "OK" if duplicate_txid_groups == expected_duplicate_txid_groups else "BAD",
        "bip30_close_rows": sum(bip30_counts.values()), "bip30_counts": bip30_counts,
        "expected_close_count": expected_close_count, "tree": tree,
        "duckdb_settings": settings,
    }


def _stage_rebuild_scan_closes(
    *, duckdb_module, root: Path, state_scan: Dict[str, Any], close_tx_span: int,
    memory: str, temp_max: str, threads: int, full_stream_hashes: bool,
) -> Tuple[bytearray, Dict[str, Any]]:
    out_count = int(state_scan["out_count"])
    closed = bytearray((out_count + 7) // 8)
    close_hash = hashlib.sha256()
    count = 0; spend_count = 0; bip_count = 0; duplicate = 0
    part_dirs = set()
    buckets_dir = root / "buckets"
    _owned_dir(buckets_dir, root)
    for p in buckets_dir.glob("bucket_*/closes/close_part=*"):
        if p.is_dir():
            try: part_dirs.add(int(p.name.split("=", 1)[1]))
            except Exception: raise RuntimeError(f"invalid close_part directory: {p}")
    for part in sorted(part_dirs):
        buckets_root = root / "buckets"
        _owned_dir(buckets_root, root)
        part_paths = list(buckets_root.glob(f"bucket_*/closes/close_part={part}/*.parquet"))
        files = _generated_regular_files(part_paths, buckets_root)
        if not files:
            raise RuntimeError(f"close_part directory discovered without regular parquet files: part={part}")
        con = duckdb_module.connect()
        scratch = root / f".duck_closepart_{part}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        try:
            configure_duckdb(con, memory, scratch, temp_max, max(1, threads))
            order = " ORDER BY closer_tx_seq,CASE WHEN close_type=2 THEN output_id ELSE vin END,output_id" if full_stream_hashes else ""
            cur = con.execute(f"SELECT output_id,closer_tx_seq,vin,close_type FROM read_parquet({sql_list(files)}, hive_partitioning=false){order}")
            part_rows = 0
            while True:
                rows = cur.fetchmany(65536)
                if not rows: break
                for oid, closer, vin, typ in rows:
                    oid = int(oid); closer = int(closer); vin = int(vin); typ = int(typ)
                    if oid < 0 or oid >= out_count:
                        raise RuntimeError(f"expected close output_id OOB: {oid}")
                    if closer // int(close_tx_span) != part:
                        raise RuntimeError(f"close_part contract mismatch part={part} closer={closer}")
                    if typ not in (1, 2):
                        raise RuntimeError(f"expected close type invalid: {typ}")
                    if typ == 2 and vin != NO_VIN:
                        raise RuntimeError(f"BIP30 expected close vin invalid: {vin}")
                    if typ == 1 and vin == NO_VIN:
                        raise RuntimeError("spend expected close uses NO_VIN")
                    bi = oid >> 3; mask = 1 << (oid & 7)
                    if closed[bi] & mask:
                        duplicate += 1
                        raise RuntimeError(f"expected close duplicate output_id={oid}")
                    closed[bi] |= mask
                    if full_stream_hashes:
                        close_hash.update(struct.pack("<QQII", oid, closer, vin, typ))
                    count += 1; part_rows += 1
                    if typ == 1: spend_count += 1
                    else: bip_count += 1
            log(f"stage_rebuild close_part={part} rows={part_rows:,} cumulative={count:,}")
        finally:
            con.close(); shutil.rmtree(scratch, ignore_errors=True)
    failed: List[str] = []
    if count != int(state_scan["close_count"]):
        failed.append(f"close_count:{count}!={state_scan['close_count']}")
    close_fp = close_hash.hexdigest() if full_stream_hashes else None
    if full_stream_hashes and close_fp != state_scan["close_stream_sha256"]:
        failed.append(f"close_stream_sha256:{close_fp}!={state_scan['close_stream_sha256']}")
    return closed, {
        "status": "OK" if not failed else "BAD", "failed_checks": failed,
        "expected_close_count": count, "spend_closes": spend_count, "bip30_closes_total": bip_count,
        "duplicate_close_outputs": duplicate, "close_stream_sha256": close_fp,
    }


def _stage_rebuild_scan_stage_streams(
    *, duckdb_module, plan: Sequence[Dict[str, Any]], closed: bytearray,
    state_scan: Dict[str, Any], memory: str, temp_max: str, threads: int,
    root: Path, full_stream_hashes: bool,
) -> Dict[str, Any]:
    failed: List[str] = []
    htx = hashlib.sha256(); hout = hashlib.sha256(); hlive = hashlib.sha256()
    tx_count = 0; out_count = 0; live_count = 0; live_value = 0; script_bytes = 0; ineligible = 0
    for wi, item in enumerate(plan):
        h1, h2 = int(item["h1"]), int(item["h2"])
        con = duckdb_module.connect()
        scratch = root / f".duck_stream_{wi:05d}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        try:
            configure_duckdb(con, memory, scratch, temp_max, max(1, threads))
            txp = sql_quote(str(item["transactions_path"])); outp = sql_quote(str(item["outputs_path"]))
            cur = con.execute(f"""
                SELECT lower(txid::VARCHAR),height::BIGINT,tx_index::BIGINT,vout_count::BIGINT,is_coinbase::BOOLEAN
                FROM read_parquet({txp}) WHERE height BETWEEN {h1} AND {h2}
                ORDER BY height,tx_index
            """)
            while True:
                rows = cur.fetchmany(65536)
                if not rows: break
                for txid, height, ti, vc, cb in rows:
                    if full_stream_hashes:
                        htx.update(bytes.fromhex(str(txid))); htx.update(struct.pack("<I", int(height)))
                        htx.update(struct.pack("<I", int(ti))); htx.update(struct.pack("<I", int(vc)))
                        htx.update(bytes([1 if cb else 0]))
                    tx_count += 1
            cur = con.execute(f"""
                SELECT lower(txid::VARCHAR),vout::BIGINT,value_sats::BIGINT,script_pubkey::BLOB,
                       height::BIGINT,tx_index::BIGINT,script_pubkey_size::BIGINT
                FROM read_parquet({outp}) WHERE height BETWEEN {h1} AND {h2}
                ORDER BY height,tx_index,vout
            """)
            while True:
                rows = cur.fetchmany(32768)
                if not rows: break
                for txid, vout, val, script, height, ti, script_size in rows:
                    sb = bytes(script)
                    if len(sb) != int(script_size):
                        raise RuntimeError(f"script size mismatch during Stage stream scan h={height} ti={ti} vout={vout}")
                    eligible = int(height) != 0 and len(sb) <= MAX_SCRIPT_SIZE and not (len(sb) > 0 and sb[0] == 0x6A)
                    if not eligible: ineligible += 1
                    oid = out_count
                    bi = oid >> 3; mask = 1 << (oid & 7)
                    is_closed = bool(closed[bi] & mask)
                    cb = int(ti) == 0
                    if full_stream_hashes:
                        fp_update(hout, str(txid), int(vout), int(val), sb, int(height), int(ti), cb)
                        hout.update(bytes([1 if eligible else 0]))
                    if eligible and not is_closed:
                        fp_update(hlive, str(txid), int(vout), int(val), sb, int(height), int(ti), cb)
                        live_count += 1; live_value += int(val)
                    script_bytes += len(sb); out_count += 1
        finally:
            con.close(); shutil.rmtree(scratch, ignore_errors=True)
        if wi == 0 or (wi + 1) % 25 == 0 or wi + 1 == len(plan):
            log(f"stage_rebuild Stage stream windows={wi+1}/{len(plan)} tx={tx_count:,} out={out_count:,} live={live_count:,}")

    tx_fp = htx.hexdigest() if full_stream_hashes else None
    out_fp = hout.hexdigest() if full_stream_hashes else None
    live_fp = hlive.hexdigest()
    if tx_count != int(state_scan["tx_count"]): failed.append(f"tx_count:{tx_count}!={state_scan['tx_count']}")
    if out_count != int(state_scan["out_count"]): failed.append(f"out_count:{out_count}!={state_scan['out_count']}")
    if script_bytes != int(state_scan["script_bytes"]): failed.append(f"script_bytes:{script_bytes}!={state_scan['script_bytes']}")
    if live_count != int(state_scan["live_count"]): failed.append(f"live_count:{live_count}!={state_scan['live_count']}")
    if live_value != int(state_scan["live_value_sats"]): failed.append(f"live_value:{live_value}!={state_scan['live_value_sats']}")
    if live_fp != state_scan["live_fingerprint_sha256"]: failed.append(f"live_fingerprint:{live_fp}!={state_scan['live_fingerprint_sha256']}")
    if full_stream_hashes and tx_fp != state_scan["tx_stream_sha256"]: failed.append(f"tx_stream_sha256:{tx_fp}!={state_scan['tx_stream_sha256']}")
    if full_stream_hashes and out_fp != state_scan["all_outputs_sha256"]: failed.append(f"all_outputs_sha256:{out_fp}!={state_scan['all_outputs_sha256']}")
    return {
        "status": "OK" if not failed else "BAD", "failed_checks": failed,
        "tx_count": tx_count, "out_count": out_count, "script_bytes": script_bytes,
        "ineligible_outputs": ineligible,
        "expected_live_count": live_count, "expected_live_value_sats": live_value,
        "expected_live_fingerprint_sha256": live_fp,
        "tx_stream_sha256": tx_fp, "all_outputs_sha256": out_fp,
        "duplicate_txid_scope": "NOT_COMPUTED_IN_STREAM_SCAN; PROVED_BY_BUCKET_RECORDS",
    }


def stage_independent_rebuild_bucketed(
    *, stage: Dict[str, Any], state: Path, state_contract: Dict[str, Any], target: int,
    state_scan: Dict[str, Any], full_stream_hashes: bool, auditor_sha256: str,
    work_base: Path, allow_resume: bool, memory: str, temp_max: str, threads: int,
    partition_threads: int, close_tx_span: int, min_free_tmp: str,
) -> Dict[str, Any]:
    if close_tx_span <= 0:
        raise RuntimeError("--stage-rebuild-close-tx-span must be >0")
    work_resolved = work_base.resolve(strict=False)
    state_resolved = state.resolve(strict=True)
    plan = _stage_rebuild_plan(stage, target)
    authoritative_stage_paths = [Path(str(stage["path"])).resolve(strict=True)]
    for item in plan:
        authoritative_stage_paths.extend([
            Path(str(item["transactions_path"])).resolve(strict=True),
            Path(str(item["inputs_path"])).resolve(strict=True),
            Path(str(item["outputs_path"])).resolve(strict=True),
        ])
    common_stage_root = Path(os.path.commonpath([str(x) for x in authoritative_stage_paths]))
    if common_stage_root.is_file():
        common_stage_root = common_stage_root.parent
    if work_resolved == state_resolved or state_resolved in work_resolved.parents:
        raise RuntimeError(f"Stage rebuild work-dir must not be inside authoritative V50 state: {work_resolved}")
    if work_resolved == common_stage_root or common_stage_root in work_resolved.parents:
        raise RuntimeError(f"Stage rebuild work-dir must not be inside authoritative Stage tree: {work_resolved}")
    work_resources = resource_preflight(work_base, temp_max, min_free_tmp)
    if work_resources["status"] != "OK":
        raise RuntimeError(f"Stage rebuild work-dir resource preflight failed: {work_resources.get('failed_checks')}")
    duckdb = require_duckdb()
    contract = _stage_rebuild_contract(
        auditor_sha256=auditor_sha256, state=state, state_contract=state_contract,
        stage=stage, target=target, plan=plan, close_tx_span=close_tx_span,
    )
    lock_root = work_base / str(contract["contract_id"])
    with StageRebuildProgressLease(lock_root):
        root, window_records, bucket_records, progress = _stage_rebuild_prepare_root(
            work_base, contract, plan, allow_resume=allow_resume
        )
        partition_ledger = Path(progress["partition_ledger"]); bucket_ledger = Path(progress["bucket_ledger"])
        if window_records:
            log(f"stage_rebuild resume partition windows={len(window_records)}/{len(plan)}")
        tx_base = int(window_records[-1]["result"]["next_tx_base"]) if window_records else 0
        out_base = int(window_records[-1]["result"]["next_out_base"]) if window_records else 0
        for idx in range(len(window_records), len(plan)):
            item = plan[idx]
            chunk_resources = resource_preflight(work_base, temp_max, min_free_tmp)
            if chunk_resources["status"] != "OK":
                raise RuntimeError(f"Stage rebuild work-dir free space became unsafe before window {idx}: {chunk_resources.get('failed_checks')}")
            log(f"stage_rebuild partition START {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']} tx_base={tx_base:,} out_base={out_base:,}")
            result = _stage_rebuild_partition_window(
                duckdb_module=duckdb, root=root, item=item, tx_base=tx_base, out_base=out_base,
                memory=memory, temp_max=temp_max, threads=max(1, partition_threads),
            )
            rec: Dict[str, Any] = {
                "schema": STAGE_REBUILD_PARTITION_RECORD_SCHEMA,
                "contract_id": contract["contract_id"], "record_no": idx + 1, "window_no": idx,
                "h1": int(item["h1"]), "h2": int(item["h2"]),
                "stage_manifest_sha256": str(item["stage_manifest_sha256"]),
                "status": str(result["status"]), "result": result, "tree": result["tree"],
                "finished_utc": utc_now(),
                "previous_record_sha256": window_records[-1]["record_sha256"] if window_records else None,
            }
            rec["record_sha256"] = canonical_json_hash(rec, exclude=("record_sha256",))
            append_jsonl_fsync(partition_ledger, rec); window_records.append(rec)
            tx_base = int(result["next_tx_base"]); out_base = int(result["next_out_base"])
            log(f"stage_rebuild partition OK {idx+1}/{len(plan)} tx={tx_base:,} out={out_base:,}")
        if tx_base != int(state_scan["tx_count"]) or out_base != int(state_scan["out_count"]):
            return {
                "status": "BAD", "failed_checks": [
                    f"partition_terminal_tx:{tx_base}!={state_scan['tx_count']}",
                    f"partition_terminal_out:{out_base}!={state_scan['out_count']}",
                ], "progress": progress,
            }

        if bucket_records:
            log(f"stage_rebuild resume causal buckets={len(bucket_records)}/{len(STAGE_REBUILD_BUCKETS)}")
            bad_committed = [r for r in bucket_records if str(r.get("status")) != "OK"]
            if bad_committed:
                rr = bad_committed[0].get("result") or {}
                return {
                    "status": "BAD",
                    "failed_checks": rr.get("failed_checks") or [f"committed_bucket_{bad_committed[0].get('bucket')}_bad"],
                    "failed_bucket": rr,
                    "progress": progress,
                    "resume_blocked_by_committed_bad": True,
                }
        for idx in range(len(bucket_records), len(STAGE_REBUILD_BUCKETS)):
            bucket = STAGE_REBUILD_BUCKETS[idx]
            chunk_resources = resource_preflight(work_base, temp_max, min_free_tmp)
            if chunk_resources["status"] != "OK":
                raise RuntimeError(f"Stage rebuild work-dir free space became unsafe before bucket {bucket}: {chunk_resources.get('failed_checks')}")
            log(f"stage_rebuild causal bucket START {idx+1}/256 bucket={bucket}")
            result = _stage_rebuild_resolve_bucket(
                duckdb_module=duckdb, root=root, bucket_no=idx, bucket=bucket, target=target,
                close_tx_span=close_tx_span, memory=memory, temp_max=temp_max, threads=max(1, threads),
            )
            rec = {
                "schema": STAGE_REBUILD_BUCKET_RECORD_SCHEMA,
                "contract_id": contract["contract_id"], "record_no": idx + 1, "bucket_no": idx,
                "bucket": bucket, "status": str(result["status"]), "result": result, "tree": result["tree"],
                "finished_utc": utc_now(),
                "previous_record_sha256": bucket_records[-1]["record_sha256"] if bucket_records else None,
            }
            rec["record_sha256"] = canonical_json_hash(rec, exclude=("record_sha256",))
            append_jsonl_fsync(bucket_ledger, rec); bucket_records.append(rec)
            log(f"stage_rebuild causal bucket {result['status']} {idx+1}/256 bucket={bucket} resolved={result['resolved_spends']:,}")
            if result["status"] != "OK":
                return {
                    "status": "BAD", "failed_checks": result.get("failed_checks") or [f"bucket_{bucket}_bad"],
                    "failed_bucket": result, "progress": progress,
                }

        partition_noncb_inputs = sum(int(r["result"]["noncoinbase_inputs"]) for r in window_records)
        bucket_outputs = sum(int(r["result"]["outputs"]) for r in bucket_records)
        noncb_inputs = sum(int(r["result"]["noncoinbase_inputs"]) for r in bucket_records)
        resolved = sum(int(r["result"]["resolved_spends"]) for r in bucket_records)
        unresolved = sum(int(r["result"]["unresolved_prevouts"]) for r in bucket_records)
        spend_ineligible = sum(int(r["result"]["spend_ineligible"]) for r in bucket_records)
        double_spends = sum(int(r["result"]["double_spends"]) for r in bucket_records)
        bip30_close_rows = sum(int(r["result"]["bip30_close_rows"]) for r in bucket_records)
        expected_close_from_buckets = sum(int(r["result"]["expected_close_count"]) for r in bucket_records)

        final_resources = resource_preflight(work_base, temp_max, min_free_tmp)
        if final_resources["status"] != "OK":
            raise RuntimeError(f"Stage rebuild work-dir free space unsafe before final scans: {final_resources.get('failed_checks')}")
        closed, close_scan = _stage_rebuild_scan_closes(
            duckdb_module=duckdb, root=root, state_scan=state_scan, close_tx_span=close_tx_span,
            memory=memory, temp_max=temp_max, threads=max(1, threads), full_stream_hashes=full_stream_hashes,
        )
        stream_scan = _stage_rebuild_scan_stage_streams(
            duckdb_module=duckdb, plan=plan, closed=closed, state_scan=state_scan,
            memory=memory, temp_max=temp_max, threads=min(2, max(1, threads)), root=root,
            full_stream_hashes=full_stream_hashes,
        )
        all_duplicate_txid_groups = sorted(
            [g for r in bucket_records for g in ((r.get("result") or {}).get("duplicate_txid_groups") or [])],
            key=lambda x: x[0],
        )
        expected_duplicate_txid_groups = _expected_duplicate_groups(target)
        duplicate_txid_contract_status = "OK" if all_duplicate_txid_groups == expected_duplicate_txid_groups else "BAD"
        failed: List[str] = []
        if duplicate_txid_contract_status != "OK":
            failed.append(f"duplicate_txid_contract:{all_duplicate_txid_groups}!={expected_duplicate_txid_groups}")
        if bucket_outputs != out_base:
            failed.append(f"bucket_output_coverage:{bucket_outputs}!={out_base}")
        if noncb_inputs != partition_noncb_inputs:
            failed.append(f"bucket_input_coverage:{noncb_inputs}!={partition_noncb_inputs}")
        if unresolved: failed.append(f"coverage_orphan_prevouts:{unresolved}/{noncb_inputs}")
        if spend_ineligible: failed.append(f"spend_of_ineligible_output:{spend_ineligible}")
        if double_spends: failed.append(f"double_spend_resolved_outputs:{double_spends}")
        if expected_close_from_buckets != int(close_scan["expected_close_count"]):
            failed.append(f"bucket_close_count:{expected_close_from_buckets}!={close_scan['expected_close_count']}")
        if resolved != int(close_scan.get("spend_closes") or 0):
            failed.append(f"spend_close_count:{close_scan.get('spend_closes')}!={resolved}")
        if bip30_close_rows != int(close_scan.get("bip30_closes_total") or 0):
            failed.append(f"bip30_close_count:{close_scan.get('bip30_closes_total')}!={bip30_close_rows}")
        if resolved + bip30_close_rows != int(close_scan["expected_close_count"]):
            failed.append(f"close_composition:{resolved}+{bip30_close_rows}!={close_scan['expected_close_count']}")
        failed.extend(close_scan.get("failed_checks") or [])
        failed.extend(stream_scan.get("failed_checks") or [])
        return {
            "status": "OK" if not failed else "BAD", "failed_checks": sorted(set(failed)),
            "engine": "TXID_PREFIX_BUCKETED_CAUSAL_V1", "bounded_memory": True,
            "bucket_contract": "first-two-lowercase-hex-chars-of-canonical-txid",
            "buckets_total": 256, "buckets_completed": len(bucket_records),
            "windows_total": len(plan), "windows_partitioned": len(window_records),
            "close_tx_span": int(close_tx_span), "progress": progress,
            "work_dir_resource_preflight": work_resources,
            "work_dir_final_resource_preflight": final_resources,
            "authoritative_stage_root": str(common_stage_root),
            "partition_threads": int(max(1, partition_threads)), "causal_threads": int(max(1, threads)),
            "coverage_status": "OK" if (unresolved == 0 and bucket_outputs == out_base and noncb_inputs == partition_noncb_inputs) else "GAP",
            "partition_output_rows": out_base, "bucket_output_rows": bucket_outputs,
            "partition_noncoinbase_inputs": partition_noncb_inputs,
            "noncoinbase_inputs": noncb_inputs, "resolved_spends": resolved,
            "unresolved_prevouts": unresolved, "spend_ineligible": spend_ineligible,
            "double_spends": double_spends, "bip30_close_rows": bip30_close_rows,
            "duplicate_txid_groups": all_duplicate_txid_groups,
            "duplicate_txid_contract_status": duplicate_txid_contract_status,
            "expected_duplicate_txid_groups": expected_duplicate_txid_groups,
            "expected_close_count": int(close_scan["expected_close_count"]),
            "expected_live_count": int(stream_scan["expected_live_count"]),
            "expected_live_value_sats": int(stream_scan["expected_live_value_sats"]),
            "expected_live_fingerprint_sha256": str(stream_scan["expected_live_fingerprint_sha256"]),
            "full_stream_hashes": bool(full_stream_hashes),
            "tx_stream_sha256": stream_scan.get("tx_stream_sha256"),
            "all_outputs_sha256": stream_scan.get("all_outputs_sha256"),
            "close_stream_sha256": close_scan.get("close_stream_sha256"),
            "close_scan": close_scan,
            "stream_scan": stream_scan,
        }


def _core_stage_import_evidence(
    *, ledger_path: Path, stage: Dict[str, Any], state: Path, state_contract: Dict[str, Any], target: int,
    expected_ledger_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate and reuse a completed trusted Core->Stage proof without rerunning raw-block chunks."""
    ledger_path = regular(ledger_path)
    root = ledger_path.parent
    contract_path = regular(root / "contract.json")
    if read_sidecar(Path(str(contract_path) + ".sha256")) != sha256_file(contract_path):
        raise RuntimeError(f"Core->Stage imported contract sidecar mismatch: {contract_path}")
    contract = load_json(contract_path)
    trusted = {
        "6fe9c39df330ea8b6cc6572db071bf30916a04165f7a84244ab48e5bd41d7dae",
        V51_5_4_AUDITOR_SHA256,
        sha256_file(Path(__file__).resolve()),
    }
    if contract.get("schema") != CORE_STAGE_PROGRESS_SCHEMA:
        raise RuntimeError("Core->Stage imported contract schema mismatch")
    if str(contract.get("auditor_sha256") or "") not in trusted:
        raise RuntimeError(f"Core->Stage evidence auditor SHA is not trusted: {contract.get('auditor_sha256')}")
    plan = _core_stage_chunk_plan(stage, target)
    checks = [
        (int(contract.get("target_height", -1)) == target, "target_height"),
        (str(contract.get("target_hash") or "") == str(state_contract["block_hash"]), "target_hash"),
        (str((contract.get("stage") or {}).get("release_sha256") or "") == str(stage["sha256"]), "stage_release_sha"),
        (str((contract.get("stage") or {}).get("window_plan_sha256") or "") == _core_stage_plan_digest(plan), "stage_plan_sha"),
        (str((contract.get("bitcoin_core") or {}).get("chain") or "") == "main", "chain"),
        (str((contract.get("bitcoin_core") or {}).get("genesis_hash") or "") == GENESIS_HASH, "genesis"),
        (str((contract.get("bitcoin_core") or {}).get("target_hash") or "") == str(state_contract["block_hash"]), "core_target"),
        (str((contract.get("bitcoin_core") or {}).get("raw_block_contract") or "") == "getblock-verbosity0-independent-parser-v1", "raw_contract"),
    ]
    bad = [name for ok, name in checks if not ok]
    if bad:
        raise RuntimeError(f"Core->Stage imported contract incompatible: {bad}")
    contract_id = str(contract.get("contract_id") or "")
    if contract_id != canonical_json_hash(contract, exclude=("contract_id",)):
        # Historical contract_id was computed before adding itself.
        tmp = dict(contract); tmp.pop("contract_id", None)
        if contract_id != canonical_json_hash(tmp):
            raise RuntimeError("Core->Stage imported contract_id mismatch")
    records = _core_stage_read_progress(ledger_path, contract_id, plan, expected_sha256=expected_ledger_sha256)
    if len(records) != len(plan):
        raise RuntimeError(f"Core->Stage imported evidence incomplete {len(records)}/{len(plan)}")
    expected_h = 0; totals = {"blocks":0,"transactions":0,"inputs":0,"outputs":0,"raw_block_bytes":0}
    for r in records:
        if str(r.get("status")) != "OK":
            raise RuntimeError(f"Core->Stage imported committed non-OK chunk: {r.get('chunk_no')}")
        if int(r["h1"]) != expected_h:
            raise RuntimeError(f"Core->Stage imported coverage gap at {expected_h}")
        expected_h = int(r["h2"]) + 1
        rr = r.get("result") or {}; cc = rr.get("counts") or {}; st = rr.get("stage") or {}
        if str(rr.get("proof_scope")) != "RAW_BLOCK_BYTES_EXACT" or rr.get("failed_checks"):
            raise RuntimeError(f"Core->Stage imported proof scope/failed checks invalid chunk={r.get('chunk_no')}")
        if int(rr.get("merkle_roots_verified") or 0) != int(cc.get("blocks") or 0):
            raise RuntimeError(f"Core->Stage imported Merkle coverage mismatch chunk={r.get('chunk_no')}")
        if rr.get("wtxid_substitution_suspected") is not False:
            raise RuntimeError(f"Core->Stage imported wtxid substitution flag chunk={r.get('chunk_no')}")
        if rr.get("core_digests") is None or st.get("digests") is None:
            raise RuntimeError(f"Core->Stage imported digests missing chunk={r.get('chunk_no')}")
        for k in ("blocks","transactions","inputs","outputs"):
            if str(rr["core_digests"].get(k)) != str(st["digests"].get(k)):
                raise RuntimeError(f"Core->Stage imported digest mismatch chunk={r.get('chunk_no')} stream={k}")
            totals[k] += int(cc.get(k) or 0)
        totals["raw_block_bytes"] += int(rr.get("raw_block_bytes") or 0)
    if expected_h != target + 1:
        raise RuntimeError(f"Core->Stage imported terminal coverage {expected_h}!={target+1}")
    ci = contract.get("bitcoin_core") or {}
    return {
        "status": "OK", "proof_scope": f"BITCOIN_CORE_RAW_BLOCKS_TO_STAGE_EXACT_0_{target}",
        "canonical_chain_scope": "ALL_BLOCKS_ACTIVE_CHAIN", "payload_scope": "TXID_ORDER_VIN_PREVOUT_VOUT_VALUE_SCRIPT_EXACT",
        "script_payload_exact": True, "merkle_exact": True, "txid_identity": "canonical txid from stripped serialization",
        "core_identity": {"chain": ci.get("chain"), "version": ci.get("version"), "genesis_hash": ci.get("genesis_hash"), "target_hash": ci.get("target_hash")},
        "core_target_hash_final": ci.get("target_hash"), "core_snapshot_stable": True,
        "chunks_total": len(plan), "chunks_completed": len(records), "coverage_complete": True,
        "coverage_gaps": [], "coverage_overlaps": [], "bad_chunks": [], "totals": totals,
        "core_stage_exact_prefix_sha256": _core_stage_prefix_sha(records),
        "imported_evidence": True, "evidence_ledger": str(ledger_path),
        "evidence_ledger_sha256": str(expected_ledger_sha256).lower() if expected_ledger_sha256 else sha256_file(ledger_path),
        "evidence_contract": str(contract_path), "evidence_auditor_sha256": contract.get("auditor_sha256"),
    }
# --- end R2.2 bounded-memory Stage->UTXO rebuild -----------------------------


# --- V51.5.3 trusted failed-run proof reuse ----------------------------------

def _copy_imported_phase(obj: Dict[str, Any], *, report_path: Path, report_sha256: str) -> Dict[str, Any]:
    out = json.loads(json.dumps(obj))
    out["imported_evidence"] = True
    out["imported_from_fatal_report"] = str(report_path)
    out["imported_fatal_report_sha256"] = str(report_sha256)
    return out


def import_v5152_reference_failure_prefix(
    *, report_path: Path, expected_report_sha256: str, target: int,
    state_contract: Dict[str, Any], state_scan: Dict[str, Any], stage: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    """Import expensive completed phases from the exact V51.5.2 reference-v40 failure.

    Reuse is deliberately narrow: the operator must provide the immutable report
    SHA, the predecessor auditor identity is pinned, failure must be exactly in
    reference_v40, and current state/Stage semantic identities must still match.
    """
    want = str(expected_report_sha256 or "").lower()
    if HASH_RE.fullmatch(want) is None:
        raise RuntimeError("--resume-fatal-report-sha256 must be an exact lowercase/uppercase SHA256")
    rp = regular(report_path)
    if int(os.lstat(rp).st_nlink) != 1:
        raise RuntimeError(f"resume FATAL report hardlink forbidden: {rp}")
    before = file_token(rp)
    raw = rp.read_bytes()
    after = file_token(rp)
    if not same_token(before, after):
        raise RuntimeError("resume FATAL report changed while reading")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != want:
        raise RuntimeError(f"resume FATAL report SHA mismatch actual={actual} expected={want}")
    try:
        old = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"resume FATAL report JSON invalid: {type(exc).__name__}: {exc}") from exc
    if not isinstance(old, dict):
        raise RuntimeError("resume FATAL report must be a JSON object")
    if str(old.get("auditor_sha256") or "").lower() != V51_5_2_AUDITOR_SHA256:
        raise RuntimeError(f"resume FATAL report auditor SHA is not trusted: {old.get('auditor_sha256')}")
    if str(old.get("version") or "") != V51_5_2_VERSION:
        raise RuntimeError(f"resume FATAL report version is not trusted: {old.get('version')}")
    if str(old.get("status") or "") != "FAILED" or str(old.get("failed_phase") or "") != "reference_v40":
        raise RuntimeError(f"resume FATAL report must be FAILED at reference_v40; status={old.get('status')} phase={old.get('failed_phase')}")
    if int(old.get("target_height", -1)) != int(target):
        raise RuntimeError(f"resume FATAL target mismatch old={old.get('target_height')} current={target}")

    oph = old.get("phases") or {}
    old_sc = oph.get("state_contract") or {}
    old_ss = oph.get("state_scan") or {}
    keys_sc = ("height","block_hash","source_sha256","core_sha256","driver_sha256","tx_count","out_count","close_count","script_bytes","live_count","live_value_sats")
    mismatches = []
    for k in keys_sc:
        if str(old_sc.get(k)) != str(state_contract.get(k)):
            mismatches.append(f"state_contract.{k}")
    keys_ss = ("height","block_hash","source_sha256","core_sha256","driver_sha256","tx_count","out_count","close_count","script_bytes","live_count","live_value_sats","live_fingerprint_sha256")
    for k in keys_ss:
        if str(old_ss.get(k)) != str(state_scan.get(k)):
            mismatches.append(f"state_scan.{k}")
    old_stage = old.get("stage") or {}
    for k in ("sha256","windows_sha256","end_height","end_hash"):
        if k in old_stage or k in stage:
            if str(old_stage.get(k)) != str(stage.get(k)):
                mismatches.append(f"stage.{k}")
    if mismatches:
        raise RuntimeError(f"resume FATAL report no longer matches current immutable state/Stage: {sorted(set(mismatches))}")

    # Require the predecessor's false-green guard to have passed, but import
    # only the three genuinely expensive proof phases. V51.5.3 recomputes the
    # zero-cost false-green guard from those imported phase results.
    required_old_ok = ("stage_semantics", "core_stage_exact", "stage_rebuild", "false_green_guard")
    for name in required_old_ok:
        if str((oph.get(name) or {}).get("status")) != "OK":
            raise RuntimeError(f"resume FATAL report phase is not reusable: {name} status={(oph.get(name) or {}).get('status')}")
    sem = oph["stage_semantics"]
    if int(sem.get("target", -1)) != int(target) or int(sem.get("windows_completed", -1)) != int(sem.get("windows_total", -2)):
        raise RuntimeError("resume FATAL Stage semantics coverage is incomplete")
    cs = oph["core_stage_exact"]
    if cs.get("coverage_complete") is not True or cs.get("script_payload_exact") is not True or cs.get("merkle_exact") is not True or cs.get("core_snapshot_stable") is not True:
        raise RuntimeError("resume FATAL Core->Stage exact proof is incomplete")
    sr = oph["stage_rebuild"]
    if sr.get("full_stream_hashes") is not True:
        raise RuntimeError("resume FATAL Stage rebuild lacks full stream hashes")
    if int(sr.get("windows_partitioned", -1)) != int(sr.get("windows_total", -2)) or int(sr.get("buckets_completed", -1)) != 256:
        raise RuntimeError("resume FATAL Stage rebuild coverage is incomplete")
    if int(sr.get("expected_live_count", -1)) != int(state_scan["live_count"]):
        raise RuntimeError("resume FATAL Stage rebuild live_count no longer matches state")
    if int(sr.get("expected_live_value_sats", -1)) != int(state_scan["live_value_sats"]):
        raise RuntimeError("resume FATAL Stage rebuild live_value no longer matches state")
    if str(sr.get("expected_live_fingerprint_sha256") or "") != str(state_scan["live_fingerprint_sha256"]):
        raise RuntimeError("resume FATAL Stage rebuild fingerprint no longer matches state")

    reusable = ("stage_semantics", "core_stage_exact", "stage_rebuild")
    return {name: _copy_imported_phase(oph[name], report_path=rp, report_sha256=actual) for name in reusable}

# --- end V51.5.3 trusted failed-run proof reuse ------------------------------

def reference_v40_compare(db: Path, target: int, state_scan: Dict[str, Any], source_sha: str) -> Dict[str, Any]:
    """Compare the legacy V40 reference only over the scope it actually certifies.

    For targets at/above the independently certified R2.25 anchor, V40 is a
    historical prefix oracle at height 456028.  It is not required (and must not
    be pretended) to cover the current target.  For older targets below the
    anchor, retain the historical exact-at-target behavior.
    """
    db = regular(db)
    wal = Path(str(db) + ".wal")
    if wal.exists():
        raise RuntimeError(f"reference DuckDB WAL present: {wal}")
    if active_old_engines():
        raise RuntimeError(f"live V40/V41 process detected; reference must be stopped: {active_old_engines()[:5]}")
    before = file_token(db)
    duckdb = require_duckdb()
    con = duckdb.connect(str(db), read_only=True)
    anchor_h = int(CERTIFIED_R225_ANCHOR["height"])
    reference_height = int(target) if int(target) < anchor_h else anchor_h
    certified_prefix = int(target) >= anchor_h
    try:
        maxh = con.execute("SELECT max(block_number) FROM block_meta").fetchone()[0]
        if maxh is None or int(maxh) < reference_height:
            raise RuntimeError(f"reference block_meta max={maxh} below required reference height={reference_height}")
        tip = con.execute("SELECT lower(block_hash) FROM block_meta WHERE block_number=?", [reference_height]).fetchone()
        expected_hash = (str(CERTIFIED_R225_ANCHOR["block_hash"]) if certified_prefix else str(state_scan["block_hash"]))
        if not tip or str(tip[0]).lower() != expected_hash.lower():
            raise RuntimeError(
                f"reference hash mismatch height={reference_height} reference={None if not tip else tip[0]} expected={expected_hash}"
            )
        try:
            src = con.execute("SELECT value FROM pipeline_meta WHERE key='stage2_global_manifest_sha256'").fetchone()
        except Exception:
            src = None
        expected_source = str(CERTIFIED_R225_ANCHOR["source_sha256"] if certified_prefix else source_sha).lower()
        source_status = "NOT_RECORDED"
        if src is not None:
            source_status = "OK" if str(src[0]).lower() == expected_source else "BAD"
            if source_status == "BAD":
                raise RuntimeError(f"reference source SHA mismatch reference={src[0]} expected={expected_source}")
        h = hashlib.sha256(); count = 0; value = 0
        q = """
          SELECT lower(txid),vout,value_sats,script_pubkey,created_height,created_tx_index,is_coinbase
          FROM utxo
          WHERE created_height<=?
            AND (spent_height IS NULL OR spent_height>?)
            AND (bip30_overwritten_height IS NULL OR bip30_overwritten_height>?)
          ORDER BY created_height,created_tx_index,vout
        """
        cur = con.execute(q, [reference_height, reference_height, reference_height])
        while True:
            rows = cur.fetchmany(32768)
            if not rows: break
            for txid, vout, val, script, ch, ti, cb in rows:
                sb = bytes(script); fp_update(h, str(txid), int(vout), int(val), sb, int(ch), int(ti), bool(cb)); count += 1; value += int(val)
            if count and count % 5_000_000 < 32768: log(f"V40 fingerprint rows={count:,}")
    finally:
        con.close()
    after = file_token(db)
    if not same_token(before, after):
        raise RuntimeError("reference DuckDB changed during audit")
    fp = h.hexdigest()
    if certified_prefix:
        expected_count = int(CERTIFIED_R225_ANCHOR["live_count"])
        expected_value = int(CERTIFIED_R225_ANCHOR["live_value_sats"])
        expected_fp = str(CERTIFIED_R225_ANCHOR["fingerprint_sha256"])
    else:
        expected_count = int(state_scan["live_count"])
        expected_value = int(state_scan["live_value_sats"])
        expected_fp = str(state_scan["live_fingerprint_sha256"])
    failed = []
    if count != expected_count: failed.append(f"count:{count}!={expected_count}")
    if value != expected_value: failed.append(f"value:{value}!={expected_value}")
    if fp != expected_fp: failed.append(f"fingerprint:{fp}!={expected_fp}")
    return {
        "status": "OK" if not failed else "BAD", "failed_checks": failed,
        "db": str(db), "reference_max_height": int(maxh), "audit_target": int(target),
        "reference_height": reference_height,
        "coverage_mode": "CERTIFIED_PREFIX" if certified_prefix else "EXACT_TARGET",
        "certified_prefix": bool(certified_prefix),
        "source_binding": source_status,
        "reference": {"count": count, "value_sats": value, "fingerprint_sha256": fp},
        "expected": {"count": expected_count, "value_sats": expected_value, "fingerprint_sha256": expected_fp, "block_hash": expected_hash},
        "v50_target": {"height": int(target), "count": state_scan["live_count"], "value_sats": state_scan["live_value_sats"], "fingerprint_sha256": state_scan["live_fingerprint_sha256"]},
    }

def active_old_engines() -> List[str]:
    hits = []
    proc = Path("/proc")
    if not proc.is_dir(): return hits
    me = os.getpid()
    for d in proc.iterdir():
        if not d.name.isdigit() or int(d.name) == me: continue
        try:
            raw = (d / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except Exception:
            continue
        if "utxo_pipeline_v40.py" in raw or "utxo_pipeline_v41.py" in raw:
            hits.append(f"pid={d.name} {raw.strip()}")
    return hits


def bitcoin_cli_path(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        return regular(Path(explicit))
    for p in (Path("/usr/local/bin/bitcoin-cli"), Path("/root/bitcoin-core-install/bin/bitcoin-cli"), Path("/usr/bin/bitcoin-cli")):
        if p.is_file() and not p.is_symlink(): return p.resolve(strict=True)
    q = shutil.which("bitcoin-cli")
    return Path(q).resolve(strict=True) if q else None


def core_hash(cli: Path, height: int, datadir: Optional[str]) -> str:
    cmd = [str(cli)]
    if datadir: cmd.append(f"-datadir={datadir}")
    cmd += ["getblockhash", str(int(height))]
    cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if cp.returncode != 0:
        raise RuntimeError(f"bitcoin-cli getblockhash failed h={height} rc={cp.returncode}: {cp.stderr.strip()}")
    h = cp.stdout.strip().lower()
    if HASH_RE.fullmatch(h) is None:
        raise RuntimeError(f"bitcoin-cli invalid hash h={height}: {h!r}")
    return h


def bitcoin_core_audit(con, target: int, explicit_cli: Optional[str], datadir: Optional[str], sample_step: int) -> Dict[str, Any]:
    cli = bitcoin_cli_path(explicit_cli)
    if cli is None:
        return {"status": "NOT_EVALUATED", "reason": "bitcoin-cli not found", "certification_blocking": True}
    heights = {0, target}
    for b in BIP30:
        if b["early"] <= target: heights.add(b["early"])
        if b["later"] <= target: heights.add(b["later"])
    if sample_step > 0:
        heights.update(range(0, target + 1, sample_step))
    heights = sorted(heights)
    stage_rows = con.execute(f"SELECT height,block_hash FROM stage_block WHERE height IN ({','.join(str(x) for x in heights)}) ORDER BY height").fetchall()
    stage_map = {int(h): str(bh) for h, bh in stage_rows}
    mismatches = []
    checked = []
    for h in heights:
        observed = core_hash(cli, h, datadir)
        expected = stage_map.get(h)
        checked.append({"height": h, "stage": expected, "bitcoin_core": observed})
        if expected != observed:
            mismatches.append({"height": h, "stage": expected, "bitcoin_core": observed})
    return {"status": "OK" if not mismatches else "BAD", "bitcoin_cli": str(cli), "datadir": datadir, "sample_step": sample_step, "heights_checked": len(checked), "mismatches": mismatches, "samples": checked}


def _token_digest(tokens: Dict[str, Dict[str, Any]]) -> str:
    return canonical_json_hash({"files": [tokens[k] for k in sorted(tokens)]})


def stage_snapshot_tokens(stage: Dict[str, Any], target: int) -> Dict[str, Dict[str, Any]]:
    paths: set[Path] = set()
    for p in (Path(stage["path"]), Path(str(stage["path"]) + ".sha256")):
        paths.add(p)
    if stage.get("windows_path"):
        paths.add(Path(stage["windows_path"]))
        paths.add(Path(str(stage["windows_path"]) + ".sha256"))
    for e in selected_entries(stage, target):
        mp = Path(e["manifest_path"])
        paths.add(mp); paths.add(Path(str(mp) + ".sha256"))
        for role in ("blocks", "transactions", "inputs", "outputs"):
            p = Path(e[role]["path"])
            paths.add(p); paths.add(Path(str(p) + ".sha256"))
    out: Dict[str, Dict[str, Any]] = {}
    for p in sorted(paths, key=lambda x: str(x)):
        t = file_token(p)
        out[str(t["path"])] = t
    return out


def compare_token_maps(before: Dict[str, Dict[str, Any]], after: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    changed: List[str] = []
    for p in sorted(set(before) | set(after)):
        if p not in before or p not in after or not same_token(before[p], after[p]):
            changed.append(p)
    return {
        "status": "OK" if not changed else "BAD",
        "files": len(before),
        "before_digest": _token_digest(before),
        "after_digest": _token_digest(after),
        "changed_count": len(changed),
        "changed_sample": changed[:50],
    }


def _read_jsonl_stable(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows, errors
    if path.is_symlink() or not path.is_file():
        return rows, [f"not_regular:{path}"]
    before = file_token(path)
    raw = path.read_bytes()
    after = file_token(path)
    if not same_token(before, after):
        return rows, [f"changed_during_read:{path}"]
    for line_no, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:
            errors.append(f"json_line_{line_no}:{type(exc).__name__}:{exc}")
            continue
        if not isinstance(obj, dict):
            errors.append(f"non_object_line_{line_no}")
            continue
        rows.append(obj)
    return rows, errors


def _validate_r12_ledger(path: Path, schema: str, require_nonempty: bool = True) -> Dict[str, Any]:
    if not path.exists():
        return {"status": "NOT_EVALUATED", "reason": f"ledger_missing:{path}", "path": str(path), "certification_blocking": True, "_rows": []}
    rows, errors = _read_jsonl_stable(path)
    prev = "0" * 64
    for idx, row in enumerate(rows, 1):
        if row.get("schema") != schema:
            errors.append(f"row_{idx}:schema:{row.get('schema')!r}")
        try:
            record_no = int(row.get("record_no", -1))
        except Exception:
            record_no = -1
        if record_no != idx:
            errors.append(f"row_{idx}:record_no")
        if row.get("previous_record_sha256") != prev:
            errors.append(f"row_{idx}:previous_record_sha256")
        observed = canonical_json_hash(row, exclude=("record_sha256",))
        if row.get("record_sha256") != observed:
            errors.append(f"row_{idx}:record_sha256")
        prev = observed
    if require_nonempty and not rows:
        errors.append("ledger_empty")
    return {
        "status": "BAD" if errors else "OK",
        "path": str(path),
        "records": len(rows),
        "tail_sha256": prev if rows else None,
        "failed_checks": errors,
        "_rows": rows,
    }


def _source_lineage_model(path: Path) -> Dict[str, Any]:
    led = _validate_r12_ledger(path, V50_SOURCE_LINEAGE_SCHEMA, require_nonempty=False)
    rows = list(led.get("_rows") or [])
    transitions: Dict[str, str] = {}
    fingerprints: Dict[str, str] = {}
    errors = list(led.get("failed_checks") or [])
    if led.get("status") == "NOT_EVALUATED":
        return {"status": "OK", "records": 0, "transitions": {}, "fingerprints": {}, "record_hashes": set(), "failed_checks": []}
    expected_old: Optional[str] = None
    for idx, row in enumerate(rows, 1):
        if row.get("action") != "SOURCE_EXTENSION_COMMIT":
            errors.append(f"row_{idx}:action:{row.get('action')!r}")
            continue
        old = str(row.get("old_source_sha256") or "").lower()
        new = str(row.get("new_source_sha256") or "").lower()
        # Source lineage is an ordered journal, not a general graph.  Every row
        # must extend the immediately previous row exactly as R12.9 enforces.
        if expected_old is not None and old != expected_old:
            errors.append(f"row_{idx}:nonlinear_chain:expected_old={expected_old}:actual_old={old}")
        expected_old = new
        oldfp = str(row.get("old_source_fingerprint_sha256") or "").lower()
        newfp = str(row.get("new_source_fingerprint_sha256") or "").lower()
        if HASH_RE.fullmatch(old) is None or HASH_RE.fullmatch(new) is None or old == new:
            errors.append(f"row_{idx}:source_transition")
        if HASH_RE.fullmatch(oldfp) is None or HASH_RE.fullmatch(newfp) is None:
            errors.append(f"row_{idx}:source_fingerprint")
        if old in transitions and transitions[old] != new:
            errors.append(f"row_{idx}:source_fork:{old}")
        transitions[old] = new
        if oldfp: fingerprints[old] = oldfp
        if newfp: fingerprints[new] = newfp
    # Reject cycles in the effective source-upgrade graph.
    for origin in list(transitions):
        seen = set()
        cur = origin
        while cur in transitions:
            if cur in seen:
                errors.append(f"source_lineage_cycle:{origin}")
                break
            seen.add(cur); cur = transitions[cur]
    return {
        "status": "BAD" if errors else "OK",
        "records": len(rows),
        "transitions": transitions,
        "fingerprints": fingerprints,
        "record_hashes": {str(r.get("record_sha256")) for r in rows},
        "rows": rows,
        "failed_checks": errors,
        "path": str(path),
    }


def _source_reaches_current(source_sha: str, current_sha: str, transitions: Dict[str, str]) -> bool:
    cur = str(source_sha).lower(); target = str(current_sha).lower(); seen = set()
    while cur != target:
        if cur in seen or cur not in transitions:
            return False
        seen.add(cur); cur = str(transitions[cur]).lower()
    return True


def source_lineage_provenance_audit(lineage_path: Path, recovery_rows: Sequence[Dict[str, Any]], sc: Dict[str, Any], stage: Dict[str, Any], target: int) -> Dict[str, Any]:
    model = _source_lineage_model(lineage_path)
    failed = list(model.get("failed_checks") or [])
    rows = list(model.get("rows") or [])
    committed_recovery = [r for r in recovery_rows if r.get("action") == "SOURCE_UPGRADE_COMMITTED"]
    epoch_source = str(recovery_rows[0].get("source_sha256") or "").lower() if recovery_rows else ""
    if rows:
        first_old = str(rows[0].get("old_source_sha256") or "").lower()
        if HASH_RE.fullmatch(epoch_source) is None or first_old != epoch_source:
            failed.append(f"lineage_origin:{first_old}!={epoch_source}")
    if not rows:
        if committed_recovery:
            failed.append("source_upgrade_recovery_without_lineage")
        return {"status": "BAD" if failed else "OK", "records": 0, "upgrades": 0, "failed_checks": failed, "path": str(lineage_path)}
    heights = [int(r.get("committed_height", -1)) for r in rows]
    hashes = stage_hashes_at(stage, heights)
    recovery_refs = [str(r.get("lineage_record_sha256") or "") for r in committed_recovery]
    for idx, row in enumerate(rows, 1):
        if str(row.get("r11_engine_sha256") or "").lower() != EXPECTED_R11_SHA256:
            failed.append(f"row_{idx}:r11_engine_sha256")
        if str(row.get("supervisor_sha256") or "").lower() != EXPECTED_R12_SUPERVISOR_SHA256:
            failed.append(f"row_{idx}:supervisor_sha256")
        try:
            h = int(row.get("committed_height", -1))
        except Exception:
            h = -1; failed.append(f"row_{idx}:committed_height")
        if h < 0 or h > target:
            failed.append(f"row_{idx}:committed_height_range")
        if h in hashes and str(row.get("committed_block_hash") or "").lower() != hashes[h]:
            failed.append(f"row_{idx}:committed_block_hash")
        pref = row.get("prefix_equivalence") if isinstance(row.get("prefix_equivalence"), dict) else {}
        if pref.get("status") != "GREEN" or int(pref.get("through_height", -1)) != h or int(pref.get("windows_checked", 0)) <= 0:
            failed.append(f"row_{idx}:prefix_equivalence")
        if pref.get("window_fingerprint_compatible") is not True or pref.get("window_fingerprint_schema") != V50_WINDOW_FINGERPRINT_SCHEMA:
            failed.append(f"row_{idx}:window_fingerprint_bridge")
        bip = row.get("bip30_preflight") if isinstance(row.get("bip30_preflight"), dict) else {}
        if bip.get("status") != "GREEN":
            failed.append(f"row_{idx}:bip30_preflight")
        if row.get("historical_execution_provenance_changed") is not False:
            failed.append(f"row_{idx}:historical_execution_provenance_changed")
        if str(row.get("pre_fingerprint_sha256") or "") != str(row.get("post_fingerprint_sha256") or ""):
            failed.append(f"row_{idx}:semantic_fingerprint_changed")
        rsha = str(row.get("record_sha256") or "")
        matching_recovery = [r for r in committed_recovery if str(r.get("lineage_record_sha256") or "") == rsha]
        if len(matching_recovery) != 1:
            failed.append(f"row_{idx}:recovery_commit_reference_count:{len(matching_recovery)}")
        else:
            rr = matching_recovery[0]
            if str(rr.get("old_source_sha256") or "").lower() != str(row.get("old_source_sha256") or "").lower():
                failed.append(f"row_{idx}:recovery_old_source_sha256")
            if str(rr.get("new_source_sha256") or "").lower() != str(row.get("new_source_sha256") or "").lower():
                failed.append(f"row_{idx}:recovery_new_source_sha256")
            try:
                rrh = int(rr.get("committed_height", -2))
            except Exception:
                rrh = -2
            if rrh != h:
                failed.append(f"row_{idx}:recovery_committed_height")
    # A committed source lineage must terminate at the source bound into state.meta/checkpoint.
    news = {str(r.get("new_source_sha256") or "").lower() for r in rows}
    olds = {str(r.get("old_source_sha256") or "").lower() for r in rows}
    terminals = sorted(news - olds)
    if len(terminals) != 1 or terminals[0] != str(sc["source_sha256"]).lower():
        failed.append(f"lineage_terminal:{terminals}!={sc['source_sha256']}")
    final_fp = r12_source_fingerprint(stage)
    known_fp = model.get("fingerprints") or {}
    if str(sc["source_sha256"]).lower() in known_fp and str(known_fp[str(sc["source_sha256"]).lower()]).lower() != final_fp:
        failed.append("current_source_fingerprint")
    return {
        "status": "BAD" if failed else "OK",
        "records": len(rows), "upgrades": len(rows), "failed_checks": failed,
        "path": str(lineage_path), "terminal_source_sha256": terminals[0] if len(terminals) == 1 else None,
        "current_source_fingerprint_sha256": final_fp,
    }


def recovery_provenance_audit(state: Path, control: Path, recovery_ledger: Path, source_lineage: Path, runs_dir: Path, sc: Dict[str, Any], stage: Dict[str, Any], target: int) -> Dict[str, Any]:
    failed: List[str] = []
    prov = state / "provenance_r12"
    if not prov.exists() or prov.is_symlink() or not prov.is_dir():
        return {"status": "NOT_EVALUATED", "reason": f"R12 provenance root missing/unsafe:{prov}", "certification_blocking": True}
    for active_name in ("active_run.json", "source_upgrade_active.json"):
        if (prov / active_name).exists() or (prov / active_name).is_symlink():
            failed.append(f"active_provenance_transaction:{active_name}")
    dirty = state / "dirty.bin"
    if dirty.exists(): failed.append("ACTIVE_DIRTY:dirty.bin")
    temp_artifacts = [str(x) for x in state.glob("*.tmp.*") if x.exists()]
    if temp_artifacts: failed.append(f"state_temp_artifacts:{temp_artifacts[:20]}")
    stop_info = {"active": False, "kind": "NONE", "consumed": 0}
    if control.exists() and control.is_dir() and not control.is_symlink():
        sp = control / "STOP"
        if sp.exists() or sp.is_symlink():
            if sp.is_symlink() or not sp.is_file():
                failed.append("control_stop_unsafe")
                stop_info.update({"active": True, "kind": "UNSAFE"})
            else:
                st = sp.stat()
                if int(st.st_nlink) != 1 or int(st.st_size) > (1 << 20):
                    failed.append("control_stop_unsafe_identity")
                    stop_info.update({"active": True, "kind": "UNSAFE"})
                else:
                    data = sp.read_bytes()
                    if data.startswith(b"schema=mybot-v50-r12-handoff-stop-v1\n"):
                        stop_info.update({"active": True, "kind": "ORPHAN_HANDOFF_GATE"})
                        failed.append("orphan_handoff_stop_gate")
                    else:
                        stop_info.update({"active": True, "kind": "OPERATOR_STOP"})
        stop_info["consumed"] = sum(1 for x in control.glob("STOP.consumed.*") if x.is_file() and not x.is_symlink())
    ledger = _validate_r12_ledger(recovery_ledger, V50_RECOVERY_LEDGER_SCHEMA, require_nonempty=True)
    rows = list(ledger.pop("_rows", []) or [])
    failed.extend(list(ledger.get("failed_checks") or []))
    if not rows:
        return {"status": "NOT_EVALUATED" if not failed else "BAD", "reason": "R12.9 recovery provenance epoch/ledger missing", "control": stop_info, "recovery_ledger": ledger, "failed_checks": failed, "certification_blocking": True}
    first = rows[0]
    if first.get("action") != V50_PROVENANCE_EPOCH_ACTION:
        failed.append("record_1:not_provenance_epoch")
    if str(first.get("state") or "") != str(state.resolve(strict=True)):
        failed.append("record_1:state_path")
    if first.get("origin") not in ("FRESH_R12_INIT", "CERTIFIED_R225_ANCHOR_ADOPTION"):
        failed.append(f"record_1:origin:{first.get('origin')!r}")
    if first.get("recovery_history_before_epoch") != "NOT_CLAIMED":
        failed.append("record_1:recovery_history_before_epoch")
    try:
        runtime_epoch = current_runtime_epoch()
    except Exception as exc:
        runtime_epoch = {}
        failed.append(f"record_1:runtime_epoch_current:{exc}")
    for k in ("python_runtime_sha256", "duckdb_python_sha256", "duckdb_native_sha256", "duckdb_version", "runtime_contract_sha256"):
        if runtime_epoch and str(first.get(k) or "") != str(runtime_epoch.get(k) or ""):
            failed.append(f"record_1:runtime_epoch:{k}")
    if HASH_RE.fullmatch(str(first.get("runtime_contract_sha256") or "").lower()) is None:
        failed.append("record_1:runtime_contract_sha256")
    allowed = {
        V50_PROVENANCE_EPOCH_ACTION, "SOURCE_UPGRADE_COMMITTED", "SOURCE_UPGRADE_ROLLBACK",
        "RUN_LEDGER_RECONCILIATION", "CORE_STATE_RECOVERY_PREPARED",
        "CORE_STATE_RECOVERY_COMMITTED", "STALE_ACTIVE_RUN_RECONCILED",
    }
    core_prepared: Dict[str, Dict[str, Any]] = {}
    core_committed: Dict[str, Dict[str, Any]] = {}
    stale_core_links: Dict[str, int] = {}
    for idx, row in enumerate(rows, 1):
        if row.get("action") not in allowed:
            failed.append(f"row_{idx}:action:{row.get('action')!r}")
        if str(row.get("r11_engine_sha256") or "").lower() != EXPECTED_R11_SHA256:
            failed.append(f"row_{idx}:r11_engine_sha256")
        if str(row.get("supervisor_sha256") or "").lower() != EXPECTED_R12_SUPERVISOR_SHA256:
            failed.append(f"row_{idx}:supervisor_sha256")
        action = row.get("action")
        if action == "SOURCE_UPGRADE_COMMITTED":
            if row.get("semantic_fingerprint_unchanged") is not True:
                failed.append(f"row_{idx}:semantic_fingerprint_unchanged")
            if HASH_RE.fullmatch(str(row.get("lineage_record_sha256") or "")) is None:
                failed.append(f"row_{idx}:lineage_record_sha256")
        elif action == "SOURCE_UPGRADE_ROLLBACK":
            if row.get("exact_metadata_restore") is not True or row.get("exact_sparse_size_restore") is not True or row.get("deep_full_hash_verify") is not True:
                failed.append(f"row_{idx}:rollback_not_exact")
        elif action == "RUN_LEDGER_RECONCILIATION":
            if row.get("deep_full_hash_verify") is not True or row.get("active_run_child_lock_confirmed") is not True:
                failed.append(f"row_{idx}:run_reconciliation_not_exact")
            if HASH_RE.fullmatch(str(row.get("apply_record_sha256") or "")) is None:
                failed.append(f"row_{idx}:apply_record_sha256")
        elif action == "CORE_STATE_RECOVERY_PREPARED":
            rid = str(row.get("recovery_id") or "")
            if not rid or rid in core_prepared:
                failed.append(f"row_{idx}:core_recovery_prepared_id")
            else:
                core_prepared[rid] = row
            if row.get("active_run_child_lock_confirmed") is not True:
                failed.append(f"row_{idx}:core_recovery_prepared_authority")
            if str(row.get("core_binary_sha256") or "").lower() != str(sc.get("core_sha256") or "").lower():
                failed.append(f"row_{idx}:core_recovery_prepared_core")
            if row.get("recovery_mode_planned") not in ("DIRTY_FINALIZE_OR_ROLLBACK", "SCRIPT_SUFFIX_ROLLBACK_WITHOUT_DIRTY"):
                failed.append(f"row_{idx}:core_recovery_prepared_mode")
            if HASH_RE.fullmatch(str(row.get("before_checkpoint_block_hash") or "").lower()) is None:
                failed.append(f"row_{idx}:core_recovery_prepared_block_hash")
            try:
                if int(row.get("before_checkpoint_height", -2)) < -1 or int(row.get("script_size_before", -1)) < 0 or int(row.get("checkpoint_script_bytes_before", -1)) < 0:
                    failed.append(f"row_{idx}:core_recovery_prepared_counters")
            except Exception:
                failed.append(f"row_{idx}:core_recovery_prepared_counters")
        elif action == "CORE_STATE_RECOVERY_COMMITTED":
            rid = str(row.get("recovery_id") or "")
            if not rid or rid in core_committed:
                failed.append(f"row_{idx}:core_recovery_committed_id")
            else:
                core_committed[rid] = row
            if row.get("active_run_child_lock_confirmed") is not True or row.get("deep_full_hash_verify") is not True:
                failed.append(f"row_{idx}:core_recovery_committed_verification")
            if str(row.get("core_binary_sha256") or "").lower() != str(sc.get("core_sha256") or "").lower():
                failed.append(f"row_{idx}:core_recovery_committed_core")
            if row.get("recovery_mode") not in ("DIRTY_FINALIZE_OR_ROLLBACK", "SCRIPT_SUFFIX_ROLLBACK_WITHOUT_DIRTY"):
                failed.append(f"row_{idx}:core_recovery_committed_mode")
            if HASH_RE.fullmatch(str(row.get("prepared_record_sha256") or "").lower()) is None:
                failed.append(f"row_{idx}:core_recovery_prepared_link")
            try:
                if int(row.get("before_checkpoint_height", -2)) != int(row.get("after_checkpoint_height", -3)):
                    failed.append(f"row_{idx}:core_recovery_checkpoint_height_changed")
                if int(row.get("script_size_after", -1)) != int(row.get("checkpoint_script_bytes_after", -2)):
                    failed.append(f"row_{idx}:core_recovery_script_not_checkpoint_bound")
            except Exception:
                failed.append(f"row_{idx}:core_recovery_committed_counters")
            if str(row.get("before_checkpoint_block_hash") or "").lower() != str(row.get("after_checkpoint_block_hash") or "").lower():
                failed.append(f"row_{idx}:core_recovery_checkpoint_hash_changed")
        elif action == "STALE_ACTIVE_RUN_RECONCILED":
            if row.get("active_run_phase") not in ("PREPARED", "CHILD_LOCK_CONFIRMED"):
                failed.append(f"row_{idx}:active_run_phase")
            if row.get("reconciliation_status") not in ("GREEN", "GREEN_RECOVERED"):
                failed.append(f"row_{idx}:reconciliation_status")
            cr = str(row.get("core_recovery_record_sha256") or "")
            if cr:
                if HASH_RE.fullmatch(cr.lower()) is None:
                    failed.append(f"row_{idx}:core_recovery_record_sha256")
                stale_core_links[cr] = stale_core_links.get(cr, 0) + 1

    # R12.9 physical recovery is a strict two-phase journal.  Certification requires
    # every PREPARED to have exactly one later COMMITTED, and every COMMITTED to be
    # linked by exactly one later stale-run reconciliation record.
    for rid, pr in core_prepared.items():
        cm = core_committed.get(rid)
        if cm is None:
            failed.append(f"core_recovery:{rid}:prepared_without_committed")
            continue
        if int(cm.get("record_no", 0)) <= int(pr.get("record_no", 0)):
            failed.append(f"core_recovery:{rid}:commit_order")
        if str(cm.get("prepared_record_sha256") or "") != str(pr.get("record_sha256") or ""):
            failed.append(f"core_recovery:{rid}:prepared_sha_link")
        for k in ("run_id", "run_contract_sha256"):
            if cm.get(k) != pr.get(k):
                failed.append(f"core_recovery:{rid}:identity:{k}")
        csha = str(cm.get("record_sha256") or "")
        if stale_core_links.get(csha, 0) != 1:
            failed.append(f"core_recovery:{rid}:stale_link_count:{stale_core_links.get(csha, 0)}")
        else:
            stale = next((x for x in rows if x.get("action") == "STALE_ACTIVE_RUN_RECONCILED" and x.get("core_recovery_record_sha256") == csha), None)
            if stale is None or int(stale.get("record_no", 0)) <= int(cm.get("record_no", 0)):
                failed.append(f"core_recovery:{rid}:stale_link_order")
            elif stale.get("run_id") != cm.get("run_id") or stale.get("run_contract_sha256") != cm.get("run_contract_sha256"):
                failed.append(f"core_recovery:{rid}:stale_identity")
    for rid in core_committed:
        if rid not in core_prepared:
            failed.append(f"core_recovery:{rid}:committed_without_prepared")
    for sha, count in stale_core_links.items():
        matches = [r for r in core_committed.values() if str(r.get("record_sha256") or "") == sha]
        if len(matches) != 1 or count != 1:
            failed.append(f"core_recovery:orphan_or_duplicate_stale_link:{sha}:{count}:{len(matches)}")

    lineage = source_lineage_provenance_audit(source_lineage, rows, sc, stage, target)
    if lineage.get("status") != "OK":
        failed.extend([f"source_lineage:{x}" for x in lineage.get("failed_checks") or []])
    interrupted = []
    if runs_dir.exists():
        if runs_dir.is_symlink() or not runs_dir.is_dir():
            failed.append("runs_dir_unsafe")
        else:
            stale_ids = {str(r.get("run_id")) for r in rows if r.get("action") == "STALE_ACTIVE_RUN_RECONCILED"}
            marker_ids: List[str] = []
            for ip in sorted(runs_dir.glob("interrupted_*.json")):
                try:
                    before = file_token(regular(ip)); obj = load_json(ip); after = file_token(regular(ip))
                    if not same_token(before, after): raise RuntimeError("changed_during_read")
                    if obj.get("schema") != V50_ACTIVE_RUN_SCHEMA or obj.get("marker_sha256") != canonical_json_hash(obj, exclude=("marker_sha256",)):
                        raise RuntimeError("marker_contract")
                    if obj.get("phase") == "CHILD_LOCK_CONFIRMED":
                        try: child_pid = int(obj.get("child_pid", -1))
                        except Exception: child_pid = -1
                        lock_ident = obj.get("child_lock_identity")
                        if child_pid <= 1 or not isinstance(lock_ident, dict): raise RuntimeError("confirmed_child_lock_identity")
                        if str(obj.get("child_lock_identity_sha256") or "") != canonical_json_hash(lock_ident):
                            raise RuntimeError("confirmed_child_lock_identity_hash")
                    rid = str(obj.get("run_id") or "")
                    if rid not in stale_ids: raise RuntimeError("no_stale_recovery_record")
                    marker_ids.append(rid)
                    interrupted.append({"path": str(ip), "run_id": rid, "phase": obj.get("phase")})
                except Exception as exc:
                    failed.append(f"interrupted_marker:{ip.name}:{exc}")
            for rid in sorted(stale_ids):
                if marker_ids.count(rid) != 1:
                    failed.append(f"stale_recovery_marker_count:{rid}:{marker_ids.count(rid)}")
    return {
        "status": "BAD" if failed else "OK", "current_state_clean": not bool(failed), "control": stop_info,
        "recovery_ledger": ledger, "source_lineage": lineage, "interrupted_runs": interrupted,
        "epoch_origin": first.get("origin"), "failed_checks": failed,
    }


def _load_run_contract(path: Path) -> Dict[str, Any]:
    p = regular(path)
    before = file_token(p); obj = load_json(p); after = file_token(p)
    if not same_token(before, after):
        raise RuntimeError(f"run contract changed during read: {p}")
    if obj.get("schema") != V50_RUN_CONTRACT_SCHEMA:
        raise RuntimeError(f"run contract schema mismatch: {p}")
    if obj.get("contract_sha256") != canonical_json_hash(obj, exclude=("contract_sha256",)):
        raise RuntimeError(f"run contract canonical hash mismatch: {p}")
    side = Path(str(p) + ".sha256")
    recorded = read_sidecar(side)
    actual_file_sha = sha256_file(p)
    if recorded != actual_file_sha:
        raise RuntimeError(f"run contract sidecar mismatch path={p} sidecar={recorded} actual={actual_file_sha}")
    return {"path": str(p), "file_sha256": actual_file_sha, "object": obj}


def _load_run_result(path: Path) -> Dict[str, Any]:
    p = regular(path); before = file_token(p); obj = load_json(p); after = file_token(p)
    if not same_token(before, after): raise RuntimeError(f"run result changed during read: {p}")
    if obj.get("schema") != V50_RUN_RESULT_SCHEMA: raise RuntimeError(f"run result schema mismatch: {p}")
    if obj.get("result_sha256") != canonical_json_hash(obj, exclude=("result_sha256",)):
        raise RuntimeError(f"run result hash mismatch: {p}")
    return obj


def run_provenance_audit(path: Optional[Path], apply_ledger: Path, recovery_ledger: Path, source_lineage: Path, runs_dir: Path, state: Path, sc: Dict[str, Any], stage: Dict[str, Any], target: int) -> Dict[str, Any]:
    failed: List[str] = []
    led = _validate_r12_ledger(apply_ledger, V50_APPLY_LEDGER_SCHEMA, require_nonempty=True)
    rows = list(led.pop("_rows", []) or [])
    failed.extend(list(led.get("failed_checks") or []))
    if not rows:
        return {"status": "NOT_EVALUATED" if not failed else "BAD", "reason": "R12 apply ledger missing/empty", "apply_ledger": led, "failed_checks": failed, "certification_blocking": True}
    recled = _validate_r12_ledger(recovery_ledger, V50_RECOVERY_LEDGER_SCHEMA, require_nonempty=True)
    recovery_rows = list(recled.pop("_rows", []) or [])
    if recled.get("status") != "OK":
        failed.append("recovery_ledger_not_proven")
    lineage = _source_lineage_model(source_lineage)
    if lineage.get("status") != "OK":
        failed.extend([f"source_lineage:{x}" for x in lineage.get("failed_checks") or []])
    transitions = dict(lineage.get("transitions") or {})
    source_fps = dict(lineage.get("fingerprints") or {})
    current_source = str(sc["source_sha256"]).lower()
    source_fps[current_source] = r12_source_fingerprint(stage)
    next_h = 0
    h2s: List[int] = []
    run_groups: Dict[str, List[Dict[str, Any]]] = {}
    baseline = False
    for idx, row in enumerate(rows, 1):
        try:
            h1, h2 = int(row.get("h1")), int(row.get("h2"))
        except Exception:
            failed.append(f"row_{idx}:range_invalid"); continue
        if h1 != next_h or h2 < h1:
            failed.append(f"row_{idx}:range:{h1}..{h2}:expected={next_h}")
        next_h = h2 + 1; h2s.append(h2)
    if next_h != target + 1:
        failed.append(f"terminal:{next_h}!={target + 1}")
    block_hashes = stage_hashes_at(stage, h2s)
    stage_hash_cache = dict(block_hashes)
    def cached_stage_hash(height: int) -> Optional[str]:
        ih = int(height)
        if ih not in stage_hash_cache:
            stage_hash_cache.update(stage_hashes_at(stage, [ih]))
        return stage_hash_cache.get(ih)
    recovered_refs = {str(r.get("apply_record_sha256") or "") for r in recovery_rows if r.get("action") == "RUN_LEDGER_RECONCILIATION"}
    for idx, row in enumerate(rows, 1):
        try: h1, h2 = int(row.get("h1")), int(row.get("h2"))
        except Exception: continue
        rtype = row.get("record_type")
        if str(row.get("state_block_hash") or "").lower() != block_hashes[h2]:
            failed.append(f"row_{idx}:state_block_hash")
        if rtype == "CERTIFIED_BASELINE_ADOPTION":
            baseline = True
            if idx != 1 or h1 != 0 or h2 != CERTIFIED_R225_ANCHOR["height"]:
                failed.append(f"row_{idx}:baseline_range")
            expected = {
                "historical_execution_provenance": False,
                "data_correctness_provenance": "INDEPENDENT_R225_EXACT",
                "audit_report_sha256": CERTIFIED_R225_ANCHOR["audit_report_sha256"],
                "auditor_sha256": CERTIFIED_R225_ANCHOR["auditor_sha256"],
                "state_block_hash": CERTIFIED_R225_ANCHOR["block_hash"],
                "state_tx_count": CERTIFIED_R225_ANCHOR["tx_count"],
                "state_out_count": CERTIFIED_R225_ANCHOR["out_count"],
                "state_close_count": CERTIFIED_R225_ANCHOR["close_count"],
                "state_script_bytes": CERTIFIED_R225_ANCHOR["script_bytes"],
                "state_live_count": CERTIFIED_R225_ANCHOR["live_count"],
                "state_live_value_sats": CERTIFIED_R225_ANCHOR["live_value_sats"],
                "state_fingerprint_sha256": CERTIFIED_R225_ANCHOR["fingerprint_sha256"],
                "source_sha256": CERTIFIED_R225_ANCHOR["source_sha256"],
                "r11_engine_sha256": EXPECTED_R11_SHA256,
                "supervisor_sha256": EXPECTED_R12_SUPERVISOR_SHA256,
            }
            for k, v in expected.items():
                if row.get(k) != v: failed.append(f"row_{idx}:baseline:{k}")
            continue
        if rtype not in ("APPLY_COMMIT", "RECOVERED_COMMITTED_PREFIX"):
            failed.append(f"row_{idx}:record_type:{rtype!r}"); continue
        if row.get("historical_execution_provenance") is not True:
            failed.append(f"row_{idx}:historical_execution_provenance")
        if str(row.get("r11_engine_sha256") or "").lower() != EXPECTED_R11_SHA256:
            failed.append(f"row_{idx}:r11_engine_sha256")
        if str(row.get("supervisor_sha256") or "").lower() != EXPECTED_R12_SUPERVISOR_SHA256:
            failed.append(f"row_{idx}:supervisor_sha256")
        source_sha = str(row.get("source_sha256") or "").lower()
        source_fp = str(row.get("source_fingerprint_sha256") or "").lower()
        if HASH_RE.fullmatch(source_sha) is None or HASH_RE.fullmatch(source_fp) is None:
            failed.append(f"row_{idx}:source_identity")
        if not _source_reaches_current(source_sha, current_source, transitions):
            failed.append(f"row_{idx}:source_not_reachable_to_current:{source_sha}")
        if source_sha in source_fps and source_fp != str(source_fps[source_sha]).lower():
            failed.append(f"row_{idx}:source_fingerprint")
        expected_wfp = r12_window_fingerprint(stage, h1, h2)
        if str(row.get("source_window_fingerprint_sha256") or "").lower() != expected_wfp:
            failed.append(f"row_{idx}:source_window_fingerprint")
        rid = str(row.get("run_id") or "")
        csha = str(row.get("run_contract_sha256") or "")
        if not rid or HASH_RE.fullmatch(csha) is None:
            failed.append(f"row_{idx}:run_identity")
        else:
            run_groups.setdefault(rid, []).append(row)
        observed = row.get("observed_commit_heights")
        if not isinstance(observed, list) or any(not isinstance(x, int) for x in observed):
            failed.append(f"row_{idx}:observed_commit_heights")
            observed = []
        if any(int(x) < h1 or int(x) > h2 for x in observed):
            failed.append(f"row_{idx}:observed_commit_range")
        if sorted(set(int(x) for x in observed)) != [int(x) for x in observed]:
            failed.append(f"row_{idx}:observed_commit_order")
        if rtype == "APPLY_COMMIT":
            if row.get("commit_log_acknowledgements_complete") is not True or h2 not in observed:
                failed.append(f"row_{idx}:commit_acknowledgement")
        else:
            if row.get("commit_log_acknowledgements_complete") is not False or row.get("recovery_provenance") != "ACTIVE_RUN_AUTHORITY_DEEP_EXACT_RECONCILIATION":
                failed.append(f"row_{idx}:recovered_commit_contract")
            if str(row.get("record_sha256") or "") not in recovered_refs:
                failed.append(f"row_{idx}:missing_recovery_reference")
    # Final durable ledger record must describe the current state exactly.
    final = rows[-1]
    final_fields = {
        "state_block_hash": str(sc["block_hash"]).lower(),
        "state_tx_count": int(sc["tx_count"]), "state_out_count": int(sc["out_count"]),
        "state_close_count": int(sc["close_count"]), "state_script_bytes": int(sc["script_bytes"]),
        "state_live_count": int(sc["live_count"]), "state_live_value_sats": int(sc["live_value_sats"]),
    }
    for k, v in final_fields.items():
        fv = final.get(k)
        if k == "state_block_hash":
            if str(fv or "").lower() != v: failed.append(f"final:{k}")
        else:
            try: iv = int(fv)
            except Exception: iv = None
            if iv != v: failed.append(f"final:{k}")
    # A certified baseline adoption has no R12 execution run yet. R12.9 creates
    # provenance_r12/runs lazily on the first actual APPLY run, so absence is
    # valid only while the durable ledger contains baseline adoption alone and
    # the caller did not request an explicit run contract. If the path exists,
    # however, it must always be a real non-symlink directory.
    post_baseline_records = any(str(r.get("record_type") or "") != "CERTIFIED_BASELINE_ADOPTION" for r in rows)
    runs_dir_required = bool(post_baseline_records or path is not None)
    runs_dir_present = bool(runs_dir.exists() or runs_dir.is_symlink())
    runs_dir_safe = bool(runs_dir_present and not runs_dir.is_symlink() and runs_dir.is_dir())
    if runs_dir_present and not runs_dir_safe:
        failed.append(f"runs_dir_unsafe:{runs_dir}")
    elif runs_dir_required and not runs_dir_present:
        failed.append(f"runs_dir_missing_required:{runs_dir}")
    runs_dir_state = "PRESENT_SAFE" if runs_dir_safe else ("ABSENT_NOT_YET_REQUIRED" if not runs_dir_required else "MISSING_REQUIRED")
    contract_summaries = []
    stale_ids = {str(r.get("run_id") or "") for r in recovery_rows if r.get("action") == "STALE_ACTIVE_RUN_RECONCILED"}
    interrupted_ids: set = set()
    if runs_dir.exists() and runs_dir.is_dir() and not runs_dir.is_symlink():
        for ip in runs_dir.glob("interrupted_*.json"):
            try:
                io = load_json(regular(ip))
                if io.get("schema") == V50_ACTIVE_RUN_SCHEMA and io.get("marker_sha256") == canonical_json_hash(io, exclude=("marker_sha256",)):
                    interrupted_ids.add(str(io.get("run_id") or ""))
            except Exception:
                pass
    explicit_contract = str(path.resolve(strict=True)) if path is not None and path.exists() else None
    explicit_seen = explicit_contract is None
    runtime_sets: Dict[str, set] = {k: set() for k in ("python_runtime_sha256", "duckdb_python_sha256", "duckdb_native_sha256")}
    epoch = recovery_rows[0] if recovery_rows else {}
    epoch_runtime = {k: str(epoch.get(k) or "").lower() for k in runtime_sets}
    for k, hv in epoch_runtime.items():
        if HASH_RE.fullmatch(hv) is None:
            failed.append(f"epoch_runtime:{k}")
    if str(epoch.get("duckdb_version") or "") != DUCKDB_VERSION:
        failed.append("epoch_runtime:duckdb_version")
    expected_runtime_contract = canonical_json_hash({
        "schema": "mybot-v50-r12-runtime-epoch-v1",
        "python_runtime_sha256": epoch_runtime.get("python_runtime_sha256", ""),
        "duckdb_python_sha256": epoch_runtime.get("duckdb_python_sha256", ""),
        "duckdb_native_sha256": epoch_runtime.get("duckdb_native_sha256", ""),
        "duckdb_version": str(epoch.get("duckdb_version") or ""),
    })
    if str(epoch.get("runtime_contract_sha256") or "") != expected_runtime_contract:
        failed.append("epoch_runtime:runtime_contract_sha256")
    for rid, group in sorted(run_groups.items(), key=lambda kv: min(int(x["h1"]) for x in kv[1])):
        cp = runs_dir / f"run_{rid}.json"
        try:
            loaded = _load_run_contract(cp); obj = loaded["object"]
        except Exception as exc:
            failed.append(f"run_{rid}:contract:{exc}"); continue
        if explicit_contract == loaded["path"]: explicit_seen = True
        min_h1 = min(int(x["h1"]) for x in group); max_h2 = max(int(x["h2"]) for x in group)
        group_csha = {str(x.get("run_contract_sha256") or "") for x in group}
        group_source = {str(x.get("source_sha256") or "").lower() for x in group}
        group_source_fp = {str(x.get("source_fingerprint_sha256") or "").lower() for x in group}
        if group_csha != {str(obj.get("contract_sha256") or "")}: failed.append(f"run_{rid}:contract_sha_link")
        if obj.get("run_id") != rid: failed.append(f"run_{rid}:run_id")
        if str(obj.get("state") or "") != str(state.resolve(strict=True)): failed.append(f"run_{rid}:state")
        if int(obj.get("start_height", -1)) != min_h1: failed.append(f"run_{rid}:start_height")
        ct = int(obj.get("target_height", -1))
        if ct < max_h2 or ct > target: failed.append(f"run_{rid}:target_height")
        th = cached_stage_hash(ct) if 0 <= ct <= target else None
        if th is None or str(obj.get("target_hash") or "").lower() != th: failed.append(f"run_{rid}:target_hash")
        if len(group_source) != 1 or str(obj.get("source_sha256") or "").lower() not in group_source: failed.append(f"run_{rid}:source_sha256")
        if len(group_source_fp) != 1 or str(obj.get("source_fingerprint_sha256") or "").lower() not in group_source_fp: failed.append(f"run_{rid}:source_fingerprint_sha256")
        srcsha = str(obj.get("source_sha256") or "").lower(); srcfp = str(obj.get("source_fingerprint_sha256") or "").lower()
        if srcsha in source_fps and srcfp != str(source_fps[srcsha]).lower(): failed.append(f"run_{rid}:source_fingerprint_lineage")
        pins = {
            "r11_engine_sha256": EXPECTED_R11_SHA256,
            "core_binary_sha256": str(sc["core_sha256"]).lower(),
            "supervisor_sha256": EXPECTED_R12_SUPERVISOR_SHA256,
            "duckdb_version": DUCKDB_VERSION,
            "writer_policy": "R11_SINGLE_CAUSAL_WRITER",
            "parquet_sha": "full",
        }
        for k, v in pins.items():
            if str(obj.get(k) or "") != v: failed.append(f"run_{rid}:{k}")
        if obj.get("historical_execution_provenance_before_r12") is not False: failed.append(f"run_{rid}:historical_execution_provenance_before_r12")
        try:
            if int(obj.get("stage_threads", 0)) < 1 or int(obj.get("window", 0)) < 1: failed.append(f"run_{rid}:execution_policy_numeric")
        except Exception: failed.append(f"run_{rid}:execution_policy_numeric")
        for k in runtime_sets:
            hv = str(obj.get(k) or "").lower()
            if HASH_RE.fullmatch(hv) is None:
                failed.append(f"run_{rid}:{k}")
            else:
                runtime_sets[k].add(hv)
                if hv != epoch_runtime.get(k):
                    failed.append(f"run_{rid}:{k}:runtime_epoch_mismatch")
        rp = runs_dir / f"run_{rid}.result.json"
        result_status = "INTERRUPTED_RECOVERED"
        if rp.exists():
            try:
                ro = _load_run_result(rp)
                if ro.get("run_id") != rid or ro.get("run_contract_sha256") != obj.get("contract_sha256"): failed.append(f"run_{rid}:result_link")
                rh = int(ro.get("final_height", -2))
                if rh < max_h2 or rh > ct: failed.append(f"run_{rid}:result_final_height")
                if ro.get("status") == "TARGET_REACHED" and rh < ct: failed.append(f"run_{rid}:result_target_reached")
                if ro.get("status") == "CONTROLLED_STOP" and rh >= ct: failed.append(f"run_{rid}:result_controlled_stop")
                if ro.get("status") not in ("TARGET_REACHED", "CONTROLLED_STOP"): failed.append(f"run_{rid}:result_status")
                if 0 <= rh <= target and str(ro.get("final_block_hash") or "").lower() != cached_stage_hash(rh): failed.append(f"run_{rid}:result_block_hash")
                result_status = str(ro.get("status"))
            except Exception as exc:
                failed.append(f"run_{rid}:result:{exc}")
        elif rid not in stale_ids or rid not in interrupted_ids:
            failed.append(f"run_{rid}:missing_result_without_stale_recovery_marker")
        contract_summaries.append({"run_id": rid, "path": loaded["path"], "contract_sha256": obj.get("contract_sha256"), "start_height": min_h1, "max_applied_height": max_h2, "target_height": ct, "result_status": result_status})
    if not explicit_seen:
        failed.append("explicit_run_contract_not_referenced")
    # R12.9 freezes runtime identity for the whole provenance epoch. Every run must match it exactly.
    runtime_variants = {k: len(v) for k, v in runtime_sets.items()}
    for k, count in runtime_variants.items():
        if count > 1:
            failed.append(f"runtime_epoch_multiple_variants:{k}:{count}")
    epoch_source = str(epoch.get("source_sha256") or "").lower()
    if HASH_RE.fullmatch(epoch_source) is None:
        failed.append("epoch_source_sha256")
    elif not _source_reaches_current(epoch_source, current_source, transitions):
        failed.append("epoch_source_not_reachable_to_current")
    if baseline:
        if epoch.get("origin") != "CERTIFIED_R225_ANCHOR_ADOPTION" or epoch.get("apply_anchor_sha256") != rows[0].get("record_sha256"):
            failed.append("baseline_epoch_link")
        if epoch_source != str(rows[0].get("source_sha256") or "").lower():
            failed.append("baseline_epoch_source")
    else:
        if epoch.get("origin") != "FRESH_R12_INIT": failed.append("fresh_init_epoch_origin")
    return {
        "status": "BAD" if failed else "OK", "failed_checks": failed, "apply_ledger": led,
        "records": len(rows), "runs": contract_summaries, "baseline_adoption": baseline,
        "historical_execution_provenance_complete": not baseline,
        "baseline_data_correctness_independently_certified": baseline,
        "current_source_fingerprint_sha256": source_fps[current_source],
        "runtime_hash_variants": runtime_variants,
        "runs_dir_state": runs_dir_state,
        "runs_dir_required": runs_dir_required,
    }


def source_catalog_audit(path: Path, target: int, expected_hash: str) -> Dict[str, Any]:
    if not path.exists():
        return {"status": "NOT_EVALUATED", "reason": f"source catalog missing:{path}", "certification_blocking": True}
    if path.is_symlink() or not path.is_file():
        return {"status": "BAD", "failed_checks": [f"source_catalog_not_regular:{path}"]}
    duckdb = require_duckdb()
    before = file_token(path)
    con = duckdb.connect(str(path), read_only=True)
    failed: List[str] = []
    try:
        tables = {str(r[0]) for r in con.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='main'").fetchall()}
        required = {"canonical_blocks", "catalog_ledger", "catalog_meta", "source_files"}
        if required - tables:
            return {"status": "BAD", "failed_checks": [f"missing_tables:{sorted(required - tables)}"]}
        mn, mx, n, dh, dbh = con.execute(
            "SELECT min(height),max(height),count(*),count(DISTINCT height),count(DISTINCT lower(block_hash)) FROM canonical_blocks WHERE height<=?",
            [target],
        ).fetchone()
        observed = (int(mn if mn is not None else -1), int(mx if mx is not None else -1), int(n or 0), int(dh or 0), int(dbh or 0))
        expected = (0, target, target + 1, target + 1, target + 1)
        if observed != expected:
            failed.append(f"canonical_prefix:{observed}!={expected}")
        chain_bad = int(con.execute(
            """WITH c AS (
                 SELECT height, lower(block_hash) AS block_hash, lower(prev_hash) AS prev_hash,
                        lag(lower(block_hash)) OVER(ORDER BY height) AS prev_block_hash
                 FROM canonical_blocks WHERE height<=?
               )
               SELECT count(*) FROM c
               WHERE (height=0 AND prev_hash<>repeat('0',64))
                  OR (height>0 AND (prev_block_hash IS NULL OR prev_hash<>prev_block_hash))""",
            [target],
        ).fetchone()[0] or 0)
        if chain_bad:
            failed.append(f"prevhash_chain:{chain_bad}")
        row = con.execute("SELECT lower(block_hash) FROM canonical_blocks WHERE height=?", [target]).fetchone()
        if not row or str(row[0]) != expected_hash:
            failed.append(f"target_hash:{None if not row else row[0]}!={expected_hash}")
        cols = {str(r[1]) for r in con.execute("PRAGMA table_info('catalog_ledger')").fetchall()}
        need = {"record_no", "generation_id", "h1", "h2", "target_hash", "target_mtp", "source_snapshot_sha256", "source_range_fingerprint_sha256", "previous_record_sha256", "record_sha256"}
        if not need.issubset(cols):
            failed.append(f"catalog_ledger_schema_missing:{sorted(need - cols)}")
        else:
            rows = con.execute(
                "SELECT record_no,generation_id,h1,h2,target_hash,target_mtp,source_snapshot_sha256,source_range_fingerprint_sha256,previous_record_sha256,record_sha256 FROM catalog_ledger ORDER BY record_no"
            ).fetchall()
            prev: Optional[str] = None
            next_h = 0
            for i, r in enumerate(rows, 1):
                rn, gid, h1, h2, th, mtp, ssha, rfp, psha, rsha = r
                h1, h2 = int(h1), int(h2)
                if int(rn) != i:
                    failed.append(f"ledger_record_no:{rn}!={i}")
                if h1 != next_h or h2 < h1:
                    failed.append(f"ledger_range:{h1}..{h2}:expected={next_h}")
                if (None if psha is None else str(psha)) != prev:
                    failed.append(f"ledger_prev_sha:{i}")
                payload = {
                    "contract": SOURCE_LEDGER_CONTRACT,
                    "record_no": int(rn), "generation_id": str(gid), "h1": h1, "h2": h2,
                    "target_hash": str(th), "target_mtp": int(mtp),
                    "source_snapshot_sha256": str(ssha), "source_range_fingerprint_sha256": str(rfp),
                    "previous_record_sha256": prev,
                }
                exp_sha = canonical_json_hash(payload)
                if str(rsha) != exp_sha:
                    failed.append(f"ledger_record_sha:{i}")
                prev = exp_sha
                next_h = h2 + 1
            maxh = con.execute("SELECT max(height) FROM canonical_blocks").fetchone()[0]
            if rows and next_h != int(maxh) + 1:
                failed.append(f"ledger_terminal:{next_h}!={int(maxh)+1}")
    finally:
        con.close()
    after = file_token(path)
    if not same_token(before, after):
        failed.append("source_catalog_changed_during_audit")
    return {"status": "BAD" if failed else "OK", "path": str(path), "failed_checks": failed, "target": target, "target_hash": expected_hash}


def _raw_files_for_range(raw_base: Path, start_day, end_day) -> List[Path]:
    """Discover only physical RAW day partitions needed by one Stage-height chunk."""
    if not raw_base.exists() or not raw_base.is_dir() or raw_base.is_symlink():
        return []
    if end_day < start_day:
        raise RuntimeError(f"RAW day range reversed: {start_day}..{end_day}")
    out: List[Path] = []
    d = start_day
    while d <= end_day:
        day_dir = raw_base / f"date={d.isoformat()}"
        if day_dir.exists():
            if day_dir.is_symlink() or not day_dir.is_dir():
                raise RuntimeError(f"RAW day path is not a real directory: {day_dir}")
            preferred = sorted(day_dir.glob("part-*.parquet"))
            candidates = preferred if preferred else sorted(day_dir.glob("*.parquet"))
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_file():
                    raise RuntimeError(f"RAW parquet is missing/not-regular/symlink: {candidate}")
                out.append(candidate.resolve(strict=True))
        d += timedelta(days=1)
    return sorted(set(out), key=lambda x: str(x))


def _raw_chunk_plan(stage: Dict[str, Any], target: int) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    expected = 0
    for e in selected_entries(stage, target):
        h1 = int(e["h1"])
        h2 = min(int(e["h2"]), int(target))
        if h1 != expected or h2 < h1:
            raise RuntimeError(f"RAW chunk plan Stage gap/overlap expected={expected} actual={h1}..{h2}")
        plan.append({
            "chunk_no": len(plan),
            "h1": h1,
            "h2": h2,
            "stage_manifest_path": str(e["manifest_path"]),
            "stage_manifest_sha256": str(e["manifest_sha256"]),
            "entry": e,
        })
        expected = h2 + 1
        if h2 == target:
            break
    if not plan or expected != target + 1:
        raise RuntimeError(f"RAW chunk plan terminal mismatch next={expected} target={target}")
    return plan


def _raw_plan_digest(plan: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash({
        "contract": "stage-window-height-plan-v1",
        "chunks": [
            {
                "chunk_no": int(x["chunk_no"]),
                "h1": int(x["h1"]),
                "h2": int(x["h2"]),
                "stage_manifest_sha256": str(x["stage_manifest_sha256"]),
            }
            for x in plan
        ],
    })


def _raw_bind_stage_chunk(con, item: Dict[str, Any]) -> None:
    e = item["entry"]
    h1, h2 = int(item["h1"]), int(item["h2"])
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_block AS
        SELECT height::BIGINT height, lower(block_hash::VARCHAR) block_hash,
               lower(prev_hash::VARCHAR) prev_hash, block_time::BIGINT block_time,
               tx_count::BIGINT tx_count
        FROM read_parquet({sql_quote(str(e['blocks']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_tx AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, is_coinbase::BOOLEAN is_coinbase,
               vin_count::BIGINT vin_count, vout_count::BIGINT vout_count
        FROM read_parquet({sql_quote(str(e['transactions']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_in AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vin_index::BIGINT vin_index,
               lower(prev_txid::VARCHAR) prev_txid, prev_vout::UBIGINT prev_vout
        FROM read_parquet({sql_quote(str(e['inputs']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_out AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vout::BIGINT vout,
               value_sats::BIGINT value_sats
        FROM read_parquet({sql_quote(str(e['outputs']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)


def _raw_file_evidence(files: Sequence[Path], sha_cache: Dict[Tuple[Any, ...], str]) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    for p in files:
        token = file_token(p)
        key = tuple(token.get(k) for k in ("path", "dev", "ino", "size", "mtime_ns", "ctime_ns"))
        digest = sha_cache.get(key)
        if digest is None:
            digest = sha256_file(Path(str(token["path"])))
            sha_cache[key] = digest
        row = dict(token)
        row["sha256"] = digest
        evidence.append(row)
    return evidence


def _raw_file_set_digest(evidence: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash({"contract": "raw-file-evidence-v1", "files": list(evidence)})


def _raw_progress_contract(
    *,
    auditor_sha256: str,
    state: Path,
    state_contract: Dict[str, Any],
    stage: Dict[str, Any],
    target: int,
    raw_base: Path,
    output_unit: str,
    radius_days: int,
    plan: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema": RAW_PROGRESS_SCHEMA,
        "auditor_version": VERSION,
        "auditor_sha256": str(auditor_sha256),
        "duckdb_version": DUCKDB_VERSION,
        "target_height": int(target),
        "target_hash": str(state_contract["block_hash"]),
        "state": {
            "path": str(state.resolve(strict=True)),
            "checkpoint_sha256": sha256_file(regular(state / "checkpoint.bin")),
            "meta_sha256": sha256_file(regular(state / "state.meta")),
            "source_sha256": str(state_contract["source_sha256"]),
            "core_sha256": str(state_contract["core_sha256"]),
            "driver_sha256": str(state_contract["driver_sha256"]),
            "tx_count": int(state_contract["tx_count"]),
            "out_count": int(state_contract["out_count"]),
            "close_count": int(state_contract["close_count"]),
        },
        "stage": {
            "kind": str(stage["kind"]),
            "release_path": str(stage["path"]),
            "release_sha256": str(stage["sha256"]),
            "window_plan_sha256": _raw_plan_digest(plan),
            "chunks_total": len(plan),
        },
        "raw": {
            "base": str(raw_base.resolve(strict=False)),
            "mode": "exact",
            "output_unit": str(output_unit),
            "chunk_contract": "stage-window-height-chunks-v1",
            "day_discovery_contract": "stage-block-time-plus-radius-v1",
            "radius_days": int(radius_days),
            "file_discovery_policy": "part-*.parquet-preferred-else-*.parquet",
            "canonical_filter": "height+block_hash",
        },
    }
    payload["contract_id"] = canonical_json_hash(payload)
    return payload


def _raw_progress_prefix_sha(records: Sequence[Dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for r in records:
        digest = str(r.get("record_sha256") or "")
        if HASH_RE.fullmatch(digest) is None:
            raise RuntimeError(f"invalid RAW progress record SHA: {digest!r}")
        h.update(bytes.fromhex(digest))
    return h.hexdigest()


def _raw_read_progress_ledger(path: Path, contract_id: str, plan: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"RAW progress ledger is not a regular file: {path}")
    before = file_token(path)
    raw = path.read_bytes()
    after = file_token(path)
    if not same_token(before, after):
        raise RuntimeError(f"RAW progress ledger changed during read: {path}")
    records: List[Dict[str, Any]] = []
    previous: Optional[str] = None
    for line_no, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise RuntimeError(f"RAW progress ledger line {line_no} is not an object")
        idx = len(records)
        if idx >= len(plan):
            raise RuntimeError(f"RAW progress ledger has more records than planned chunks: line={line_no}")
        expected = plan[idx]
        if obj.get("schema") != RAW_CHUNK_RECORD_SCHEMA:
            raise RuntimeError(f"RAW progress record schema mismatch line={line_no}")
        if str(obj.get("contract_id") or "") != contract_id:
            raise RuntimeError(f"RAW progress contract mismatch line={line_no}")
        if int(obj.get("record_no", -1)) != idx + 1 or int(obj.get("chunk_no", -1)) != idx:
            raise RuntimeError(f"RAW progress sequence mismatch line={line_no}")
        if int(obj.get("h1", -1)) != int(expected["h1"]) or int(obj.get("h2", -1)) != int(expected["h2"]):
            raise RuntimeError(f"RAW progress range mismatch line={line_no}")
        if str(obj.get("stage_manifest_sha256") or "") != str(expected["stage_manifest_sha256"]):
            raise RuntimeError(f"RAW progress Stage manifest mismatch line={line_no}")
        if obj.get("previous_record_sha256") != previous:
            raise RuntimeError(f"RAW progress previous SHA mismatch line={line_no}")
        expected_sha = canonical_json_hash(obj, exclude=("record_sha256",))
        if str(obj.get("record_sha256") or "") != expected_sha:
            raise RuntimeError(f"RAW progress record SHA mismatch line={line_no}")
        status = str(obj.get("status") or "")
        if status not in {"OK", "BAD", "PARTIAL", "NOT_EVALUATED"}:
            raise RuntimeError(f"RAW progress invalid status line={line_no}: {status!r}")
        previous = expected_sha
        records.append(obj)
    return records


def _raw_validate_resume_files(records: Sequence[Dict[str, Any]], raw_base: Path) -> Dict[str, Any]:
    """Re-discover each completed RAW day-range, require the exact same file set, then re-hash it."""
    expected_by_path: Dict[str, Dict[str, Any]] = {}
    file_sets_checked = 0
    for r in records:
        files = r.get("raw_files") or []
        if not isinstance(files, list):
            raise RuntimeError(f"RAW progress raw_files is not a list chunk={r.get('chunk_no')}")
        result = r.get("result") if isinstance(r.get("result"), dict) else {}
        start_raw = result.get("raw_day_start")
        end_raw = result.get("raw_day_end")
        status = str(r.get("status") or "")
        if start_raw and end_raw:
            try:
                start_day = datetime.fromisoformat(str(start_raw)).date()
                end_day = datetime.fromisoformat(str(end_raw)).date()
            except Exception as exc:
                raise RuntimeError(
                    f"RAW progress invalid day range chunk={r.get('chunk_no')}: {start_raw}..{end_raw}"
                ) from exc
            current_files = _raw_files_for_range(raw_base, start_day, end_day)
            current_paths = [str(x) for x in current_files]
            recorded_paths = sorted(
                str(x.get("path")) for x in files if isinstance(x, dict) and x.get("path")
            )
            if current_paths != recorded_paths:
                raise RuntimeError(
                    f"RAW file-set changed since chunk commit chunk={r.get('chunk_no')} "
                    f"days={start_day}..{end_day} recorded={recorded_paths} current={current_paths}"
                )
            file_sets_checked += 1
        elif status in {"OK", "PARTIAL", "NOT_EVALUATED"}:
            raise RuntimeError(
                f"RAW progress chunk lacks durable discovery range chunk={r.get('chunk_no')} status={status}"
            )

        for item in files:
            if not isinstance(item, dict):
                raise RuntimeError(f"RAW progress raw_file evidence malformed chunk={r.get('chunk_no')}")
            path = str(item.get("path") or "")
            if not path:
                raise RuntimeError(f"RAW progress raw_file path missing chunk={r.get('chunk_no')}")
            prior = expected_by_path.get(path)
            if prior is not None:
                if canonical_json_hash(prior) != canonical_json_hash(item):
                    raise RuntimeError(f"RAW progress file evidence changed across chunks: {path}")
            else:
                expected_by_path[path] = item
    checked = 0
    bytes_hashed = 0
    for path in sorted(expected_by_path):
        expected = expected_by_path[path]
        current = file_token(Path(path))
        for key in ("path", "dev", "ino", "size", "mtime_ns", "ctime_ns"):
            if current.get(key) != expected.get(key):
                raise RuntimeError(f"RAW resume token mismatch path={path} field={key}: {current.get(key)}!={expected.get(key)}")
        actual_sha = sha256_file(Path(path))
        if actual_sha != str(expected.get("sha256") or ""):
            raise RuntimeError(f"RAW resume SHA mismatch path={path}")
        checked += 1
        bytes_hashed += int(current["size"])
        if checked == 1 or checked % 250 == 0 or checked == len(expected_by_path):
            log(f"RAW resume evidence rehash files={checked}/{len(expected_by_path)}")
    return {
        "status": "OK",
        "file_sets_checked": file_sets_checked,
        "files_checked": checked,
        "bytes_hashed": bytes_hashed,
    }


def _raw_init_progress(
    root_base: Path,
    contract: Dict[str, Any],
    plan: Sequence[Dict[str, Any]],
    *,
    allow_resume: bool,
    raw_base: Path,
) -> Tuple[Path, List[Dict[str, Any]], Dict[str, Any]]:
    contract_id = str(contract["contract_id"])
    root = root_base / contract_id
    root.mkdir(parents=True, exist_ok=True)
    contract_path = root / "contract.json"
    ledger_path = root / "chunks.jsonl"
    dirty_path = root / "dirty.json"
    if contract_path.exists():
        observed = load_json(contract_path)
        if canonical_json_hash(observed) != canonical_json_hash(contract):
            raise RuntimeError(f"RAW progress contract payload mismatch: {contract_path}")
        side = Path(str(contract_path) + ".sha256")
        expected_side = read_sidecar(side)
        actual = sha256_file(contract_path)
        if expected_side != actual:
            raise RuntimeError(f"RAW progress contract sidecar mismatch: {contract_path}")
    else:
        write_evidence(contract_path, contract)
    records = _raw_read_progress_ledger(ledger_path, contract_id, plan)
    if records and not allow_resume:
        raise RuntimeError(f"RAW progress exists but resume disabled: {root}")
    recovered_dirty: Optional[Dict[str, Any]] = None
    if dirty_path.exists():
        if not allow_resume:
            raise RuntimeError(f"RAW dirty marker exists but resume disabled: {dirty_path}")
        recovered_dirty = load_json(dirty_path)
        if str(recovered_dirty.get("contract_id") or "") != contract_id:
            raise RuntimeError(f"RAW dirty marker contract mismatch: {dirty_path}")
        expected_chunk = len(records)
        if int(recovered_dirty.get("chunk_no", -1)) != expected_chunk:
            raise RuntimeError(
                f"RAW dirty marker does not point at next uncommitted chunk: "
                f"dirty={recovered_dirty.get('chunk_no')} expected={expected_chunk}"
            )
        archived = root / f"dirty.recovered.{utc_stamp()}.{os.getpid()}.{uuid.uuid4().hex[:8]}.json"
        os.replace(dirty_path, archived)
        fsync_dir(root)
        recovered_dirty = dict(recovered_dirty)
        recovered_dirty["archived_path"] = str(archived)
    resume_validation = {"status": "NOT_NEEDED", "files_checked": 0, "bytes_hashed": 0}
    if records:
        resume_validation = _raw_validate_resume_files(records, raw_base)
    return root, records, {
        "contract_path": str(contract_path),
        "ledger_path": str(ledger_path),
        "dirty_path": str(dirty_path),
        "recovered_dirty": recovered_dirty,
        "resume_validation": resume_validation,
    }


def _raw_chunk_audit(
    *,
    duckdb_module,
    item: Dict[str, Any],
    raw_base: Path,
    output_unit: str,
    radius_days: int,
    memory_limit: str,
    temp_max: str,
    threads: int,
    temp_root: Path,
    sha_cache: Dict[Tuple[Any, ...], str],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    h1, h2 = int(item["h1"]), int(item["h2"])
    chunk_tmp = temp_root / f"raw_chunk_{int(item['chunk_no']):05d}_{h1}_{h2}"
    chunk_tmp.mkdir(parents=True, exist_ok=False)
    con = duckdb_module.connect(":memory:")
    try:
        duckdb_settings = configure_duckdb(con, memory_limit, chunk_tmp / "duckdb_tmp", temp_max, max(1, threads))
        _raw_bind_stage_chunk(con, item)
        times = con.execute("SELECT min(block_time),max(block_time),count(*) FROM stage_block").fetchone()
        if not times or times[0] is None or times[1] is None:
            return {"status": "BAD", "failed_checks": ["stage_chunk_block_time_missing"], "h1": h1, "h2": h2}, []
        stage_rows = int(times[2] or 0)
        if stage_rows != h2 - h1 + 1:
            return {"status": "BAD", "failed_checks": [f"stage_chunk_height_coverage:{stage_rows}!={h2-h1+1}"], "h1": h1, "h2": h2}, []
        min_day = datetime.fromtimestamp(int(times[0]), timezone.utc).date() - timedelta(days=radius_days)
        max_day = datetime.fromtimestamp(int(times[1]), timezone.utc).date() + timedelta(days=radius_days)
        files = _raw_files_for_range(raw_base, min_day, max_day)
        if not files:
            return {
                "status": "NOT_EVALUATED",
                "reason": f"RAW files missing for Stage-time range {min_day}..{max_day}",
                "h1": h1, "h2": h2, "raw_day_start": min_day.isoformat(), "raw_day_end": max_day.isoformat(),
                "files": 0, "certification_blocking": True,
            }, []
        evidence = _raw_file_evidence(files, sha_cache)
        rawsql = sql_list([str(p) for p in files])
        con.execute(
            f"CREATE TEMP VIEW raw_source_v50 AS "
            f"SELECT * FROM read_parquet({rawsql}, union_by_name=true) "
            f"WHERE TRY_CAST(block_number AS BIGINT) BETWEEN {h1} AND {h2}"
        )
        cols = {str(r[0]) for r in con.execute("DESCRIBE SELECT * FROM raw_source_v50").fetchall()}
        required = {"hash", "block_number", "block_hash", "block_timestamp", "is_coinbase", "inputs", "outputs"}
        missing = sorted(required - cols)
        schema = {
            "columns": sorted(cols), "missing_required": missing,
            "has_input_count": "input_count" in cols,
            "has_output_count": "output_count" in cols,
            "has_tx_index": "index" in cols,
        }
        if missing:
            return {
                "status": "NOT_EVALUATED",
                "reason": f"RAW schema cannot prove full transaction payload; missing={missing}",
                "schema": schema, "files": len(files), "h1": h1, "h2": h2,
                "raw_day_start": min_day.isoformat(), "raw_day_end": max_day.isoformat(),
                "certification_blocking": True,
            }, evidence

        failed: List[str] = []
        warnings: List[str] = []
        raw_rows = int(con.execute("SELECT count(*) FROM raw_source_v50").fetchone()[0] or 0)
        noncb_null = int(con.execute(
            "SELECT count(*) FROM raw_source_v50 WHERE NOT coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false) AND (inputs IS NULL OR coalesce(array_length(inputs),0)=0)"
        ).fetchone()[0] or 0)
        output_empty = int(con.execute(
            "SELECT count(*) FROM raw_source_v50 WHERE outputs IS NULL OR coalesce(array_length(outputs),0)=0"
        ).fetchone()[0] or 0)
        if noncb_null:
            failed.append(f"FALSE_GREEN_RAW_NONCOINBASE_INPUTS_NULL_OR_EMPTY:{noncb_null}")
        if output_empty:
            failed.append(f"FALSE_GREEN_RAW_OUTPUTS_NULL_OR_EMPTY:{output_empty}")
        if "input_count" in cols:
            ic_bad = int(con.execute(
                """SELECT count(*) FROM raw_source_v50
                   WHERE NOT coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false)
                     AND TRY_CAST(input_count AS BIGINT) IS DISTINCT FROM array_length(inputs)"""
            ).fetchone()[0] or 0)
            if ic_bad:
                failed.append(f"raw_noncoinbase_input_count_array_mismatch:{ic_bad}")
        if "output_count" in cols:
            oc_bad = int(con.execute(
                "SELECT count(*) FROM raw_source_v50 WHERE TRY_CAST(output_count AS BIGINT) IS DISTINCT FROM array_length(outputs)"
            ).fetchone()[0] or 0)
            if oc_bad:
                failed.append(f"raw_output_count_array_mismatch:{oc_bad}")

        con.execute(
            """CREATE TEMP VIEW raw_canon_v50 AS
               SELECT r.* FROM raw_source_v50 r
               JOIN stage_block b
                 ON TRY_CAST(r.block_number AS BIGINT)=b.height
                AND lower(r.block_hash::VARCHAR)=b.block_hash"""
        )
        raw_heights = int(con.execute("SELECT count(DISTINCT TRY_CAST(block_number AS BIGINT)) FROM raw_canon_v50").fetchone()[0] or 0)
        if raw_heights != h2 - h1 + 1:
            failed.append(f"raw_canonical_height_coverage:{raw_heights}!={h2-h1+1}")
        competing = int(con.execute(
            "SELECT count(*) FROM (SELECT TRY_CAST(block_number AS BIGINT) h,count(DISTINCT lower(block_hash::VARCHAR)) n FROM raw_source_v50 GROUP BY 1 HAVING n>1)"
        ).fetchone()[0] or 0)
        raw_dup = int(con.execute(
            "SELECT count(*) FROM (SELECT TRY_CAST(block_number AS BIGINT),lower(block_hash::VARCHAR),lower(hash::VARCHAR),count(*) n FROM raw_canon_v50 GROUP BY 1,2,3 HAVING n<>1)"
        ).fetchone()[0] or 0)
        if raw_dup:
            failed.append(f"raw_duplicate_transaction_rows:{raw_dup}")
        tx_mismatch = int(con.execute(
            """WITH r AS (
                 SELECT TRY_CAST(block_number AS BIGINT) height,lower(block_hash::VARCHAR) block_hash,
                        lower(hash::VARCHAR) txid,TRY_CAST(is_coinbase AS BOOLEAN) is_coinbase
                 FROM raw_canon_v50
               ), s AS (
                 SELECT t.height,b.block_hash,t.txid,t.is_coinbase FROM stage_tx t JOIN stage_block b USING(height)
               )
               SELECT count(*) FROM r FULL OUTER JOIN s USING(height,block_hash,txid)
               WHERE r.txid IS NULL OR s.txid IS NULL OR r.is_coinbase IS DISTINCT FROM s.is_coinbase"""
        ).fetchone()[0] or 0)
        if tx_mismatch:
            failed.append(f"raw_stage_tx_set_or_coinbase_mismatch:{tx_mismatch}")
        raw_cb_bad = int(con.execute(
            "SELECT count(*) FROM (SELECT TRY_CAST(block_number AS BIGINT) h,count(*) FILTER(WHERE TRY_CAST(is_coinbase AS BOOLEAN)) cb FROM raw_canon_v50 GROUP BY 1 HAVING cb<>1)"
        ).fetchone()[0] or 0)
        if raw_cb_bad:
            failed.append(f"raw_coinbase_cardinality_bad_blocks:{raw_cb_bad}")

        order_status = "NOT_PROVABLE"
        raw_tx_dense_bad = None
        if "index" in cols:
            null_index = int(con.execute('SELECT count(*) FROM raw_canon_v50 WHERE TRY_CAST("index" AS BIGINT) IS NULL').fetchone()[0] or 0)
            if null_index == 0:
                raw_tx_dense_bad = int(con.execute(
                    """WITH g AS (
                         SELECT TRY_CAST(block_number AS BIGINT) height,
                                count(*) n,
                                min(TRY_CAST("index" AS BIGINT)) mn,
                                max(TRY_CAST("index" AS BIGINT)) mx,
                                count(DISTINCT TRY_CAST("index" AS BIGINT)) di,
                                sum(CASE WHEN TRY_CAST(is_coinbase AS BOOLEAN) THEN 1 ELSE 0 END) cb,
                                max(CASE WHEN TRY_CAST(is_coinbase AS BOOLEAN) AND TRY_CAST("index" AS BIGINT)=0 THEN 1 ELSE 0 END) cb0,
                                max(CASE WHEN TRY_CAST(is_coinbase AS BOOLEAN) AND TRY_CAST("index" AS BIGINT)<>0 THEN 1 ELSE 0 END) cb_nonzero
                         FROM raw_canon_v50 GROUP BY 1
                       )
                       SELECT count(*) FROM g
                       WHERE mn<>0 OR mx<>n-1 OR di<>n OR cb<>1 OR cb0<>1 OR cb_nonzero<>0"""
                ).fetchone()[0] or 0)
                if raw_tx_dense_bad:
                    failed.append(f"raw_tx_index_dense_or_coinbase_zero_bad_blocks:{raw_tx_dense_bad}")
                order_bad = int(con.execute(
                    'WITH r AS (SELECT TRY_CAST(block_number AS BIGINT) height,lower(hash::VARCHAR) txid,TRY_CAST("index" AS BIGINT) tx_index FROM raw_canon_v50) '
                    'SELECT count(*) FROM r FULL OUTER JOIN stage_tx s USING(height,txid) '
                    'WHERE r.txid IS NULL OR s.txid IS NULL OR r.tx_index<>s.tx_index'
                ).fetchone()[0] or 0)
                if order_bad:
                    failed.append(f"raw_stage_tx_index_mismatch:{order_bad}")
                elif not raw_tx_dense_bad:
                    order_status = "OK"
            else:
                warnings.append(f"raw_tx_index_null_rows:{null_index}")

        try:
            declared_input_expr = (
                "max(TRY_CAST(t.input_count AS BIGINT))" if "input_count" in cols else "NULL::BIGINT"
            )
            raw_in_dense_bad = int(con.execute(
                f"""WITH g AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,
                            count(*) n,min(TRY_CAST(inp.index AS BIGINT)) mn,
                            max(TRY_CAST(inp.index AS BIGINT)) mx,
                            count(DISTINCT TRY_CAST(inp.index AS BIGINT)) di,
                            max(coalesce(array_length(t.inputs),0)) arrn,
                            {declared_input_expr} declared
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.inputs) u(inp)
                     WHERE NOT coalesce(TRY_CAST(t.is_coinbase AS BOOLEAN),false)
                     GROUP BY 1,2
                   )
                   SELECT count(*) FROM g
                   WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>arrn
                      OR (declared IS NOT NULL AND n<>declared)"""
            ).fetchone()[0] or 0)
            if raw_in_dense_bad:
                failed.append(f"raw_noncoinbase_vin_dense_or_cardinality_bad_tx:{raw_in_dense_bad}")
            raw_stage_in_count_bad = int(con.execute(
                """WITH r AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,count(*) n
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.inputs) u(inp)
                     WHERE NOT coalesce(TRY_CAST(t.is_coinbase AS BOOLEAN),false)
                     GROUP BY 1,2
                   ), s AS (
                     SELECT i.height,i.txid,count(*) n
                     FROM stage_in i JOIN stage_tx t USING(height,tx_index,txid)
                     WHERE NOT t.is_coinbase GROUP BY 1,2
                   )
                   SELECT count(*) FROM r FULL OUTER JOIN s USING(height,txid)
                   WHERE r.n IS NULL OR s.n IS NULL OR r.n<>s.n"""
            ).fetchone()[0] or 0)
            if raw_stage_in_count_bad:
                failed.append(f"raw_stage_noncoinbase_input_cardinality_mismatch:{raw_stage_in_count_bad}")

            coinbase_shape_bad = int(con.execute(
                """SELECT count(*) FROM raw_canon_v50
                   WHERE coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false)
                     AND coalesce(array_length(inputs),0)>1"""
            ).fetchone()[0] or 0)
            if coinbase_shape_bad:
                failed.append(f"raw_coinbase_input_cardinality_gt1:{coinbase_shape_bad}")
            coinbase_regular_prevout = int(con.execute(
                """SELECT count(*) FROM raw_canon_v50 t CROSS JOIN UNNEST(t.inputs) u(inp)
                   WHERE coalesce(TRY_CAST(t.is_coinbase AS BOOLEAN),false)
                     AND regexp_full_match(lower(trim(inp.spent_transaction_hash::VARCHAR)),'[0-9a-f]{64}')
                     AND lower(trim(inp.spent_transaction_hash::VARCHAR))<>repeat('0',64)
                     AND TRY_CAST(inp.spent_output_index AS BIGINT) IS NOT NULL
                     AND TRY_CAST(inp.spent_output_index AS BIGINT)<>4294967295"""
            ).fetchone()[0] or 0)
            if coinbase_regular_prevout:
                failed.append(f"raw_coinbase_encodes_regular_prevout:{coinbase_regular_prevout}")
            coinbase_inputs_omitted = int(con.execute(
                """SELECT count(*) FROM raw_canon_v50
                   WHERE coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false)
                     AND coalesce(array_length(inputs),0)=0"""
            ).fetchone()[0] or 0)
            coinbase_inputs_present = int(con.execute(
                """SELECT count(*) FROM raw_canon_v50
                   WHERE coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false)
                     AND coalesce(array_length(inputs),0)=1"""
            ).fetchone()[0] or 0)

            invalid_in = int(con.execute(
                """SELECT count(*) FROM raw_canon_v50 t CROSS JOIN UNNEST(t.inputs) u(inp)
                   WHERE NOT coalesce(TRY_CAST(t.is_coinbase AS BOOLEAN),false)
                     AND (inp.spent_transaction_hash IS NULL
                          OR NOT regexp_full_match(lower(trim(inp.spent_transaction_hash::VARCHAR)),'[0-9a-f]{64}')
                          OR lower(trim(inp.spent_transaction_hash::VARCHAR))=repeat('0',64)
                          OR TRY_CAST(inp.spent_output_index AS BIGINT) IS NULL
                          OR TRY_CAST(inp.index AS BIGINT) IS NULL)"""
            ).fetchone()[0] or 0)
            if invalid_in:
                failed.append(f"raw_invalid_noncoinbase_inputs:{invalid_in}")
            in_mismatch = int(con.execute(
                """WITH r AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,
                            TRY_CAST(inp.index AS BIGINT) vin_index,
                            lower(inp.spent_transaction_hash::VARCHAR) prev_txid,
                            TRY_CAST(inp.spent_output_index AS UBIGINT) prev_vout
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.inputs) u(inp)
                     WHERE NOT coalesce(TRY_CAST(t.is_coinbase AS BOOLEAN),false)
                   ), s AS (
                     SELECT i.height,i.txid,i.vin_index,i.prev_txid,i.prev_vout
                     FROM stage_in i JOIN stage_tx t USING(height,tx_index,txid)
                     WHERE NOT t.is_coinbase
                   )
                   SELECT count(*) FROM r FULL OUTER JOIN s USING(height,txid,vin_index)
                   WHERE r.txid IS NULL OR s.txid IS NULL OR r.prev_txid<>s.prev_txid OR r.prev_vout<>s.prev_vout"""
            ).fetchone()[0] or 0)
            if in_mismatch:
                failed.append(f"raw_stage_input_prevout_mismatch:{in_mismatch}")
        except Exception as exc:
            return {
                "status": "NOT_EVALUATED",
                "reason": f"RAW input struct contract not provable:{type(exc).__name__}:{exc}",
                "schema": schema, "files": len(files), "h1": h1, "h2": h2,
                "raw_day_start": min_day.isoformat(), "raw_day_end": max_day.isoformat(),
                "failed_checks": failed, "warnings": warnings, "certification_blocking": True,
            }, evidence

        factor = "100000000" if output_unit == "btc" else "1"
        try:
            raw_out_dense_bad = int(con.execute(
                """WITH g AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,
                            count(*) n,min(TRY_CAST(out.index AS BIGINT)) mn,
                            max(TRY_CAST(out.index AS BIGINT)) mx,
                            count(DISTINCT TRY_CAST(out.index AS BIGINT)) di,
                            max(coalesce(array_length(t.outputs),0)) arrn
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.outputs) u(out)
                     GROUP BY 1,2
                   )
                   SELECT count(*) FROM g
                   WHERE mn<>0 OR mx<>n-1 OR di<>n OR n<>arrn"""
            ).fetchone()[0] or 0)
            if raw_out_dense_bad:
                failed.append(f"raw_vout_dense_or_cardinality_bad_tx:{raw_out_dense_bad}")
            raw_stage_out_count_bad = int(con.execute(
                """WITH r AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,count(*) n
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.outputs) u(out) GROUP BY 1,2
                   ), s AS (
                     SELECT height,txid,count(*) n FROM stage_out GROUP BY 1,2
                   )
                   SELECT count(*) FROM r FULL OUTER JOIN s USING(height,txid)
                   WHERE r.n IS NULL OR s.n IS NULL OR r.n<>s.n"""
            ).fetchone()[0] or 0)
            if raw_stage_out_count_bad:
                failed.append(f"raw_stage_output_cardinality_mismatch:{raw_stage_out_count_bad}")

            invalid_out = int(con.execute(
                f"""SELECT count(*) FROM raw_canon_v50 t CROSS JOIN UNNEST(t.outputs) u(out)
                    WHERE TRY_CAST(out.index AS BIGINT) IS NULL OR TRY_CAST(out.index AS BIGINT)<0
                       OR TRY_CAST(out.value AS DOUBLE) IS NULL OR NOT isfinite(TRY_CAST(out.value AS DOUBLE))
                       OR TRY_CAST(out.value AS DOUBLE)<0
                       OR TRY_CAST(round(TRY_CAST(out.value AS DECIMAL(38,8))*{factor}) AS BIGINT)>?""",
                [MAX_MONEY_SATS],
            ).fetchone()[0] or 0)
            if invalid_out:
                failed.append(f"raw_invalid_outputs:{invalid_out}")
            out_mismatch = int(con.execute(
                f"""WITH r AS (
                     SELECT TRY_CAST(t.block_number AS BIGINT) height,lower(t.hash::VARCHAR) txid,
                            TRY_CAST(out.index AS BIGINT) vout,
                            TRY_CAST(round(TRY_CAST(out.value AS DECIMAL(38,8))*{factor}) AS BIGINT) value_sats
                     FROM raw_canon_v50 t CROSS JOIN UNNEST(t.outputs) u(out)
                   ), s AS (SELECT height,txid,vout,value_sats FROM stage_out)
                   SELECT count(*) FROM r FULL OUTER JOIN s USING(height,txid,vout)
                   WHERE r.txid IS NULL OR s.txid IS NULL OR r.value_sats<>s.value_sats"""
            ).fetchone()[0] or 0)
            if out_mismatch:
                failed.append(f"raw_stage_output_value_mismatch:{out_mismatch}")
        except Exception as exc:
            return {
                "status": "NOT_EVALUATED",
                "reason": f"RAW output struct contract not provable:{type(exc).__name__}:{exc}",
                "schema": schema, "files": len(files), "h1": h1, "h2": h2,
                "failed_checks": failed, "warnings": warnings, "certification_blocking": True,
            }, evidence

        if h1 == 0:
            genesis = con.execute(
                "SELECT count(*) FILTER(WHERE TRY_CAST(block_number AS BIGINT)=0), "
                "count(*) FILTER(WHERE TRY_CAST(block_number AS BIGINT)=0 AND lower(block_hash::VARCHAR)=? AND lower(hash::VARCHAR)=? AND coalesce(TRY_CAST(is_coinbase AS BOOLEAN),false)) "
                "FROM raw_canon_v50",
                [GENESIS_HASH, GENESIS_TXID],
            ).fetchone()
            if (int(genesis[0] or 0), int(genesis[1] or 0)) != (1, 1):
                failed.append(f"raw_genesis_identity:{genesis}")

        changed: List[str] = []
        expected_tokens = {str(x["path"]): x for x in evidence}
        for path, before in expected_tokens.items():
            after = file_token(Path(path))
            if not same_token(before, after):
                changed.append(path)
        if changed:
            failed.append(f"raw_files_changed_during_chunk:{changed[:20]}")

        status = "BAD" if failed else ("OK" if order_status == "OK" else "PARTIAL")
        return {
            "status": status,
            "scope": "PRESEGWIT_RAW_TX_INPUT_OUTPUT_VALUES",
            "payload_scope": "TX_ORDER_PREVOUT_OUTPUT_VALUE_EXACT_SCRIPT_NOT_PROVEN",
            "payload_exact": False,
            "h1": h1, "h2": h2,
            "raw_day_start": min_day.isoformat(), "raw_day_end": max_day.isoformat(),
            "files": len(files), "raw_tx_rows": raw_rows, "canonical_heights": raw_heights,
            "competing_block_height_groups": competing, "tx_order_status": order_status,
            "raw_tx_dense_bad_blocks": raw_tx_dense_bad,
            "coinbase_inputs_omitted": coinbase_inputs_omitted,
            "coinbase_inputs_present": coinbase_inputs_present,
            "coinbase_input_scope": "OMISSION_ALLOWED_PRESEGWIT_IF_PRESENT_NOT_REGULAR_PREVOUT",
            "script_payload_status": "NOT_PROVABLE_FROM_AWS_RAW",
            "duckdb_settings": duckdb_settings,
            "failed_checks": failed, "warnings": warnings, "schema": schema,
            "certification_blocking": status != "OK",
        }, evidence
    finally:
        try:
            con.close()
        finally:
            shutil.rmtree(chunk_tmp, ignore_errors=True)


def raw_source_audit_chunked(
    *,
    stage: Dict[str, Any],
    state: Path,
    state_contract: Dict[str, Any],
    target: int,
    raw_base: Path,
    output_unit: str,
    auditor_sha256: str,
    progress_base: Path,
    radius_days: int,
    allow_resume: bool,
    chunk_memory_limit: str,
    temp_max: str,
    chunk_threads: int,
    run_tmp: Path,
) -> Dict[str, Any]:
    if target >= SEGWIT_HEIGHT:
        return {
            "status": "NOT_EVALUATED",
            "reason": "post-SegWit AWS RAW hash identity is not accepted as canonical txid without an independently validated canonical map",
            "scope": f"0..{target}",
            "certification_blocking": True,
        }
    if not raw_base.exists() or not raw_base.is_dir() or raw_base.is_symlink():
        return {
            "status": "NOT_EVALUATED", "reason": f"RAW base missing/not-real-directory: {raw_base}",
            "certification_blocking": True,
        }
    plan = _raw_chunk_plan(stage, target)
    contract = _raw_progress_contract(
        auditor_sha256=auditor_sha256,
        state=state,
        state_contract=state_contract,
        stage=stage,
        target=target,
        raw_base=raw_base,
        output_unit=output_unit,
        radius_days=radius_days,
        plan=plan,
    )
    duckdb = require_duckdb()
    sha_cache: Dict[Tuple[Any, ...], str] = {}
    with RawProgressLease(progress_base / str(contract["contract_id"])):
        root, records, progress = _raw_init_progress(
            progress_base,
            contract,
            plan,
            allow_resume=allow_resume,
            raw_base=raw_base,
        )
        ledger_path = Path(progress["ledger_path"])
        dirty_path = Path(progress["dirty_path"])
        if records:
            log(f"RAW exact resume chunks={len(records)}/{len(plan)} prefix={_raw_progress_prefix_sha(records)}")
        start_idx = len(records)
        for idx in range(start_idx, len(plan)):
            item = plan[idx]
            dirty = {
                "schema": "mybot-v50-raw-audit-dirty-v1",
                "contract_id": contract["contract_id"],
                "chunk_no": idx,
                "h1": int(item["h1"]), "h2": int(item["h2"]),
                "started_utc": utc_now(), "pid": os.getpid(),
            }
            atomic_replace_json(dirty_path, dirty)
            log(f"RAW chunk START {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
            result, raw_evidence = _raw_chunk_audit(
                duckdb_module=duckdb,
                item=item,
                raw_base=raw_base,
                output_unit=output_unit,
                radius_days=radius_days,
                memory_limit=chunk_memory_limit,
                temp_max=temp_max,
                threads=chunk_threads,
                temp_root=run_tmp / "raw_chunks",
                sha_cache=sha_cache,
            )
            record: Dict[str, Any] = {
                "schema": RAW_CHUNK_RECORD_SCHEMA,
                "contract_id": contract["contract_id"],
                "record_no": idx + 1,
                "chunk_no": idx,
                "h1": int(item["h1"]), "h2": int(item["h2"]),
                "stage_manifest_sha256": str(item["stage_manifest_sha256"]),
                "status": str(result.get("status") or "NOT_EVALUATED"),
                "result": result,
                "raw_files": raw_evidence,
                "raw_file_set_sha256": _raw_file_set_digest(raw_evidence),
                "finished_utc": utc_now(),
                "previous_record_sha256": records[-1]["record_sha256"] if records else None,
            }
            record["record_sha256"] = canonical_json_hash(record, exclude=("record_sha256",))
            append_jsonl_fsync(ledger_path, record)
            try:
                dirty_path.unlink()
            except FileNotFoundError:
                raise RuntimeError(f"RAW dirty marker disappeared before commit acknowledgement: {dirty_path}")
            fsync_dir(root)
            records.append(record)
            log(
                f"RAW chunk {record['status']} {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']} "
                f"files={len(raw_evidence)}"
            )

        if len(records) != len(plan):
            return {
                "status": "PARTIAL",
                "reason": "RAW exact chunk coverage incomplete",
                "chunks_total": len(plan), "chunks_completed": len(records),
                "certification_blocking": True,
                "progress": progress,
            }
        # Freeze the evidence set across the entire multi-hour run. This second
        # full SHA pass is intentional: an early RAW file changing after its
        # chunk was checked must invalidate the final exact-prefix proof.
        final_raw_snapshot = _raw_validate_resume_files(records, raw_base)
        # Re-validate exact terminal coverage from durable records, not from loop counters.
        expected_h = 0
        coverage_gaps: List[str] = []
        coverage_overlaps: List[str] = []
        for r in records:
            h1, h2 = int(r["h1"]), int(r["h2"])
            if h1 > expected_h:
                coverage_gaps.append(f"{expected_h}..{h1-1}")
            elif h1 < expected_h:
                coverage_overlaps.append(f"record={r['record_no']} h1={h1} expected={expected_h}")
            expected_h = max(expected_h, h2 + 1)
        if expected_h != target + 1:
            coverage_gaps.append(f"terminal_next={expected_h}!={target+1}")
        counts = {k: 0 for k in ("OK", "BAD", "PARTIAL", "NOT_EVALUATED")}
        chunk_summaries: List[Dict[str, Any]] = []
        failed_chunks: List[Dict[str, Any]] = []
        unique_files: set[str] = set()
        for r in records:
            status = str(r["status"])
            counts[status] = counts.get(status, 0) + 1
            result = r.get("result") if isinstance(r.get("result"), dict) else {}
            summary = {
                "chunk_no": int(r["chunk_no"]), "h1": int(r["h1"]), "h2": int(r["h2"]),
                "status": status,
                "failed_checks": result.get("failed_checks") or [],
                "warnings": result.get("warnings") or [],
                "reason": result.get("reason"),
                "raw_tx_rows": result.get("raw_tx_rows"),
                "canonical_heights": result.get("canonical_heights"),
                "raw_files": len(r.get("raw_files") or []),
                "record_sha256": r["record_sha256"],
            }
            chunk_summaries.append(summary)
            if status != "OK":
                failed_chunks.append(summary)
            for f in r.get("raw_files") or []:
                if isinstance(f, dict) and f.get("path"):
                    unique_files.add(str(f["path"]))
        if coverage_gaps or coverage_overlaps:
            status = "BAD"
        elif counts.get("BAD", 0):
            status = "BAD"
        elif counts.get("PARTIAL", 0) or counts.get("NOT_EVALUATED", 0):
            status = "PARTIAL"
        else:
            status = "OK"
        payload_exact = bool(records) and all(
            isinstance(r.get("result"), dict) and r["result"].get("payload_exact") is True
            for r in records
            if str(r.get("status") or "") == "OK"
        ) and counts.get("OK", 0) == len(records)
        return {
            "status": status,
            "scope": f"PRESEGWIT_RAW_EXACT_PREFIX_0_{target}",
            "payload_scope": "TX_ORDER_PREVOUT_OUTPUT_VALUE_EXACT_SCRIPT_NOT_PROVEN",
            "payload_exact": payload_exact,
            "script_payload_status": "PROVEN" if payload_exact else "NOT_PROVABLE_FROM_AWS_RAW",
            "chunk_contract": "stage-window-height-chunks-v1",
            "chunks_total": len(plan),
            "chunks_completed": len(records),
            "chunks_ok": counts.get("OK", 0),
            "chunks_bad": counts.get("BAD", 0),
            "chunks_partial": counts.get("PARTIAL", 0),
            "chunks_not_evaluated": counts.get("NOT_EVALUATED", 0),
            "first_height": int(records[0]["h1"]) if records else None,
            "last_height": int(records[-1]["h2"]) if records else None,
            "coverage_gaps": coverage_gaps,
            "coverage_overlaps": coverage_overlaps,
            "unique_raw_files": len(unique_files),
            "raw_exact_prefix_sha256": _raw_progress_prefix_sha(records),
            "progress_contract_id": contract["contract_id"],
            "progress_root": str(root),
            "progress": progress,
            "final_raw_snapshot_validation": final_raw_snapshot,
            "failed_chunks": failed_chunks,
            "chunk_summaries": chunk_summaries,
            "certification_blocking": status != "OK",
        }

def false_green_guard_r213(target: int, sem: Dict[str, Any], rebuild: Dict[str, Any], core_stage: Dict[str, Any]) -> Dict[str, Any]:
    failed: List[str] = []
    warnings: List[str] = []
    not_eval: List[str] = []
    if sem.get("false_green_guard_status") != "OK":
        failed.extend(sem.get("false_green_failed_checks") or ["stage_semantic_false_green_guard"])
    duplicate_contract = str(rebuild.get("duplicate_txid_contract_status") or "NOT_EVALUATED")
    if duplicate_contract != "OK":
        failed.append(f"DUPLICATE_TXID_CONTRACT:{duplicate_contract}")
    unresolved = int(rebuild.get("unresolved_prevouts") or 0)
    noncb = int(rebuild.get("noncoinbase_inputs") or 0)
    orphan_pct = (100.0 * unresolved / noncb) if noncb else 0.0
    if unresolved:
        failed.append(f"FALSE_GREEN_COVERAGE_GAP:{unresolved}/{noncb}")
        if orphan_pct >= 50.0:
            failed.append(f"FALSE_GREEN_HIGH_ORPHAN_RATE:{orphan_pct:.6f}%")
        elif orphan_pct >= 10.0:
            warnings.append(f"HIGH_ORPHAN_RATE:{orphan_pct:.6f}%")
    cs = str(core_stage.get("status") or "NOT_EVALUATED")
    if cs == "BAD":
        failed.extend(core_stage.get("failed_checks") or ["CORE_STAGE_EXACT_BAD"])
    elif cs != "OK":
        not_eval.append(f"core_stage_exact:{cs}:{core_stage.get('reason') or core_stage.get('proof_scope')}")
    else:
        if core_stage.get("coverage_complete") is not True:
            failed.append("CORE_STAGE_FALSE_GREEN_INCOMPLETE_COVERAGE")
        if core_stage.get("script_payload_exact") is not True:
            failed.append("CORE_STAGE_SCRIPT_PAYLOAD_NOT_EXACT")
        if core_stage.get("merkle_exact") is not True:
            failed.append("CORE_STAGE_MERKLE_NOT_EXACT")
        if core_stage.get("core_snapshot_stable") is not True:
            failed.append("CORE_STAGE_CORE_SNAPSHOT_UNSTABLE")
    status = "BAD" if failed else ("NOT_EVALUATED" if not_eval else ("WARN" if warnings else "OK"))
    return {
        "status": status,
        "failed_checks": sorted(set(failed)),
        "warnings": sorted(set(warnings)),
        "not_evaluated": sorted(set(not_eval)),
        "orphan_rate_pct": orphan_pct,
        "certification_blocking": status != "OK",
    }


class BitcoinRPCError(RuntimeError):
    def __init__(self, method: str, error: Any):
        super().__init__(f"Bitcoin Core RPC error method={method}: {error}")
        self.method = method
        self.error = error


class BitcoinRPC:
    """Small persistent JSON-RPC client for the local Bitcoin Core node.

    Credentials are read from the cookie file and are never returned in evidence.
    The HTTP connection is retried once on transport failure; RPC method errors are
    surfaced without retry so a pruned/missing block cannot be hidden.
    """
    def __init__(self, url: str, cookie: Path, timeout: int = 120):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise RuntimeError(f"unsupported Bitcoin RPC URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise RuntimeError(f"Bitcoin RPC URL has no host: {url!r}")
        self.url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.cookie = regular(cookie)
        self.timeout = max(5, int(timeout))
        self._conn = None
        self._next_id = 1

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _connect(self):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _auth_header(self) -> str:
        cred = self.cookie.read_text(encoding="utf-8").strip()
        if ":" not in cred:
            raise RuntimeError(f"invalid Bitcoin Core cookie format: {self.cookie}")
        return "Basic " + base64.b64encode(cred.encode("utf-8")).decode("ascii")

    def batch(self, calls: Sequence[Tuple[str, Sequence[Any]]]) -> List[Any]:
        if not calls:
            return []
        ids: List[int] = []
        payload: List[Dict[str, Any]] = []
        for method, params in calls:
            rid = self._next_id
            self._next_id += 1
            ids.append(rid)
            payload.append({"jsonrpc": "2.0", "id": rid, "method": method, "params": list(params)})
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": self._auth_header(),
            "Connection": "keep-alive",
        }
        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            try:
                if self._conn is None:
                    self._conn = self._connect()
                self._conn.request("POST", self.path, body=body, headers=headers)
                resp = self._conn.getresponse()
                raw = resp.read()
                if resp.status != 200:
                    raise RuntimeError(f"Bitcoin Core RPC HTTP {resp.status}: {raw[:500]!r}")
                obj = json.loads(raw.decode("utf-8"))
                if not isinstance(obj, list):
                    raise RuntimeError("Bitcoin Core batch RPC response is not a list")
                by_id: Dict[int, Dict[str, Any]] = {}
                for item in obj:
                    if not isinstance(item, dict) or "id" not in item:
                        raise RuntimeError("Bitcoin Core batch RPC item malformed")
                    by_id[int(item["id"])] = item
                results: List[Any] = []
                for rid, (method, _params) in zip(ids, calls):
                    item = by_id.get(rid)
                    if item is None:
                        raise RuntimeError(f"Bitcoin Core batch RPC missing id={rid} method={method}")
                    if item.get("error") is not None:
                        raise BitcoinRPCError(method, item.get("error"))
                    results.append(item.get("result"))
                return results
            except BitcoinRPCError:
                raise
            except (OSError, http.client.HTTPException, json.JSONDecodeError, RuntimeError) as exc:
                last_exc = exc
                self.close()
                if attempt == 0:
                    continue
                raise RuntimeError(f"Bitcoin Core RPC transport/protocol failure: {type(exc).__name__}: {exc}") from exc
        raise RuntimeError(f"Bitcoin Core RPC failed: {last_exc}")

    def call(self, method: str, *params: Any) -> Any:
        return self.batch([(method, params)])[0]


class CoreStageProgressLease:
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self.root / "LOCK"
        self.fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o640)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            self.fd = -1
            raise RuntimeError(f"Core->Stage audit progress is already in use: {lock}") from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _read_compact_size(buf: bytes, pos: int) -> Tuple[int, int, bytes]:
    if pos >= len(buf):
        raise RuntimeError("CompactSize truncated")
    start = pos
    first = buf[pos]
    pos += 1
    if first < 253:
        return first, pos, buf[start:pos]
    if first == 253:
        if pos + 2 > len(buf):
            raise RuntimeError("CompactSize uint16 truncated")
        value = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
        if value < 253:
            raise RuntimeError("non-canonical CompactSize uint16")
    elif first == 254:
        if pos + 4 > len(buf):
            raise RuntimeError("CompactSize uint32 truncated")
        value = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if value <= 0xFFFF:
            raise RuntimeError("non-canonical CompactSize uint32")
    else:
        if pos + 8 > len(buf):
            raise RuntimeError("CompactSize uint64 truncated")
        value = struct.unpack_from("<Q", buf, pos)[0]
        pos += 8
        if value <= 0xFFFFFFFF:
            raise RuntimeError("non-canonical CompactSize uint64")
    return int(value), pos, buf[start:pos]


def _take(buf: bytes, pos: int, n: int, label: str) -> Tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise RuntimeError(f"{label} truncated need={n} pos={pos} size={len(buf)}")
    return buf[pos:pos+n], pos+n


def _parse_raw_tx(buf: bytes, pos: int) -> Tuple[Dict[str, Any], int]:
    start = pos
    version, pos = _take(buf, pos, 4, "tx.version")
    has_witness = False
    marker_flag = b""
    if pos + 2 <= len(buf) and buf[pos] == 0 and buf[pos + 1] != 0:
        marker_flag = buf[pos:pos+2]
        if marker_flag[1] != 1:
            raise RuntimeError(f"unsupported transaction witness flag=0x{marker_flag[1]:02x}")
        has_witness = True
        pos += 2
    vin_count, pos, vin_count_raw = _read_compact_size(buf, pos)
    if vin_count <= 0:
        raise RuntimeError(f"transaction has invalid vin_count={vin_count}")
    inputs: List[Dict[str, Any]] = []
    vin_raw_parts: List[bytes] = []
    for vin_index in range(vin_count):
        vin_start = pos
        prev_le, pos = _take(buf, pos, 32, "txin.prev_txid")
        prev_vout_raw, pos = _take(buf, pos, 4, "txin.prev_vout")
        prev_vout = struct.unpack("<I", prev_vout_raw)[0]
        script_len, pos, _script_len_raw = _read_compact_size(buf, pos)
        script_sig, pos = _take(buf, pos, script_len, "txin.scriptSig")
        sequence_raw, pos = _take(buf, pos, 4, "txin.sequence")
        vin_raw_parts.append(buf[vin_start:pos])
        inputs.append({
            "vin_index": vin_index,
            "prev_txid": prev_le[::-1].hex(),
            "prev_vout": int(prev_vout),
            "script_sig": script_sig,
            "sequence": struct.unpack("<I", sequence_raw)[0],
        })
    vout_count, pos, vout_count_raw = _read_compact_size(buf, pos)
    if vout_count <= 0:
        raise RuntimeError(f"transaction has invalid vout_count={vout_count}")
    outputs: List[Dict[str, Any]] = []
    vout_raw_parts: List[bytes] = []
    for vout in range(vout_count):
        out_start = pos
        value_raw, pos = _take(buf, pos, 8, "txout.value")
        value = struct.unpack("<Q", value_raw)[0]
        if value > MAX_MONEY_SATS:
            raise RuntimeError(f"transaction output value exceeds MAX_MONEY: {value}")
        script_len, pos, _script_len_raw = _read_compact_size(buf, pos)
        script, pos = _take(buf, pos, script_len, "txout.scriptPubKey")
        vout_raw_parts.append(buf[out_start:pos])
        outputs.append({"vout": vout, "value_sats": int(value), "script_pubkey": script})
    if has_witness:
        for vin_index in range(vin_count):
            items, pos, _ = _read_compact_size(buf, pos)
            for _i in range(items):
                item_len, pos, _ = _read_compact_size(buf, pos)
                _item, pos = _take(buf, pos, item_len, f"witness[{vin_index}]")
    locktime, pos = _take(buf, pos, 4, "tx.locktime")
    full = buf[start:pos]
    stripped = version + vin_count_raw + b"".join(vin_raw_parts) + vout_count_raw + b"".join(vout_raw_parts) + locktime
    txid_internal = _sha256d(stripped)
    wtxid_internal = _sha256d(full)
    txid = txid_internal[::-1].hex()
    wtxid = wtxid_internal[::-1].hex()
    null_prev = inputs[0]["prev_txid"] == "0" * 64 and inputs[0]["prev_vout"] == 0xFFFFFFFF
    is_coinbase = vin_count == 1 and null_prev
    if not is_coinbase:
        for i in inputs:
            if i["prev_txid"] == "0" * 64 and i["prev_vout"] == 0xFFFFFFFF:
                raise RuntimeError("non-coinbase transaction contains null prevout")
    return {
        "txid": txid,
        "wtxid": wtxid,
        "txid_internal": txid_internal,
        "has_witness": has_witness,
        "vin_count": vin_count,
        "vout_count": vout_count,
        "inputs": inputs,
        "outputs": outputs,
        "is_coinbase": is_coinbase,
        "size": pos - start,
    }, pos


def _merkle_root_internal(txids_internal: Sequence[bytes]) -> bytes:
    if not txids_internal:
        raise RuntimeError("cannot compute Merkle root for empty transaction list")
    level = list(txids_internal)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [_sha256d(level[i] + level[i+1]) for i in range(0, len(level), 2)]
    return level[0]


def _parse_raw_block_hex(raw_hex: str, expected_hash: str) -> Dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex).strip())
    except ValueError as exc:
        raise RuntimeError("Bitcoin Core getblock(verbosity=0) returned invalid hex") from exc
    if len(raw) < 81:
        raise RuntimeError(f"raw block too short: {len(raw)}")
    header = raw[:80]
    block_hash = _sha256d(header)[::-1].hex()
    if block_hash != expected_hash.lower():
        raise RuntimeError(f"raw block hash mismatch computed={block_hash} expected={expected_hash}")
    version = struct.unpack_from("<I", header, 0)[0]
    prev_hash = header[4:36][::-1].hex()
    merkle_header_internal = header[36:68]
    merkle_header = merkle_header_internal[::-1].hex()
    block_time = struct.unpack_from("<I", header, 68)[0]
    bits = struct.unpack_from("<I", header, 72)[0]
    nonce = struct.unpack_from("<I", header, 76)[0]
    tx_count, pos, _ = _read_compact_size(raw, 80)
    if tx_count <= 0:
        raise RuntimeError(f"block has invalid tx_count={tx_count}")
    txs: List[Dict[str, Any]] = []
    txids_internal: List[bytes] = []
    for _tx_index in range(tx_count):
        tx, pos = _parse_raw_tx(raw, pos)
        txs.append(tx)
        txids_internal.append(tx["txid_internal"])
    if pos != len(raw):
        raise RuntimeError(f"raw block trailing bytes parsed={pos} total={len(raw)}")
    if not txs[0]["is_coinbase"]:
        raise RuntimeError("block transaction index 0 is not coinbase")
    if sum(1 for x in txs if x["is_coinbase"]) != 1:
        raise RuntimeError("block does not contain exactly one coinbase transaction")
    merkle_computed_internal = _merkle_root_internal(txids_internal)
    if merkle_computed_internal != merkle_header_internal:
        raise RuntimeError(
            f"block Merkle mismatch header={merkle_header} computed={merkle_computed_internal[::-1].hex()}"
        )
    return {
        "block_hash": block_hash,
        "prev_hash": prev_hash,
        "merkle_root": merkle_header,
        "block_time": int(block_time),
        "version": int(version),
        "bits": int(bits),
        "nonce": int(nonce),
        "tx_count": int(tx_count),
        "transactions": txs,
        "size": len(raw),
    }


def _core_parser_selftest() -> Dict[str, Any]:
    tx_hex = (
        "0100000001" + "00" * 32 + "ffffffff" + "4d" +
        "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" +
        "ffffffff01" + "00f2052a01000000" + "43" +
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac" +
        "00000000"
    )
    header_hex = (
        "01000000" + "00" * 32 +
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
        "29ab5f49ffff001d1dac2b7c"
    )
    block = _parse_raw_block_hex(header_hex + "01" + tx_hex, GENESIS_HASH)
    tx = block["transactions"][0]
    failed: List[str] = []
    if tx["txid"] != GENESIS_TXID:
        failed.append(f"genesis_txid:{tx['txid']}!={GENESIS_TXID}")
    if tx["wtxid"] != GENESIS_TXID:
        failed.append(f"genesis_wtxid:{tx['wtxid']}!={GENESIS_TXID}")
    if block["merkle_root"] != GENESIS_TXID:
        failed.append(f"genesis_merkle:{block['merkle_root']}!={GENESIS_TXID}")
    if block["prev_hash"] != "0" * 64:
        failed.append("genesis_prevhash_nonzero")
    if block["block_time"] != 1231006505:
        failed.append(f"genesis_time:{block['block_time']}")
    if tx["outputs"][0]["value_sats"] != 5_000_000_000:
        failed.append(f"genesis_value:{tx['outputs'][0]['value_sats']}")
    return {"status": "BAD" if failed else "OK", "failed_checks": failed}


def _digest_u32(h: Any, value: int) -> None:
    if value < 0 or value > 0xFFFFFFFF:
        raise RuntimeError(f"u32 out of range: {value}")
    h.update(struct.pack("<I", int(value)))


def _digest_u64(h: Any, value: int) -> None:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise RuntimeError(f"u64 out of range: {value}")
    h.update(struct.pack("<Q", int(value)))


def _digest_hash32(h: Any, value: str) -> None:
    value = str(value).lower()
    if HASH_RE.fullmatch(value) is None:
        raise RuntimeError(f"invalid 32-byte hash for stream digest: {value!r}")
    h.update(bytes.fromhex(value))


def _digest_blob(h: Any, value: bytes) -> None:
    b = bytes(value)
    _digest_u32(h, len(b))
    h.update(b)


def _digest_block_row(h: Any, height: int, block_hash: str, prev_hash: str, block_time: int, tx_count: int) -> None:
    h.update(b"B")
    _digest_u32(h, height)
    _digest_hash32(h, block_hash)
    _digest_hash32(h, prev_hash)
    _digest_u64(h, block_time)
    _digest_u32(h, tx_count)


def _digest_tx_row(h: Any, height: int, tx_index: int, txid: str, is_coinbase: bool, vin_count: int, vout_count: int) -> None:
    h.update(b"T")
    _digest_u32(h, height)
    _digest_u32(h, tx_index)
    _digest_hash32(h, txid)
    h.update(b"\x01" if is_coinbase else b"\x00")
    _digest_u32(h, vin_count)
    _digest_u32(h, vout_count)


def _digest_input_row(h: Any, height: int, tx_index: int, txid: str, vin_index: int, prev_txid: str, prev_vout: int) -> None:
    h.update(b"I")
    _digest_u32(h, height)
    _digest_u32(h, tx_index)
    _digest_hash32(h, txid)
    _digest_u32(h, vin_index)
    _digest_hash32(h, prev_txid)
    _digest_u32(h, prev_vout)


def _digest_output_row(h: Any, height: int, tx_index: int, txid: str, vout: int, value_sats: int, script: bytes) -> None:
    h.update(b"O")
    _digest_u32(h, height)
    _digest_u32(h, tx_index)
    _digest_hash32(h, txid)
    _digest_u32(h, vout)
    _digest_u64(h, value_sats)
    _digest_blob(h, script)


def _core_stage_chunk_plan(stage: Dict[str, Any], target: int) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    expected = 0
    for e in selected_entries(stage, target):
        h1 = int(e["h1"])
        h2 = min(int(e["h2"]), int(target))
        if h1 != expected or h2 < h1:
            raise RuntimeError(f"Core->Stage chunk plan gap/overlap expected={expected} actual={h1}..{h2}")
        plan.append({
            "chunk_no": len(plan),
            "h1": h1,
            "h2": h2,
            "stage_manifest_path": str(e["manifest_path"]),
            "stage_manifest_sha256": str(e["manifest_sha256"]),
            "entry": e,
        })
        expected = h2 + 1
        if h2 == target:
            break
    if not plan or expected != target + 1:
        raise RuntimeError(f"Core->Stage chunk plan terminal mismatch next={expected} target={target}")
    return plan


def _core_stage_plan_digest(plan: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash({
        "contract": "core-stage-window-height-plan-v1",
        "chunks": [
            {
                "chunk_no": int(x["chunk_no"]),
                "h1": int(x["h1"]),
                "h2": int(x["h2"]),
                "stage_manifest_sha256": str(x["stage_manifest_sha256"]),
            }
            for x in plan
        ],
    })


def _core_bind_stage_chunk(con, item: Dict[str, Any]) -> None:
    e = item["entry"]
    h1, h2 = int(item["h1"]), int(item["h2"])
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_block AS
        SELECT height::BIGINT height, lower(block_hash::VARCHAR) block_hash,
               lower(prev_hash::VARCHAR) prev_hash, block_time::BIGINT block_time,
               tx_count::BIGINT tx_count
        FROM read_parquet({sql_quote(str(e['blocks']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_tx AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, is_coinbase::BOOLEAN is_coinbase,
               vin_count::BIGINT vin_count, vout_count::BIGINT vout_count
        FROM read_parquet({sql_quote(str(e['transactions']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_in AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vin_index::BIGINT vin_index,
               lower(prev_txid::VARCHAR) prev_txid, prev_vout::UBIGINT prev_vout
        FROM read_parquet({sql_quote(str(e['inputs']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)
    con.execute(f"""
        CREATE OR REPLACE TEMP VIEW stage_out AS
        SELECT height::BIGINT height, tx_index::BIGINT tx_index,
               lower(txid::VARCHAR) txid, vout::BIGINT vout,
               value_sats::BIGINT value_sats, script_pubkey::BLOB script_pubkey,
               script_pubkey_size::BIGINT script_pubkey_size
        FROM read_parquet({sql_quote(str(e['outputs']['path']))}, union_by_name=true)
        WHERE height BETWEEN {h1} AND {h2}
    """)


def _stream_stage_query(cur, kind: str) -> Tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    while True:
        rows = cur.fetchmany(8192)
        if not rows:
            break
        for r in rows:
            if kind == "block":
                _digest_block_row(digest, int(r[0]), str(r[1]), str(r[2]), int(r[3]), int(r[4]))
            elif kind == "tx":
                _digest_tx_row(digest, int(r[0]), int(r[1]), str(r[2]), bool(r[3]), int(r[4]), int(r[5]))
            elif kind == "in":
                _digest_input_row(digest, int(r[0]), int(r[1]), str(r[2]), int(r[3]), str(r[4]), int(r[5]))
            elif kind == "out":
                script = bytes(r[5])
                if len(script) != int(r[6]):
                    raise RuntimeError(f"Stage script size mismatch during Core exact stream: {len(script)}!={int(r[6])}")
                _digest_output_row(digest, int(r[0]), int(r[1]), str(r[2]), int(r[3]), int(r[4]), script)
            else:
                raise RuntimeError(f"unknown Stage stream kind: {kind}")
            count += 1
    return count, digest.hexdigest()


def _stage_core_chunk_evidence(
    duckdb_module,
    item: Dict[str, Any],
    memory_limit: str,
    temp_max: str,
    threads: int,
    temp_root: Path,
) -> Dict[str, Any]:
    h1, h2 = int(item["h1"]), int(item["h2"])
    chunk_tmp = temp_root / f"core_stage_{int(item['chunk_no']):05d}_{h1}_{h2}"
    chunk_tmp.mkdir(parents=True, exist_ok=False)
    con = duckdb_module.connect(":memory:")
    try:
        settings = configure_duckdb(con, memory_limit, chunk_tmp / "duckdb_tmp", temp_max, max(1, threads))
        _core_bind_stage_chunk(con, item)
        block_rows = con.execute(
            "SELECT height,block_hash,prev_hash,block_time,tx_count FROM stage_block ORDER BY height"
        ).fetchall()
        if len(block_rows) != h2 - h1 + 1:
            raise RuntimeError(f"Stage chunk block coverage {len(block_rows)}!={h2-h1+1}")
        block_digest = hashlib.sha256()
        block_map: Dict[int, Dict[str, Any]] = {}
        for r in block_rows:
            height = int(r[0])
            row = {
                "block_hash": str(r[1]), "prev_hash": str(r[2]),
                "block_time": int(r[3]), "tx_count": int(r[4]),
            }
            block_map[height] = row
            _digest_block_row(block_digest, height, row["block_hash"], row["prev_hash"], row["block_time"], row["tx_count"])
        tx_count, tx_sha = _stream_stage_query(con.execute(
            "SELECT height,tx_index,txid,is_coinbase,vin_count,vout_count FROM stage_tx ORDER BY height,tx_index"
        ), "tx")
        in_count, in_sha = _stream_stage_query(con.execute(
            "SELECT height,tx_index,txid,vin_index,prev_txid,prev_vout FROM stage_in ORDER BY height,tx_index,vin_index"
        ), "in")
        out_count, out_sha = _stream_stage_query(con.execute(
            "SELECT height,tx_index,txid,vout,value_sats,script_pubkey,script_pubkey_size FROM stage_out ORDER BY height,tx_index,vout"
        ), "out")
        return {
            "block_map": block_map,
            "counts": {"blocks": len(block_rows), "transactions": tx_count, "inputs": in_count, "outputs": out_count},
            "digests": {
                "blocks": block_digest.hexdigest(), "transactions": tx_sha,
                "inputs": in_sha, "outputs": out_sha,
            },
            "duckdb_settings": settings,
        }
    finally:
        try:
            con.close()
        finally:
            shutil.rmtree(chunk_tmp, ignore_errors=True)


def _core_identity(rpc: BitcoinRPC, target: int) -> Dict[str, Any]:
    chaininfo = rpc.call("getblockchaininfo")
    netinfo = rpc.call("getnetworkinfo")
    if not isinstance(chaininfo, dict) or not isinstance(netinfo, dict):
        raise RuntimeError("Bitcoin Core identity RPC returned malformed object")
    chain = str(chaininfo.get("chain") or "")
    blocks_raw = chaininfo.get("blocks")
    headers_raw = chaininfo.get("headers")
    blocks = int(blocks_raw) if blocks_raw is not None else -1
    headers = int(headers_raw) if headers_raw is not None else -1
    pruned = bool(chaininfo.get("pruned", False))
    pruneheight = int(chaininfo.get("pruneheight") or 0) if pruned else 0
    genesis, target_hash = rpc.batch([
        ("getblockhash", [0]),
        ("getblockhash", [int(target)]),
    ])
    return {
        "chain": chain,
        "blocks": blocks,
        "headers": headers,
        "pruned": pruned,
        "pruneheight": pruneheight,
        "version": int(netinfo.get("version") or 0),
        "subversion": str(netinfo.get("subversion") or ""),
        "genesis_hash": str(genesis).lower(),
        "target_hash": str(target_hash).lower(),
    }


def _core_stage_progress_contract(
    *,
    auditor_sha256: str,
    state: Path,
    state_contract: Dict[str, Any],
    stage: Dict[str, Any],
    target: int,
    core_identity: Dict[str, Any],
    rpc_url: str,
    plan: Sequence[Dict[str, Any]],
    block_batch: int,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema": CORE_STAGE_PROGRESS_SCHEMA,
        "auditor_version": VERSION,
        "auditor_sha256": str(auditor_sha256),
        "target_height": int(target),
        "target_hash": str(state_contract["block_hash"]),
        "state": {
            "path": str(state.resolve(strict=True)),
            "checkpoint_sha256": sha256_file(regular(state / "checkpoint.bin")),
            "meta_sha256": sha256_file(regular(state / "state.meta")),
            "source_sha256": str(state_contract["source_sha256"]),
            "core_sha256": str(state_contract["core_sha256"]),
            "driver_sha256": str(state_contract["driver_sha256"]),
        },
        "stage": {
            "kind": str(stage["kind"]),
            "release_path": str(stage["path"]),
            "release_sha256": str(stage["sha256"]),
            "window_plan_sha256": _core_stage_plan_digest(plan),
            "chunks_total": len(plan),
        },
        "bitcoin_core": {
            "chain": str(core_identity["chain"]),
            "version": int(core_identity["version"]),
            "genesis_hash": str(core_identity["genesis_hash"]),
            "target_hash": str(core_identity["target_hash"]),
            "rpc_endpoint": str(rpc_url),
            "raw_block_contract": "getblock-verbosity0-independent-parser-v1",
            "block_batch": int(block_batch),
        },
        "comparison": {
            "chunk_contract": "stage-window-height-chunks-v1",
            "block_fields": "height,hash,prevhash,time,tx_count",
            "tx_fields": "height,tx_index,canonical_txid,coinbase,vin_count,vout_count",
            "input_fields": "height,tx_index,txid,vin_index,prev_txid,prev_vout",
            "output_fields": "height,tx_index,txid,vout,value_sats,raw_script_pubkey",
            "merkle": "independent SHA256d tree from canonical txid",
        },
    }
    payload["contract_id"] = canonical_json_hash(payload)
    return payload


def _core_stage_read_progress(path: Path, contract_id: str, plan: Sequence[Dict[str, Any]], expected_sha256: Optional[str] = None) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Core->Stage progress ledger is not a regular file: {path}")
    if int(path.stat().st_nlink) != 1:
        raise RuntimeError(f"Core->Stage progress ledger hardlink forbidden: {path}")
    before = file_token(path)
    raw = path.read_bytes()
    after = file_token(path)
    if not same_token(before, after):
        raise RuntimeError(f"Core->Stage progress ledger changed during read: {path}")
    if expected_sha256 is not None:
        want = str(expected_sha256).lower()
        if HASH_RE.fullmatch(want) is None:
            raise RuntimeError("Core->Stage evidence ledger expected SHA256 is invalid")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != want:
            raise RuntimeError(f"Core->Stage evidence ledger SHA256 mismatch actual={actual} expected={want}")
    records: List[Dict[str, Any]] = []
    previous: Optional[str] = None
    for line_no, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise RuntimeError(f"Core->Stage ledger line {line_no} is not an object")
        idx = len(records)
        if idx >= len(plan):
            raise RuntimeError("Core->Stage ledger has more records than planned chunks")
        expected = plan[idx]
        if obj.get("schema") != CORE_STAGE_CHUNK_RECORD_SCHEMA:
            raise RuntimeError(f"Core->Stage record schema mismatch line={line_no}")
        if str(obj.get("contract_id") or "") != contract_id:
            raise RuntimeError(f"Core->Stage contract mismatch line={line_no}")
        if int(obj.get("record_no", -1)) != idx + 1 or int(obj.get("chunk_no", -1)) != idx:
            raise RuntimeError(f"Core->Stage sequence mismatch line={line_no}")
        if int(obj.get("h1", -1)) != int(expected["h1"]) or int(obj.get("h2", -1)) != int(expected["h2"]):
            raise RuntimeError(f"Core->Stage range mismatch line={line_no}")
        if str(obj.get("stage_manifest_sha256") or "") != str(expected["stage_manifest_sha256"]):
            raise RuntimeError(f"Core->Stage manifest mismatch line={line_no}")
        if obj.get("previous_record_sha256") != previous:
            raise RuntimeError(f"Core->Stage previous SHA mismatch line={line_no}")
        expected_sha = canonical_json_hash(obj, exclude=("record_sha256",))
        if str(obj.get("record_sha256") or "") != expected_sha:
            raise RuntimeError(f"Core->Stage record SHA mismatch line={line_no}")
        if str(obj.get("status") or "") not in {"OK", "BAD"}:
            raise RuntimeError(f"Core->Stage committed record has invalid status line={line_no}")
        previous = expected_sha
        records.append(obj)
    return records


def _core_stage_init_progress(
    root_base: Path,
    contract: Dict[str, Any],
    plan: Sequence[Dict[str, Any]],
    allow_resume: bool,
) -> Tuple[Path, List[Dict[str, Any]], Dict[str, Any]]:
    contract_id = str(contract["contract_id"])
    root = root_base / contract_id
    root.mkdir(parents=True, exist_ok=True)
    contract_path = root / "contract.json"
    ledger_path = root / "chunks.jsonl"
    dirty_path = root / "dirty.json"
    if contract_path.exists():
        observed = load_json(contract_path)
        if canonical_json_hash(observed) != canonical_json_hash(contract):
            raise RuntimeError(f"Core->Stage progress contract payload mismatch: {contract_path}")
        if read_sidecar(Path(str(contract_path) + ".sha256")) != sha256_file(contract_path):
            raise RuntimeError(f"Core->Stage progress contract sidecar mismatch: {contract_path}")
    else:
        write_evidence(contract_path, contract)
    records = _core_stage_read_progress(ledger_path, contract_id, plan)
    if records and not allow_resume:
        raise RuntimeError(f"Core->Stage progress exists but resume disabled: {root}")
    recovered_dirty: Optional[Dict[str, Any]] = None
    if dirty_path.exists():
        if not allow_resume:
            raise RuntimeError(f"Core->Stage dirty marker exists but resume disabled: {dirty_path}")
        recovered_dirty = load_json(dirty_path)
        if str(recovered_dirty.get("contract_id") or "") != contract_id:
            raise RuntimeError(f"Core->Stage dirty marker contract mismatch: {dirty_path}")
        dirty_chunk = int(recovered_dirty.get("chunk_no", -1))
        next_chunk = len(records)
        # Two crash-safe states are legitimate:
        #   dirty == next_chunk: chunk started but no durable ledger commit -> retry it;
        #   dirty == next_chunk-1: ledger commit is durable but crash happened before/while
        #                         unlinking the dirty marker -> keep commit and clear stale dirty.
        if dirty_chunk == next_chunk:
            recovered_dirty["recovery_class"] = "UNCOMMITTED_CHUNK_RETRY"
        elif records and dirty_chunk == next_chunk - 1 and int(records[-1].get("chunk_no", -2)) == dirty_chunk:
            recovered_dirty["recovery_class"] = "STALE_DIRTY_AFTER_DURABLE_COMMIT"
        else:
            raise RuntimeError(
                f"Core->Stage dirty marker/ledger mismatch dirty={dirty_chunk} records={next_chunk}"
            )
        archived = root / f"dirty.recovered.{utc_stamp()}.{os.getpid()}.{uuid.uuid4().hex[:8]}.json"
        os.replace(dirty_path, archived)
        fsync_dir(root)
        recovered_dirty = dict(recovered_dirty)
        recovered_dirty["archived_path"] = str(archived)
    return root, records, {
        "contract_path": str(contract_path), "ledger_path": str(ledger_path),
        "dirty_path": str(dirty_path), "recovered_dirty": recovered_dirty,
    }


def _core_stage_prefix_sha(records: Sequence[Dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for r in records:
        digest = str(r.get("record_sha256") or "")
        if HASH_RE.fullmatch(digest) is None:
            raise RuntimeError(f"invalid Core->Stage record SHA: {digest!r}")
        h.update(bytes.fromhex(digest))
    return h.hexdigest()


def _core_stage_chunk_audit(
    *,
    rpc: BitcoinRPC,
    duckdb_module,
    item: Dict[str, Any],
    block_batch: int,
    stage_memory_limit: str,
    temp_max: str,
    stage_threads: int,
    temp_root: Path,
) -> Dict[str, Any]:
    h1, h2 = int(item["h1"]), int(item["h2"])
    stage_ev = _stage_core_chunk_evidence(
        duckdb_module, item, stage_memory_limit, temp_max, stage_threads, temp_root
    )
    block_map = stage_ev.pop("block_map")
    heights = list(range(h1, h2 + 1))
    hash_calls: List[Tuple[str, Sequence[Any]]] = []
    if h1 > 0:
        hash_calls.append(("getblockhash", [h1 - 1]))
    hash_calls.extend(("getblockhash", [h]) for h in heights)
    try:
        hash_results = rpc.batch(hash_calls)
    except BitcoinRPCError as exc:
        return {"status": "NOT_EVALUATED", "reason": str(exc), "h1": h1, "h2": h2}
    offset = 0
    prior_active: Optional[str] = None
    if h1 > 0:
        prior_active = str(hash_results[0]).lower()
        offset = 1
    active = {h: str(hash_results[offset + i]).lower() for i, h in enumerate(heights)}
    failed: List[str] = []
    mismatch_samples: List[Dict[str, Any]] = []
    for h in heights:
        expected = block_map[h]["block_hash"]
        observed = active[h]
        if HASH_RE.fullmatch(observed) is None:
            failed.append(f"core_active_hash_invalid:h={h}")
        elif observed != expected:
            failed.append(f"core_stage_active_hash_mismatch:h={h}")
            if len(mismatch_samples) < 20:
                mismatch_samples.append({"height": h, "field": "block_hash", "stage": expected, "core": observed})
    if failed:
        return {
            "status": "BAD", "h1": h1, "h2": h2,
            "failed_checks": failed, "mismatch_samples": mismatch_samples,
            "stage": stage_ev,
        }

    core_hashers = {k: hashlib.sha256() for k in ("blocks", "transactions", "transactions_wtxid", "inputs", "outputs")}
    counts = {"blocks": 0, "transactions": 0, "inputs": 0, "outputs": 0, "witness_transactions": 0}
    bytes_received = 0
    merkle_verified = 0
    for start in range(0, len(heights), max(1, int(block_batch))):
        bh = heights[start:start + max(1, int(block_batch))]
        calls = [("getblock", [active[h], 0]) for h in bh]
        try:
            raw_blocks = rpc.batch(calls)
        except BitcoinRPCError as exc:
            return {
                "status": "NOT_EVALUATED", "reason": str(exc), "h1": h1, "h2": h2,
                "blocks_completed": counts["blocks"], "stage": stage_ev,
            }
        for height, raw_hex in zip(bh, raw_blocks):
            block = _parse_raw_block_hex(str(raw_hex), active[height])
            bytes_received += block["size"]
            expected_prev = "0" * 64 if height == 0 else (prior_active if height == h1 else active[height - 1])
            if block["prev_hash"] != expected_prev:
                failed.append(f"core_prevhash_chain:h={height}")
            stage_b = block_map[height]
            for field, core_value in (
                ("prev_hash", block["prev_hash"]),
                ("block_time", block["block_time"]),
                ("tx_count", block["tx_count"]),
            ):
                if core_value != stage_b[field]:
                    failed.append(f"core_stage_{field}_mismatch:h={height}")
                    if len(mismatch_samples) < 20:
                        mismatch_samples.append({"height": height, "field": field, "stage": stage_b[field], "core": core_value})
            _digest_block_row(
                core_hashers["blocks"], height, block["block_hash"], block["prev_hash"],
                block["block_time"], block["tx_count"]
            )
            counts["blocks"] += 1
            merkle_verified += 1
            for tx_index, tx in enumerate(block["transactions"]):
                if tx_index == 0 and not tx["is_coinbase"]:
                    failed.append(f"core_coinbase_missing_at_zero:h={height}")
                if tx_index > 0 and tx["is_coinbase"]:
                    failed.append(f"core_coinbase_nonzero:h={height}:tx_index={tx_index}")
                _digest_tx_row(
                    core_hashers["transactions"], height, tx_index, tx["txid"], tx["is_coinbase"],
                    tx["vin_count"], tx["vout_count"]
                )
                _digest_tx_row(
                    core_hashers["transactions_wtxid"], height, tx_index, tx["wtxid"], tx["is_coinbase"],
                    tx["vin_count"], tx["vout_count"]
                )
                if tx["has_witness"]:
                    counts["witness_transactions"] += 1
                counts["transactions"] += 1
                for inp in tx["inputs"]:
                    _digest_input_row(
                        core_hashers["inputs"], height, tx_index, tx["txid"], inp["vin_index"],
                        inp["prev_txid"], inp["prev_vout"]
                    )
                    counts["inputs"] += 1
                for out in tx["outputs"]:
                    _digest_output_row(
                        core_hashers["outputs"], height, tx_index, tx["txid"], out["vout"],
                        out["value_sats"], out["script_pubkey"]
                    )
                    counts["outputs"] += 1
        log(f"Core->Stage chunk heights={h1}..{h2} raw_blocks={min(start+len(bh),len(heights))}/{len(heights)}")

    core_digests = {
        "blocks": core_hashers["blocks"].hexdigest(),
        "transactions": core_hashers["transactions"].hexdigest(),
        "transactions_wtxid": core_hashers["transactions_wtxid"].hexdigest(),
        "inputs": core_hashers["inputs"].hexdigest(),
        "outputs": core_hashers["outputs"].hexdigest(),
    }
    stage_counts = stage_ev["counts"]
    stage_digests = stage_ev["digests"]
    for key in ("blocks", "transactions", "inputs", "outputs"):
        if int(counts[key]) != int(stage_counts[key]):
            failed.append(f"core_stage_{key}_count:{counts[key]}!={stage_counts[key]}")
        if core_digests[key] != stage_digests[key]:
            failed.append(f"core_stage_{key}_digest_mismatch")
    wtxid_substitution_suspected = (
        core_digests["transactions"] != stage_digests["transactions"]
        and core_digests["transactions_wtxid"] == stage_digests["transactions"]
        and counts["witness_transactions"] > 0
    )
    if wtxid_substitution_suspected:
        failed.append("WTXID_AS_CANONICAL_TXID_SUSPECTED")
    return {
        "status": "BAD" if failed else "OK",
        "h1": h1, "h2": h2,
        "proof_scope": "RAW_BLOCK_BYTES_EXACT",
        "canonical_chain": "getblockhash(height) active-chain exact",
        "parser": "independent Bitcoin serialization parser; no V50/SOURCE imports",
        "counts": counts,
        "core_digests": core_digests,
        "stage": stage_ev,
        "merkle_roots_verified": merkle_verified,
        "raw_block_bytes": bytes_received,
        "wtxid_substitution_suspected": wtxid_substitution_suspected,
        "failed_checks": sorted(set(failed)),
        "mismatch_samples": mismatch_samples,
    }


def core_stage_exact_audit(
    *,
    stage: Dict[str, Any],
    state: Path,
    state_contract: Dict[str, Any],
    target: int,
    auditor_sha256: str,
    progress_base: Path,
    allow_resume: bool,
    rpc_url: str,
    rpc_cookie: Optional[str],
    datadir: Optional[str],
    block_batch: int,
    stage_memory_limit: str,
    temp_max: str,
    stage_threads: int,
    rpc_timeout: int,
    run_tmp: Path,
) -> Dict[str, Any]:
    selftest = _core_parser_selftest()
    if selftest["status"] != "OK":
        return {"status": "BAD", "failed_checks": ["core_parser_selftest"] + selftest["failed_checks"]}
    cookie = _rpc_cookie(rpc_cookie, datadir)
    if cookie is None:
        return {
            "status": "NOT_EVALUATED", "reason": "Bitcoin Core RPC cookie unavailable",
            "certification_blocking": True,
        }
    rpc = BitcoinRPC(rpc_url, cookie, timeout=max(5, int(rpc_timeout)))
    try:
        try:
            identity = _core_identity(rpc, target)
        except (BitcoinRPCError, RuntimeError) as exc:
            return {"status": "NOT_EVALUATED", "reason": str(exc), "certification_blocking": True}
        failed: List[str] = []
        if identity["chain"] != "main":
            failed.append(f"bitcoin_core_chain:{identity['chain']}!=main")
        if identity["blocks"] < target:
            return {
                "status": "NOT_EVALUATED", "reason": f"Bitcoin Core blocks={identity['blocks']} below target={target}",
                "core_identity": identity, "certification_blocking": True,
            }
        if identity["genesis_hash"] != GENESIS_HASH:
            failed.append(f"bitcoin_core_genesis:{identity['genesis_hash']}!={GENESIS_HASH}")
        if identity["target_hash"] != str(state_contract["block_hash"]):
            failed.append(f"bitcoin_core_target:{identity['target_hash']}!={state_contract['block_hash']}")
        if identity["pruned"] and identity["pruneheight"] > 0:
            return {
                "status": "NOT_EVALUATED",
                "reason": f"Bitcoin Core is pruned pruneheight={identity['pruneheight']}; full 0..{target} raw payload unavailable",
                "core_identity": identity, "certification_blocking": True,
            }
        if failed:
            return {"status": "BAD", "failed_checks": failed, "core_identity": identity}
        plan = _core_stage_chunk_plan(stage, target)
        contract = _core_stage_progress_contract(
            auditor_sha256=auditor_sha256,
            state=state,
            state_contract=state_contract,
            stage=stage,
            target=target,
            core_identity=identity,
            rpc_url=rpc_url,
            plan=plan,
            block_batch=max(1, int(block_batch)),
        )
        lock_root = progress_base / str(contract["contract_id"])
        duckdb = require_duckdb()
        with CoreStageProgressLease(lock_root):
            root, records, progress = _core_stage_init_progress(
                progress_base, contract, plan, allow_resume=allow_resume
            )
            ledger_path = Path(progress["ledger_path"])
            dirty_path = Path(progress["dirty_path"])
            if records:
                log(f"Core->Stage exact resume chunks={len(records)}/{len(plan)} prefix={_core_stage_prefix_sha(records)}")
            if records and str(records[-1].get("status")) == "BAD":
                return {
                    "status": "BAD", "reason": "committed BAD Core->Stage chunk in progress ledger",
                    "failed_chunk": records[-1], "progress": progress,
                }
            start_idx = len(records)
            transient: Optional[Dict[str, Any]] = None
            for idx in range(start_idx, len(plan)):
                item = plan[idx]
                dirty = {
                    "schema": "mybot-v50-core-stage-dirty-v1",
                    "contract_id": contract["contract_id"], "chunk_no": idx,
                    "h1": int(item["h1"]), "h2": int(item["h2"]),
                    "started_utc": utc_now(), "pid": os.getpid(),
                }
                atomic_replace_json(dirty_path, dirty)
                log(f"Core->Stage chunk START {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
                result = _core_stage_chunk_audit(
                    rpc=rpc, duckdb_module=duckdb, item=item,
                    block_batch=max(1, int(block_batch)),
                    stage_memory_limit=stage_memory_limit, temp_max=temp_max,
                    stage_threads=max(1, int(stage_threads)), temp_root=run_tmp / "core_stage_chunks",
                )
                status = str(result.get("status") or "NOT_EVALUATED")
                if status in {"NOT_EVALUATED", "PARTIAL"}:
                    transient = result
                    log(f"Core->Stage chunk {status} {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
                    break
                if status not in {"OK", "BAD"}:
                    raise RuntimeError(f"Core->Stage chunk invalid status: {status}")
                record: Dict[str, Any] = {
                    "schema": CORE_STAGE_CHUNK_RECORD_SCHEMA,
                    "contract_id": contract["contract_id"], "record_no": idx + 1, "chunk_no": idx,
                    "h1": int(item["h1"]), "h2": int(item["h2"]),
                    "stage_manifest_sha256": str(item["stage_manifest_sha256"]),
                    "status": status, "result": result, "finished_utc": utc_now(),
                    "previous_record_sha256": records[-1]["record_sha256"] if records else None,
                }
                record["record_sha256"] = canonical_json_hash(record, exclude=("record_sha256",))
                append_jsonl_fsync(ledger_path, record)
                try:
                    dirty_path.unlink()
                except FileNotFoundError:
                    raise RuntimeError(f"Core->Stage dirty marker disappeared before commit: {dirty_path}")
                fsync_dir(root)
                records.append(record)
                log(f"Core->Stage chunk {status} {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
                if status == "BAD":
                    break

            expected_h = 0
            gaps: List[str] = []
            overlaps: List[str] = []
            bad_chunks: List[Dict[str, Any]] = []
            totals = {"blocks": 0, "transactions": 0, "inputs": 0, "outputs": 0, "raw_block_bytes": 0}
            for r in records:
                rh1, rh2 = int(r["h1"]), int(r["h2"])
                if rh1 > expected_h:
                    gaps.append(f"{expected_h}..{rh1-1}")
                elif rh1 < expected_h:
                    overlaps.append(f"record={r['record_no']} h1={rh1} expected={expected_h}")
                expected_h = max(expected_h, rh2 + 1)
                result = r.get("result") if isinstance(r.get("result"), dict) else {}
                counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
                for k in ("blocks", "transactions", "inputs", "outputs"):
                    totals[k] += int(counts.get(k) or 0)
                totals["raw_block_bytes"] += int(result.get("raw_block_bytes") or 0)
                if str(r.get("status")) != "OK":
                    bad_chunks.append({"chunk_no": r["chunk_no"], "h1": rh1, "h2": rh2, "status": r["status"], "failed_checks": result.get("failed_checks")})
            complete = len(records) == len(plan) and expected_h == target + 1 and not gaps and not overlaps
            any_bad = any(str(r.get("status")) == "BAD" for r in records)
            try:
                final_target = str(rpc.call("getblockhash", int(target))).lower()
            except Exception as exc:
                final_target = None
                transient = transient or {"reason": f"final Core target revalidation failed: {exc}"}
            snapshot_stable = final_target == identity["target_hash"]
            if final_target is not None and not snapshot_stable:
                any_bad = True
                bad_chunks.append({"chunk_no": None, "status": "BAD", "failed_checks": ["bitcoin_core_target_changed_during_audit"]})
            if any_bad:
                status = "BAD"
            elif not complete or transient is not None:
                status = "PARTIAL"
            else:
                status = "OK"
            return {
                "status": status,
                "proof_scope": f"BITCOIN_CORE_RAW_BLOCKS_TO_STAGE_EXACT_0_{target}",
                "canonical_chain_scope": "ALL_BLOCKS_ACTIVE_CHAIN",
                "payload_scope": "TXID_ORDER_VIN_PREVOUT_VOUT_VALUE_SCRIPT_EXACT",
                "script_payload_exact": status == "OK",
                "merkle_exact": status == "OK",
                "txid_identity": "canonical txid from stripped serialization; wtxid separately diagnosed",
                "core_identity": identity,
                "core_target_hash_final": final_target,
                "core_snapshot_stable": snapshot_stable,
                "chunks_total": len(plan), "chunks_completed": len(records),
                "coverage_complete": complete, "coverage_gaps": gaps, "coverage_overlaps": overlaps,
                "bad_chunks": bad_chunks,
                "transient_or_incomplete": transient,
                "totals": totals,
                "core_stage_exact_prefix_sha256": _core_stage_prefix_sha(records),
                "progress_contract_id": contract["contract_id"],
                "progress_root": str(root), "progress": progress,
                "parser_selftest": selftest,
                "certification_blocking": status != "OK",
            }
    finally:
        rpc.close()



def _chain_digest_update(h: Any, height: int, block_hash: str) -> None:
    """Canonical digest element for one active-chain height/hash pair."""
    bh = str(block_hash).lower()
    if HASH_RE.fullmatch(bh) is None:
        raise RuntimeError(f"invalid block hash for chain digest height={height}: {bh!r}")
    h.update(struct.pack(">Q", int(height)))
    h.update(bytes.fromhex(bh))


def core_chain_revalidation_guard(
    *,
    stage: Dict[str, Any],
    start: int,
    end: int,
    rpc_url: str,
    rpc_cookie: Optional[str],
    datadir: Optional[str],
    rpc_timeout: int,
    batch_size: int,
) -> Dict[str, Any]:
    """Independent read-only active-chain revalidation against Stage block hashes.

    This guard intentionally does not reuse Core->Stage chunk evidence.  It opens
    the immutable Stage blocks payload directly, asks Bitcoin Core getblockhash(h)
    for every height in the requested range in bounded batches, and compares every
    result.  The range-end active-chain hash is sampled both before and after the
    sweep so a chain change during the guard cannot silently authorize GREEN.
    """
    start = int(start); end = int(end)
    if start < 0 or end < start:
        return {
            "status": "BAD",
            "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
            "failed_checks": [f"invalid_range:{start}..{end}"],
            "certification_blocking": True,
        }
    cookie = _rpc_cookie(rpc_cookie, datadir)
    if cookie is None:
        return {
            "status": "NOT_EVALUATED",
            "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
            "reason": "Bitcoin Core RPC cookie unavailable",
            "certification_blocking": True,
        }
    entries = [
        e for e in selected_entries(stage, end)
        if int(e["h2"]) >= start and int(e["h1"]) <= end
    ]
    if not entries:
        return {
            "status": "BAD",
            "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
            "failed_checks": ["no_stage_block_payloads_for_guard"],
            "certification_blocking": True,
        }
    block_paths = [str(regular(Path(e["blocks"]["path"]))) for e in entries]
    before_tokens = {x: file_token(Path(x)) for x in block_paths}
    duckdb = require_duckdb()
    con = duckdb.connect(":memory:")
    expected_digest = hashlib.sha256()
    observed_digest = hashlib.sha256()
    mismatch_samples: List[Dict[str, Any]] = []
    mismatch_count = 0
    checked = 0
    expected_next = start
    expected_end_hash: Optional[str] = None
    batch_size = max(1, int(batch_size))
    try:
        con.execute(f"""
            CREATE TEMP VIEW guard_stage_block AS
            SELECT height::BIGINT AS height, lower(block_hash::VARCHAR) AS block_hash
            FROM read_parquet({sql_list(block_paths)}, union_by_name=true)
            WHERE height BETWEEN {start} AND {end}
        """)
        summary = con.execute("""
            SELECT count(*), min(height), max(height), count(DISTINCT height),
                   count(DISTINCT block_hash),
                   count(*) FILTER (WHERE block_hash IS NULL OR NOT regexp_full_match(block_hash,'[0-9a-f]{64}'))
            FROM guard_stage_block
        """).fetchone()
        n, hmin, hmax, dh, dbh, bad_hash = [int(x or 0) for x in summary]
        expected_n = end - start + 1
        failed: List[str] = []
        if (n, hmin, hmax, dh, dbh) != (expected_n, start, end, expected_n, expected_n):
            failed.append(f"stage_guard_coverage:{n},{hmin},{hmax},{dh},{dbh}:expected={start}..{end}")
        if bad_hash:
            failed.append(f"stage_guard_bad_hash_format:{bad_hash}")
        if failed:
            return {
                "status": "BAD",
                "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
                "range": {"start": start, "end": end, "heights": expected_n},
                "failed_checks": failed,
                "certification_blocking": True,
            }

        end_row = con.execute("SELECT block_hash FROM guard_stage_block WHERE height=?", [end]).fetchone()
        expected_end_hash = str(end_row[0]).lower() if end_row else None
        if expected_end_hash is None:
            return {
                "status": "BAD", "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
                "failed_checks": ["stage_guard_end_hash_missing"], "certification_blocking": True,
            }
        initial_end_map = _rpc_batch_getblockhash(rpc_url, cookie, [end], timeout=max(5, int(rpc_timeout)))
        initial_end_hash = initial_end_map[end]

        cursor = con.execute("SELECT height,block_hash FROM guard_stage_block ORDER BY height")
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break
            heights: List[int] = []
            expected_map: Dict[int, str] = {}
            for rh, rbh in rows:
                h = int(rh); bh = str(rbh).lower()
                if h != expected_next:
                    return {
                        "status": "BAD", "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
                        "failed_checks": [f"stage_guard_noncontiguous:{h}:expected={expected_next}"],
                        "heights_checked": checked, "certification_blocking": True,
                    }
                expected_next += 1
                heights.append(h); expected_map[h] = bh
            observed = _rpc_batch_getblockhash(rpc_url, cookie, heights, timeout=max(5, int(rpc_timeout)))
            for h in heights:
                e = expected_map[h]
                o = observed.get(h)
                _chain_digest_update(expected_digest, h, e)
                if o is None:
                    mismatch_count += 1
                    if len(mismatch_samples) < 100:
                        mismatch_samples.append({"height": h, "stage": e, "bitcoin_core": None})
                    continue
                _chain_digest_update(observed_digest, h, o)
                if e != o:
                    mismatch_count += 1
                    if len(mismatch_samples) < 100:
                        mismatch_samples.append({"height": h, "stage": e, "bitcoin_core": o})
            checked += len(heights)
            if checked == len(heights) or checked % 100000 < len(heights) or expected_next > end:
                log(f"Core chain guard checked={checked:,}/{expected_n:,} mismatches={mismatch_count}")

        final_end_map = _rpc_batch_getblockhash(rpc_url, cookie, [end], timeout=max(5, int(rpc_timeout)))
        final_end_hash = final_end_map[end]
        after_tokens = {x: file_token(Path(x)) for x in block_paths}
        stage_stable = all(same_token(before_tokens[k], after_tokens.get(k, {})) for k in before_tokens)
        failed: List[str] = []
        if checked != expected_n or expected_next != end + 1:
            failed.append(f"guard_coverage:{checked}!={expected_n}")
        if mismatch_count:
            failed.append(f"active_chain_stage_mismatches:{mismatch_count}")
        if initial_end_hash != expected_end_hash:
            failed.append(f"initial_end_hash:{initial_end_hash}!={expected_end_hash}")
        if final_end_hash != expected_end_hash:
            failed.append(f"final_end_hash:{final_end_hash}!={expected_end_hash}")
        if final_end_hash != initial_end_hash:
            failed.append(f"end_anchor_changed_during_guard:{initial_end_hash}->{final_end_hash}")
        if not stage_stable:
            failed.append("stage_block_payload_changed_during_guard")
        status = "OK" if not failed else "BAD"
        return {
            "status": status,
            "proof_scope": "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE",
            "range": {"start": start, "end": end, "heights": expected_n},
            "heights_checked": checked,
            "batch_size": batch_size,
            "mismatch_count": mismatch_count,
            "mismatch_samples": mismatch_samples,
            "expected_chain_digest_sha256": expected_digest.hexdigest(),
            "observed_chain_digest_sha256": observed_digest.hexdigest(),
            "stage_end_hash": expected_end_hash,
            "core_end_hash_initial": initial_end_hash,
            "core_end_hash_final": final_end_hash,
            "end_anchor_stable": final_end_hash == initial_end_hash == expected_end_hash,
            "stage_payload_stable": stage_stable,
            "state_mutation": "NONE_BY_CONTRACT",
            "failed_checks": failed,
            "certification_blocking": status != "OK",
        }
    finally:
        con.close()

def bitcoin_core_final_snapshot(
    core_stage: Dict[str, Any], target: int, rpc_url: str, rpc_cookie: Optional[str], datadir: Optional[str], rpc_timeout: int
) -> Dict[str, Any]:
    if str(core_stage.get("status")) != "OK":
        return {
            "status": "NOT_EVALUATED",
            "reason": "Core->Stage exact is not complete; final Core snapshot anchor cannot upgrade certification",
            "certification_blocking": True,
        }
    cookie = _rpc_cookie(rpc_cookie, datadir)
    if cookie is None:
        return {"status": "NOT_EVALUATED", "reason": "Bitcoin Core RPC cookie unavailable", "certification_blocking": True}
    rpc = BitcoinRPC(rpc_url, cookie, timeout=max(5, int(rpc_timeout)))
    try:
        genesis, tip = rpc.batch([("getblockhash", [0]), ("getblockhash", [int(target)])])
        genesis = str(genesis).lower()
        tip = str(tip).lower()
        expected = str((core_stage.get("core_identity") or {}).get("target_hash") or "")
        failed: List[str] = []
        if genesis != GENESIS_HASH:
            failed.append(f"genesis:{genesis}!={GENESIS_HASH}")
        if tip != expected:
            failed.append(f"target_changed:{tip}!={expected}")
        return {
            "status": "BAD" if failed else "OK",
            "proof_scope": "FINAL_CORE_SNAPSHOT_REVALIDATION",
            "target_height": target, "target_hash": tip,
            "failed_checks": failed,
        }
    finally:
        rpc.close()


def _rpc_cookie(explicit: Optional[str], datadir: Optional[str]) -> Optional[Path]:
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if datadir:
        candidates.append(Path(datadir) / ".cookie")
    candidates.extend([Path("/root/.bitcoin/.cookie"), Path("/opt/mybot_data/bitcoin/.cookie")])
    for p in candidates:
        if p.is_file() and not p.is_symlink():
            return p.resolve(strict=True)
    return None


def _rpc_batch_getblockhash(url: str, cookie: Path, heights: Sequence[int], timeout: int = 120) -> Dict[int, str]:
    cred = cookie.read_text(encoding="utf-8").strip()
    token = base64.b64encode(cred.encode()).decode()
    payload = [{"jsonrpc": "2.0", "id": int(h), "method": "getblockhash", "params": [int(h)]} for h in heights]
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Basic " + token},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        obj = json.loads(r.read().decode())
    if not isinstance(obj, list):
        raise RuntimeError("Bitcoin Core batch RPC did not return list")
    out: Dict[int, str] = {}
    for item in obj:
        if item.get("error") is not None:
            raise RuntimeError(f"Bitcoin Core RPC error id={item.get('id')}: {item.get('error')}")
        h = int(item["id"])
        value = str(item.get("result") or "").lower()
        if HASH_RE.fullmatch(value) is None:
            raise RuntimeError(f"invalid Core hash h={h}:{value!r}")
        out[h] = value
    return out


def bitcoin_core_audit_r2(con, target: int, explicit_cli: Optional[str], datadir: Optional[str], sample_step: int, proof_mode: str, rpc_url: str, rpc_cookie: Optional[str], batch_size: int) -> Dict[str, Any]:
    if proof_mode == "all":
        cookie = _rpc_cookie(rpc_cookie, datadir)
        if cookie is not None:
            mismatches: List[Dict[str, Any]] = []
            checked = 0
            for h1 in range(0, target + 1, max(1, batch_size)):
                h2 = min(target, h1 + max(1, batch_size) - 1)
                rows = con.execute("SELECT height,block_hash FROM stage_block WHERE height BETWEEN ? AND ? ORDER BY height", [h1, h2]).fetchall()
                heights = [int(r[0]) for r in rows]
                expected = {int(h): str(bh) for h, bh in rows}
                observed = _rpc_batch_getblockhash(rpc_url, cookie, heights)
                for h in heights:
                    if expected[h] != observed.get(h):
                        mismatches.append({"height": h, "stage": expected[h], "bitcoin_core": observed.get(h)})
                checked += len(heights)
                if checked <= len(heights) or checked % 100000 < len(heights) or h2 == target:
                    log(f"Bitcoin Core ALL_BLOCKS checked={checked:,}/{target+1:,}")
            return {
                "status": "OK" if not mismatches else "BAD",
                "proof_scope": "ALL_BLOCKS",
                "heights_checked": checked,
                "rpc_url": rpc_url,
                "cookie_path": str(cookie),
                "mismatch_count": len(mismatches),
                "mismatches": mismatches[:100],
            }
        fallback = bitcoin_core_audit(con, target, explicit_cli, datadir, sample_step)
        return {
            "status": "NOT_EVALUATED",
            "proof_scope": "SAMPLED_FALLBACK",
            "reason": "ALL_BLOCKS requested but RPC cookie unavailable; sampled bitcoin-cli result is evidence only",
            "fallback": fallback,
            "certification_blocking": True,
        }
    if proof_mode == "tip":
        out = bitcoin_core_audit(con, target, explicit_cli, datadir, 0)
        out["proof_scope"] = "TIP_PLUS_BIP30"
        return out
    out = bitcoin_core_audit(con, target, explicit_cli, datadir, sample_step)
    out["proof_scope"] = "SAMPLED"
    return out

def safety_gate(state: Path, audit_freeze: Optional[AuditFreezeLease] = None) -> Dict[str, Any]:
    dirty = state / "dirty.bin"
    errors = []
    if dirty.exists() or dirty.is_symlink(): errors.append(f"dirty.bin present/unsafe:{dirty}")
    if audit_freeze is not None:
        locks = audit_freeze.summary()
        driver_lock = {"status": "OK", **locks.get("R11 driver", {})}
        supervisor_lock = {"status": "OK", **locks.get("R12 supervisor", {})}
        state_lock = {"status": "OK", **locks.get("V50 state", {})}
    else:
        driver_lock = _try_driver_lock(state)
        supervisor_lock = _try_supervisor_lock(state)
        state_lock = {"status": "NOT_HELD"}
        if driver_lock.get("status") == "BAD": errors.append(f"driver lock busy/invalid:{driver_lock}")
        if supervisor_lock.get("status") == "BAD": errors.append(f"supervisor lock busy/invalid:{supervisor_lock}")
    old = active_old_engines()
    if old:
        errors.append(f"legacy_mutator_processes_active:{old[:20]}")
    return {"status": "BAD" if errors else "OK", "errors": errors, "driver_lock": driver_lock, "supervisor_lock": supervisor_lock, "state_lock": state_lock, "old_engines": old}


def certification(report: Dict[str, Any], require_reference: bool) -> Dict[str, Any]:
    p = report.get("phases", {})
    mandatory_struct = (
        "safety", "resource_preflight", "state_contract", "supervisor_contract", "stage_release", "quick_invariants", "state_scan",
        "stage_semantics", "stage_stable_snapshot", "stable_snapshot",
    )
    structural = all(str(p.get(x, {}).get("status")) == "OK" for x in mandatory_struct)
    stage_exact = (
        structural
        and str(p.get("stage_sha", {}).get("status")) == "OK"
        and str(p.get("stage_rebuild", {}).get("status")) == "OK"
        and p.get("stage_rebuild", {}).get("full_stream_hashes") is True
    )
    v40_ok = str(p.get("reference_v40", {}).get("status")) == "OK"
    core_stage = p.get("core_stage_exact", {})
    core_stage_ok = (
        str(core_stage.get("status")) == "OK"
        and core_stage.get("coverage_complete") is True
        and core_stage.get("script_payload_exact") is True
        and core_stage.get("merkle_exact") is True
        and core_stage.get("core_snapshot_stable") is True
    )
    fg_ok = str(p.get("false_green_guard", {}).get("status")) == "OK"
    chain_guard = p.get("core_chain_guard", {})
    chain_guard_ok = (
        str(chain_guard.get("status")) == "OK"
        and str(chain_guard.get("proof_scope")) == "ALL_HEIGHTS_ACTIVE_CHAIN_VS_STAGE"
        and int(chain_guard.get("heights_checked") or 0) == int((chain_guard.get("range") or {}).get("heights") or -1)
        and int(chain_guard.get("mismatch_count") or 0) == 0
        and chain_guard.get("end_anchor_stable") is True
        and chain_guard.get("stage_payload_stable") is True
    )
    core_final_ok = str(p.get("bitcoin_core", {}).get("status")) == "OK"
    recovery_ok = str(p.get("recovery_provenance", {}).get("status")) == "OK"
    run_ok = str(p.get("run_provenance", {}).get("status")) == "OK"
    source_ok = str(p.get("source_catalog", {}).get("status")) == "OK"

    if not structural:
        level = "FAILED"
    elif not stage_exact:
        level = "V50_STRUCTURAL_GREEN"
    elif require_reference and not v40_ok:
        level = "V50_STAGE_INDEPENDENT_EXACT"
    elif not core_stage_ok or not fg_ok or not chain_guard_ok or not core_final_ok:
        level = "V50_V40_STAGE_EXACT" if (require_reference and v40_ok) else "V50_STAGE_INDEPENDENT_EXACT"
    elif not recovery_ok or not run_ok:
        level = "V50_CANONICAL_DATA_CERTIFIED_PROVENANCE_PARTIAL"
    else:
        rp = p.get("run_provenance", {})
        level = "V50_CANONICAL_CERTIFIED_R12_PROVENANCE" if rp.get("baseline_adoption") is True else "V50_CANONICAL_CERTIFIED_FULL_EXECUTION_PROVENANCE"

    blocking: List[str] = []
    for name in (
        "safety", "resource_preflight", "state_contract", "supervisor_contract", "stage_release", "quick_invariants", "state_scan", "stage_sha",
        "stage_semantics", "core_stage_exact", "stage_rebuild", "false_green_guard", "core_chain_guard", "bitcoin_core",
        "stage_stable_snapshot", "stable_snapshot", "recovery_provenance", "run_provenance",
    ):
        status = str(p.get(name, {}).get("status") or "NOT_EVALUATED")
        if status != "OK":
            blocking.append(f"{name}:{status}")
    if str(p.get("stage_rebuild", {}).get("status")) == "OK" and p.get("stage_rebuild", {}).get("full_stream_hashes") is not True:
        blocking.append("stage_rebuild:FULL_STREAM_HASHES_DISABLED")
    if str(core_stage.get("status")) == "OK":
        if core_stage.get("coverage_complete") is not True:
            blocking.append("core_stage_exact:COVERAGE_INCOMPLETE")
        if core_stage.get("script_payload_exact") is not True:
            blocking.append("core_stage_exact:SCRIPT_PAYLOAD_NOT_EXACT")
        if core_stage.get("merkle_exact") is not True:
            blocking.append("core_stage_exact:MERKLE_NOT_EXACT")
        if core_stage.get("core_snapshot_stable") is not True:
            blocking.append("core_stage_exact:SNAPSHOT_NOT_STABLE")
    if str(chain_guard.get("status")) == "OK" and not chain_guard_ok:
        blocking.append("core_chain_guard:INVARIANT_INCOMPLETE")
    if require_reference and not v40_ok:
        blocking.append(f"reference_v40:{p.get('reference_v40', {}).get('status')}")
    optional_non_green: List[str] = []
    for name in ("legacy_aws", "source_catalog"):
        status = str(p.get(name, {}).get("status") or "NOT_EVALUATED")
        if status not in {"OK", "DISABLED_OPTIONAL", "NOT_EVALUATED"}:
            optional_non_green.append(f"{name}:{status}")
    return {
        "level": level,
        "blocking": sorted(set(blocking)),
        "optional_non_green": sorted(set(optional_non_green)),
        "structural_green": structural,
        "stage_independent_exact": stage_exact,
        "stage_full_historical_hashes": p.get("stage_rebuild", {}).get("full_stream_hashes") is True,
        "v40_exact": v40_ok,
        "core_stage_exact": core_stage_ok,
        "core_stage_script_payload_exact": core_stage.get("script_payload_exact") is True,
        "core_stage_merkle_exact": core_stage.get("merkle_exact") is True,
        "false_green_guard": fg_ok,
        "core_chain_revalidation_guard": chain_guard_ok,
        "core_chain_heights_checked": int(chain_guard.get("heights_checked") or 0),
        "core_chain_mismatch_count": int(chain_guard.get("mismatch_count") or 0),
        "bitcoin_core_final_snapshot": core_final_ok,
        "source_catalog_optional_provenance": source_ok,
        "legacy_aws_certification_impact": "NONE",
        "recovery_history_proven": recovery_ok,
        "run_provenance_proven": run_ok,
        "historical_execution_provenance_complete": bool(p.get("run_provenance", {}).get("historical_execution_provenance_complete")) if run_ok else False,
        "baseline_data_correctness_independently_certified": bool(p.get("run_provenance", {}).get("baseline_data_correctness_independently_certified")) if run_ok else False,
        "r12_supervisor_exact": str(p.get("supervisor_contract", {}).get("status")) == "OK",
    }


def markdown_report(report: Dict[str, Any]) -> str:
    lines = [f"# V51 Audit {report.get('target_height')}", "", f"- Version: `{report.get('version')}`", f"- Started: `{report.get('started_utc')}`", f"- Finished: `{report.get('finished_utc')}`", f"- Certification: **{report.get('certification',{}).get('level')}**", "", "## Phases", ""]
    for name in PHASE_ORDER:
        item = report.get("phases", {}).get(name)
        if item is None: continue
        lines.append(f"- `{name}`: **{item.get('status')}** ({item.get('elapsed_sec','?')} s)")
        if item.get("failed_checks"): lines.append(f"  - failed: `{item.get('failed_checks')}`")
        if item.get("error"): lines.append(f"  - error: `{item.get('error')}`")
    lines += ["", "## Core results", ""]
    ss = report.get("phases", {}).get("state_scan", {})
    sr = report.get("phases", {}).get("stage_rebuild", {})
    rv = report.get("phases", {}).get("reference_v40", {})
    lines += [
        f"- V50 live: `{ss.get('live_count')}` outputs / `{ss.get('live_value_sats')}` sats",
        f"- V50 fingerprint: `{ss.get('live_fingerprint_sha256')}`",
        f"- Stage expected fingerprint: `{sr.get('expected_live_fingerprint_sha256')}`",
        f"- V40 reference fingerprint: `{(rv.get('reference') or {}).get('fingerprint_sha256')}`",
        "",
        "## False-green policy",
        "",
        "`NOT_EVALUATED`, incomplete coverage, dirty state, unstable snapshot, or a missing mandatory canonical anchor cannot produce the maximum certification level.",
        "",
    ]
    return "\n".join(lines)



def classify_audit_failure(exc: BaseException, report: Dict[str, Any], args, tmp: Path) -> Dict[str, Any]:
    text = str(exc)
    low = text.lower()
    failed_phase = None
    for name in PHASE_ORDER:
        ph = (report.get("phases") or {}).get(name) or {}
        if ph.get("status") == "BAD":
            failed_phase = name
    classification = "AUDIT_FAILURE"
    reason = "UNCLASSIFIED"
    operator_message = text
    recommended_action = "Inspect the failed phase and immutable FATAL evidence before retrying."
    failed_item = ((report.get("phases") or {}).get(failed_phase) or {}) if failed_phase else {}
    failed_checks = failed_item.get("failed_checks") or []
    if "max_temp_directory_size" in low or "failed to offload data block" in low:
        classification = "RESOURCE_FAILURE"; reason = "TEMP_QUOTA_EXHAUSTED"
        operator_message = "DuckDB exhausted the configured audit spill/temp quota; authoritative state corruption is not indicated."
        recommended_action = "Use bounded/windowed execution or increase the audit-owned temp allowance after a free-space preflight."
    elif "out of memory" in low or "failed to pin block" in low or "cannot allocate memory" in low:
        classification = "RESOURCE_FAILURE"; reason = "MEMORY_LIMIT_EXHAUSTED"
        operator_message = "DuckDB exhausted the configured audit memory limit; authoritative state corruption is not indicated."
        recommended_action = "Use the bounded Stage-semantics engine and/or reduce per-connection threads; do not mutate the UTXO state."
    elif failed_checks or "mismatch" in low or "unresolved_prevout" in low or "coverage_orphan_prevouts" in low or "false_green" in low:
        classification = "DATA_OR_PROOF_FAILURE"; reason = "SEMANTIC_MISMATCH"
        operator_message = "A semantic/proof invariant failed; treat this as certification-blocking until investigated."
        recommended_action = "Do not APPLY further state. Inspect the failed check and exact evidence."
    try:
        usage = shutil.disk_usage(tmp)
        disk = {"path": str(tmp), "total_bytes": int(usage.total), "used_bytes": int(usage.used), "free_bytes": int(usage.free)}
    except Exception:
        disk = {"path": str(tmp), "unavailable": True}
    return {
        "classification": classification,
        "reason_code": reason,
        "error_type": type(exc).__name__,
        "error": text,
        "failed_phase": failed_phase,
        "state_mutated": False,
        "state_corruption_indicated": classification == "DATA_OR_PROOF_FAILURE",
        "operator_message": operator_message,
        "recommended_action": recommended_action,
        "resource": {
            "memory_limit": str(getattr(args, "memory_limit", "")),
            "threads": int(getattr(args, "threads", 0) or 0),
            "stage_semantics_memory_limit": str(getattr(args, "stage_semantics_memory_limit", "")),
            "stage_semantics_threads": int(getattr(args, "stage_semantics_threads", 0) or 0),
            "temp_max": str(getattr(args, "temp_max", "")),
            "min_free_tmp": str(getattr(args, "min_free_tmp", "")),
            "process_rss_bytes": _process_rss_bytes(),
            "filesystem": disk,
        },
    }

def full_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Independent superset audit for MyBot V51 / V50 dense-state lineage")
    p.add_argument("--state", default=str(DEFAULT_STATE))
    p.add_argument("--stage-base", default=str(DEFAULT_STAGE_BASE))
    p.add_argument("--stage-release")
    p.add_argument("--driver", default=str(DEFAULT_DRIVER), help="exact certified R11 causal driver bound in state.meta")
    p.add_argument("--supervisor", default=str(DEFAULT_SUPERVISOR), help="exact R12 supervisor whose V2 provenance is being certified")
    p.add_argument("--core", default=str(DEFAULT_CORE))
    p.add_argument("--reference-db", default=str(DEFAULT_REFERENCE_DB))
    p.add_argument("--no-reference", action="store_true", help="do not use V40 as a regression oracle")
    p.add_argument("--expected-height", type=int)
    p.add_argument("--tmp", default=str(DEFAULT_TMP))
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    p.add_argument("--memory-limit", default="24GB")
    p.add_argument("--temp-max", default="700GB")
    p.add_argument("--min-free-tmp", default="200GiB",
                   help="minimum free-space reserve kept in addition to --temp-max")
    p.add_argument("--threads", type=int, default=8, help="legacy/global DuckDB threads; not used by bounded Stage semantics")
    p.add_argument("--stage-semantics-engine", choices=("windowed", "global"), default="windowed",
                   help="production default is bounded per-Stage-window semantics; global is regression-only")
    p.add_argument("--stage-semantics-memory-limit", default="12GiB",
                   help="DuckDB memory limit for one isolated Stage semantic window")
    p.add_argument("--stage-semantics-threads", type=int, default=2,
                   help="DuckDB threads for one isolated Stage semantic window")
    p.add_argument("--stage-semantics-progress-dir",
                   help="durable bounded Stage-semantics progress root; default: <output-dir>/stage_semantics_progress")
    p.add_argument("--stage-semantics-no-resume", action="store_true",
                   help="reject matching bounded Stage-semantics progress instead of resuming")
    p.add_argument("--stage-sha", choices=("full", "manifest"), default="full")
    p.add_argument("--no-full-stream-hashes", action="store_true", help="diagnostic weakening: skip exact historical tx/output/close stream hashes")
    p.add_argument("--raw-base", default=str(DEFAULT_RAW_BASE))
    p.add_argument("--raw-mode", choices=("off", "exact"), default="off",
                   help="LEGACY diagnostic only; AWS RAW is OFF by default and has no certification impact")
    p.add_argument("--legacy-aws-audit", action="store_true",
                   help="explicitly run legacy AWS RAW->Stage diagnostics; never required for production certification")
    p.add_argument("--raw-output-unit", choices=("btc", "sats"), default="btc")
    p.add_argument("--raw-chunk-radius-days", type=int, default=3,
                   help="calendar safety radius around each Stage chunk min/max block_time")
    p.add_argument("--raw-chunk-memory-limit", default="24GiB",
                   help="DuckDB memory limit for each isolated RAW chunk connection")
    p.add_argument("--raw-chunk-threads", type=int, default=4,
                   help="DuckDB threads for each isolated RAW chunk connection")
    p.add_argument("--raw-progress-dir",
                   help="durable RAW exact progress root; default: <output-dir>/raw_progress")
    p.add_argument("--raw-no-resume", action="store_true",
                   help="reject existing matching RAW progress instead of resuming it")
    p.add_argument("--source-catalog", default=str(DEFAULT_SOURCE_CATALOG))
    p.add_argument("--run-contract", help="optional explicit R12 run contract; if supplied it must be one of the contracts referenced by the apply ledger")
    p.add_argument("--control", default=str(DEFAULT_CONTROL))
    p.add_argument("--recovery-ledger", default=str(DEFAULT_RECOVERY_LEDGER))
    p.add_argument("--apply-ledger", default=str(DEFAULT_APPLY_LEDGER))
    p.add_argument("--source-lineage", default=str(DEFAULT_SOURCE_LINEAGE))
    p.add_argument("--runs-dir", default=str(DEFAULT_RUNS_DIR))
    p.add_argument("--core-stage-mode", choices=("exact", "off"), default="exact",
                   help="production canonical source proof: Bitcoin Core raw blocks -> Stage exact")
    p.add_argument("--core-stage-progress-dir",
                   help="durable Core->Stage exact progress root; default: <output-dir>/core_stage_progress")
    p.add_argument("--core-stage-no-resume", action="store_true",
                   help="reject existing matching Core->Stage progress instead of resuming")
    p.add_argument("--core-stage-block-batch", type=int, default=8,
                   help="raw getblock(verbosity=0) RPC calls per batch; keep bounded because JSON contains hex payload")
    p.add_argument("--core-stage-memory-limit", default="12GiB",
                   help="DuckDB memory limit for one isolated Stage-window digest connection")
    p.add_argument("--core-stage-threads", type=int, default=4,
                   help="DuckDB threads for one isolated Core->Stage Stage-window digest")
    p.add_argument("--core-stage-evidence-ledger",
                   help="reuse a completed trusted Core->Stage chunks.jsonl instead of rerunning raw-block proof")
    p.add_argument("--core-stage-evidence-ledger-sha256",
                   help="required exact SHA256 binding for --core-stage-evidence-ledger")
    p.add_argument("--stage-rebuild-engine", choices=("bucketed", "global"), default="bucketed",
                   help="Stage->UTXO engine; bucketed is production default, global is regression oracle for small anchors")
    p.add_argument("--stage-rebuild-work-dir", default="/opt/mybot_tmp/utxo_v50_stage_rebuild",
                   help="persistent bounded-rebuild work/progress root; survives audit failure for resume")
    p.add_argument("--stage-rebuild-memory-limit", default="24GiB",
                   help="DuckDB memory limit for each isolated partition/bucket/close-part connection")
    p.add_argument("--stage-rebuild-partition-threads", type=int, default=1,
                   help="DuckDB threads while materializing Stage windows into txid buckets; 1 minimizes parquet file fan-out")
    p.add_argument("--stage-rebuild-threads", type=int, default=4,
                   help="DuckDB threads for each isolated causal bucket/close-part connection")
    p.add_argument("--stage-rebuild-close-tx-span", type=int, default=1000000,
                   help="closer_tx_seq range per final ordered close partition")
    p.add_argument("--stage-rebuild-no-resume", action="store_true",
                   help="reject existing matching bounded Stage-rebuild progress instead of resuming")
    p.add_argument("--resume-fatal-report", help="V51.5.5 compatibility: reuse expensive completed proof phases from a pinned V51.5.2 FATAL report that failed only at reference_v40; core_chain_guard always reruns fresh")
    p.add_argument("--resume-fatal-report-sha256", help="required exact SHA256 of --resume-fatal-report; fail-closed proof import pin")
    p.add_argument("--bitcoin-cli")
    p.add_argument("--bitcoin-datadir")
    p.add_argument("--core-sample-step", type=int, default=50000)
    p.add_argument("--core-proof", choices=("all", "sampled", "tip"), default="tip", help="legacy hash-only diagnostic mode; Core->Stage exact supersedes it")
    p.add_argument("--bitcoin-rpc-url", default="http://127.0.0.1:8332")
    p.add_argument("--core-rpc-timeout", type=int, default=300, help="timeout seconds for local Bitcoin Core RPC batches")
    p.add_argument("--bitcoin-rpc-cookie")
    p.add_argument("--core-rpc-batch", type=int, default=2000)
    return p

def full_main(argv: Optional[Sequence[str]] = None) -> int:
    args = full_parser().parse_args(argv)
    state = Path(args.state)
    tmp = Path(args.tmp)
    output_dir = Path(args.output_dir)
    report: Dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "version": VERSION,
        "started_utc": utc_now(),
        "status": "FAILED",
        "phases": {},
        "arguments": vars(args),
        "lineage": {
            "n30": "R67 false-green/coverage/recovery/provenance lineage; AWS RAW retained only as optional legacy diagnostic",
            "n41": "Core-v2 Stage/source/lifecycle/run-contract lineage; upgraded to raw Bitcoin Core block exact proof",
            "policy": "superset; NOT_EVALUATED can never authorize maximum certification",
        },
    }
    report["auditor_sha256"] = sha256_file(Path(__file__).resolve())
    con = None
    run_tmp = tmp / f"run_{utc_stamp()}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    run_tmp.mkdir(parents=True, exist_ok=False)
    stage_tokens_before: Optional[Dict[str, Dict[str, Any]]] = None
    try:
        with AuditFreezeLease(state) as audit_freeze:
            state_before = state_snapshot_tokens(state)
            saf = phase(report, "safety", lambda: safety_gate(state, audit_freeze))
            if saf["status"] != "OK":
                raise RuntimeError(f"safety gate failed: {saf}")

            resources = phase(
                report,
                "resource_preflight",
                lambda: resource_preflight(tmp, args.temp_max, args.min_free_tmp),
            )
            if resources["status"] != "OK":
                raise RuntimeError(f"resource preflight failed: {resources.get('failed_checks')}")

            sc = phase(report, "state_contract", lambda: parse_state_contract(state, Path(args.driver), Path(args.core)))
            target = int(sc["height"])
            if args.expected_height is not None and target != int(args.expected_height):
                raise RuntimeError(f"checkpoint height={target} != expected-height={args.expected_height}")
            if target < 0:
                raise RuntimeError("V50 state is empty")
            report["target_height"] = target

            sup = phase(report, "supervisor_contract", lambda: inspect_v50_supervisor(Path(args.supervisor)))
            if sup["status"] != "OK":
                raise RuntimeError(f"R12 supervisor contract failed: {sup}")

            stage = phase(report, "stage_release", lambda: load_stage(args))
            if int(stage["end_height"]) < target:
                raise RuntimeError(f"Stage HWM={stage['end_height']} below V50 target={target}")
            if stage["sha256"].lower() != sc["source_sha256"].lower():
                raise RuntimeError(f"V50/Stage source SHA mismatch state={sc['source_sha256']} stage={stage['sha256']}")
            report["stage"] = {
                k: stage[k]
                for k in ("kind", "sha256", "path", "start_height", "end_height", "end_hash", "windows_sha256", "windows_path")
                if k in stage
            }
            stage_tokens_before = stage_snapshot_tokens(stage, target)

            qi = phase(
                report,
                "quick_invariants",
                lambda: quick_invariants(
                    state, sc, stage, Path(args.apply_ledger), args.bitcoin_cli, args.bitcoin_datadir,
                    args.bitcoin_rpc_url, args.bitcoin_rpc_cookie, max(5, int(args.core_rpc_timeout)),
                ),
            )
            if qi["status"] != "OK":
                raise RuntimeError(f"quick invariants failed before full state scan: {qi.get('failed_checks')}")

            ss = phase(report, "state_scan", lambda: run_state_scanner(state, run_tmp / "runtime"))
            for key in (
                "height", "block_hash", "source_sha256", "core_sha256", "driver_sha256",
                "tx_count", "out_count", "close_count", "script_bytes", "live_count", "live_value_sats",
            ):
                if str(ss.get(key)) != str(sc.get(key)):
                    raise RuntimeError(f"independent scanner/state contract mismatch {key}: {ss.get(key)} != {sc.get(key)}")

            phase(report, "stage_sha", lambda: audit_stage_sha(stage, target, args.stage_sha))

            rec = phase(
                report,
                "recovery_provenance",
                lambda: recovery_provenance_audit(
                    state, Path(args.control), Path(args.recovery_ledger), Path(args.source_lineage),
                    Path(args.runs_dir), sc, stage, target,
                ),
            )
            if rec["status"] == "BAD":
                raise RuntimeError(f"recovery provenance failed: {rec}")

            runp = phase(
                report,
                "run_provenance",
                lambda: run_provenance_audit(
                    Path(args.run_contract) if args.run_contract else None,
                    Path(args.apply_ledger), Path(args.recovery_ledger), Path(args.source_lineage),
                    Path(args.runs_dir), state, sc, stage, target,
                ),
            )
            if runp["status"] == "BAD":
                raise RuntimeError(f"run provenance failed: {runp}")

            imported_prefix = None
            if args.resume_fatal_report or args.resume_fatal_report_sha256:
                if not args.resume_fatal_report or not args.resume_fatal_report_sha256:
                    raise RuntimeError("--resume-fatal-report and --resume-fatal-report-sha256 must be supplied together")
                imported_prefix = import_v5152_reference_failure_prefix(
                    report_path=Path(args.resume_fatal_report), expected_report_sha256=args.resume_fatal_report_sha256,
                    target=target, state_contract=sc, state_scan=ss, stage=stage,
                )
                sem = imported_prefix["stage_semantics"]
                core_stage = imported_prefix["core_stage_exact"]
                rebuild = imported_prefix["stage_rebuild"]
                for _name, _obj in imported_prefix.items():
                    report["phases"][_name] = _obj
                report["proof_reuse"] = {
                    "status": "OK", "source": str(Path(args.resume_fatal_report)),
                    "sha256": str(args.resume_fatal_report_sha256).lower(),
                    "predecessor_auditor_sha256": V51_5_2_AUDITOR_SHA256,
                    "reason": "trusted V51.5.2 run failed only at corrected reference_v40 phase",
                    "reused_phases": sorted(imported_prefix),
                }
                report["memory_lifecycle"] = {
                    "stage_semantics_engine": "IMPORTED_TRUSTED_V51.5.2_PROOF",
                    "core_stage_engine": "IMPORTED_TRUSTED_V51.5.2_PROOF",
                    "stage_rebuild_engine": "IMPORTED_TRUSTED_V51.5.2_PROOF",
                }
                log(f"trusted proof reuse OK report={args.resume_fatal_report} sha256={str(args.resume_fatal_report_sha256).lower()} phases={','.join(sorted(imported_prefix))}")

                # Re-run cheap/independent checks instead of importing their old
                # verdicts.  This preserves current-environment evidence while
                # avoiding only the three expensive proof phases.
                report["phases"]["legacy_aws"] = {
                    "status": "DISABLED_OPTIONAL",
                    "reason": "trusted proof-reuse path; optional legacy AWS RAW diagnostics not requested",
                    "certification_impact": "NONE",
                    "elapsed_sec": 0.0,
                }
                source_audit = phase(
                    report,
                    "source_catalog",
                    lambda: source_catalog_audit(Path(args.source_catalog), target, sc["block_hash"]),
                )
                if source_audit["status"] == "BAD":
                    raise RuntimeError(f"Source Catalog audit failed: {source_audit.get('failed_checks')}")
                fg = phase(report, "false_green_guard", lambda: false_green_guard_r213(target, sem, rebuild, core_stage))
                if fg["status"] == "BAD":
                    raise RuntimeError(f"false-green guard failed: {fg.get('failed_checks')}")
            else:
                duckdb = require_duckdb()
                audit_db = run_tmp / "audit_work.duckdb"
                if args.stage_semantics_engine == "global":
                    con = duckdb.connect(str(audit_db))
                    report["duckdb_settings_stage_semantics"] = configure_duckdb(
                        con, args.memory_limit, run_tmp / "duckdb_tmp", args.temp_max, args.threads
                    )
                    report["stage_bind"] = bind_stage_views(con, stage, target)
                    sem = phase(report, "stage_semantics", lambda: stage_semantics_global(con, target, sc))
                    con.close(); con = None
                else:
                    semantics_progress = Path(args.stage_semantics_progress_dir) if args.stage_semantics_progress_dir else output_dir / "stage_semantics_progress"
                    sem = phase(
                        report, "stage_semantics",
                        lambda: stage_semantics_windowed(
                            duckdb_module=duckdb, stage=stage, target=target, state_contract=sc,
                            auditor_sha256=report["auditor_sha256"], progress_base=semantics_progress,
                            allow_resume=not args.stage_semantics_no_resume,
                            memory=args.stage_semantics_memory_limit, temp_max=args.temp_max,
                            threads=max(1, int(args.stage_semantics_threads)), scratch_root=run_tmp / "stage_semantics_windows",
                            min_free_tmp=args.min_free_tmp, stage_token_digest=_token_digest(stage_tokens_before or {}),
                        ),
                    )
                if sem["status"] != "OK":
                    raise RuntimeError(f"Stage semantic audit failed: {sem['failed_checks']}")

                report["memory_lifecycle"] = {
                    "stage_semantics_engine": str(args.stage_semantics_engine),
                    "stage_semantics_window_connections_isolated": args.stage_semantics_engine == "windowed",
                    "main_connection_closed_after_stage_semantics": con is None,
                    "core_stage_chunk_connections_isolated": args.core_stage_mode == "exact",
                    "legacy_aws_chunk_connections_isolated": bool(args.legacy_aws_audit or args.raw_mode == "exact"),
                }

                if args.core_stage_evidence_ledger or args.core_stage_evidence_ledger_sha256:
                    if not args.core_stage_evidence_ledger or not args.core_stage_evidence_ledger_sha256:
                        raise RuntimeError("--core-stage-evidence-ledger and --core-stage-evidence-ledger-sha256 must be supplied together")
                    core_stage = phase(
                        report,
                        "core_stage_exact",
                        lambda: _core_stage_import_evidence(
                            ledger_path=Path(args.core_stage_evidence_ledger), stage=stage, state=state,
                            state_contract=sc, target=target, expected_ledger_sha256=args.core_stage_evidence_ledger_sha256,
                        ),
                    )
                elif args.core_stage_mode == "off":
                    core_stage = {
                        "status": "NOT_EVALUATED",
                        "reason": "--core-stage-mode off",
                        "certification_blocking": True,
                        "elapsed_sec": 0.0,
                    }
                    report["phases"]["core_stage_exact"] = core_stage
                else:
                    core_progress = Path(args.core_stage_progress_dir) if args.core_stage_progress_dir else output_dir / "core_stage_progress"
                    core_stage = phase(
                        report,
                        "core_stage_exact",
                        lambda: core_stage_exact_audit(
                            stage=stage, state=state, state_contract=sc, target=target,
                            auditor_sha256=report["auditor_sha256"], progress_base=core_progress,
                            allow_resume=not args.core_stage_no_resume, rpc_url=args.bitcoin_rpc_url,
                            rpc_cookie=args.bitcoin_rpc_cookie, datadir=args.bitcoin_datadir,
                            block_batch=max(1, int(args.core_stage_block_batch)),
                            stage_memory_limit=args.core_stage_memory_limit, temp_max=args.temp_max,
                            stage_threads=max(1, int(args.core_stage_threads)),
                            rpc_timeout=max(5, int(args.core_rpc_timeout)), run_tmp=run_tmp,
                        ),
                    )
                    if core_stage["status"] == "BAD":
                        raise RuntimeError(f"Bitcoin Core->Stage exact failed: {core_stage.get('bad_chunks') or core_stage.get('failed_checks')}")

                legacy_enabled = bool(args.legacy_aws_audit or args.raw_mode == "exact")
                if not legacy_enabled:
                    legacy_raw = {
                        "status": "DISABLED_OPTIONAL",
                        "reason": "legacy AWS RAW diagnostics disabled by default",
                        "certification_impact": "NONE",
                        "elapsed_sec": 0.0,
                    }
                    report["phases"]["legacy_aws"] = legacy_raw
                else:
                    progress_base = Path(args.raw_progress_dir) if args.raw_progress_dir else output_dir / "raw_progress"
                    legacy_raw = phase(
                        report,
                        "legacy_aws",
                        lambda: raw_source_audit_chunked(
                            stage=stage,
                            state=state,
                            state_contract=sc,
                            target=target,
                            raw_base=Path(args.raw_base),
                            output_unit=args.raw_output_unit,
                            auditor_sha256=report["auditor_sha256"],
                            progress_base=progress_base,
                            radius_days=max(0, int(args.raw_chunk_radius_days)),
                            allow_resume=not args.raw_no_resume,
                            chunk_memory_limit=args.raw_chunk_memory_limit,
                            temp_max=args.temp_max,
                            chunk_threads=max(1, int(args.raw_chunk_threads)),
                            run_tmp=run_tmp,
                        ),
                    )
                    legacy_raw["certification_impact"] = "NONE"

                source_audit = phase(
                    report,
                    "source_catalog",
                    lambda: source_catalog_audit(Path(args.source_catalog), target, sc["block_hash"]),
                )
                if source_audit["status"] == "BAD":
                    raise RuntimeError(f"Source Catalog audit failed: {source_audit.get('failed_checks')}")

                if args.stage_rebuild_engine == "global":
                    # Regression oracle only: retains the proven R2.1.3 algorithm for small anchors.
                    con = duckdb.connect(str(audit_db))
                    report["duckdb_settings_stage_rebuild"] = configure_duckdb(
                        con, args.memory_limit, run_tmp / "duckdb_tmp", args.temp_max, args.threads
                    )
                    report["stage_rebind_after_source_proofs"] = bind_stage_views(con, stage, target)
                    report["memory_lifecycle"]["main_connection_reopened_before_stage_rebuild"] = True
                    rebuild = phase(
                        report, "stage_rebuild",
                        lambda: stage_independent_rebuild_global(con, target, ss, not args.no_full_stream_hashes),
                    )
                    con.close(); con = None
                else:
                    report["memory_lifecycle"]["stage_rebuild_isolated_connections"] = True
                    report["memory_lifecycle"]["stage_rebuild_engine"] = "txid-prefix-bucketed-causal-v1"
                    rebuild_work = Path(args.stage_rebuild_work_dir)
                    rebuild = phase(
                        report, "stage_rebuild",
                        lambda: stage_independent_rebuild_bucketed(
                            stage=stage, state=state, state_contract=sc, target=target, state_scan=ss,
                            full_stream_hashes=not args.no_full_stream_hashes,
                            auditor_sha256=report["auditor_sha256"], work_base=rebuild_work,
                            allow_resume=not args.stage_rebuild_no_resume,
                            memory=args.stage_rebuild_memory_limit, temp_max=args.temp_max,
                            threads=max(1, int(args.stage_rebuild_threads)),
                            partition_threads=max(1, int(args.stage_rebuild_partition_threads)),
                            close_tx_span=max(1, int(args.stage_rebuild_close_tx_span)),
                            min_free_tmp=args.min_free_tmp,
                        ),
                    )
                if rebuild["status"] != "OK":
                    raise RuntimeError(f"independent Stage->UTXO failed: {rebuild['failed_checks']}")

                fg = phase(report, "false_green_guard", lambda: false_green_guard_r213(target, sem, rebuild, core_stage))
                if fg["status"] == "BAD":
                    raise RuntimeError(f"false-green guard failed: {fg.get('failed_checks')}")

            if args.no_reference:
                report["phases"]["reference_v40"] = {
                    "status": "NOT_EVALUATED",
                    "reason": "--no-reference",
                    "certification_blocking": False,
                    "elapsed_sec": 0.0,
                }
            else:
                rv = phase(
                    report,
                    "reference_v40",
                    lambda: reference_v40_compare(Path(args.reference_db), target, ss, stage["sha256"]),
                )
                if rv["status"] != "OK":
                    raise RuntimeError(f"V40 exact comparison failed: {rv['failed_checks']}")

            chain_guard = phase(
                report,
                "core_chain_guard",
                lambda: core_chain_revalidation_guard(
                    stage=stage, start=0, end=target,
                    rpc_url=args.bitcoin_rpc_url, rpc_cookie=args.bitcoin_rpc_cookie,
                    datadir=args.bitcoin_datadir, rpc_timeout=max(5, int(args.core_rpc_timeout)),
                    batch_size=max(1, int(args.core_rpc_batch)),
                ),
            )
            if chain_guard["status"] != "OK":
                raise RuntimeError(f"Core chain revalidation guard failed: {chain_guard.get('failed_checks') or chain_guard.get('reason')}")

            ca = phase(
                report,
                "bitcoin_core",
                lambda: bitcoin_core_final_snapshot(
                    core_stage,
                    target,
                    args.bitcoin_rpc_url,
                    args.bitcoin_rpc_cookie,
                    args.bitcoin_datadir,
                    max(5, int(args.core_rpc_timeout)),
                ),
            )
            if ca["status"] == "BAD":
                raise RuntimeError(f"Bitcoin Core final snapshot changed: {ca}")

            stage_after = stage_snapshot_tokens(stage, target)
            stage_stable = phase(report, "stage_stable_snapshot", lambda: compare_token_maps(stage_tokens_before or {}, stage_after))
            if stage_stable["status"] != "OK":
                raise RuntimeError(f"Stage changed during audit: {stage_stable['changed_sample']}")

            state_after = state_snapshot_tokens(state)
            def stable_state() -> Dict[str, Any]:
                changed: List[str] = []
                for name in sorted(set(state_before) | set(state_after)):
                    before = state_before.get(name)
                    after = state_after.get(name)
                    if name == "dirty.bin":
                        if (before or {}).get("exists") or (after or {}).get("exists"):
                            changed.append("dirty.bin")
                    elif before is None or after is None or not same_token(before, after):
                        changed.append(name)
                return {
                    "status": "OK" if not changed else "BAD",
                    "changed": changed,
                    "before_digest": canonical_json_hash(state_before),
                    "after_digest": canonical_json_hash(state_after),
                }
            stable = phase(report, "stable_snapshot", stable_state)
            if stable["status"] != "OK":
                raise RuntimeError(f"V50 state changed during audit: {stable['changed']}")

            if target == LEGACY_END:
                anchor_ok = (
                    int(ss["live_count"]) == FROZEN_LIVE_COUNT
                    and int(ss["live_value_sats"]) == FROZEN_LIVE_VALUE
                    and ss["block_hash"] == LEGACY_END_HASH
                )
                report["frozen_anchor_617698"] = {
                    "status": "OK" if anchor_ok else "BAD",
                    "expected_live_count": FROZEN_LIVE_COUNT,
                    "actual_live_count": ss["live_count"],
                    "expected_live_value_sats": FROZEN_LIVE_VALUE,
                    "actual_live_value_sats": ss["live_value_sats"],
                    "expected_hash": LEGACY_END_HASH,
                    "actual_hash": ss["block_hash"],
                }
                if not anchor_ok:
                    raise RuntimeError("frozen 617698 anchor mismatch")

        report["finished_utc"] = utc_now()
        report["phases"]["report"] = {"status": "OK", "elapsed_sec": 0.0}
        report["certification"] = certification(report, require_reference=not args.no_reference)
        max_levels = {
            "V50_CANONICAL_CERTIFIED_R12_PROVENANCE",
            "V50_CANONICAL_CERTIFIED_FULL_EXECUTION_PROVENANCE",
        }
        report["status"] = "GREEN" if report["certification"]["level"] in max_levels and not report["certification"].get("blocking") else "PARTIAL"

        output_dir.mkdir(parents=True, exist_ok=True)
        stem = f"audit_v51_5_4_{report['target_height']}_{utc_stamp()}_{uuid.uuid4().hex[:8]}"
        out = output_dir / f"{stem}.json"
        digest = write_evidence(out, report)
        md = output_dir / f"{stem}.md"
        atomic_immutable_write(md, (markdown_report(report) + "\n").encode("utf-8"))
        md_sha = sha256_file(md)
        atomic_immutable_write(Path(str(md) + ".sha256"), f"{md_sha}  {md.name}\n".encode("ascii"))
        print(json.dumps({
            "status": report["status"],
            "certification": report["certification"],
            "target_height": report["target_height"],
            "report": str(out),
            "report_sha256": digest,
            "markdown": str(md),
            "auditor_sha256": report["auditor_sha256"],
        }, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report["status"] == "GREEN" else 2
    except Exception as exc:
        report["finished_utc"] = utc_now()
        report["status"] = "FAILED"
        report["fatal"] = classify_audit_failure(exc, report, args, tmp)
        report["error_type"] = report["fatal"]["error_type"]
        report["failed_phase"] = report["fatal"]["failed_phase"]
        report["failure_classification"] = report["fatal"]["classification"]
        report["failure_reason_code"] = report["fatal"]["reason_code"]
        report["error"] = report["fatal"]["error"]
        try:
            report["certification"] = certification(report, require_reference=not args.no_reference)
            report["certification"]["level"] = "FAILED"
            output_dir.mkdir(parents=True, exist_ok=True)
            out = output_dir / f"audit_v51_5_4_FATAL_{utc_stamp()}_{uuid.uuid4().hex[:8]}.json"
            digest = write_evidence(out, report)
            print(json.dumps({
                "status": "FAILED",
                "classification": report["fatal"]["classification"],
                "reason_code": report["fatal"]["reason_code"],
                "failed_phase": report["fatal"]["failed_phase"],
                "error_type": report["fatal"]["error_type"],
                "operator_message": report["fatal"]["operator_message"],
                "recommended_action": report["fatal"]["recommended_action"],
                "error": report["fatal"]["error"],
                "report": str(out), "sha256": digest,
            }, ensure_ascii=False, indent=2), file=sys.stderr)
        except Exception as report_exc:
            print(f"V51_AUDIT_FATAL {type(exc).__name__}: {exc}; report_write_failed={type(report_exc).__name__}:{report_exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
        shutil.rmtree(run_tmp, ignore_errors=True)



# ---------------------------------------------------------------------------
# V51.4 universal read-only Bitcoin Core -> Stage range audit
# ---------------------------------------------------------------------------
CORE_STAGE_RANGE_REPORT_SCHEMA = "mybot-v51-core-stage-range-audit-v1"
CORE_STAGE_RANGE_CONTRACT_SCHEMA = "mybot-v51-core-stage-range-contract-v1"
CORE_STAGE_RANGE_RECORD_SCHEMA = "mybot-v51-core-stage-range-chunk-v1"
CORE_STAGE_RANGE_DIRTY_SCHEMA = "mybot-v51-core-stage-range-dirty-v1"
CORE_STAGE_RANGE_TIME_BASIS = "bitcoin-core-mediantime"


def _range_file_token(path: Path) -> Tuple[int, int, int, int]:
    p = regular(path)
    st = p.stat()
    return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))


def _range_stable_sha256(path: Path) -> Tuple[str, int]:
    before = _range_file_token(path)
    digest = sha256_file(path)
    after = _range_file_token(path)
    if before != after:
        raise RuntimeError(f"file changed during SHA256 read: {path}")
    return digest, before[2]


def _range_plan(stage: Dict[str, Any], start: int, end: int) -> List[Dict[str, Any]]:
    if start < 0 or end < start:
        raise RuntimeError(f"invalid range {start}..{end}")
    if start < int(stage["start_height"]) or end > int(stage["end_height"]):
        raise RuntimeError(
            f"Stage coverage {stage['start_height']}..{stage['end_height']} does not cover requested {start}..{end}"
        )
    plan: List[Dict[str, Any]] = []
    expected = start
    for e in stage["entries"]:
        eh1, eh2 = int(e["h1"]), int(e["h2"])
        if eh2 < start or eh1 > end:
            continue
        h1, h2 = max(start, eh1), min(end, eh2)
        if h1 != expected:
            raise RuntimeError(f"Stage range plan gap/overlap expected={expected} actual={h1}..{h2}")
        plan.append({
            "chunk_no": len(plan), "h1": h1, "h2": h2,
            "stage_manifest_path": str(e["manifest_path"]),
            "stage_manifest_sha256": str(e["manifest_sha256"]), "entry": e,
        })
        expected = h2 + 1
    if not plan or expected != end + 1:
        raise RuntimeError(f"Stage range plan terminal mismatch next={expected} end={end}")
    return plan


def _range_plan_digest(plan: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash({
        "schema": "mybot-v51-core-stage-range-plan-v1",
        "chunks": [{
            "chunk_no": int(x["chunk_no"]), "h1": int(x["h1"]), "h2": int(x["h2"]),
            "stage_manifest_sha256": str(x["stage_manifest_sha256"]),
            "payloads": {role: {"sha256": str(x["entry"][role]["sha256"]), "rows": int(x["entry"][role]["rows"])}
                         for role in ("blocks", "transactions", "inputs", "outputs")},
        } for x in plan],
    })


def _range_verify_chunk_payload_shas(item: Dict[str, Any]) -> Dict[str, Any]:
    checked: Dict[str, Any] = {}
    total = 0
    for role in ("blocks", "transactions", "inputs", "outputs"):
        ref = item["entry"][role]
        p = Path(str(ref["path"])).resolve(strict=True)
        actual, size = _range_stable_sha256(p)
        expected = str(ref["sha256"])
        if actual != expected:
            raise RuntimeError(
                f"Stage payload SHA mismatch chunk={item['chunk_no']} role={role} actual={actual} expected={expected} path={p}"
            )
        checked[role] = {"path": str(p), "sha256": actual, "bytes": size}
        total += size
    return {"files": checked, "bytes_hashed": total}


def _range_rpc_identity(rpc: BitcoinRPC, start: int, end: int) -> Dict[str, Any]:
    info = rpc.call("getblockchaininfo")
    net = rpc.call("getnetworkinfo")
    if not isinstance(info, dict) or not isinstance(net, dict):
        raise RuntimeError("Bitcoin Core identity RPC malformed")
    prev_h = start - 1 if start > 0 else 0
    genesis, prev_hash, start_hash, end_hash = rpc.batch([
        ("getblockhash", [0]), ("getblockhash", [prev_h]),
        ("getblockhash", [start]), ("getblockhash", [end]),
    ])
    obj = {
        "chain": str(info.get("chain") or ""),
        "blocks": int(info.get("blocks") if info.get("blocks") is not None else -1),
        "headers": int(info.get("headers") if info.get("headers") is not None else -1),
        "pruned": bool(info.get("pruned", False)),
        "pruneheight": int(info.get("pruneheight") or 0) if info.get("pruned", False) else 0,
        "version": int(net.get("version") or 0), "subversion": str(net.get("subversion") or ""),
        "genesis_hash": str(genesis).lower(), "predecessor_height": prev_h,
        "predecessor_hash": str(prev_hash).lower(), "start_hash": str(start_hash).lower(),
        "end_hash": str(end_hash).lower(),
    }
    failed: List[str] = []
    if obj["chain"] != "main": failed.append(f"chain:{obj['chain']}!=main")
    if obj["blocks"] < end: failed.append(f"blocks:{obj['blocks']}<{end}")
    if obj["headers"] < end: failed.append(f"headers:{obj['headers']}<{end}")
    if obj["genesis_hash"] != GENESIS_HASH: failed.append(f"genesis:{obj['genesis_hash']}!={GENESIS_HASH}")
    if obj["pruned"] and obj["pruneheight"] > start: failed.append(f"pruned:pruneheight={obj['pruneheight']}>start={start}")
    if failed:
        raise RuntimeError("Bitcoin Core identity failed: " + ", ".join(failed))
    return obj


def _range_parse_date(value: str, *, end: bool) -> int:
    try:
        d = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RuntimeError(f"invalid UTC date {value!r}; required YYYY-MM-DD") from exc
    if end:
        d += timedelta(days=1)
        return int(d.timestamp()) - 1
    return int(d.timestamp())


def _range_parse_time(value: str) -> int:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value or ""):
        raise RuntimeError(f"invalid UTC time {value!r}; required YYYY-MM-DDTHH:MM:SSZ")
    try:
        return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError as exc:
        raise RuntimeError(f"invalid UTC time {value!r}") from exc


def _range_mtp_at_height(rpc: BitcoinRPC, height: int, cache: Dict[int, int]) -> int:
    if height in cache:
        return cache[height]
    bh = str(rpc.call("getblockhash", [int(height)])).lower()
    hdr = rpc.call("getblockheader", [bh, True])
    if not isinstance(hdr, dict) or hdr.get("mediantime") is None:
        raise RuntimeError(f"Bitcoin Core getblockheader missing mediantime height={height}")
    mtp = int(hdr["mediantime"])
    cache[height] = mtp
    return mtp


def _range_resolve_mtp(rpc: BitcoinRPC, ts: int, lo: int, hi: int, *, first_ge: bool, cache: Dict[int, int]) -> int:
    lo_mtp = _range_mtp_at_height(rpc, lo, cache)
    hi_mtp = _range_mtp_at_height(rpc, hi, cache)
    if first_ge:
        if ts <= lo_mtp: return lo
        if ts > hi_mtp: raise RuntimeError(f"requested time is after Stage coverage by Core mediantime: ts={ts} stage_end_mtp={hi_mtp}")
        a, b = lo, hi
        while a < b:
            m = (a + b) // 2
            if _range_mtp_at_height(rpc, m, cache) >= ts: b = m
            else: a = m + 1
        h = a
        if _range_mtp_at_height(rpc, h, cache) < ts or (h > lo and _range_mtp_at_height(rpc, h - 1, cache) >= ts):
            raise RuntimeError("mediantime lower-bound resolution invariant failed")
        return h
    if ts < lo_mtp: raise RuntimeError(f"requested time is before Stage coverage by Core mediantime: ts={ts} stage_start_mtp={lo_mtp}")
    if ts >= hi_mtp: return hi
    a, b = lo, hi
    while a < b:
        m = (a + b + 1) // 2
        if _range_mtp_at_height(rpc, m, cache) <= ts: a = m
        else: b = m - 1
    h = a
    if _range_mtp_at_height(rpc, h, cache) > ts or (h < hi and _range_mtp_at_height(rpc, h + 1, cache) <= ts):
        raise RuntimeError("mediantime upper-bound resolution invariant failed")
    return h


def _range_boundary_request(args: argparse.Namespace, which: str) -> Tuple[str, Any]:
    vals = [("height", getattr(args, which)), ("date", getattr(args, which + "_date")), ("time", getattr(args, which + "_time"))]
    chosen = [(k, v) for k, v in vals if v is not None]
    if len(chosen) != 1:
        raise RuntimeError(f"exactly one --{which}/--{which}-date/--{which}-time is required")
    return chosen[0]


def _range_resolve_requested(args: argparse.Namespace, stage: Dict[str, Any], rpc: BitcoinRPC) -> Dict[str, Any]:
    slo, shi = int(stage["start_height"]), int(stage["end_height"])
    if args.tail:
        if any(getattr(args, x) is not None for x in ("from", "from_date", "from_time", "to", "to_date", "to_time")):
            raise RuntimeError("--tail cannot be combined with explicit range boundaries")
        sc = parse_state_contract(Path(args.state), Path(args.driver), Path(args.core))
        start, end = int(sc["height"]) + 1, shi
        if start > end:
            raise RuntimeError(f"no Stage tail after certified/current state height={sc['height']} stage_end={shi}")
        return {"requested": {"mode": "tail", "state_height": int(sc["height"]), "stage_end": shi},
                "resolved": {"from_height": start, "to_height": end}, "time_basis": None}
    fk, fv = _range_boundary_request(args, "from")
    tk, tv = _range_boundary_request(args, "to")
    cache: Dict[int, int] = {}
    def resolve(kind: str, value: Any, *, start_boundary: bool) -> int:
        if kind == "height":
            return int(value)
        ts = _range_parse_date(str(value), end=not start_boundary) if kind == "date" else _range_parse_time(str(value))
        return _range_resolve_mtp(rpc, ts, slo, shi, first_ge=start_boundary, cache=cache)
    start = resolve(fk, fv, start_boundary=True)
    end = resolve(tk, tv, start_boundary=False)
    if start < slo or end > shi or end < start:
        raise RuntimeError(f"resolved range {start}..{end} invalid for Stage coverage {slo}..{shi}")
    req = {"mode": "explicit", "from": {"kind": fk, "value": fv}, "to": {"kind": tk, "value": tv}}
    return {"requested": req, "resolved": {"from_height": start, "to_height": end},
            "time_basis": CORE_STAGE_RANGE_TIME_BASIS if fk in {"date","time"} or tk in {"date","time"} else None}


def _range_read_ledger(path: Path, contract_id: str, plan: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not path.exists(): return []
    regular(path)
    records: List[Dict[str, Any]] = []; prev: Optional[str] = None
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip(): continue
            obj = json.loads(line); idx = len(records)
            if idx >= len(plan): raise RuntimeError("range progress ledger longer than plan")
            expected = plan[idx]
            if obj.get("schema") != CORE_STAGE_RANGE_RECORD_SCHEMA: raise RuntimeError(f"range ledger schema mismatch line={line_no}")
            if str(obj.get("contract_id") or "") != contract_id: raise RuntimeError(f"range ledger contract mismatch line={line_no}")
            if int(obj.get("record_no", -1)) != idx + 1 or int(obj.get("chunk_no", -1)) != idx: raise RuntimeError(f"range ledger sequence mismatch line={line_no}")
            if int(obj.get("h1", -1)) != int(expected["h1"]) or int(obj.get("h2", -1)) != int(expected["h2"]): raise RuntimeError(f"range ledger bounds mismatch line={line_no}")
            if str(obj.get("stage_manifest_sha256") or "") != str(expected["stage_manifest_sha256"]): raise RuntimeError(f"range ledger Stage manifest mismatch line={line_no}")
            if obj.get("previous_record_sha256") != prev: raise RuntimeError(f"range ledger hash-chain mismatch line={line_no}")
            rec_sha = canonical_json_hash(obj, exclude=("record_sha256",))
            if str(obj.get("record_sha256") or "") != rec_sha: raise RuntimeError(f"range ledger record SHA mismatch line={line_no}")
            if str(obj.get("status") or "") not in {"OK","BAD"}: raise RuntimeError(f"range ledger committed status invalid line={line_no}")
            records.append(obj); prev = rec_sha
    return records


class _RangeLease:
    def __init__(self, path: Path): self.path = path; self.fd: Optional[int] = None
    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try: fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.fd); self.fd = None
            raise RuntimeError(f"Core->Stage range audit already running for this contract: {self.path}") from exc
        return self
    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN); os.close(self.fd); self.fd = None


def _range_atomic_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    data = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path); fsync_dir(path.parent)
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass


def _range_append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8") + b"\n"
        os.write(fd, data); os.fsync(fd)
    finally: os.close(fd)
    fsync_dir(path.parent)


def _range_prepare_progress(base: Path, contract: Dict[str, Any], plan: Sequence[Dict[str, Any]], allow_resume: bool) -> Tuple[Path,List[Dict[str,Any]],Path,Path]:
    cid = str(contract["contract_id"]); root = base / cid; root.mkdir(parents=True, exist_ok=True)
    contract_path, ledger_path, dirty_path = root / "contract.json", root / "chunks.jsonl", root / "dirty.json"
    if contract_path.exists():
        if not allow_resume: raise RuntimeError(f"matching Core->Stage range progress already exists and --no-resume was requested: {root}")
        observed = json.loads(regular(contract_path).read_text(encoding="utf-8"))
        if canonical_json_hash(observed) != canonical_json_hash(contract): raise RuntimeError(f"range progress contract mismatch: {contract_path}")
    else: _range_atomic_json(contract_path, contract)
    records = _range_read_ledger(ledger_path, cid, plan)
    if dirty_path.exists():
        dirty = json.loads(regular(dirty_path).read_text(encoding="utf-8"))
        if str(dirty.get("contract_id") or "") != cid: raise RuntimeError("range dirty marker contract mismatch")
        dchunk, next_chunk = int(dirty.get("chunk_no", -1)), len(records)
        allowed = {next_chunk} if not records else {next_chunk, next_chunk - 1}
        if dchunk not in allowed: raise RuntimeError(f"range dirty/ledger mismatch dirty={dchunk} records={next_chunk}")
        archived = root / f"dirty.recovered.{utc_stamp()}.{os.getpid()}.{uuid.uuid4().hex[:8]}.json"
        os.replace(dirty_path, archived); fsync_dir(root); log(f"Core->Stage range recovered stale dirty marker -> {archived.name}")
    return root, records, ledger_path, dirty_path


def _range_totals(records: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    totals = {"blocks":0,"transactions":0,"inputs":0,"outputs":0,"witness_transactions":0,"raw_block_bytes":0,"stage_bytes_hashed":0}
    for rec in records:
        result = rec.get("result") if isinstance(rec.get("result"), dict) else {}
        counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
        for k in ("blocks","transactions","inputs","outputs","witness_transactions"): totals[k] += int(counts.get(k) or 0)
        totals["raw_block_bytes"] += int(result.get("raw_block_bytes") or 0)
        ps = rec.get("stage_payload_sha") if isinstance(rec.get("stage_payload_sha"), dict) else {}
        totals["stage_bytes_hashed"] += int(ps.get("bytes_hashed") or 0)
    return totals


def _range_stage_tokens(stage: Dict[str, Any], plan: Sequence[Dict[str, Any]]) -> Dict[str, Tuple[int,int,int,int]]:
    paths: Dict[str, Path] = {}
    for key in ("path", "windows_path"):
        if stage.get(key):
            p = Path(str(stage[key])).resolve(strict=True); paths[str(p)] = p
    for item in plan:
        mp = Path(item["stage_manifest_path"]).resolve(strict=True); paths[str(mp)] = mp
        for role in ("blocks","transactions","inputs","outputs"):
            p = Path(str(item["entry"][role]["path"])).resolve(strict=True); paths[str(p)] = p
    return {name: _range_file_token(p) for name,p in sorted(paths.items())}


def core_stage_range_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="V51.5.4 read-only exact Bitcoin Core -> Stage audit for any contiguous height/time range")
    p.add_argument("--stage-base", default=str(DEFAULT_STAGE_BASE))
    p.add_argument("--state", default=str(DEFAULT_STATE), help="read only; used only by --tail to resolve state_height+1")
    p.add_argument("--driver", default=str(DEFAULT_DRIVER), help="read only; used only by --tail state contract")
    p.add_argument("--core", default=str(DEFAULT_CORE), help="read only; used only by --tail state contract")
    p.add_argument("--from", dest="from", type=int)
    p.add_argument("--to", dest="to", type=int)
    p.add_argument("--from-date")
    p.add_argument("--to-date")
    p.add_argument("--from-time")
    p.add_argument("--to-time")
    p.add_argument("--tail", action="store_true", help="resolve current state height + 1 through Stage release end")
    p.add_argument("--bitcoin-rpc-url", default="http://127.0.0.1:8332")
    p.add_argument("--bitcoin-rpc-cookie")
    p.add_argument("--bitcoin-datadir")
    p.add_argument("--rpc-timeout", type=int, default=300)
    p.add_argument("--block-batch", type=int, default=8)
    p.add_argument("--guard-batch", type=int, default=2000, help="heights per RPC batch for mandatory final all-height Core chain guard")
    p.add_argument("--memory-limit", default="24GiB", help="per-window DuckDB limit")
    p.add_argument("--threads", type=int, default=2, help="per-window DuckDB threads")
    p.add_argument("--temp-max", default="200GB")
    p.add_argument("--tmp", default="/opt/mybot_tmp/utxo_v51_core_stage_range")
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    p.add_argument("--progress-dir", help="default: <output-dir>/core_stage_range_progress")
    p.add_argument("--no-resume", action="store_true")
    p.add_argument("--resolve-only", action="store_true", help="resolve date/time/tail to heights and validate coverage, but do not hash/compare blocks")
    p.add_argument("--json", action="store_true", help="machine-readable result; default output is operator-friendly")
    return p


def core_stage_range_main(argv: Optional[Sequence[str]] = None) -> int:
    args = core_stage_range_parser().parse_args(argv)
    started = time.monotonic(); output_dir = Path(args.output_dir); tmp_root = Path(args.tmp)
    stage = load_legacy_stage(Path(args.stage_base))
    cookie = _rpc_cookie(args.bitcoin_rpc_cookie, args.bitcoin_datadir)
    if cookie is None:
        raise RuntimeError("Bitcoin Core RPC cookie unavailable")
    rpc = BitcoinRPC(args.bitcoin_rpc_url, cookie, timeout=max(5, int(args.rpc_timeout)))
    try:
        resolved = _range_resolve_requested(args, stage, rpc)
        start, end = int(resolved["resolved"]["from_height"]), int(resolved["resolved"]["to_height"])
        plan = _range_plan(stage, start, end)
        identity = _range_rpc_identity(rpc, start, end)
        preview = {
            "schema":"mybot-v51-core-stage-range-resolution-v1", "status":"READY",
            "requested":resolved["requested"], "resolved":resolved["resolved"], "time_basis":resolved["time_basis"],
            "stage":{"path":str(stage["path"]),"sha256":str(stage["sha256"]),"coverage":[int(stage["start_height"]),int(stage["end_height"])],"chunks":len(plan)},
            "core":{"chain":identity["chain"],"blocks":identity["blocks"],"start_hash":identity["start_hash"],"end_hash":identity["end_hash"]},
            "mode":"READ_ONLY",
        }
        if args.resolve_only:
            if args.json:
                print(json.dumps(preview, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                req = resolved["requested"]
                print("CORE -> STAGE RANGE     READY")
                print(f"Requested               {req}")
                print(f"Resolved                {start} .. {end}")
                print(f"Blocks                  {end-start+1:,}")
                print(f"Stage coverage          {stage['start_height']} .. {stage['end_height']}")
                print(f"Stage manifest SHA256   {stage['sha256']}")
                print(f"Bitcoin Core            {identity['chain']} h={identity['blocks']}")
                print(f"Time basis              {resolved['time_basis'] or 'height'}")
                print("Mode                    READ-ONLY")
            return 0
        if int(args.block_batch) < 1 or int(args.threads) < 1: raise RuntimeError("block-batch and threads must be >= 1")
        if _core_parser_selftest().get("status") != "OK": raise RuntimeError("V51.5.4 raw Bitcoin parser selftest failed")
        auditor_sha = sha256_file(Path(__file__).resolve())
        global CORE_STAGE_RANGE_COMPACT_PROGRESS
        CORE_STAGE_RANGE_COMPACT_PROGRESS = True
        contract: Dict[str, Any] = {
            "schema":CORE_STAGE_RANGE_CONTRACT_SCHEMA, "auditor_version":VERSION, "auditor_sha256":auditor_sha,
            "requested":resolved["requested"], "resolved":resolved["resolved"], "time_basis":resolved["time_basis"],
            "stage":{"path":str(Path(stage["path"]).resolve(strict=True)),"global_sha256":str(stage["sha256"]),"windows_sha256":str(stage["windows_sha256"]),"plan_sha256":_range_plan_digest(plan),"chunks":len(plan)},
            "core":{"chain":identity["chain"],"version":identity["version"],"genesis_hash":identity["genesis_hash"],"predecessor_height":identity["predecessor_height"],"predecessor_hash":identity["predecessor_hash"],"start_hash":identity["start_hash"],"end_hash":identity["end_hash"],"rpc_url":str(args.bitcoin_rpc_url)},
            "execution":{"block_batch":int(args.block_batch),"memory_limit":str(args.memory_limit),"threads":int(args.threads),"temp_max":str(args.temp_max)},
            "proof":{"active_chain":"getblockhash(height)","raw_blocks":"getblock(hash,0)","block_hash":"SHA256d(header)","merkle":"independent canonical-txid tree","txid":"stripped serialization canonical txid","wtxid":"separate; substitution detected","payload":"height/tx_index/txid/vin-prevout/vout-value/raw-script exact digests","stage_payload_sha":"full SHA256 of all four selected-window Parquet payloads"},
        }
        contract["contract_id"] = canonical_json_hash(contract)
        progress_base = Path(args.progress_dir) if args.progress_dir else output_dir / "core_stage_range_progress"
        progress_base.mkdir(parents=True, exist_ok=True); output_dir.mkdir(parents=True, exist_ok=True); tmp_root.mkdir(parents=True, exist_ok=True)
        duckdb = require_duckdb(); stage_before = _range_stage_tokens(stage, plan)
        root = progress_base / str(contract["contract_id"])
        with _RangeLease(root / "LOCK"):
            root, records, ledger_path, dirty_path = _range_prepare_progress(progress_base, contract, plan, not args.no_resume)
            if records: log(f"Core->Stage range RESUME chunks={len(records)}/{len(plan)}")
            if not (records and str(records[-1].get("status")) == "BAD"):
                for idx in range(len(records), len(plan)):
                    item = plan[idx]
                    _range_atomic_json(dirty_path, {"schema":CORE_STAGE_RANGE_DIRTY_SCHEMA,"contract_id":contract["contract_id"],"chunk_no":idx,"h1":int(item["h1"]),"h2":int(item["h2"]),"started_utc":utc_now(),"pid":os.getpid()})
                    log(f"Core->Stage range chunk START {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
                    stage_sha = _range_verify_chunk_payload_shas(item)
                    result = _core_stage_chunk_audit(rpc=rpc, duckdb_module=duckdb, item=item,
                        block_batch=int(args.block_batch), stage_memory_limit=str(args.memory_limit), temp_max=str(args.temp_max),
                        stage_threads=int(args.threads), temp_root=tmp_root)
                    status = str(result.get("status") or "NOT_EVALUATED")
                    if status in {"NOT_EVALUATED","PARTIAL"}:
                        try: dirty_path.unlink()
                        except FileNotFoundError: pass
                        fsync_dir(root); break
                    if status not in {"OK","BAD"}: raise RuntimeError(f"invalid range chunk status: {status}")
                    rec = {"schema":CORE_STAGE_RANGE_RECORD_SCHEMA,"contract_id":contract["contract_id"],"record_no":idx+1,"chunk_no":idx,"h1":int(item["h1"]),"h2":int(item["h2"]),"stage_manifest_sha256":str(item["stage_manifest_sha256"]),"stage_payload_sha":stage_sha,"status":status,"result":result,"finished_utc":utc_now(),"previous_record_sha256":records[-1]["record_sha256"] if records else None}
                    rec["record_sha256"] = canonical_json_hash(rec, exclude=("record_sha256",)); _range_append_jsonl(ledger_path, rec)
                    dirty_path.unlink(); fsync_dir(root); records.append(rec)
                    log(f"Core->Stage range chunk {status} {idx+1}/{len(plan)} heights={item['h1']}..{item['h2']}")
                    if status == "BAD": break
            final_prev, final_start, final_end = rpc.batch([("getblockhash",[int(identity["predecessor_height"])]),("getblockhash",[start]),("getblockhash",[end])])
            final_anchors={"predecessor_hash":str(final_prev).lower(),"start_hash":str(final_start).lower(),"end_hash":str(final_end).lower()}
            core_stable = final_anchors["predecessor_hash"]==identity["predecessor_hash"] and final_anchors["start_hash"]==identity["start_hash"] and final_anchors["end_hash"]==identity["end_hash"]
            chain_guard = core_chain_revalidation_guard(
                stage=stage, start=start, end=end, rpc_url=args.bitcoin_rpc_url,
                rpc_cookie=args.bitcoin_rpc_cookie, datadir=args.bitcoin_datadir,
                rpc_timeout=max(5,int(args.rpc_timeout)), batch_size=max(1,int(args.guard_batch)),
            )
            chain_guard_ok = str(chain_guard.get("status")) == "OK"
            stage_after = _range_stage_tokens(stage, plan); stage_stable = stage_before == stage_after
            completed=len(records); bad=[r for r in records if str(r.get("status"))!="OK"]; complete=completed==len(plan)
            final_status="GREEN" if complete and not bad and core_stable and chain_guard_ok and stage_stable else ("FAILED" if bad or not core_stable or not chain_guard_ok or not stage_stable else "PARTIAL")
            report={"schema":CORE_STAGE_RANGE_REPORT_SCHEMA,"version":VERSION,"auditor_sha256":auditor_sha,"status":final_status,"created_utc":utc_now(),"requested":resolved["requested"],"resolved":resolved["resolved"],"time_basis":resolved["time_basis"],"range":{"start":start,"end":end,"blocks":end-start+1},"stage":{"global_sha256":str(stage["sha256"]),"release_path":str(stage["path"]),"windows_sha256":str(stage["windows_sha256"]),"chunks_total":len(plan),"snapshot_stable":stage_stable},"core_identity_start":identity,"core_anchors_final":final_anchors,"core_snapshot_stable":core_stable,"core_chain_guard":chain_guard,"contract_id":contract["contract_id"],"progress_root":str(root),"chunks_completed":completed,"chunks_total":len(plan),"coverage_complete":complete,"bad_chunks":[{"chunk_no":r["chunk_no"],"h1":r["h1"],"h2":r["h2"],"failed_checks":(r.get("result") or {}).get("failed_checks",[])} for r in bad],"totals":_range_totals(records),"proof":contract["proof"],"certification":{"core_stage_exact":final_status=="GREEN","core_chain_revalidation_guard":chain_guard_ok,"stage_payload_sha_exact":final_status=="GREEN","merkle_exact":final_status=="GREEN","script_payload_exact":final_status=="GREEN","wtxid_substitution_detected":any(bool((r.get("result") or {}).get("wtxid_substitution_suspected")) for r in records),"state_mutation":"NONE_BY_CONTRACT","apply_authority":"NONE"},"elapsed_sec":round(time.monotonic()-started,3)}
            output_dir.mkdir(parents=True, exist_ok=True)
            stem=f"audit_v51_5_4_core_stage_{start}_{end}_{final_status}_{utc_stamp()}_{uuid.uuid4().hex[:8]}"; out=output_dir/f"{stem}.json"; digest=write_evidence(out,report)
            result_obj={"status":final_status,"mode":"core-stage","requested":resolved["requested"],"resolved":resolved["resolved"],"time_basis":resolved["time_basis"],"chunks":f"{completed}/{len(plan)}","report":str(out),"report_sha256":digest,"auditor_sha256":auditor_sha,"apply_eligible":final_status=="GREEN"}
            if args.json:
                print(json.dumps(result_obj,ensure_ascii=False,indent=2,sort_keys=True))
            else:
                totals=report.get("totals") or {}
                print()
                print(f"CORE -> STAGE EXACT AUDIT  {final_status}")
                print(f"Resolved range             {start} .. {end}")
                print(f"Blocks                     {end-start+1:,}")
                print(f"Windows                    {completed}/{len(plan)}")
                print(f"Transactions               {int(totals.get('transactions') or 0):,}")
                print(f"Inputs                     {int(totals.get('inputs') or 0):,}")
                print(f"Outputs                    {int(totals.get('outputs') or 0):,}")
                print(f"Witness transactions       {int(totals.get('witness_transactions') or 0):,}")
                print(f"Stage snapshot             {'STABLE' if stage_stable else 'CHANGED'}")
                print(f"Bitcoin Core snapshot      {'STABLE' if core_stable else 'CHANGED'}")
                print(f"Core chain all-height guard {'GREEN' if chain_guard_ok else 'RED'} ({int(chain_guard.get('heights_checked') or 0):,} heights)")
                print(f"WTXID-as-TXID              {'DETECTED' if report['certification']['wtxid_substitution_detected'] else 'NO'}")
                print(f"Time basis                 {resolved['time_basis'] or 'height'}")
                print(f"Report                     {out}")
                print(f"Report SHA256              {digest}")
                print(f"APPLY eligibility          {'YES' if final_status=='GREEN' else 'NO'}")
            return 0 if final_status=="GREEN" else (3 if final_status=="PARTIAL" else 2)
    finally:
        CORE_STAGE_RANGE_COMPACT_PROGRESS = False
        rpc.close()



STAGE_SEMANTICS_ONLY_REPORT_SCHEMA = "mybot-v51-stage-semantics-only-v1"



def core_chain_guard_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="V51.5.4 independent read-only all-height Bitcoin Core active-chain guard")
    p.add_argument("--state", default=str(DEFAULT_STATE))
    p.add_argument("--stage-base", default=str(DEFAULT_STAGE_BASE))
    p.add_argument("--driver", default=str(DEFAULT_DRIVER))
    p.add_argument("--core", default=str(DEFAULT_CORE))
    p.add_argument("--expected-height", type=int)
    p.add_argument("--bitcoin-rpc-url", default="http://127.0.0.1:8332")
    p.add_argument("--bitcoin-rpc-cookie")
    p.add_argument("--bitcoin-datadir")
    p.add_argument("--rpc-timeout", type=int, default=300)
    p.add_argument("--batch", type=int, default=2000)
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    p.add_argument("--json", action="store_true")
    return p


def core_chain_guard_main(argv: Optional[Sequence[str]] = None) -> int:
    args = core_chain_guard_parser().parse_args(argv)
    started = time.monotonic()
    state = Path(args.state)
    output_dir = Path(args.output_dir)
    auditor_sha = sha256_file(Path(__file__).resolve())
    sc = parse_state_contract(state, Path(args.driver), Path(args.core))
    target = int(sc["height"])
    if args.expected_height is not None and target != int(args.expected_height):
        raise RuntimeError(f"checkpoint height={target} != expected-height={args.expected_height}")
    stage = load_legacy_stage(Path(args.stage_base))
    result = core_chain_revalidation_guard(
        stage=stage, start=0, end=target,
        rpc_url=args.bitcoin_rpc_url, rpc_cookie=args.bitcoin_rpc_cookie,
        datadir=args.bitcoin_datadir, rpc_timeout=max(5, int(args.rpc_timeout)),
        batch_size=max(1, int(args.batch)),
    )
    failed = list(result.get("failed_checks") or [])
    if str(result.get("stage_end_hash") or "") != str(sc.get("block_hash") or ""):
        failed.append(f"stage_state_target_hash:{result.get('stage_end_hash')}!={sc.get('block_hash')}")
    if failed:
        result["status"] = "BAD"
        result["failed_checks"] = sorted(set(failed))
        result["certification_blocking"] = True
    report = {
        "schema": "mybot-v51-core-chain-guard-v1",
        "version": VERSION,
        "auditor_sha256": auditor_sha,
        "status": result.get("status"),
        "created_utc": utc_now(),
        "state": {"path": str(state.resolve(strict=True)), "height": target, "block_hash": sc.get("block_hash")},
        "stage": {"path": str(stage.get("path")), "sha256": str(stage.get("sha256")), "windows_sha256": str(stage.get("windows_sha256"))},
        "guard": result,
        "elapsed_sec": round(time.monotonic()-started, 3),
        "state_mutation": "NONE_BY_CONTRACT",
        "certification_impact": "MANDATORY_IN_V51.5.4_FULL_AUDIT; STANDALONE_EVIDENCE_ONLY",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"audit_v51_5_4_core_chain_{target}_{str(result.get('status') or 'UNKNOWN')}_{utc_stamp()}_{uuid.uuid4().hex[:8]}"
    out = output_dir / f"{stem}.json"
    digest = write_evidence(out, report)
    obj = {"status": result.get("status"), "mode": "core-chain", "height": target, "heights_checked": result.get("heights_checked"), "mismatch_count": result.get("mismatch_count"), "report": str(out), "report_sha256": digest, "auditor_sha256": auditor_sha}
    if args.json:
        print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print()
        print(f"CORE CHAIN REVALIDATION GUARD  {result.get('status')}")
        print(f"Height                      0 .. {target}")
        print(f"Heights checked             {int(result.get('heights_checked') or 0):,}")
        print(f"Mismatches                  {int(result.get('mismatch_count') or 0):,}")
        print(f"End anchor stable           {result.get('end_anchor_stable')}")
        print(f"Stage payload stable        {result.get('stage_payload_stable')}")
        print(f"Expected chain digest       {result.get('expected_chain_digest_sha256')}")
        print(f"Observed chain digest       {result.get('observed_chain_digest_sha256')}")
        print(f"Report                      {out}")
        print(f"Report SHA256               {digest}")
    return 0 if result.get("status") == "OK" else 2

def stage_semantics_only_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="V51.5.4 bounded-memory Stage semantics diagnostic (read-only; not a full certification)")
    p.add_argument("--state", default=str(DEFAULT_STATE))
    p.add_argument("--stage-base", default=str(DEFAULT_STAGE_BASE))
    p.add_argument("--stage-release")
    p.add_argument("--driver", default=str(DEFAULT_DRIVER))
    p.add_argument("--core", default=str(DEFAULT_CORE))
    p.add_argument("--expected-height", type=int)
    p.add_argument("--tmp", default=str(DEFAULT_TMP))
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    p.add_argument("--memory-limit", default="12GiB", help="DuckDB memory limit per isolated Stage window")
    p.add_argument("--temp-max", default="700GB")
    p.add_argument("--min-free-tmp", default="200GiB")
    p.add_argument("--threads", type=int, default=2)
    p.add_argument("--progress-dir", help="durable progress root; default: <output-dir>/stage_semantics_progress")
    p.add_argument("--no-resume", action="store_true")
    p.add_argument("--stage-sha", choices=("full", "manifest"), default="full")
    p.add_argument("--json", action="store_true")
    return p


def stage_semantics_only_main(argv: Optional[Sequence[str]] = None) -> int:
    args = stage_semantics_only_parser().parse_args(argv)
    state = Path(args.state); tmp = Path(args.tmp); output_dir = Path(args.output_dir)
    started = time.monotonic()
    report: Dict[str, Any] = {
        "schema": STAGE_SEMANTICS_ONLY_REPORT_SCHEMA,
        "version": VERSION,
        "started_utc": utc_now(),
        "status": "FAILED",
        "mode": "stage-semantics",
        "read_only": True,
        "certification_impact": "DIAGNOSTIC_ONLY_FULL_AUDIT_REQUIRED",
        "arguments": vars(args),
        "phases": {},
    }
    report["auditor_sha256"] = sha256_file(Path(__file__).resolve())
    run_tmp = tmp / f"stage_semantics_only_{utc_stamp()}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    run_tmp.mkdir(parents=True, exist_ok=False)
    try:
        with AuditFreezeLease(state) as audit_freeze:
            state_before = state_snapshot_tokens(state)
            saf = safety_gate(state, audit_freeze)
            report["phases"]["safety"] = saf
            if saf.get("status") != "OK": raise RuntimeError(f"safety gate failed: {saf}")
            resources = resource_preflight(tmp, args.temp_max, args.min_free_tmp)
            report["phases"]["resource_preflight"] = resources
            if resources.get("status") != "OK": raise RuntimeError(f"resource preflight failed: {resources.get('failed_checks')}")
            sc = parse_state_contract(state, Path(args.driver), Path(args.core))
            report["phases"]["state_contract"] = sc
            target = int(sc["height"]); report["target_height"] = target
            if args.expected_height is not None and target != int(args.expected_height):
                raise RuntimeError(f"checkpoint height={target} != expected-height={args.expected_height}")
            stage = load_stage(args)
            report["phases"]["stage_release"] = {"status":"OK","kind":stage["kind"],"sha256":stage["sha256"],"end_height":stage["end_height"]}
            if int(stage["end_height"]) < target: raise RuntimeError(f"Stage HWM={stage['end_height']} below target={target}")
            if str(stage["sha256"]).lower() != str(sc["source_sha256"]).lower():
                raise RuntimeError(f"V50/Stage source SHA mismatch state={sc['source_sha256']} stage={stage['sha256']}")
            stage_before = stage_snapshot_tokens(stage, target)
            sha_result = audit_stage_sha(stage, target, args.stage_sha)
            report["phases"]["stage_sha"] = {"status":"OK", **sha_result}
            duckdb = require_duckdb()
            progress = Path(args.progress_dir) if args.progress_dir else output_dir / "stage_semantics_progress"
            sem = phase(
                report, "stage_semantics",
                lambda: stage_semantics_windowed(
                    duckdb_module=duckdb, stage=stage, target=target, state_contract=sc,
                    auditor_sha256=report["auditor_sha256"], progress_base=progress,
                    allow_resume=not args.no_resume, memory=args.memory_limit, temp_max=args.temp_max,
                    threads=max(1,int(args.threads)), scratch_root=run_tmp / "windows",
                    min_free_tmp=args.min_free_tmp, stage_token_digest=_token_digest(stage_before),
                ),
            )
            if sem.get("status") != "OK": raise RuntimeError(f"Stage semantic audit failed: {sem.get('failed_checks')}")
            stage_after = stage_snapshot_tokens(stage, target)
            stage_stable = compare_token_maps(stage_before, stage_after)
            report["phases"]["stage_stable_snapshot"] = stage_stable
            if stage_stable.get("status") != "OK": raise RuntimeError(f"Stage changed during semantic audit: {stage_stable.get('changed_sample')}")
            state_after = state_snapshot_tokens(state)
            changed=[]
            for name in sorted(set(state_before)|set(state_after)):
                before=state_before.get(name); after=state_after.get(name)
                if name=="dirty.bin":
                    if (before or {}).get("exists") or (after or {}).get("exists"): changed.append("dirty.bin")
                elif before is None or after is None or not same_token(before,after): changed.append(name)
            stable={"status":"OK" if not changed else "BAD","changed":changed,
                    "before_digest":canonical_json_hash(state_before),"after_digest":canonical_json_hash(state_after)}
            report["phases"]["stable_snapshot"] = stable
            if changed: raise RuntimeError(f"V50 state changed during semantic audit: {changed}")
        report["status"]="GREEN"; report["finished_utc"]=utc_now(); report["elapsed_sec"]=round(time.monotonic()-started,3)
        output_dir.mkdir(parents=True, exist_ok=True)
        stem=f"audit_v51_5_4_stage_semantics_{report['target_height']}_GREEN_{utc_stamp()}_{uuid.uuid4().hex[:8]}"
        out=output_dir/f"{stem}.json"; digest=write_evidence(out,report)
        obj={"status":"GREEN","mode":"stage-semantics","target_height":target,"windows":f"{sem.get('windows_completed')}/{sem.get('windows_total')}",
             "peak_window_rss_bytes":sem.get("peak_window_rss_bytes"),"peak_window_temp_bytes":sem.get("peak_window_temp_bytes"),
             "report":str(out),"report_sha256":digest,"auditor_sha256":report["auditor_sha256"],"full_certification":False}
        if args.json: print(json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True))
        else:
            print(); print("STAGE SEMANTICS BOUNDED AUDIT  GREEN")
            print(f"Target height                   {target}")
            print(f"Windows                         {sem.get('windows_completed')}/{sem.get('windows_total')}")
            print(f"Peak window RSS                 {int(sem.get('peak_window_rss_bytes') or 0)/(1<<30):.2f} GiB")
            print(f"Peak window temp                {int(sem.get('peak_window_temp_bytes') or 0)/(1<<30):.2f} GiB")
            print(f"Progress                        {sem.get('progress_root')}")
            print(f"Report                          {out}")
            print(f"Report SHA256                   {digest}")
            print("Certification                   DIAGNOSTIC ONLY; full V51.5 audit still required")
        return 0
    except Exception as exc:
        report["finished_utc"]=utc_now(); report["status"]="FAILED"; report["elapsed_sec"]=round(time.monotonic()-started,3)
        # Map semantics-only argument names to the common classifier fields.
        setattr(args,"stage_semantics_memory_limit",args.memory_limit); setattr(args,"stage_semantics_threads",args.threads)
        report["fatal"]=classify_audit_failure(exc,report,args,tmp)
        report["error_type"]=report["fatal"]["error_type"]; report["failed_phase"]=report["fatal"]["failed_phase"]
        report["failure_classification"]=report["fatal"]["classification"]; report["failure_reason_code"]=report["fatal"]["reason_code"]; report["error"]=report["fatal"]["error"]
        try:
            output_dir.mkdir(parents=True,exist_ok=True)
            out=output_dir/f"audit_v51_5_4_stage_semantics_FATAL_{utc_stamp()}_{uuid.uuid4().hex[:8]}.json"; digest=write_evidence(out,report)
            print(json.dumps({"status":"FAILED","mode":"stage-semantics","classification":report["fatal"]["classification"],"reason_code":report["fatal"]["reason_code"],
                              "failed_phase":report["fatal"]["failed_phase"],"operator_message":report["fatal"]["operator_message"],
                              "recommended_action":report["fatal"]["recommended_action"],"error":report["fatal"]["error"],"report":str(out),"sha256":digest},
                             ensure_ascii=False,indent=2),file=sys.stderr)
        except Exception as report_exc:
            print(f"V51_STAGE_SEMANTICS_FATAL {type(exc).__name__}: {exc}; report_write_failed={type(report_exc).__name__}:{report_exc}",file=sys.stderr,flush=True)
        return 1
    finally:
        shutil.rmtree(run_tmp,ignore_errors=True)

def main(argv: Optional[Sequence[str]] = None) -> int:
    av = list(sys.argv[1:] if argv is None else argv)
    if av and av[0] == "core-stage":
        return core_stage_range_main(av[1:])
    if av and av[0] == "core-chain":
        return core_chain_guard_main(av[1:])
    if av and av[0] == "stage-semantics":
        return stage_semantics_only_main(av[1:])
    return full_main(av)


if __name__ == "__main__":
    sys.exit(main())
