#!/usr/bin/env python3
# MyBot / UTXO Core v1
# Full Stage 2 — canonical Bitcoin block/transaction extractor.
#
# PURPOSE
# -------
# Decode every canonical block 0..617698 from frozen Bitcoin Core blk*.dat
# through the frozen Stage 1 physical locator, using the exact transaction
# decoder that passed Stage 2 preflight v2.2.
#
# Stage 2 is intentionally NOT the UTXO state builder. It materializes a
# consensus-validated transaction layer:
#   blocks.parquet
#   transactions.parquet
#   inputs.parquet
#   outputs.parquet
#
# Input scriptSig and witness payload bytes are fully parsed and committed by
# validated txid/wtxid, but are intentionally not duplicated into Stage 2.
# Inputs retain scriptSig size, witness item count and serialized witness size.
# Raw blk*.dat + Stage 1 locator remain the canonical byte source for exact
# scriptSig/witness re-read. Output scriptPubKey bytes ARE materialized because
# they are required by the downstream UTXO state.
#
# FULL RELEASE LAYOUT
# -------------------
# stage2/windows/window_000000_000999/
#   blocks.parquet
#   transactions.parquet
#   inputs.parquet
#   outputs.parquet
#   *.sha256
#   manifest.json
#
# ...
#
# stage2/manifests/canonical_transactions_0_617698.windows.tsv
# stage2/manifests/canonical_transactions_0_617698.windows.tsv.sha256
# stage2/manifests/canonical_transactions_0_617698.json
# stage2/manifests/canonical_transactions_0_617698.json.sha256
#
# SMOKE MODE
# ----------
#   python3 build_canonical_transactions.py --smoke 481824 481825
#
# Smoke output goes under:
#   stage2/audit/smoke_481824_481825/
#
# FAIL-CLOSED
# -----------
# - Requires frozen Stage 0, Stage 1, semantic audit and Stage 2 preflight.
# - Requires the exact preflight decoder source SHA that passed on real blocks.
# - Requires DuckDB 1.4.4 exactly.
# - Acquires Bitcoin Core datadir lock for the entire run.
# - Revalidates Stage 1 block-file inventory against current filesystem state.
# - Recomputes every canonical block hash, prevhash, txid/wtxid, Merkle root,
#   witness commitment, transaction context-free checks and exact boundaries.
# - Publishes each full window atomically only after Parquet and cross-table
#   validation succeeds.
# - Existing valid windows are resumable; invalid/partial outputs are fatal.
# - No global release manifest is emitted until all 618 windows are GREEN.

import argparse
import fcntl
from collections import OrderedDict
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Frozen project paths / provenance
# ---------------------------------------------------------------------------

BASE = Path("/opt/mybot_data/etl/utxo_core_v1")
DATADIR = Path("/opt/mybot_data/bitcoin")
BLOCKS_DIR = DATADIR / "blocks"

MANIFEST_DIR = BASE / "manifests"
STAGE1_DIR = BASE / "stage"
STAGE2_DIR = BASE / "stage2"
WINDOWS_DIR = STAGE2_DIR / "windows"
STAGE2_MANIFEST_DIR = STAGE2_DIR / "manifests"
STAGE2_AUDIT_DIR = STAGE2_DIR / "audit"
STAGE2_LOG_DIR = STAGE2_DIR / "logs"

TMP_ROOT = Path("/opt/mybot_tmp/utxo_core_v1_stage2")
DUCKDB_TMP = Path("/opt/mybot_tmp/duckdb_tmp")

START_HEIGHT = 0
END_HEIGHT = 617698
WINDOW_SIZE = 1000
EXPECTED_BLOCK_ROWS = END_HEIGHT - START_HEIGHT + 1
EXPECTED_WINDOW_COUNT = (EXPECTED_BLOCK_ROWS + WINDOW_SIZE - 1) // WINDOW_SIZE

CANONICAL_MANIFEST = MANIFEST_DIR / "canonical_chain_0_617698.tsv"
CANONICAL_MANIFEST_SHA = Path(str(CANONICAL_MANIFEST) + ".sha256")
CANONICAL_MANIFEST_META = MANIFEST_DIR / "canonical_chain_0_617698.meta.json"

LOCATOR = STAGE1_DIR / "block_locator_0_617698.tsv"
LOCATOR_SHA = Path(str(LOCATOR) + ".sha256")
LOCATOR_META = STAGE1_DIR / "block_locator_0_617698.meta.json"

INVENTORY = STAGE1_DIR / "block_files_inventory.tsv"
INVENTORY_SHA = Path(str(INVENTORY) + ".sha256")

SEMANTIC_AUDIT = STAGE1_DIR / "block_locator_0_617698.semantic_audit.json"
SEMANTIC_AUDIT_SHA = Path(str(SEMANTIC_AUDIT) + ".sha256")

PREFLIGHT_SCRIPT = Path("/root/mybot/stage2_decoder_preflight.py")
PREFLIGHT_AUDIT = STAGE2_AUDIT_DIR / "decoder_preflight_v2_2.json"
PREFLIGHT_AUDIT_SHA = Path(str(PREFLIGHT_AUDIT) + ".sha256")
PREFLIGHT_LOG = STAGE2_LOG_DIR / "decoder_preflight_v2_2.log"
PREFLIGHT_LOG_SHA = Path(str(PREFLIGHT_LOG) + ".sha256")

XOR_FILE = BLOCKS_DIR / "xor.dat"
DATADIR_LOCK = DATADIR / ".lock"

GLOBAL_MANIFEST = STAGE2_MANIFEST_DIR / "canonical_transactions_0_617698.json"
GLOBAL_MANIFEST_SHA = Path(str(GLOBAL_MANIFEST) + ".sha256")
GLOBAL_WINDOWS_TSV = (
    STAGE2_MANIFEST_DIR / "canonical_transactions_0_617698.windows.tsv"
)
GLOBAL_WINDOWS_TSV_SHA = Path(str(GLOBAL_WINDOWS_TSV) + ".sha256")

EXPECTED_MANIFEST_SHA256 = (
    "5227507e9b38fbdb63040c1e197cdfb9b39cc2d054c6744722113206c4847161"
)
EXPECTED_LOCATOR_SHA256 = (
    "0e045ecee898095f1a35789c2d21efccc737b390e998c2a0c79c6bf659c516ed"
)
EXPECTED_INVENTORY_SHA256 = (
    "e14cd67e47492c32e0f796782744878ab2c02c2b5b89b05dd0c339a27aee041c"
)
EXPECTED_SEMANTIC_AUDIT_SHA256 = (
    "422e652f850cbdf0f2c546b852a1d9e97dbb093c87e2c4cc46e3bedb154c4662"
)
EXPECTED_PREFLIGHT_SCRIPT_SHA256 = (
    "a981378473ea41f157eaf94c7de233ddbdab1985a4a618fd3962696c6cfa3ec9"
)
EXPECTED_PREFLIGHT_AUDIT_SHA256 = (
    "07aed6438f4a889534e73116de458d20c239ddd14a32705c76b3d2741161c532"
)
EXPECTED_PREFLIGHT_LOG_SHA256 = (
    "461603347b7f142d365df6d5bc58aafa0a8574476cfbe0858cb08f451fbaa38c"
)
EXPECTED_XOR_HEX = "2af1c3e24315d54b"
EXPECTED_XOR_SHA256 = (
    "b5e50a9b6a79fce708c9fcfb62a76c512aec637192961c94fd99ffe051b9d6e7"
)
EXPECTED_END_HASH = (
    "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
)
EXPECTED_TARGET_PREV_HASH = (
    "000000000000000000067461ebbba39991e7b65aa8c51ed2e3805834d6a74c1a"
)
EXPECTED_TARGET_MERKLE_ROOT = (
    "51d342fa7f79d8c02cf397b77e3060f29045c95dc4a488b0a21c76da12399308"
)
EXPECTED_TARGET_NTX = 313
EXPECTED_TARGET_SIZE = 116637
EXPECTED_TARGET_STRIPPED_SIZE = 87793
EXPECTED_TARGET_WEIGHT = 380016

EXPECTED_DUCKDB_VERSION = "1.4.4"

MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MAX_BLOCK_WEIGHT = 4_000_000
WITNESS_SCALE_FACTOR = 4
SEGWIT_ACTIVE_HEIGHT = 481824

PARQUET_COMPRESSION = "zstd"
PARQUET_ROW_GROUP_SIZE = 131072

DUCKDB_THREADS = 10
DUCKDB_MEMORY_LIMIT = "80GB"

BLK_RE = re.compile(r"^blk([0-9]{5})\.dat$")


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(16 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_file(path):
    with open(path, "rb") as f:
        os.fsync(f.fileno())


def atomic_write_text(path, text):
    tmp = Path(str(path) + ".tmp")
    if path.exists() or tmp.exists():
        raise RuntimeError(
            f"refuse overwrite/stale temp: path={path} tmp={tmp}"
        )

    with open(tmp, "x", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp, path)
    fsync_dir(path.parent)


def valid_hash(value, label):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise RuntimeError(f"{label}: invalid lowercase 64-char hash {value!r}")
    return value


def tsv_line(*values):
    fields = []
    for value in values:
        if isinstance(value, bool):
            value = "1" if value else "0"
        else:
            value = str(value)

        if "\t" in value or "\n" in value or "\r" in value:
            raise RuntimeError(f"unsafe TSV field: {value!r}")

        fields.append(value)

    return "\t".join(fields) + "\n"


def blob_hex_or_dash(data):
    return data.hex() if data else "-"


def sql_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def sidecar_sha_value(path):
    parts = path.read_text(encoding="utf-8").strip().split()
    if not parts:
        raise RuntimeError(f"empty SHA sidecar: {path}")
    return parts[0].lower()


def verify_sha(path, sidecar=None, expected=None):
    if not path.is_file():
        raise RuntimeError(f"missing artifact: {path}")

    actual = sha256_file(path)

    if sidecar is not None:
        if not sidecar.is_file():
            raise RuntimeError(f"missing SHA sidecar: {sidecar}")

        recorded = sidecar_sha_value(sidecar)
        if recorded != actual:
            raise RuntimeError(
                f"SHA sidecar mismatch for {path}\n"
                f"sidecar={recorded}\nactual ={actual}"
            )

    if expected is not None and actual != expected:
        raise RuntimeError(
            f"pinned SHA mismatch for {path}\n"
            f"expected={expected}\nactual  ={actual}"
        )

    return actual


def remove_tree_only_after_success(path):
    if path.exists():
        shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Frozen decoder loading / environment
# ---------------------------------------------------------------------------

def require_duckdb():
    try:
        import duckdb
    except Exception as exc:
        raise RuntimeError(
            "duckdb Python package is required; expected version "
            f"{EXPECTED_DUCKDB_VERSION}"
        ) from exc

    version = getattr(duckdb, "__version__", None)

    if version != EXPECTED_DUCKDB_VERSION:
        raise RuntimeError(
            "DuckDB version mismatch\n"
            f"expected={EXPECTED_DUCKDB_VERSION}\nactual  ={version}"
        )

    return duckdb


def load_frozen_decoder():
    actual = verify_sha(
        PREFLIGHT_SCRIPT,
        expected=EXPECTED_PREFLIGHT_SCRIPT_SHA256,
    )

    spec = importlib.util.spec_from_file_location(
        "mybot_frozen_stage2_decoder",
        str(PREFLIGHT_SCRIPT),
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load decoder module: {PREFLIGHT_SCRIPT}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    required = (
        "Reader",
        "sha256d",
        "display_hash",
        "encode_compact_size",
        "parse_transaction",
        "check_transaction_context_free",
        "merkle_root",
        "validate_witness_commitment",
        "xor_at",
    )

    for name in required:
        if not hasattr(module, name):
            raise RuntimeError(
                f"frozen decoder missing required symbol: {name}"
            )

    return module, actual


def require_core_stopped_and_lock():
    proc = subprocess.run(
        ["systemctl", "is-active", "bitcoind"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    state = proc.stdout.strip()

    if state != "inactive":
        raise RuntimeError(
            f"bitcoind service must be inactive, got {state!r}"
        )

    pgrep = subprocess.run(
        ["pgrep", "-x", "bitcoind"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if pgrep.returncode == 0:
        raise RuntimeError("bitcoind process exists outside systemd")

    if pgrep.returncode not in (0, 1):
        raise RuntimeError(
            f"pgrep bitcoind failed with rc={pgrep.returncode}"
        )

    if not DATADIR_LOCK.is_file():
        raise RuntimeError(
            f"Bitcoin Core datadir lock file missing: {DATADIR_LOCK}"
        )

    lock_fd = os.open(DATADIR_LOCK, os.O_RDWR)

    try:
        fcntl.lockf(
            lock_fd,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
            0,
            0,
            os.SEEK_SET,
        )
    except OSError as exc:
        os.close(lock_fd)
        raise RuntimeError(
            f"cannot acquire Bitcoin Core datadir lock: {exc}"
        ) from exc

    # Close TOCTOU gap.
    pgrep2 = subprocess.run(
        ["pgrep", "-x", "bitcoind"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if pgrep2.returncode == 0:
        os.close(lock_fd)
        raise RuntimeError(
            "bitcoind appeared while acquiring datadir lock"
        )

    if pgrep2.returncode not in (0, 1):
        os.close(lock_fd)
        raise RuntimeError(
            f"second pgrep bitcoind failed rc={pgrep2.returncode}"
        )

    return lock_fd


# ---------------------------------------------------------------------------
# Provenance and source loading
# ---------------------------------------------------------------------------

def verify_frozen_provenance():
    manifest_sha = verify_sha(
        CANONICAL_MANIFEST,
        CANONICAL_MANIFEST_SHA,
        EXPECTED_MANIFEST_SHA256,
    )

    locator_sha = verify_sha(
        LOCATOR,
        LOCATOR_SHA,
        EXPECTED_LOCATOR_SHA256,
    )

    inventory_sha = verify_sha(
        INVENTORY,
        INVENTORY_SHA,
        EXPECTED_INVENTORY_SHA256,
    )

    semantic_sha = verify_sha(
        SEMANTIC_AUDIT,
        SEMANTIC_AUDIT_SHA,
        EXPECTED_SEMANTIC_AUDIT_SHA256,
    )

    preflight_audit_sha = verify_sha(
        PREFLIGHT_AUDIT,
        PREFLIGHT_AUDIT_SHA,
        EXPECTED_PREFLIGHT_AUDIT_SHA256,
    )

    preflight_log_sha = verify_sha(
        PREFLIGHT_LOG,
        PREFLIGHT_LOG_SHA,
        EXPECTED_PREFLIGHT_LOG_SHA256,
    )

    xor_sha = verify_sha(
        XOR_FILE,
        expected=EXPECTED_XOR_SHA256,
    )

    xor_key = XOR_FILE.read_bytes()

    if len(xor_key) != 8:
        raise RuntimeError(f"xor.dat length={len(xor_key)}, expected 8")

    if xor_key.hex() != EXPECTED_XOR_HEX:
        raise RuntimeError(
            f"xor.dat key mismatch: {xor_key.hex()}"
        )

    manifest_meta = json.loads(
        CANONICAL_MANIFEST_META.read_text(encoding="utf-8")
    )

    if manifest_meta.get("release_complete") is not True:
        raise RuntimeError("Stage 0 release_complete != true")

    if manifest_meta.get("row_count") != EXPECTED_BLOCK_ROWS:
        raise RuntimeError("Stage 0 row_count mismatch")

    locator_meta = json.loads(
        LOCATOR_META.read_text(encoding="utf-8")
    )

    if locator_meta.get("release_complete") is not True:
        raise RuntimeError("Stage 1 release_complete != true")

    if locator_meta.get("row_count") != EXPECTED_BLOCK_ROWS:
        raise RuntimeError("Stage 1 row_count mismatch")

    semantic = json.loads(
        SEMANTIC_AUDIT.read_text(encoding="utf-8")
    )

    if semantic.get("status") != "GREEN":
        raise RuntimeError("Stage 1 semantic audit is not GREEN")

    preflight = json.loads(
        PREFLIGHT_AUDIT.read_text(encoding="utf-8")
    )

    if preflight.get("status") != "GREEN":
        raise RuntimeError("Stage 2 decoder preflight is not GREEN")

    if preflight.get("sample_blocks") != 11:
        raise RuntimeError("unexpected Stage 2 preflight sample count")

    if (
        preflight.get("script_sha256")
        != EXPECTED_PREFLIGHT_SCRIPT_SHA256
    ):
        raise RuntimeError(
            "preflight audit references unexpected decoder script SHA"
        )

    return {
        "manifest_sha256": manifest_sha,
        "locator_sha256": locator_sha,
        "inventory_sha256": inventory_sha,
        "semantic_audit_sha256": semantic_sha,
        "preflight_audit_sha256": preflight_audit_sha,
        "preflight_log_sha256": preflight_log_sha,
        "xor_sha256": xor_sha,
        "xor_key": xor_key,
    }


def load_manifest():
    hashes = []

    with open(CANONICAL_MANIFEST, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n")

        if header != "height\tblock_hash":
            raise RuntimeError(
                f"unexpected canonical manifest header: {header!r}"
            )

        expected_height = START_HEIGHT

        for line_no, line in enumerate(f, start=2):
            parts = line.rstrip("\n").split("\t")

            if len(parts) != 2:
                raise RuntimeError(
                    f"malformed manifest line {line_no}"
                )

            height = int(parts[0])
            block_hash = valid_hash(
                parts[1],
                f"manifest height={height}",
            )

            if height != expected_height:
                raise RuntimeError(
                    "manifest height gap/order error: "
                    f"expected={expected_height} actual={height}"
                )

            hashes.append(block_hash)
            expected_height += 1

    if len(hashes) != EXPECTED_BLOCK_ROWS:
        raise RuntimeError(
            f"manifest rows={len(hashes)}, expected={EXPECTED_BLOCK_ROWS}"
        )

    if hashes[-1] != EXPECTED_END_HASH:
        raise RuntimeError("manifest final anchor mismatch")

    if len(set(hashes)) != len(hashes):
        raise RuntimeError("duplicate canonical block hash in manifest")

    return hashes


def load_locator(manifest_hashes):
    rows = [None] * EXPECTED_BLOCK_ROWS

    expected_header = (
        "height\tblock_hash\tprev_hash\tblk_file\tfile_number\t"
        "record_offset\tblock_offset\tblock_size\trecord_size"
    )

    with open(LOCATOR, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n")

        if header != expected_header:
            raise RuntimeError(
                f"unexpected Stage 1 locator header: {header!r}"
            )

        for line_no, line in enumerate(f, start=2):
            parts = line.rstrip("\n").split("\t")

            if len(parts) != 9:
                raise RuntimeError(
                    f"malformed locator line {line_no}"
                )

            (
                height_s,
                block_hash,
                prev_hash,
                blk_file,
                file_number_s,
                record_offset_s,
                block_offset_s,
                block_size_s,
                record_size_s,
            ) = parts

            height = int(height_s)

            if not (START_HEIGHT <= height <= END_HEIGHT):
                raise RuntimeError(
                    f"locator height out of target: {height}"
                )

            if rows[height] is not None:
                raise RuntimeError(
                    f"duplicate locator height: {height}"
                )

            if block_hash != manifest_hashes[height]:
                raise RuntimeError(
                    f"locator/manifest hash mismatch height={height}"
                )

            expected_prev = (
                "0" * 64
                if height == 0
                else manifest_hashes[height - 1]
            )

            if prev_hash != expected_prev:
                raise RuntimeError(
                    f"locator prevhash mismatch height={height}"
                )

            match = BLK_RE.fullmatch(blk_file)

            if match is None:
                raise RuntimeError(
                    f"bad locator blk filename: {blk_file!r}"
                )

            file_number = int(file_number_s)

            if int(match.group(1)) != file_number:
                raise RuntimeError(
                    f"locator file-number mismatch height={height}"
                )

            record_offset = int(record_offset_s)
            block_offset = int(block_offset_s)
            block_size = int(block_size_s)
            record_size = int(record_size_s)

            if record_offset < 0:
                raise RuntimeError(
                    f"negative record offset height={height}"
                )

            if block_offset != record_offset + 8:
                raise RuntimeError(
                    f"bad block offset height={height}"
                )

            if not (
                81 <= block_size <= MAX_BLOCK_SERIALIZED_SIZE
            ):
                raise RuntimeError(
                    f"bad block size={block_size} height={height}"
                )

            if record_size != block_size + 8:
                raise RuntimeError(
                    f"bad record size height={height}"
                )

            rows[height] = {
                "height": height,
                "block_hash": block_hash,
                "prev_hash": prev_hash,
                "blk_file": blk_file,
                "file_number": file_number,
                "record_offset": record_offset,
                "block_offset": block_offset,
                "block_size": block_size,
                "record_size": record_size,
            }

    missing = [
        h for h, row in enumerate(rows)
        if row is None
    ]

    if missing:
        raise RuntimeError(
            f"missing locator heights={len(missing)} first={missing[:20]}"
        )

    return rows


def load_inventory():
    with open(INVENTORY, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n").split("\t")

        required = {
            "file_number",
            "blk_file",
            "size_bytes",
            "mtime_ns",
            "inode",
            "device",
        }

        if not required.issubset(set(header)):
            raise RuntimeError(
                f"inventory missing required columns: {header!r}"
            )

        # v1.1 inventory should also have ctime_ns. If absent, we keep the
        # Stage 1 pinned SHA and validate all other stable fields.
        index = {name: i for i, name in enumerate(header)}
        rows = []

        for line_no, line in enumerate(f, start=2):
            parts = line.rstrip("\n").split("\t")

            if len(parts) != len(header):
                raise RuntimeError(
                    f"malformed inventory line {line_no}"
                )

            row = {
                "file_number": int(parts[index["file_number"]]),
                "blk_file": parts[index["blk_file"]],
                "size_bytes": int(parts[index["size_bytes"]]),
                "mtime_ns": int(parts[index["mtime_ns"]]),
                "inode": int(parts[index["inode"]]),
                "device": int(parts[index["device"]]),
            }

            if "ctime_ns" in index:
                row["ctime_ns"] = int(parts[index["ctime_ns"]])

            rows.append(row)

    rows.sort(key=lambda x: x["file_number"])

    if not rows:
        raise RuntimeError("empty Stage 1 inventory")

    for expected, row in enumerate(rows):
        if row["file_number"] != expected:
            raise RuntimeError(
                "inventory blk numbering gap: "
                f"expected={expected} actual={row['file_number']}"
            )

        if row["blk_file"] != f"blk{expected:05d}.dat":
            raise RuntimeError(
                f"inventory filename mismatch at {expected}"
            )

    return rows


def verify_block_files_against_inventory(inventory):
    for i, expected in enumerate(inventory, start=1):
        path = BLOCKS_DIR / expected["blk_file"]

        if not path.is_file():
            raise RuntimeError(f"missing block file: {path}")

        st = path.stat()

        checks = {
            "size_bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "inode": st.st_ino,
            "device": st.st_dev,
        }

        if "ctime_ns" in expected:
            checks["ctime_ns"] = st.st_ctime_ns

        for field, actual in checks.items():
            if expected[field] != actual:
                raise RuntimeError(
                    "block source differs from frozen Stage 1 inventory\n"
                    f"file={path}\nfield={field}\n"
                    f"expected={expected[field]}\nactual  ={actual}"
                )

        if i % 1000 == 0:
            print(
                f"inventory re-stat {i}/{len(inventory)} files",
                flush=True,
            )


# ---------------------------------------------------------------------------
# Physical block read and full decode
# ---------------------------------------------------------------------------

class BlockFileReader:
    """Small LRU of read-only blk*.dat file descriptors for extraction speed."""

    def __init__(self, xor_key, decoder, max_open=32):
        self.xor_key = xor_key
        self.decoder = decoder
        self.max_open = max_open
        self._fds = OrderedDict()

    def _get_fd(self, blk_file):
        fd = self._fds.pop(blk_file, None)

        if fd is not None:
            self._fds[blk_file] = fd
            return fd

        path = BLOCKS_DIR / blk_file

        if not path.is_file():
            raise RuntimeError(f"missing block file: {path}")

        fd = os.open(path, os.O_RDONLY)
        self._fds[blk_file] = fd

        while len(self._fds) > self.max_open:
            _, old_fd = self._fds.popitem(last=False)
            os.close(old_fd)

        return fd

    def read(self, locator_row):
        blk_file = locator_row["blk_file"]
        fd = self._get_fd(blk_file)

        record_offset = locator_row["record_offset"]
        block_offset = locator_row["block_offset"]
        block_size = locator_row["block_size"]

        st = os.fstat(fd)

        if record_offset + 8 + block_size > st.st_size:
            raise RuntimeError(
                f"locator record extends beyond {blk_file}"
            )

        raw_storage = os.pread(fd, 8, record_offset)
        raw_block = os.pread(fd, block_size, block_offset)

        if len(raw_storage) != 8:
            raise RuntimeError(
                f"short storage-header read "
                f"{blk_file}@{record_offset}"
            )

        if len(raw_block) != block_size:
            raise RuntimeError(
                f"short block read {blk_file}@{block_offset}"
            )

        storage = self.decoder.xor_at(
            raw_storage,
            record_offset,
            self.xor_key,
        )

        if storage[:4] != MAINNET_MAGIC:
            raise RuntimeError(
                f"mainnet magic mismatch "
                f"{blk_file}@{record_offset}"
            )

        stored_size = struct.unpack("<I", storage[4:8])[0]

        if stored_size != block_size:
            raise RuntimeError(
                "storage/locator block size mismatch "
                f"height={locator_row['height']} "
                f"storage={stored_size} locator={block_size}"
            )

        return self.decoder.xor_at(
            raw_block,
            block_offset,
            self.xor_key,
        )

    def close(self):
        while self._fds:
            _, fd = self._fds.popitem(last=False)
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def decode_block_full(
    block,
    height,
    expected_hash,
    expected_prev,
    decoder,
):
    label = f"height={height}"

    if len(block) < 81:
        raise RuntimeError(
            f"{label}: block too short size={len(block)}"
        )

    if len(block) > MAX_BLOCK_SERIALIZED_SIZE:
        raise RuntimeError(
            f"{label}: serialized block too large size={len(block)}"
        )

    r = decoder.Reader(block, label)
    header = r.read(80)

    header_hash = decoder.display_hash(
        decoder.sha256d(header)
    )

    if header_hash != expected_hash:
        raise RuntimeError(
            f"{label}: block hash mismatch "
            f"expected={expected_hash} actual={header_hash}"
        )

    version_i32 = struct.unpack("<i", header[0:4])[0]
    prev_hash = header[4:36][::-1].hex()
    merkle_header_raw = header[36:68]
    block_time = struct.unpack("<I", header[68:72])[0]
    bits = struct.unpack("<I", header[72:76])[0]
    nonce = struct.unpack("<I", header[76:80])[0]

    if prev_hash != expected_prev:
        raise RuntimeError(
            f"{label}: previousblockhash mismatch"
        )

    tx_count = r.compact_size()

    if tx_count == 0:
        raise RuntimeError(f"{label}: zero transactions")

    if tx_count * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise RuntimeError(
            f"{label}: impossible transaction count={tx_count}"
        )

    txs = []

    for tx_index in range(tx_count):
        tx = decoder.parse_transaction(r, tx_index)
        decoder.check_transaction_context_free(
            tx,
            label,
            tx_index,
        )
        txs.append(tx)

    if r.pos != len(block):
        raise RuntimeError(
            f"{label}: exact block boundary failure "
            f"parsed={r.pos} size={len(block)} remaining={r.remaining()}"
        )

    if not txs[0]["is_coinbase"]:
        raise RuntimeError(
            f"{label}: transaction 0 is not coinbase"
        )

    for tx_index, tx in enumerate(txs[1:], start=1):
        if tx["is_coinbase"]:
            raise RuntimeError(
                f"{label}: extra coinbase tx_index={tx_index}"
            )

    root_raw, mutated = decoder.merkle_root(
        [tx["txid_raw"] for tx in txs]
    )

    if mutated:
        raise RuntimeError(
            f"{label}: mutated transaction merkle tree"
        )

    if root_raw != merkle_header_raw:
        raise RuntimeError(
            f"{label}: transaction merkle root mismatch "
            f"header={merkle_header_raw[::-1].hex()} "
            f"calculated={root_raw[::-1].hex()}"
        )

    stripped_size = (
        80
        + len(decoder.encode_compact_size(tx_count))
        + sum(tx["stripped_size"] for tx in txs)
    )

    weight = stripped_size * 3 + len(block)

    if weight > MAX_BLOCK_WEIGHT:
        raise RuntimeError(
            f"{label}: block weight={weight} > {MAX_BLOCK_WEIGHT}"
        )

    segwit_active = height >= SEGWIT_ACTIVE_HEIGHT

    witness = decoder.validate_witness_commitment(
        txs,
        label,
        segwit_active=segwit_active,
    )

    result = {
        "height": height,
        "block_hash": header_hash,
        "prev_hash": prev_hash,
        "merkle_root": root_raw[::-1].hex(),
        "version_i32": version_i32,
        "time": block_time,
        "bits": bits,
        "nonce": nonce,
        "block_size": len(block),
        "stripped_size": stripped_size,
        "weight": weight,
        "tx_count": tx_count,
        "witness_tx_count": sum(
            1 for tx in txs if tx["has_witness"]
        ),
        "txid_wtxid_diff_count": sum(
            1
            for tx in txs
            if tx["txid_raw"] != tx["wtxid_raw"]
        ),
        "witness_commitment_present": bool(
            witness["present"]
        ),
        "witness_commitment_index": (
            witness["index"]
            if witness["index"] is not None
            else -1
        ),
        "txs": txs,
    }

    if height == END_HEIGHT:
        frozen = {
            "block_hash": EXPECTED_END_HASH,
            "prev_hash": EXPECTED_TARGET_PREV_HASH,
            "merkle_root": EXPECTED_TARGET_MERKLE_ROOT,
            "block_size": EXPECTED_TARGET_SIZE,
            "stripped_size": EXPECTED_TARGET_STRIPPED_SIZE,
            "weight": EXPECTED_TARGET_WEIGHT,
            "tx_count": EXPECTED_TARGET_NTX,
        }

        for key, expected in frozen.items():
            actual = result[key]
            if actual != expected:
                raise RuntimeError(
                    f"{label}: independent frozen Core anchor "
                    f"{key} mismatch expected={expected} actual={actual}"
                )

        if not result["witness_commitment_present"]:
            raise RuntimeError(
                f"{label}: final anchor witness commitment missing"
            )

    return result


def witness_stack_serialized_size(stack, decoder):
    size = len(decoder.encode_compact_size(len(stack)))

    for item in stack:
        size += len(decoder.encode_compact_size(len(item)))
        size += len(item)

    return size


# ---------------------------------------------------------------------------
# TSV staging
# ---------------------------------------------------------------------------

BLOCKS_HEADER = (
    "height\tblock_hash\tprev_hash\tmerkle_root\tversion_i32\t"
    "block_time\tbits\tnonce\tblock_size\tstripped_size\tweight\t"
    "tx_count\twitness_tx_count\ttxid_wtxid_diff_count\t"
    "witness_commitment_present\twitness_commitment_index\t"
    "blk_file\tfile_number\trecord_offset\tblock_offset\n"
)

TRANSACTIONS_HEADER = (
    "height\ttx_index\ttxid\twtxid\tversion_i32\tlocktime\t"
    "vin_count\tvout_count\tserialized_size\tstripped_size\tweight\t"
    "is_coinbase\thas_witness\ttxid_wtxid_differ\n"
)

INPUTS_HEADER = (
    "height\ttx_index\ttxid\tvin_index\tprev_txid\tprev_vout\t"
    "script_sig_size\tsequence\twitness_item_count\t"
    "witness_serialized_size\n"
)

OUTPUTS_HEADER = (
    "height\ttx_index\ttxid\tvout\tvalue_sats\t"
    "script_pubkey_hex\tscript_pubkey_size\n"
)


def open_staging_files(stage_tmp):
    paths = {
        "blocks": stage_tmp / "blocks.tsv",
        "transactions": stage_tmp / "transactions.tsv",
        "inputs": stage_tmp / "inputs.tsv",
        "outputs": stage_tmp / "outputs.tsv",
    }

    files = {}

    for name, path in paths.items():
        files[name] = open(
            path,
            "x",
            encoding="ascii",
            buffering=4 * 1024 * 1024,
        )

    files["blocks"].write(BLOCKS_HEADER)
    files["transactions"].write(TRANSACTIONS_HEADER)
    files["inputs"].write(INPUTS_HEADER)
    files["outputs"].write(OUTPUTS_HEADER)

    return paths, files


def close_fsync_staging(files):
    first_error = None

    for f in files.values():
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception as exc:
            if first_error is None:
                first_error = exc

        try:
            f.close()
        except Exception as exc:
            if first_error is None:
                first_error = exc

    if first_error is not None:
        raise first_error


def write_decoded_block(
    decoded,
    locator_row,
    block,
    files,
    decoder,
    counters,
):
    files["blocks"].write(
        tsv_line(
            decoded["height"],
            decoded["block_hash"],
            decoded["prev_hash"],
            decoded["merkle_root"],
            decoded["version_i32"],
            decoded["time"],
            decoded["bits"],
            decoded["nonce"],
            decoded["block_size"],
            decoded["stripped_size"],
            decoded["weight"],
            decoded["tx_count"],
            decoded["witness_tx_count"],
            decoded["txid_wtxid_diff_count"],
            decoded["witness_commitment_present"],
            decoded["witness_commitment_index"],
            locator_row["blk_file"],
            locator_row["file_number"],
            locator_row["record_offset"],
            locator_row["block_offset"],
        )
    )

    counters["blocks"] += 1
    counters["block_bytes"] += decoded["block_size"]
    counters["stripped_block_bytes"] += decoded["stripped_size"]
    counters["block_weight"] += decoded["weight"]
    counters["witness_transactions"] += decoded["witness_tx_count"]
    counters["txid_wtxid_differences"] += decoded[
        "txid_wtxid_diff_count"
    ]

    for tx_index, tx in enumerate(decoded["txs"]):
        version_i32 = struct.unpack(
            "<i",
            block[tx["start"]:tx["start"] + 4],
        )[0]

        tx_weight = (
            tx["stripped_size"] * 3
            + tx["size"]
        )

        files["transactions"].write(
            tsv_line(
                decoded["height"],
                tx_index,
                tx["txid"],
                tx["wtxid"],
                version_i32,
                tx["locktime"],
                tx["vin_count"],
                tx["vout_count"],
                tx["size"],
                tx["stripped_size"],
                tx_weight,
                tx["is_coinbase"],
                tx["has_witness"],
                tx["txid_raw"] != tx["wtxid_raw"],
            )
        )

        counters["transactions"] += 1

        for vin_index, txin in enumerate(tx["inputs"]):
            if tx["has_witness"]:
                stack = tx["witnesses"][vin_index]
                witness_count = len(stack)
                witness_size = witness_stack_serialized_size(
                    stack,
                    decoder,
                )
            else:
                witness_count = 0
                witness_size = 0

            files["inputs"].write(
                tsv_line(
                    decoded["height"],
                    tx_index,
                    tx["txid"],
                    vin_index,
                    txin["prev_txid"],
                    txin["prev_vout"],
                    len(txin["script_sig"]),
                    txin["sequence"],
                    witness_count,
                    witness_size,
                )
            )

            counters["inputs"] += 1

        for vout, txout in enumerate(tx["outputs"]):
            files["outputs"].write(
                tsv_line(
                    decoded["height"],
                    tx_index,
                    tx["txid"],
                    vout,
                    txout["value"],
                    blob_hex_or_dash(
                        txout["script_pubkey"]
                    ),
                    len(txout["script_pubkey"]),
                )
            )

            counters["outputs"] += 1


# ---------------------------------------------------------------------------
# DuckDB TSV -> typed Parquet
# ---------------------------------------------------------------------------

def configure_duckdb(con):
    DUCKDB_TMP.mkdir(parents=True, exist_ok=True)

    con.execute(f"SET threads={DUCKDB_THREADS}")
    con.execute(
        f"SET memory_limit={sql_quote(DUCKDB_MEMORY_LIMIT)}"
    )
    con.execute(
        f"SET temp_directory={sql_quote(str(DUCKDB_TMP))}"
    )
    con.execute("SET preserve_insertion_order=true")


def parquet_copy_sql(select_sql, output_path):
    return f"""
COPY (
{select_sql}
)
TO {sql_quote(str(output_path))}
(
    FORMAT parquet,
    COMPRESSION {PARQUET_COMPRESSION},
    ROW_GROUP_SIZE {PARQUET_ROW_GROUP_SIZE}
)
"""


def convert_tsv_to_parquet(duckdb, stage_paths, release_tmp):
    safe_name = release_tmp.name.replace(".", "_")
    db_path = TMP_ROOT / f"duckdb_{safe_name}.duckdb"
    wal_path = Path(str(db_path) + ".wal")

    stale = [p for p in (db_path, wal_path) if p.exists()]
    if stale:
        raise RuntimeError(
            "stale DuckDB staging artifact(s); inspect/remove explicitly: "
            + ", ".join(str(p) for p in stale)
        )

    con = duckdb.connect(str(db_path))
    success = False

    try:
        configure_duckdb(con)

        # blocks
        con.execute("""
CREATE TEMP TABLE raw_blocks (
    height VARCHAR,
    block_hash VARCHAR,
    prev_hash VARCHAR,
    merkle_root VARCHAR,
    version_i32 VARCHAR,
    block_time VARCHAR,
    bits VARCHAR,
    nonce VARCHAR,
    block_size VARCHAR,
    stripped_size VARCHAR,
    weight VARCHAR,
    tx_count VARCHAR,
    witness_tx_count VARCHAR,
    txid_wtxid_diff_count VARCHAR,
    witness_commitment_present VARCHAR,
    witness_commitment_index VARCHAR,
    blk_file VARCHAR,
    file_number VARCHAR,
    record_offset VARCHAR,
    block_offset VARCHAR
)
""")
        con.execute(
            "COPY raw_blocks FROM "
            f"{sql_quote(str(stage_paths['blocks']))} "
            "(FORMAT csv, DELIMITER '\t', HEADER true)"
        )

        select_blocks = """
SELECT
    CAST(height AS INTEGER) AS height,
    block_hash,
    prev_hash,
    merkle_root,
    CAST(version_i32 AS INTEGER) AS version_i32,
    CAST(block_time AS BIGINT) AS block_time,
    CAST(bits AS BIGINT) AS bits,
    CAST(nonce AS BIGINT) AS nonce,
    CAST(block_size AS BIGINT) AS block_size,
    CAST(stripped_size AS BIGINT) AS stripped_size,
    CAST(weight AS BIGINT) AS weight,
    CAST(tx_count AS BIGINT) AS tx_count,
    CAST(witness_tx_count AS BIGINT) AS witness_tx_count,
    CAST(txid_wtxid_diff_count AS BIGINT) AS txid_wtxid_diff_count,
    witness_commitment_present = '1' AS witness_commitment_present,
    CAST(witness_commitment_index AS INTEGER) AS witness_commitment_index,
    blk_file,
    CAST(file_number AS INTEGER) AS file_number,
    CAST(record_offset AS BIGINT) AS record_offset,
    CAST(block_offset AS BIGINT) AS block_offset
FROM raw_blocks
ORDER BY height
"""
        con.execute(
            parquet_copy_sql(
                select_blocks,
                release_tmp / "blocks.parquet",
            )
        )
        con.execute("DROP TABLE raw_blocks")

        # transactions
        con.execute("""
CREATE TEMP TABLE raw_transactions (
    height VARCHAR,
    tx_index VARCHAR,
    txid VARCHAR,
    wtxid VARCHAR,
    version_i32 VARCHAR,
    locktime VARCHAR,
    vin_count VARCHAR,
    vout_count VARCHAR,
    serialized_size VARCHAR,
    stripped_size VARCHAR,
    weight VARCHAR,
    is_coinbase VARCHAR,
    has_witness VARCHAR,
    txid_wtxid_differ VARCHAR
)
""")
        con.execute(
            "COPY raw_transactions FROM "
            f"{sql_quote(str(stage_paths['transactions']))} "
            "(FORMAT csv, DELIMITER '\t', HEADER true)"
        )

        select_transactions = """
SELECT
    CAST(height AS INTEGER) AS height,
    CAST(tx_index AS INTEGER) AS tx_index,
    txid,
    wtxid,
    CAST(version_i32 AS INTEGER) AS version_i32,
    CAST(locktime AS BIGINT) AS locktime,
    CAST(vin_count AS BIGINT) AS vin_count,
    CAST(vout_count AS BIGINT) AS vout_count,
    CAST(serialized_size AS BIGINT) AS serialized_size,
    CAST(stripped_size AS BIGINT) AS stripped_size,
    CAST(weight AS BIGINT) AS weight,
    is_coinbase = '1' AS is_coinbase,
    has_witness = '1' AS has_witness,
    txid_wtxid_differ = '1' AS txid_wtxid_differ
FROM raw_transactions
ORDER BY height, tx_index
"""
        con.execute(
            parquet_copy_sql(
                select_transactions,
                release_tmp / "transactions.parquet",
            )
        )
        con.execute("DROP TABLE raw_transactions")

        # inputs
        con.execute("""
CREATE TEMP TABLE raw_inputs (
    height VARCHAR,
    tx_index VARCHAR,
    txid VARCHAR,
    vin_index VARCHAR,
    prev_txid VARCHAR,
    prev_vout VARCHAR,
    script_sig_size VARCHAR,
    sequence VARCHAR,
    witness_item_count VARCHAR,
    witness_serialized_size VARCHAR
)
""")
        con.execute(
            "COPY raw_inputs FROM "
            f"{sql_quote(str(stage_paths['inputs']))} "
            "(FORMAT csv, DELIMITER '\t', HEADER true)"
        )

        select_inputs = """
SELECT
    CAST(height AS INTEGER) AS height,
    CAST(tx_index AS INTEGER) AS tx_index,
    txid,
    CAST(vin_index AS INTEGER) AS vin_index,
    prev_txid,
    CAST(prev_vout AS BIGINT) AS prev_vout,
    CAST(script_sig_size AS BIGINT) AS script_sig_size,
    CAST(sequence AS BIGINT) AS sequence,
    CAST(witness_item_count AS BIGINT) AS witness_item_count,
    CAST(witness_serialized_size AS BIGINT) AS witness_serialized_size
FROM raw_inputs
ORDER BY height, tx_index, vin_index
"""
        con.execute(
            parquet_copy_sql(
                select_inputs,
                release_tmp / "inputs.parquet",
            )
        )
        con.execute("DROP TABLE raw_inputs")

        # outputs
        con.execute("""
CREATE TEMP TABLE raw_outputs (
    height VARCHAR,
    tx_index VARCHAR,
    txid VARCHAR,
    vout VARCHAR,
    value_sats VARCHAR,
    script_pubkey_hex VARCHAR,
    script_pubkey_size VARCHAR
)
""")
        con.execute(
            "COPY raw_outputs FROM "
            f"{sql_quote(str(stage_paths['outputs']))} "
            "(FORMAT csv, DELIMITER '\t', HEADER true)"
        )

        select_outputs = """
SELECT
    CAST(height AS INTEGER) AS height,
    CAST(tx_index AS INTEGER) AS tx_index,
    txid,
    CAST(vout AS BIGINT) AS vout,
    CAST(value_sats AS BIGINT) AS value_sats,
    CASE
        WHEN script_pubkey_hex = '-' THEN encode('')
        ELSE from_hex(script_pubkey_hex)
    END AS script_pubkey,
    CAST(script_pubkey_size AS BIGINT) AS script_pubkey_size
FROM raw_outputs
ORDER BY height, tx_index, vout
"""
        con.execute(
            parquet_copy_sql(
                select_outputs,
                release_tmp / "outputs.parquet",
            )
        )
        con.execute("DROP TABLE raw_outputs")
        success = True

    finally:
        con.close()

        if success:
            if wal_path.exists():
                wal_path.unlink()
            if db_path.exists():
                db_path.unlink()


# ---------------------------------------------------------------------------
# Parquet validation
# ---------------------------------------------------------------------------

def parquet_count(con, path):
    return con.execute(
        f"SELECT count(*) FROM read_parquet({sql_quote(str(path))})"
    ).fetchone()[0]


def validate_parquets(
    duckdb,
    release_tmp,
    range_start,
    range_end,
    counters,
):
    con = duckdb.connect(":memory:")

    try:
        configure_duckdb(con)

        paths = {
            name: release_tmp / f"{name}.parquet"
            for name in (
                "blocks",
                "transactions",
                "inputs",
                "outputs",
            )
        }

        for path in paths.values():
            if not path.is_file() or path.stat().st_size <= 0:
                raise RuntimeError(
                    f"missing/empty parquet output: {path}"
                )

        counts = {
            name: parquet_count(con, path)
            for name, path in paths.items()
        }

        expected_counts = {
            "blocks": counters["blocks"],
            "transactions": counters["transactions"],
            "inputs": counters["inputs"],
            "outputs": counters["outputs"],
        }

        if counts != expected_counts:
            raise RuntimeError(
                "Parquet row-count mismatch\n"
                f"expected={expected_counts}\nactual  ={counts}"
            )

        block_summary = con.execute(
            f"""
SELECT
    min(height),
    max(height),
    count(DISTINCT height),
    count(DISTINCT block_hash),
    sum(tx_count),
    sum(witness_tx_count),
    sum(txid_wtxid_diff_count)
FROM read_parquet({sql_quote(str(paths['blocks']))})
"""
        ).fetchone()

        expected_block_rows = range_end - range_start + 1

        if block_summary[0] != range_start:
            raise RuntimeError("blocks.parquet min height mismatch")

        if block_summary[1] != range_end:
            raise RuntimeError("blocks.parquet max height mismatch")

        if block_summary[2] != expected_block_rows:
            raise RuntimeError(
                "blocks.parquet distinct height count mismatch"
            )

        if block_summary[3] != expected_block_rows:
            raise RuntimeError(
                "blocks.parquet distinct hash count mismatch"
            )

        if block_summary[4] != counters["transactions"]:
            raise RuntimeError(
                "sum(block.tx_count) != transaction rows"
            )

        if block_summary[5] != counters["witness_transactions"]:
            raise RuntimeError(
                "sum(block.witness_tx_count) mismatch"
            )

        if block_summary[6] != counters["txid_wtxid_differences"]:
            raise RuntimeError(
                "sum(block.txid_wtxid_diff_count) mismatch"
            )

        tx_summary = con.execute(
            f"""
SELECT
    count(*),
    sum(vin_count),
    sum(vout_count),
    sum(CASE WHEN is_coinbase THEN 1 ELSE 0 END),
    sum(CASE WHEN txid_wtxid_differ THEN 1 ELSE 0 END),
    count(*) FILTER (
        WHERE length(txid) <> 64 OR length(wtxid) <> 64
    )
FROM read_parquet({sql_quote(str(paths['transactions']))})
"""
        ).fetchone()

        tx_duplicate_keys = con.execute(
            f"""
SELECT count(*)
FROM (
    SELECT height, tx_index
    FROM read_parquet({sql_quote(str(paths['transactions']))})
    GROUP BY height, tx_index
    HAVING count(*) <> 1
)
"""
        ).fetchone()[0]

        if tx_duplicate_keys != 0:
            raise RuntimeError(
                "duplicate (height, tx_index) transaction key"
            )

        if tx_summary[1] != counters["inputs"]:
            raise RuntimeError(
                "sum(vin_count) != inputs rows"
            )

        if tx_summary[2] != counters["outputs"]:
            raise RuntimeError(
                "sum(vout_count) != outputs rows"
            )

        if tx_summary[3] != expected_block_rows:
            raise RuntimeError(
                "coinbase transaction count != block count"
            )

        if tx_summary[4] != counters["txid_wtxid_differences"]:
            raise RuntimeError(
                "transaction txid/wtxid difference count mismatch"
            )

        if tx_summary[5] != 0:
            raise RuntimeError(
                "invalid transaction hash string length"
            )

        input_summary = con.execute(
            f"""
SELECT
    count(*),
    count(*) FILTER (
        WHERE length(prev_txid) <> 64
    ),
    count(*) FILTER (
        WHERE script_sig_size < 0
           OR witness_item_count < 0
           OR witness_serialized_size < 0
    )
FROM read_parquet({sql_quote(str(paths['inputs']))})
"""
        ).fetchone()

        input_duplicate_keys = con.execute(
            f"""
SELECT count(*)
FROM (
    SELECT height, tx_index, vin_index
    FROM read_parquet({sql_quote(str(paths['inputs']))})
    GROUP BY height, tx_index, vin_index
    HAVING count(*) <> 1
)
"""
        ).fetchone()[0]

        if input_duplicate_keys != 0:
            raise RuntimeError(
                "duplicate input positional key"
            )

        if input_summary[1] != 0:
            raise RuntimeError(
                "invalid prev_txid string length"
            )

        if input_summary[2] != 0:
            raise RuntimeError(
                "negative input size/count metadata"
            )

        output_summary = con.execute(
            f"""
SELECT
    count(*),
    count(*) FILTER (
        WHERE octet_length(script_pubkey) <> script_pubkey_size
    ),
    count(*) FILTER (
        WHERE value_sats < 0 OR value_sats > 2100000000000000
    )
FROM read_parquet({sql_quote(str(paths['outputs']))})
"""
        ).fetchone()

        output_duplicate_keys = con.execute(
            f"""
SELECT count(*)
FROM (
    SELECT height, tx_index, vout
    FROM read_parquet({sql_quote(str(paths['outputs']))})
    GROUP BY height, tx_index, vout
    HAVING count(*) <> 1
)
"""
        ).fetchone()[0]

        if output_duplicate_keys != 0:
            raise RuntimeError(
                "duplicate output positional key"
            )

        if output_summary[1] != 0:
            raise RuntimeError(
                "scriptPubKey BLOB length mismatch"
            )

        if output_summary[2] != 0:
            raise RuntimeError(
                "output value outside MoneyRange"
            )

        return counts

    finally:
        con.close()


# ---------------------------------------------------------------------------
# Window release manifests / resume
# ---------------------------------------------------------------------------

def range_name(start, end):
    return f"window_{start:06d}_{end:06d}"


def window_dir(start, end):
    return WINDOWS_DIR / range_name(start, end)


def window_manifest_path(start, end):
    return window_dir(start, end) / "manifest.json"


def expected_window_ranges():
    ranges = []

    start = START_HEIGHT

    while start <= END_HEIGHT:
        end = min(start + WINDOW_SIZE - 1, END_HEIGHT)
        ranges.append((start, end))
        start = end + 1

    if len(ranges) != EXPECTED_WINDOW_COUNT:
        raise RuntimeError(
            f"internal window-count error: {len(ranges)}"
        )

    return ranges


def build_file_sha_map(directory):
    result = {}

    for name in (
        "blocks.parquet",
        "transactions.parquet",
        "inputs.parquet",
        "outputs.parquet",
    ):
        path = directory / name
        result[name] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }

    return result


def write_sha_sidecars(directory, files):
    for name, info in files.items():
        sidecar = directory / f"{name}.sha256"

        with open(sidecar, "x", encoding="ascii") as f:
            f.write(f"{info['sha256']}  {name}\n")
            f.flush()
            os.fsync(f.fileno())


def validate_existing_window(
    directory,
    start,
    end,
    provenance,
    script_sha,
    duckdb=None,
    full_parquet_check=False,
):
    manifest_path = directory / "manifest.json"
    manifest_sidecar = directory / "manifest.json.sha256"

    if not manifest_path.is_file() or not manifest_sidecar.is_file():
        raise RuntimeError(
            f"existing window has no manifest/sidecar: {directory}"
        )

    manifest_actual_sha = sha256_file(manifest_path)

    if sidecar_sha_value(manifest_sidecar) != manifest_actual_sha:
        raise RuntimeError(
            f"existing window manifest SHA sidecar mismatch: {directory}"
        )

    obj = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    if obj.get("release_complete") is not True:
        raise RuntimeError(
            f"existing window not release_complete: {directory}"
        )

    if obj.get("start_height") != start:
        raise RuntimeError(
            f"existing window start mismatch: {directory}"
        )

    if obj.get("end_height") != end:
        raise RuntimeError(
            f"existing window end mismatch: {directory}"
        )

    if obj.get("extractor_script_sha256") != script_sha:
        raise RuntimeError(
            "existing window built by different extractor script\n"
            f"window={directory}"
        )

    frozen = obj.get("provenance", {})

    expected_provenance = {
        "stage0_manifest_sha256": provenance["manifest_sha256"],
        "stage1_locator_sha256": provenance["locator_sha256"],
        "stage1_inventory_sha256": provenance["inventory_sha256"],
        "stage1_semantic_audit_sha256": provenance[
            "semantic_audit_sha256"
        ],
        "stage2_preflight_audit_sha256": provenance[
            "preflight_audit_sha256"
        ],
        "stage2_preflight_log_sha256": provenance[
            "preflight_log_sha256"
        ],
        "stage2_decoder_script_sha256": (
            EXPECTED_PREFLIGHT_SCRIPT_SHA256
        ),
        "xor_dat_sha256": provenance["xor_sha256"],
    }

    if frozen != expected_provenance:
        raise RuntimeError(
            f"existing window provenance mismatch: {directory}"
        )

    files = obj.get("files", {})

    expected_names = {
        "blocks.parquet",
        "transactions.parquet",
        "inputs.parquet",
        "outputs.parquet",
    }

    if set(files) != expected_names:
        raise RuntimeError(
            f"existing window file set mismatch: {directory}"
        )

    for name in sorted(expected_names):
        path = directory / name
        sidecar = directory / f"{name}.sha256"

        if not path.is_file() or not sidecar.is_file():
            raise RuntimeError(
                f"missing existing window file/sidecar: {path}"
            )

        actual = sha256_file(path)

        if files[name].get("sha256") != actual:
            raise RuntimeError(
                f"existing window manifest SHA mismatch: {path}"
            )

        if sidecar_sha_value(sidecar) != actual:
            raise RuntimeError(
                f"existing window sidecar SHA mismatch: {path}"
            )

        if files[name].get("size_bytes") != path.stat().st_size:
            raise RuntimeError(
                f"existing window size mismatch: {path}"
            )

    if full_parquet_check:
        if duckdb is None:
            raise RuntimeError(
                "internal: duckdb required for full window validation"
            )

        counters = obj.get("counts", {})

        validate_parquets(
            duckdb,
            directory,
            start,
            end,
            counters,
        )

    return obj


def publish_range(
    range_start,
    range_end,
    output_final,
    output_tmp,
    stage_tmp,
    manifest_schema,
    provenance,
    script_sha,
    decoder_sha,
    duckdb,
    manifest_extra=None,
):
    if output_final.exists():
        raise RuntimeError(
            f"refuse overwrite final range directory: {output_final}"
        )

    if output_tmp.exists():
        raise RuntimeError(
            f"stale output temp exists: {output_tmp}"
        )

    if stage_tmp.exists():
        raise RuntimeError(
            f"stale staging temp exists: {stage_tmp}"
        )

    output_tmp.mkdir(parents=True)
    stage_tmp.mkdir(parents=True)

    counters = {
        "blocks": 0,
        "transactions": 0,
        "inputs": 0,
        "outputs": 0,
        "witness_transactions": 0,
        "txid_wtxid_differences": 0,
        "block_bytes": 0,
        "stripped_block_bytes": 0,
        "block_weight": 0,
    }

    started = time.time()

    return {
        "counters": counters,
        "started": started,
    }


def finalize_range(
    range_start,
    range_end,
    output_final,
    output_tmp,
    stage_tmp,
    manifest_schema,
    provenance,
    script_sha,
    decoder_sha,
    duckdb,
    counters,
    started,
    stage_paths,
    manifest_extra=None,
):
    convert_tsv_to_parquet(
        duckdb,
        stage_paths,
        output_tmp,
    )

    parquet_counts = validate_parquets(
        duckdb,
        output_tmp,
        range_start,
        range_end,
        counters,
    )

    files = build_file_sha_map(output_tmp)
    write_sha_sidecars(output_tmp, files)

    obj = {
        "schema": manifest_schema,
        "release_complete": True,
        "created_utc": utc_now(),
        "start_height": range_start,
        "end_height": range_end,
        "block_rows": range_end - range_start + 1,
        "window_size_setting": WINDOW_SIZE,
        "duckdb_version": EXPECTED_DUCKDB_VERSION,
        "parquet": {
            "compression": PARQUET_COMPRESSION,
            "row_group_size": PARQUET_ROW_GROUP_SIZE,
        },
        "counts": counters,
        "validated_parquet_counts": parquet_counts,
        "files": files,
        "extractor_script_sha256": script_sha,
        "decoder_script_sha256": decoder_sha,
        "provenance": {
            "stage0_manifest_sha256": provenance[
                "manifest_sha256"
            ],
            "stage1_locator_sha256": provenance[
                "locator_sha256"
            ],
            "stage1_inventory_sha256": provenance[
                "inventory_sha256"
            ],
            "stage1_semantic_audit_sha256": provenance[
                "semantic_audit_sha256"
            ],
            "stage2_preflight_audit_sha256": provenance[
                "preflight_audit_sha256"
            ],
            "stage2_preflight_log_sha256": provenance[
                "preflight_log_sha256"
            ],
            "stage2_decoder_script_sha256": decoder_sha,
            "xor_dat_sha256": provenance["xor_sha256"],
        },
        "validation": {
            "canonical_block_hash_all": True,
            "canonical_prevhash_all": True,
            "exact_block_boundary_all": True,
            "context_free_tx_checks_all": True,
            "txid_wtxid_all": True,
            "merkle_root_all": True,
            "witness_commitment_all": True,
            "parquet_cross_table_counts": True,
            "parquet_output_script_blob_lengths": True,
        },
        "elapsed_seconds": round(time.time() - started, 6),
    }

    if manifest_extra:
        obj.update(manifest_extra)

    manifest_path = output_tmp / "manifest.json"

    with open(manifest_path, "x", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())

    manifest_sha = sha256_file(manifest_path)

    with open(
        output_tmp / "manifest.json.sha256",
        "x",
        encoding="ascii",
    ) as f:
        f.write(
            f"{manifest_sha}  manifest.json\n"
        )
        f.flush()
        os.fsync(f.fileno())

    fsync_dir(output_tmp)

    os.replace(output_tmp, output_final)
    fsync_dir(output_final.parent)

    # Post-publication manifest/sidecar check before deleting raw TSVs.
    verify_sha(
        output_final / "manifest.json",
        output_final / "manifest.json.sha256",
        manifest_sha,
    )

    # Only after atomic publication do we remove raw staging TSVs.
    remove_tree_only_after_success(stage_tmp)

    return obj, manifest_sha


# ---------------------------------------------------------------------------
# Extraction orchestration
# ---------------------------------------------------------------------------

def extract_range(
    range_start,
    range_end,
    output_final,
    output_tmp,
    stage_tmp,
    manifest_schema,
    manifest_hashes,
    locator_rows,
    xor_key,
    decoder,
    provenance,
    script_sha,
    decoder_sha,
    duckdb,
    manifest_extra=None,
):
    state = publish_range(
        range_start,
        range_end,
        output_final,
        output_tmp,
        stage_tmp,
        manifest_schema,
        provenance,
        script_sha,
        decoder_sha,
        duckdb,
        manifest_extra,
    )

    counters = state["counters"]
    started = state["started"]

    stage_paths = None
    files = None

    try:
        stage_paths, files = open_staging_files(stage_tmp)

        with BlockFileReader(
            xor_key,
            decoder,
            max_open=32,
        ) as block_reader:
            for height in range(range_start, range_end + 1):
                loc = locator_rows[height]

                block = block_reader.read(loc)

                expected_prev = (
                    "0" * 64
                    if height == 0
                    else manifest_hashes[height - 1]
                )

                decoded = decode_block_full(
                    block,
                    height,
                    manifest_hashes[height],
                    expected_prev,
                    decoder,
                )

                write_decoded_block(
                    decoded,
                    loc,
                    block,
                    files,
                    decoder,
                    counters,
                )

                if (
                    height == range_start
                    or (height - range_start + 1) % 100 == 0
                    or height == range_end
                ):
                    elapsed = time.time() - started
                    print(
                        f"height={height:6d} "
                        f"range={range_start:06d}-{range_end:06d} "
                        f"blocks={counters['blocks']:,} "
                        f"tx={counters['transactions']:,} "
                        f"vin={counters['inputs']:,} "
                        f"vout={counters['outputs']:,} "
                        f"elapsed={elapsed:.1f}s",
                        flush=True,
                    )

        close_fsync_staging(files)
        files = None

        print(
            f"PARQUET_BUILD range={range_start:06d}-{range_end:06d}",
            flush=True,
        )

        obj, manifest_sha = finalize_range(
            range_start,
            range_end,
            output_final,
            output_tmp,
            stage_tmp,
            manifest_schema,
            provenance,
            script_sha,
            decoder_sha,
            duckdb,
            counters,
            started,
            stage_paths,
            manifest_extra,
        )

        print(
            f"RANGE_GREEN {range_start:06d}-{range_end:06d} "
            f"blocks={counters['blocks']:,} "
            f"tx={counters['transactions']:,} "
            f"vin={counters['inputs']:,} "
            f"vout={counters['outputs']:,} "
            f"manifest_sha256={manifest_sha}",
            flush=True,
        )

        return obj

    except Exception:
        if files is not None:
            for f in files.values():
                try:
                    f.close()
                except Exception:
                    pass

        print(
            "RANGE_FAILED; temp artifacts intentionally preserved:\n"
            f"  parquet temp: {output_tmp}\n"
            f"  TSV staging : {stage_tmp}",
            file=sys.stderr,
            flush=True,
        )
        raise


def run_smoke(
    start,
    end,
    manifest_hashes,
    locator_rows,
    xor_key,
    decoder,
    provenance,
    script_sha,
    decoder_sha,
    duckdb,
):
    if not (START_HEIGHT <= start <= end <= END_HEIGHT):
        raise RuntimeError(
            f"invalid smoke range: {start}..{end}"
        )

    name = f"smoke_{start:06d}_{end:06d}"
    output_final = STAGE2_AUDIT_DIR / name
    output_tmp = STAGE2_AUDIT_DIR / f".{name}.tmp"
    stage_tmp = TMP_ROOT / f"{name}.tmp"

    if output_final.exists():
        raise RuntimeError(
            f"smoke output already exists; refuse overwrite: {output_final}"
        )

    extract_range(
        start,
        end,
        output_final,
        output_tmp,
        stage_tmp,
        "mybot_stage2_smoke_v1",
        manifest_hashes,
        locator_rows,
        xor_key,
        decoder,
        provenance,
        script_sha,
        decoder_sha,
        duckdb,
        manifest_extra={
            "run_mode": "smoke",
        },
    )

    print()
    print("============================================")
    print("STAGE 2 SMOKE RELEASE COMPLETE")
    print("============================================")
    print(f"range  = {start}..{end}")
    print(f"output = {output_final}")


def validate_global_release_if_present(
    provenance,
    script_sha,
    duckdb,
):
    present = [
        GLOBAL_MANIFEST.exists(),
        GLOBAL_MANIFEST_SHA.exists(),
        GLOBAL_WINDOWS_TSV.exists(),
        GLOBAL_WINDOWS_TSV_SHA.exists(),
    ]

    if not any(present):
        return False

    if not all(present):
        raise RuntimeError(
            "partial global Stage 2 manifest publication exists"
        )

    global_sha = verify_sha(
        GLOBAL_MANIFEST,
        GLOBAL_MANIFEST_SHA,
    )

    windows_tsv_sha = verify_sha(
        GLOBAL_WINDOWS_TSV,
        GLOBAL_WINDOWS_TSV_SHA,
    )

    obj = json.loads(
        GLOBAL_MANIFEST.read_text(encoding="utf-8")
    )

    if obj.get("release_complete") is not True:
        raise RuntimeError(
            "existing global Stage 2 manifest not complete"
        )

    if obj.get("extractor_script_sha256") != script_sha:
        raise RuntimeError(
            "existing global Stage 2 built by different script"
        )

    if obj.get("window_count") != EXPECTED_WINDOW_COUNT:
        raise RuntimeError(
            "existing global Stage 2 window_count mismatch"
        )

    if (
        obj.get("windows_tsv", {}).get("sha256")
        != windows_tsv_sha
    ):
        raise RuntimeError(
            "global windows TSV SHA does not match global manifest"
        )

    # A global "complete" marker is only accepted after every physical window
    # and every file checksum is revalidated.
    ranges = expected_window_ranges()

    for index, (start, end) in enumerate(ranges, start=1):
        directory = window_dir(start, end)

        if not directory.is_dir():
            raise RuntimeError(
                f"global release missing window directory: {directory}"
            )

        validate_existing_window(
            directory,
            start,
            end,
            provenance,
            script_sha,
            duckdb=duckdb,
            full_parquet_check=False,
        )

        if index % 50 == 0 or index == len(ranges):
            print(
                f"GLOBAL_REVERIFY windows={index}/{len(ranges)}",
                flush=True,
            )

    print(
        "GLOBAL_STAGE2_ALREADY_COMPLETE "
        f"sha256={global_sha}"
    )

    return True


def publish_global_manifest(
    windows,
    provenance,
    script_sha,
):
    if (
        GLOBAL_MANIFEST.exists()
        or GLOBAL_MANIFEST_SHA.exists()
        or GLOBAL_WINDOWS_TSV.exists()
        or GLOBAL_WINDOWS_TSV_SHA.exists()
    ):
        raise RuntimeError(
            "refuse overwrite existing global Stage 2 manifest artifacts"
        )

    windows_tmp = Path(str(GLOBAL_WINDOWS_TSV) + ".tmp")
    windows_sha_tmp = Path(str(GLOBAL_WINDOWS_TSV_SHA) + ".tmp")
    global_tmp = Path(str(GLOBAL_MANIFEST) + ".tmp")
    global_sha_tmp = Path(str(GLOBAL_MANIFEST_SHA) + ".tmp")

    temps = (
        windows_tmp,
        windows_sha_tmp,
        global_tmp,
        global_sha_tmp,
    )

    stale = [p for p in temps if p.exists()]

    if stale:
        raise RuntimeError(
            "stale global manifest temp(s): "
            + ", ".join(str(p) for p in stale)
        )

    totals = {
        "blocks": 0,
        "transactions": 0,
        "inputs": 0,
        "outputs": 0,
        "witness_transactions": 0,
        "txid_wtxid_differences": 0,
        "block_bytes": 0,
        "stripped_block_bytes": 0,
        "block_weight": 0,
    }

    with open(windows_tmp, "x", encoding="ascii") as f:
        f.write(
            "window_start\twindow_end\twindow_manifest_sha256\t"
            "blocks_sha256\ttransactions_sha256\tinputs_sha256\t"
            "outputs_sha256\tblocks\ttransactions\tinputs\toutputs\n"
        )

        expected_start = START_HEIGHT

        for item in windows:
            start = item["start"]
            end = item["end"]
            obj = item["manifest"]

            if start != expected_start:
                raise RuntimeError(
                    "global window continuity failure "
                    f"expected_start={expected_start} actual={start}"
                )

            expected_start = end + 1

            counts = obj["counts"]
            files = obj["files"]

            for key in totals:
                totals[key] += counts[key]

            f.write(
                tsv_line(
                    start,
                    end,
                    item["manifest_sha256"],
                    files["blocks.parquet"]["sha256"],
                    files["transactions.parquet"]["sha256"],
                    files["inputs.parquet"]["sha256"],
                    files["outputs.parquet"]["sha256"],
                    counts["blocks"],
                    counts["transactions"],
                    counts["inputs"],
                    counts["outputs"],
                )
            )

        if expected_start != END_HEIGHT + 1:
            raise RuntimeError(
                "global window coverage does not reach target end"
            )

        f.flush()
        os.fsync(f.fileno())

    windows_sha = sha256_file(windows_tmp)

    with open(windows_sha_tmp, "x", encoding="ascii") as f:
        f.write(
            f"{windows_sha}  {GLOBAL_WINDOWS_TSV.name}\n"
        )
        f.flush()
        os.fsync(f.fileno())

    global_obj = {
        "schema": "mybot_stage2_canonical_transactions_v1",
        "release_complete": True,
        "created_utc": utc_now(),
        "start_height": START_HEIGHT,
        "end_height": END_HEIGHT,
        "block_rows": EXPECTED_BLOCK_ROWS,
        "window_size": WINDOW_SIZE,
        "window_count": len(windows),
        "totals": totals,
        "windows_tsv": {
            "file": GLOBAL_WINDOWS_TSV.name,
            "sha256": windows_sha,
        },
        "extractor_script_sha256": script_sha,
        "decoder_script_sha256": EXPECTED_PREFLIGHT_SCRIPT_SHA256,
        "duckdb_version": EXPECTED_DUCKDB_VERSION,
        "provenance": {
            "stage0_manifest_sha256": provenance[
                "manifest_sha256"
            ],
            "stage1_locator_sha256": provenance[
                "locator_sha256"
            ],
            "stage1_inventory_sha256": provenance[
                "inventory_sha256"
            ],
            "stage1_semantic_audit_sha256": provenance[
                "semantic_audit_sha256"
            ],
            "stage2_preflight_audit_sha256": provenance[
                "preflight_audit_sha256"
            ],
            "stage2_preflight_log_sha256": provenance[
                "preflight_log_sha256"
            ],
            "xor_dat_sha256": provenance["xor_sha256"],
        },
        "validation": {
            "all_windows_release_complete": True,
            "all_window_file_sha256_verified": True,
            "height_coverage_contiguous": True,
            "canonical_block_hash_all": True,
            "canonical_prevhash_all": True,
            "exact_block_boundary_all": True,
            "context_free_tx_checks_all": True,
            "txid_wtxid_all": True,
            "merkle_root_all": True,
            "witness_commitment_all": True,
            "parquet_cross_table_counts_all": True,
        },
    }

    with open(global_tmp, "x", encoding="utf-8") as f:
        json.dump(global_obj, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())

    global_sha = sha256_file(global_tmp)

    with open(global_sha_tmp, "x", encoding="ascii") as f:
        f.write(
            f"{global_sha}  {GLOBAL_MANIFEST.name}\n"
        )
        f.flush()
        os.fsync(f.fileno())

    os.replace(windows_tmp, GLOBAL_WINDOWS_TSV)
    os.replace(windows_sha_tmp, GLOBAL_WINDOWS_TSV_SHA)
    fsync_dir(STAGE2_MANIFEST_DIR)

    os.replace(global_tmp, GLOBAL_MANIFEST)
    os.replace(global_sha_tmp, GLOBAL_MANIFEST_SHA)
    fsync_dir(STAGE2_MANIFEST_DIR)

    # Post-publication verification.
    verify_sha(
        GLOBAL_WINDOWS_TSV,
        GLOBAL_WINDOWS_TSV_SHA,
        windows_sha,
    )

    verify_sha(
        GLOBAL_MANIFEST,
        GLOBAL_MANIFEST_SHA,
        global_sha,
    )

    return global_obj, global_sha


def run_full(
    manifest_hashes,
    locator_rows,
    xor_key,
    decoder,
    provenance,
    script_sha,
    decoder_sha,
    duckdb,
):
    if validate_global_release_if_present(
        provenance,
        script_sha,
        duckdb,
    ):
        return

    ranges = expected_window_ranges()
    completed = []

    print(
        f"FULL_STAGE2 windows={len(ranges)} "
        f"range={START_HEIGHT}..{END_HEIGHT} "
        f"window_size={WINDOW_SIZE}"
    )

    for index, (start, end) in enumerate(ranges, start=1):
        final_dir = window_dir(start, end)
        tmp_dir = WINDOWS_DIR / f".{range_name(start, end)}.tmp"
        stage_tmp = TMP_ROOT / f"{range_name(start, end)}.tmp"

        if tmp_dir.exists() or stage_tmp.exists():
            raise RuntimeError(
                "stale temp blocks resume; inspect/remove explicitly\n"
                f"parquet_temp={tmp_dir}\n"
                f"staging_temp={stage_tmp}"
            )

        if final_dir.exists():
            print(
                f"RESUME_VERIFY window={index}/{len(ranges)} "
                f"{start:06d}-{end:06d}",
                flush=True,
            )

            obj = validate_existing_window(
                final_dir,
                start,
                end,
                provenance,
                script_sha,
                duckdb=duckdb,
                full_parquet_check=False,
            )

            manifest_sha = sha256_file(
                final_dir / "manifest.json"
            )

            completed.append({
                "start": start,
                "end": end,
                "manifest": obj,
                "manifest_sha256": manifest_sha,
            })

            print(
                f"RESUME_GREEN {start:06d}-{end:06d}",
                flush=True,
            )
            continue

        print()
        print(
            f"=== WINDOW {index}/{len(ranges)} "
            f"{start:06d}-{end:06d} ===",
            flush=True,
        )

        obj = extract_range(
            start,
            end,
            final_dir,
            tmp_dir,
            stage_tmp,
            "mybot_stage2_window_v1",
            manifest_hashes,
            locator_rows,
            xor_key,
            decoder,
            provenance,
            script_sha,
            decoder_sha,
            duckdb,
            manifest_extra={
                "run_mode": "full",
                "window_index": index,
                "window_count": len(ranges),
            },
        )

        manifest_sha = sha256_file(
            final_dir / "manifest.json"
        )

        completed.append({
            "start": start,
            "end": end,
            "manifest": obj,
            "manifest_sha256": manifest_sha,
        })

    if len(completed) != EXPECTED_WINDOW_COUNT:
        raise RuntimeError(
            f"completed windows={len(completed)}, "
            f"expected={EXPECTED_WINDOW_COUNT}"
        )

    print()
    print("=== GLOBAL STAGE 2 RELEASE ===")

    global_obj, global_sha = publish_global_manifest(
        completed,
        provenance,
        script_sha,
    )

    print()
    print("==================================================")
    print("FULL STAGE 2 CANONICAL TRANSACTIONS RELEASE COMPLETE")
    print("==================================================")
    print(f"windows      = {global_obj['window_count']}")
    print(f"blocks       = {global_obj['totals']['blocks']}")
    print(f"transactions = {global_obj['totals']['transactions']}")
    print(f"inputs       = {global_obj['totals']['inputs']}")
    print(f"outputs      = {global_obj['totals']['outputs']}")
    print(f"manifest sha = {global_sha}")
    print(f"manifest     = {GLOBAL_MANIFEST}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test():
    if EXPECTED_WINDOW_COUNT != 618:
        raise RuntimeError(
            f"selftest: expected 618 windows, got {EXPECTED_WINDOW_COUNT}"
        )

    ranges = expected_window_ranges()

    if ranges[0] != (0, 999):
        raise RuntimeError("selftest: first window mismatch")

    if ranges[-1] != (617000, 617698):
        raise RuntimeError("selftest: last window mismatch")

    if len(ranges) != 618:
        raise RuntimeError("selftest: window count mismatch")

    if sum(end - start + 1 for start, end in ranges) != 617699:
        raise RuntimeError("selftest: block coverage mismatch")

    if blob_hex_or_dash(b"") != "-":
        raise RuntimeError("selftest: empty BLOB sentinel")

    if blob_hex_or_dash(b"\xaa\xbb") != "aabb":
        raise RuntimeError("selftest: BLOB hex encoding")

    if tsv_line(1, True, "abc") != "1\t1\tabc\n":
        raise RuntimeError("selftest: TSV formatter")

    if BLK_RE.fullmatch("blk01968.dat") is None:
        raise RuntimeError("selftest: blk regex positive")

    if BLK_RE.fullmatch("../blk01968.dat") is not None:
        raise RuntimeError("selftest: blk regex traversal")

    if EXPECTED_TARGET_NTX != 313:
        raise RuntimeError("selftest: target nTx anchor")

    if EXPECTED_TARGET_SIZE != 116637:
        raise RuntimeError("selftest: target size anchor")

    if EXPECTED_TARGET_STRIPPED_SIZE != 87793:
        raise RuntimeError("selftest: target stripped-size anchor")

    if EXPECTED_TARGET_WEIGHT != 380016:
        raise RuntimeError("selftest: target weight anchor")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "MyBot Stage 2 canonical block/transaction extractor"
        )
    )

    parser.add_argument(
        "--smoke",
        nargs=2,
        type=int,
        metavar=("START", "END"),
        help=(
            "extract one isolated smoke range under stage2/audit; "
            "does not touch full windows"
        ),
    )

    return parser.parse_args()


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    os.umask(0o027)

    print("=== MYBOT FULL STAGE 2 CANONICAL TRANSACTION EXTRACTOR v1.2 ===")
    print()

    print("=== INTERNAL SELFTEST ===")
    self_test()
    print("SELFTEST_OK")
    print()

    args = parse_args()

    WINDOWS_DIR.mkdir(parents=True, exist_ok=True)
    STAGE2_MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    STAGE2_AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    STAGE2_LOG_DIR.mkdir(parents=True, exist_ok=True)
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    DUCKDB_TMP.mkdir(parents=True, exist_ok=True)

    script_path = Path(__file__).resolve()
    script_sha = sha256_file(script_path)

    print("=== EXTRACTOR ===")
    print(f"script={script_path}")
    print(f"sha256={script_sha}")
    print()

    print("=== DUCKDB ===")
    duckdb = require_duckdb()
    print(
        f"DUCKDB_OK version={duckdb.__version__} "
        f"threads={DUCKDB_THREADS} "
        f"memory_limit={DUCKDB_MEMORY_LIMIT}"
    )
    print()

    print("=== FROZEN STAGE 2 DECODER ===")
    decoder, decoder_sha = load_frozen_decoder()
    print(f"DECODER_OK sha256={decoder_sha}")
    print()

    print("=== CORE / DATADIR LOCK ===")
    lock_fd = require_core_stopped_and_lock()
    print(
        f"CORE_DATADIR_LOCK_OK path={DATADIR_LOCK} fd={lock_fd}"
    )
    print()

    try:
        print("=== VERIFY FROZEN PROVENANCE ===")
        provenance = verify_frozen_provenance()

        for key in (
            "manifest_sha256",
            "locator_sha256",
            "inventory_sha256",
            "semantic_audit_sha256",
            "preflight_audit_sha256",
            "preflight_log_sha256",
            "xor_sha256",
        ):
            print(f"{key}={provenance[key]}")
        print()

        print("=== LOAD CANONICAL MANIFEST / LOCATOR ===")
        manifest_hashes = load_manifest()
        locator_rows = load_locator(manifest_hashes)

        print(
            f"MANIFEST_LOCATOR_OK rows={len(locator_rows)} "
            f"end_hash={manifest_hashes[-1]}"
        )
        print()

        print("=== VERIFY BLOCK SOURCE AGAINST STAGE 1 INVENTORY ===")
        inventory = load_inventory()
        verify_block_files_against_inventory(inventory)

        print(
            f"BLOCK_SOURCE_OK files={len(inventory)}"
        )
        print()

        if args.smoke is not None:
            start, end = args.smoke

            run_smoke(
                start,
                end,
                manifest_hashes,
                locator_rows,
                provenance["xor_key"],
                decoder,
                provenance,
                script_sha,
                decoder_sha,
                duckdb,
            )
        else:
            run_full(
                manifest_hashes,
                locator_rows,
                provenance["xor_key"],
                decoder,
                provenance,
                script_sha,
                decoder_sha,
                duckdb,
            )

        print()
        print("=== FINAL SOURCE RE-STAT ===")
        verify_block_files_against_inventory(inventory)
        print("FINAL_BLOCK_SOURCE_UNCHANGED_OK")

    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print()
        print(f"FATAL: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
