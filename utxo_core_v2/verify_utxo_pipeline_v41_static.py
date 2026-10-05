#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import re
import sys
from pathlib import Path
from typing import Dict

EXPECTED_V40_SHA256 = "08b376031ccf73f0292574c45dc50b1ce358b31a9abe6ddc6cf7f04cb6cda46c"
EXPECTED_V30_SHA256 = "d8bd57a9702ef0a93afd0b51f9232306645827a93fea0253fb64e4d87f63921a"
PRESERVED_EXACT_FUNCTIONS = (
    "_core_prepare_apply_window",
    "_core_adjust_window_end_for_bip30",
    "_core_ensure_schema",
    "_core_final_audit",
    "_core_preflight_bip30",
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(8 * 1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def functions(text: str) -> Dict[str, ast.FunctionDef]:
    tree = ast.parse(text)
    return {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def source_function(text: str, funcs: Dict[str, ast.FunctionDef], name: str) -> str:
    node = funcs.get(name)
    if node is None:
        raise RuntimeError(f"function missing: {name}")
    return ast.get_source_segment(text, node) or ""


def normalized_apply_function(text: str, funcs: Dict[str, ast.FunctionDef]) -> str:
    src = source_function(text, funcs, "_core_apply_block_window")
    # v41 is permitted to parameterize only the release SHA and ledger contract;
    # causal SQL/body must remain byte-identical after normalizing those two
    # provenance values and the expanded function signature.
    lines = src.splitlines()
    lines[0] = "def _core_apply_block_window(...):"
    body = "\n".join(lines)
    body = body.replace("str(ledger_contract), str(source_global_manifest_sha256)",
                        "V40_CORE_LEDGER_CONTRACT, CORE_RELEASE_GLOBAL_MANIFEST_SHA256")
    return body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v30", default="/root/mybot/utxo_pipeline_v30.py")
    ap.add_argument("--v40", default="/root/mybot/utxo_pipeline_v40.py")
    ap.add_argument("--v41", default="/root/mybot/utxo_pipeline_v41.py")
    args = ap.parse_args()
    v30, v40, v41 = map(Path, (args.v30, args.v40, args.v41))
    failures = []
    if sha256(v30) != EXPECTED_V30_SHA256:
        failures.append("parent_v30_sha256")
    if sha256(v40) != EXPECTED_V40_SHA256:
        failures.append("frozen_v40_sha256")
    t40 = v40.read_text(encoding="utf-8", errors="replace")
    t41 = v41.read_text(encoding="utf-8", errors="replace")
    f40, f41 = functions(t40), functions(t41)
    for name in PRESERVED_EXACT_FUNCTIONS:
        if source_function(t40, f40, name) != source_function(t41, f41, name):
            failures.append(f"causal_function_changed:{name}")
    if normalized_apply_function(t40, f40) != normalized_apply_function(t41, f41):
        failures.append("apply_window_body_changed_beyond_provenance_parameterization")
    required = {
        "_v41_core_stage2_apply", "_v41_assert_single_writer_policy",
        "_v41_read_stage_release_descriptor", "_v41_validate_db_prefix",
        "_v41_validate_ledger_source_bindings", "_v41_load_effective_window",
        "_v41_save_scheduler",
    }
    missing = sorted(required - set(f41))
    failures += [f"missing_v41_function:{x}" for x in missing]
    if "required=1" not in source_function(t41, f41, "_v41_assert_single_writer_policy"):
        failures.append("single_writer_hard_lock_missing")
    apply_src = source_function(t41, f41, "_v41_core_stage2_apply")
    for token in (
        "effective_window = _v41_load_effective_window",
        "effective_window = int(next_size)",
        "V41_CORE_LEDGER_CONTRACT",
        "_v41_validate_db_prefix",
    ):
        if token not in apply_src:
            failures.append(f"v41_apply_contract_missing:{token}")
    # Main routing must send the Core rebuild mode to the v41 engine.
    if "rc = int(_v41_core_stage2_apply())" not in t41:
        failures.append("main_not_routed_to_v41")
    print(f"V30_SHA256: {sha256(v30)}")
    print(f"V40_SHA256: {sha256(v40)}")
    print(f"V41_SHA256: {sha256(v41)}")
    print(f"PRESERVED_CAUSAL_FUNCTIONS: {len(PRESERVED_EXACT_FUNCTIONS)}")
    print("UTXO_PIPELINE_V41_STATIC_VERIFICATION:", "GREEN" if not failures else "BAD")
    if failures:
        for item in failures:
            print("  -", item)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
