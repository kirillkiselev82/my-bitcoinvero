from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .config import Config
from .util import atomic_json, fsync_dir, verify_sidecar


def current_path(cfg: Config) -> Path:
    return cfg.run_dir / "current.json"


def last_path(cfg: Config) -> Path:
    return cfg.run_dir / "last_run.json"


def read_current(cfg: Config) -> Optional[Dict[str, Any]]:
    p = current_path(cfg)
    if not p.exists():
        return None
    try:
        o = json.loads(p.read_text())
        return o if isinstance(o, dict) else None
    except Exception:
        return None


def write_current(cfg: Config, obj: Dict[str, Any]) -> None:
    atomic_json(current_path(cfg), obj)


def clear_current(cfg: Config) -> None:
    p = current_path(cfg)
    try:
        p.unlink()
    except FileNotFoundError:
        return
    fsync_dir(p.parent)


def write_last(cfg: Config, obj: Dict[str, Any]) -> None:
    atomic_json(last_path(cfg), obj)


def duckdb_scalar(cfg: Config, sql: str) -> Optional[str]:
    if not cfg.db.exists():
        return None
    code = (
        "import duckdb,sys; db=sys.argv[1]; q=sys.argv[2]; "
        "c=duckdb.connect(db,read_only=True); r=c.execute(q).fetchone(); c.close(); "
        "print('' if r is None or r[0] is None else r[0])"
    )
    p = subprocess.run(
        [str(cfg.python), "-c", code, str(cfg.db), sql],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        return None
    return p.stdout.strip()


def apply_hwm(cfg: Config) -> Optional[int]:
    v = duckdb_scalar(cfg, "SELECT max(block_number) FROM block_meta")
    try:
        return int(v) if v not in (None, "") else (-1 if cfg.db.exists() else None)
    except Exception:
        return None


def apply_tip_time(cfg: Config) -> Optional[str]:
    return duckdb_scalar(
        cfg,
        "SELECT CAST(block_timestamp AS VARCHAR) FROM block_meta ORDER BY block_number DESC LIMIT 1",
    )


def latest_stage_release(cfg: Config) -> Optional[Path]:
    items = []
    if cfg.stage_release_dir.exists():
        for p in cfg.stage_release_dir.glob("stage_release_0_*.json"):
            try:
                h = int(p.stem.split("_")[-1])
            except Exception:
                continue
            if Path(str(p) + ".sha256").is_file():
                items.append((h, p))
    return max(items, key=lambda x: x[0])[1] if items else None


def source_stage_hwm(cfg: Config) -> Dict[str, Any]:
    """Read Source/Stage HWM through the engine's read-only status command."""
    cmd = [
        str(cfg.python), str(cfg.build_stage),
        "--base", str(cfg.v2_base),
        "--legacy-base", str(cfg.legacy_base),
        "--datadir", str(cfg.datadir),
        "--tmp-root", str(cfg.tmpdir.parent / "utxo_core_v2_stage"),
        "--extractor", str(cfg.extractor),
        "--decoder", str(cfg.decoder),
        "--locator-reference", str(cfg.locator_reference),
        "--bitcoin-cli", str(cfg.bitcoin_cli),
        "--stop-file", str(cfg.stop_file),
        "status",
    ]
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return {"status": "UNKNOWN", "error": p.stderr.strip() or p.stdout.strip()}
    try:
        obj = json.loads(p.stdout)
    except Exception as exc:
        return {"status": "UNKNOWN", "error": f"status JSON parse failed: {exc}"}
    if not isinstance(obj, dict):
        return {"status": "UNKNOWN", "error": "status response is not object"}
    obj["status"] = "OK"
    return obj


def latest_audit_hwm(cfg: Config) -> Optional[int]:
    root = cfg.v2_base / "audit"
    if not root.exists():
        return None
    candidates = []
    for p in root.glob("audit_*.json"):
        if p.name.startswith("audit_FATAL_"):
            continue
        try:
            raw = p.stem.split("_")[1]
            h = int(raw)
        except Exception:
            continue
        side = Path(str(p) + ".sha256")
        if not side.is_file():
            continue
        try:
            verify_sidecar(p)
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(obj, dict) and str(obj.get("status", "")).startswith(("FINAL_GREEN", "AUDIT_GREEN")):
            candidates.append((h, p))
    return max(candidates, key=lambda x: x[0])[0] if candidates else None
