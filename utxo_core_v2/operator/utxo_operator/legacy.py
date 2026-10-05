from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .util import iter_cmdlines

LAUNCH_RE = re.compile(r"CORE APPLY worker launch range=(\d+)-(\d+).*?size=(\d+).*?attempt=(\d+)")
COMMIT_RE = re.compile(r"CORE APPLY COMMITTED range=(\d+)-(\d+).*?created=(\d+).*?spends=(\d+).*?elapsed=([0-9.]+)s")
OOM_RE = re.compile(r"(?:OOM|out of memory|OutOfMemory)", re.I)
PREFLIGHT_GREEN_RE = re.compile(r"CORE STAGE2 SOURCE PREFLIGHT: GREEN")


def _read_tail(path: Path, max_bytes: int = 32 * 1024 * 1024) -> List[str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()
            data = fh.read()
        return data.decode("utf-8", "replace").splitlines()
    except Exception:
        return []


def _parse_kv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key:
                out[key] = value.strip()
    except Exception:
        pass
    return out


def _latest_info(cfg: Config) -> Optional[Path]:
    root = cfg.legacy_base / "logs"
    if not root.is_dir():
        return None
    items: List[Path] = []
    for pattern in ("core_v40_resume_*.info", "core_v40_rebuild_*.info", "utxo_operator_*.info"):
        items.extend(p for p in root.glob(pattern) if p.is_file() and not p.is_symlink())
    if not items:
        return None
    try:
        return max(items, key=lambda p: p.stat().st_mtime_ns)
    except Exception:
        return max(items, key=lambda p: p.name)


def _legacy_processes(cfg: Config) -> List[Tuple[int, str]]:
    needle = str(cfg.frozen_v40)
    return [(pid, cmd) for pid, cmd in iter_cmdlines() if needle in cmd]


def _proc_memory_gib(pid: int) -> Tuple[Optional[float], Optional[float]]:
    rss = hwm = None
    try:
        for line in Path(f"/proc/{int(pid)}/status").read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1]) / 1024.0 / 1024.0
            elif line.startswith("VmHWM:"):
                hwm = int(line.split()[1]) / 1024.0 / 1024.0
    except Exception:
        pass
    return rss, hwm


def _height_times(cfg: Config, heights: List[int]) -> Dict[int, str]:
    hs = sorted(set(int(x) for x in heights))
    if not hs:
        return {}
    stage2 = cfg.legacy_base / "stage2"
    child = r'''
import duckdb,sys
from datetime import datetime,timezone
from pathlib import Path
root=Path(sys.argv[1]); hs=[int(x) for x in sys.argv[2:]]
files=sorted(str(p) for p in root.rglob("blocks.parquet") if p.is_file())
if not files: raise SystemExit(3)
con=duckdb.connect()
try:
    desc=con.execute("DESCRIBE SELECT * FROM read_parquet(?)",[files]).fetchall()
    cols={str(r[0]):str(r[1]) for r in desc}
    hcol=next((x for x in ("block_number","block_height","height") if x in cols),None)
    tcol=next((x for x in ("block_time","block_ts","block_timestamp","timestamp","time") if x in cols),None)
    if not hcol or not tcol: raise SystemExit(4)
    marks=",".join("?" for _ in hs)
    rows=con.execute(f"SELECT {hcol},{tcol} FROM read_parquet(?) WHERE {hcol} IN ({marks}) ORDER BY {hcol}",[files]+hs).fetchall()
    for h,v in rows:
        if isinstance(v,datetime):
            dt=v if v.tzinfo else v.replace(tzinfo=timezone.utc)
            text=dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            text=datetime.fromtimestamp(int(v),tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"{int(h)}\t{text}")
finally:
    con.close()
'''
    try:
        proc = subprocess.run(
            [str(cfg.python), "-c", child, str(stage2)] + [str(x) for x in hs],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}
    out: Dict[int, str] = {}
    for line in proc.stdout.splitlines():
        if "\t" not in line:
            continue
        raw_h, text = line.split("\t", 1)
        try:
            out[int(raw_h)] = text.strip()
        except Exception:
            pass
    return out


def live_status(cfg: Config) -> Dict[str, Any]:
    procs = _legacy_processes(cfg)
    if not procs:
        return {"running": False}

    info = _latest_info(cfg)
    kv = _parse_kv(info) if info else {}
    log = Path(kv.get("log", "")) if kv.get("log") else None
    lines = _read_tail(log) if log and log.is_file() and not log.is_symlink() else []

    current = None
    last_commit = None
    oom_count = 0
    source_green = False
    for line in lines:
        m = LAUNCH_RE.search(line)
        if m:
            current = {
                "h1": int(m.group(1)), "h2": int(m.group(2)),
                "size": int(m.group(3)), "attempt": int(m.group(4)),
            }
        m = COMMIT_RE.search(line)
        if m:
            last_commit = {
                "h1": int(m.group(1)), "h2": int(m.group(2)),
                "created": int(m.group(3)), "spends": int(m.group(4)),
                "elapsed": float(m.group(5)),
            }
        if OOM_RE.search(line) and "CONFIG" not in line:
            oom_count += 1
        if PREFLIGHT_GREEN_RE.search(line):
            source_green = True

    if current and last_commit and int(current["h2"]) <= int(last_commit["h2"]):
        current = None

    target = None
    for key in ("target_end_height", "end_height", "UTXO_CORE_END_HEIGHT"):
        raw = kv.get(key)
        if raw is not None:
            try:
                target = int(raw)
                break
            except Exception:
                pass
    if target is None:
        target = 617698

    writer = None
    for pid, cmd in procs:
        if "--v40-core-apply-worker-job" not in cmd:
            continue
        rss, hwm = _proc_memory_gib(pid)
        writer = {"pid": pid, "rss_gib": rss, "hwm_gib": hwm, "cmd": cmd}
        break

    heights: List[int] = []
    if current:
        heights.extend([int(current["h1"]), int(current["h2"])])
    elif last_commit:
        heights.extend([int(last_commit["h1"]), int(last_commit["h2"])])
    times = _height_times(cfg, heights)

    return {
        "running": True,
        "processes": procs,
        "info": str(info) if info else None,
        "log": str(log) if log else None,
        "source_green": source_green,
        "current": current,
        "last_commit": last_commit,
        "oom_count": oom_count,
        "target": target,
        "writer": writer,
        "times": times,
    }
