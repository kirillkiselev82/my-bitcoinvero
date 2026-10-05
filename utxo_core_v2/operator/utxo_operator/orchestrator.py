from __future__ import annotations

import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from . import __version__
from .config import Config
from .core import cli as bitcoin_cli, service_state, start as core_start, stop as core_stop, wait_rpc
from .renderer import event
from .safety import OperatorLock
from .state import apply_hwm, clear_current, read_current, write_current, write_last
from .util import atomic_json, iter_cmdlines, sha256_file, utc_now, utc_stamp, verify_sidecar, write_sha_sidecar
from .verify import verify_release

EXIT_OK = 0
EXIT_CONTROLLED_STOP = 75
EXIT_SOURCE = 76
EXIT_DISK = 77
EXIT_MEMORY = 78
EXIT_PREFIX = 79
EXIT_LEDGER = 80
EXIT_OOM_MIN = 81
EXIT_BUSY = 82
EXIT_AUDIT = 84
EXIT_CORE_RESTORE = 85
EXIT_LOCK_RELEASE = 86
EXIT_GENERAL = 1

RUN_CONTRACT_SCHEMA = "utxo-core-v2-run-contract-v1"
RUN_STATE_SCHEMA = "utxo-core-v2-run-state-v1"
_MEMORY_RE = re.compile(r"^\s*\d+(?:\.\d+)?\s*(?:[kmgt]i?b)\s*$", re.IGNORECASE)


class EngineFailure(RuntimeError):
    def __init__(self, message: str, exit_code: int = EXIT_GENERAL):
        super().__init__(message)
        self.exit_code = int(exit_code)


def _log(log: Path, msg: str) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now().isoformat()} {msg}"
    with log.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    print(msg, flush=True)


def _update(cfg: Config, state: Dict[str, Any], **kw: Any) -> None:
    state.update(kw)
    state["updated_utc"] = utc_now().isoformat()
    write_current(cfg, state)


def _engine_cmd(
    cfg: Config,
    script: Path,
    args: list[str],
    log: Path,
    env: Optional[Dict[str, str]] = None,
) -> int:
    merged = os.environ.copy()
    merged.update(env or {})
    cmd = [str(cfg.python), str(script), *map(str, args)]
    _log(log, "EXEC " + " ".join(cmd))
    with log.open("a", encoding="utf-8") as f:
        p = subprocess.run(cmd, env=merged, stdout=f, stderr=subprocess.STDOUT, text=True)
        f.flush()
        os.fsync(f.fileno())
    _log(log, f"EXEC_RC {p.returncode} script={script.name}")
    return int(p.returncode)


def _build_stage_common_args(cfg: Config) -> list[str]:
    return [
        "--base", str(cfg.v2_base),
        "--legacy-base", str(cfg.legacy_base),
        "--datadir", str(cfg.datadir),
        "--tmp-root", str(cfg.tmpdir.parent / "utxo_core_v2_stage"),
        "--extractor", str(cfg.extractor),
        "--decoder", str(cfg.decoder),
        "--locator-reference", str(cfg.locator_reference),
        "--bitcoin-cli", str(cfg.bitcoin_cli),
        "--stop-file", str(cfg.stop_file),
    ]


def _ensure_no_foreign_engine(cfg: Config) -> None:
    me = os.getpid()
    needles = [str(cfg.build_stage), str(cfg.calculator), str(cfg.auditor), str(cfg.frozen_v40)]
    hits = []
    for pid, cmd in iter_cmdlines():
        if pid == me:
            continue
        if any(n in cmd for n in needles):
            hits.append((pid, cmd))
    if hits:
        raise EngineFailure(
            "active UTXO engine(s) block new run: "
            + " | ".join(f"{p}:{c[:180]}" for p, c in hits[:8]),
            EXIT_BUSY,
        )


def _disk_free_gib(path: Path) -> float:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    st = os.statvfs(str(probe))
    return st.f_bavail * st.f_frsize / 1024**3


def _memory_gib(value: str) -> float:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]i?b)\s*", str(value), re.IGNORECASE)
    if not m:
        raise EngineFailure(f"invalid memory size: {value!r}", EXIT_MEMORY)
    amount = float(m.group(1))
    unit = m.group(2).lower()
    # Convert to GiB; decimal GB/TB follow DuckDB-style decimal units.
    factors = {
        "kb": 1000.0 / 1024**3, "mb": 1000.0**2 / 1024**3,
        "gb": 1000.0**3 / 1024**3, "tb": 1000.0**4 / 1024**3,
        "kib": 1.0 / 1024**2, "mib": 1.0 / 1024,
        "gib": 1.0, "tib": 1024.0,
    }
    return amount * factors[unit]


def _host_memory_gib() -> Dict[str, float]:
    values: Dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            parts = raw.strip().split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * 1024  # kB -> bytes
    except Exception as exc:
        raise EngineFailure(f"MEMORY_GUARD cannot read /proc/meminfo: {exc}", EXIT_MEMORY) from exc
    total = values.get("MemTotal", 0) / 1024**3
    available = values.get("MemAvailable", 0) / 1024**3
    if total <= 0 or available < 0:
        raise EngineFailure("MEMORY_GUARD invalid /proc/meminfo", EXIT_MEMORY)
    return {"total_gib": total, "available_gib": available}


def _resource_guard(cfg: Config, requested_memory: Optional[str] = None) -> None:
    data = _disk_free_gib(cfg.v2_base)
    tmp = _disk_free_gib(cfg.tmpdir)
    if data < cfg.min_free_data_gib:
        raise EngineFailure(
            f"DISK_GUARD data_free={data:.1f}GiB min={cfg.min_free_data_gib}", EXIT_DISK
        )
    if tmp < cfg.min_free_tmp_gib:
        raise EngineFailure(
            f"DISK_GUARD tmp_free={tmp:.1f}GiB min={cfg.min_free_tmp_gib}", EXIT_DISK
        )
    mem = _host_memory_gib()
    reserve = float(cfg.min_available_memory_gib)
    if mem["available_gib"] < reserve:
        raise EngineFailure(
            f"MEMORY_GUARD available={mem['available_gib']:.1f}GiB min={reserve:.1f}GiB", EXIT_MEMORY
        )
    if requested_memory:
        requested = _memory_gib(requested_memory)
        ceiling = max(0.0, mem["total_gib"] - reserve)
        if requested > ceiling:
            raise EngineFailure(
                f"MEMORY_GUARD requested={requested:.1f}GiB exceeds host-safe ceiling={ceiling:.1f}GiB "
                f"(total={mem['total_gib']:.1f}GiB reserve={reserve:.1f}GiB)",
                EXIT_MEMORY,
            )


def _validate_run_args(*, to_day: str, confirmations: int, cores: int, memory: str, window: int) -> None:
    # date parsing is deliberately delegated to build_stage snapshot, but reject
    # obviously unsafe operator values before any service mutation.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(to_day)):
        raise EngineFailure(f"invalid --to date: {to_day!r}; expected YYYY-MM-DD")
    if int(confirmations) < 0:
        raise EngineFailure(f"confirmations must be >=0, got {confirmations}")
    if int(cores) < 1:
        raise EngineFailure(f"stage cores must be >=1, got {cores}")
    if int(window) < 1:
        raise EngineFailure(f"apply window must be >=1, got {window}")
    if _MEMORY_RE.fullmatch(str(memory)) is None:
        raise EngineFailure(f"memory must look like 80GB or 80GiB, got {memory!r}")


def _read_json_verified(path: Path) -> Dict[str, Any]:
    verify_sidecar(path)
    o = __import__("json").loads(path.read_text(encoding="utf-8"))
    if not isinstance(o, dict):
        raise EngineFailure(f"JSON object expected: {path}")
    return o


def _stage_release_for_target(cfg: Config, target: int) -> Path:
    p = cfg.stage_release_dir / f"stage_release_0_{target}.json"
    verify_sidecar(p)
    return p


def _make_contract(
    cfg: Config,
    state: Dict[str, Any],
    snapshot_path: Path,
    release: Path,
    initial_core_state: str,
) -> Path:
    snap = _read_json_verified(snapshot_path)
    _read_json_verified(release)
    target = snap["target"]
    payload = {
        "schema": RUN_CONTRACT_SCHEMA,
        "created_utc": utc_now().isoformat(),
        "run_id": state["run_id"],
        "requested_utc_day": state["requested_utc_day"],
        "confirmations": int(state["confirmations"]),
        "target": {
            "height": int(target["height"]),
            "hash": str(target["block_hash"]),
            "block_time": int(target["block_time"]),
            "median_time_past": int(target["median_time_past"]),
        },
        "source": {
            "snapshot_path": str(snapshot_path),
            "snapshot_sha256": sha256_file(snapshot_path),
            "catalog_path": str(cfg.source_catalog),
        },
        "stage": {"release_path": str(release), "release_sha256": sha256_file(release)},
        "apply": {
            "db_path": str(cfg.db),
            "writer_threads": 1,
            "memory_limit": str(state["memory"]),
            "configured_window": int(state["apply_window"]),
            "sticky_window": True,
            "auto_grow": False,
        },
        "software": {
            "operator_version": __version__,
            "operator_files": {
                name: {"path": str(path), "sha256": sha256_file(path)}
                for name, path in {
                    "orchestrator": Path(__file__).resolve(),
                    "cli": Path(__file__).resolve().with_name("cli.py"),
                    "config": Path(__file__).resolve().with_name("config.py"),
                    "safety": Path(__file__).resolve().with_name("safety.py"),
                    "state": Path(__file__).resolve().with_name("state.py"),
                    "verify": Path(__file__).resolve().with_name("verify.py"),
                }.items()
            },
            "build_stage": {"path": str(cfg.build_stage), "sha256": sha256_file(cfg.build_stage)},
            "calculator": {"path": str(cfg.calculator), "sha256": sha256_file(cfg.calculator)},
            "auditor": {"path": str(cfg.auditor), "sha256": sha256_file(cfg.auditor)},
            "frozen_v40": {"path": str(cfg.frozen_v40), "sha256": sha256_file(cfg.frozen_v40)},
            "frozen_v30": {"path": str(cfg.parent_v30), "sha256": sha256_file(cfg.parent_v30)},
            "extractor": {"path": str(cfg.extractor), "sha256": sha256_file(cfg.extractor)},
            "decoder": {"path": str(cfg.decoder), "sha256": sha256_file(cfg.decoder)},
            "locator_reference": {"path": str(cfg.locator_reference), "sha256": sha256_file(cfg.locator_reference)},
        },
        "core": {"initial_service_state": initial_core_state, "datadir": str(cfg.datadir)},
        "policy": {
            "target_immutable": True,
            "no_automatic_destructive_recovery": True,
            "confirmations": int(state["confirmations"]),
            "date_resolution": "max canonical height with MTP <= UTC day 23:59:59",
            "apply_writer_threads_locked": 1,
        },
    }
    p = Path(state["run_path"]) / "run_contract.json"
    atomic_json(p, payload, overwrite=False)
    write_sha_sidecar(p, overwrite=False)
    return p


def _restore_core(cfg: Config, initial: str, log: Path) -> None:
    now = service_state()
    if initial == "active" and now != "active":
        _log(log, "CORE_RESTORE start -> active")
        core_start()
        wait_rpc(cfg.bitcoin_cli, cfg.datadir)
    elif initial == "inactive" and now != "inactive":
        _log(log, "CORE_RESTORE stop -> inactive")
        core_stop()


def _fail_state(cfg: Config, current: Dict[str, Any], log: Path, exc: BaseException, code: int) -> int:
    msg = str(exc)
    _log(log, event("RED", "✗", "RUN FAILED", [msg, f"exit_code={code}"]))
    _update(
        cfg,
        current,
        status="FAILED",
        owner_pid=None,
        error=msg,
        exit_code=int(code),
        finished_utc=utc_now().isoformat(),
    )
    write_last(cfg, current)
    return int(code)


def run_pipeline(
    cfg: Config,
    *,
    to_day: str,
    confirmations: int,
    cores: int,
    memory: str,
    window: int,
    resume: bool = False,
) -> int:
    current = read_current(cfg)
    if resume:
        if not current or not str(current.get("status", "")).startswith("STOPPED_CLEAN"):
            raise EngineFailure("no STOPPED_CLEAN run available for resume")
        to_day = str(current["requested_utc_day"])
        confirmations = int(current["confirmations"])
        cores = int(current["stage_cores"])
        memory = str(current["memory"])
        window = int(current["apply_window"])
        run_id = str(current["run_id"])
        run_path = Path(current["run_path"])
        log = Path(current["log_path"])
    else:
        if current and not (str(current.get("status", "")).startswith("COMPLETE") or str(current.get("status", "")) == "FAILED"):
            raise EngineFailure(
                f"unfinished current run exists status={current.get('status')} run_id={current.get('run_id')}; "
                "use utxo resume/doctor"
            )
        _validate_run_args(
            to_day=to_day, confirmations=confirmations, cores=cores, memory=memory, window=window
        )
        run_id = f"run-{utc_stamp()}-{uuid.uuid4().hex[:10]}"
        run_path = cfg.run_dir / "runs" / run_id
        run_path.mkdir(parents=True, exist_ok=False)
        log = cfg.log_dir / f"{run_id}.log"
        current = {
            "schema": RUN_STATE_SCHEMA,
            "run_id": run_id,
            "run_path": str(run_path),
            "log_path": str(log),
            "requested_utc_day": to_day,
            "confirmations": int(confirmations),
            "stage_cores": int(cores),
            "memory": str(memory),
            "apply_window": int(window),
            "status": "STARTING",
            "phase": "PREFLIGHT",
            "created_utc": utc_now().isoformat(),
        }
        write_current(cfg, current)

    _validate_run_args(to_day=to_day, confirmations=confirmations, cores=cores, memory=memory, window=window)
    lock = OperatorLock(cfg.operator_lock, run_id, "run")
    initial_core: Optional[str] = None
    terminal = False
    exit_code = EXIT_GENERAL
    try:
        lock.acquire()
        _ensure_no_foreign_engine(cfg)
        _resource_guard(cfg, memory)
        vr = verify_release(cfg)
        if vr["status"] != "GREEN":
            raise EngineFailure(f"RELEASE_IDENTITY_BAD {vr}")

        _log(
            log,
            event(
                "BLUE",
                "▶",
                "RUN START",
                [f"Run: {run_id}", f"Target day: {to_day} UTC", f"Confirmations: {confirmations}"],
            ),
        )
        initial_core = service_state()
        if initial_core not in {"active", "inactive"}:
            raise EngineFailure(f"unsupported initial bitcoind state: {initial_core}", EXIT_SOURCE)

        _update(
            cfg,
            current,
            status="RUNNING",
            phase="SOURCE_SNAPSHOT",
            initial_core_state=initial_core,
            owner_pid=os.getpid(),
        )
        if service_state() != "active":
            _log(log, "SOURCE requires Core RPC: starting bitcoind temporarily")
            core_start()
        wait_rpc(cfg.bitcoin_cli, cfg.datadir)

        snapshot = run_path / "source_snapshot.json"
        if not snapshot.exists():
            rc = _engine_cmd(
                cfg,
                cfg.build_stage,
                [
                    *_build_stage_common_args(cfg),
                    "snapshot",
                    "--to", to_day,
                    "--confirmations", str(confirmations),
                    "--output", str(snapshot),
                ],
                log,
            )
            if rc != 0:
                raise EngineFailure(f"SOURCE_SNAPSHOT_FAILED rc={rc}", EXIT_SOURCE)
        snap = _read_json_verified(snapshot)
        target = int(snap["target"]["height"])
        target_hash = str(snap["target"]["block_hash"])
        _update(
            cfg,
            current,
            target_height=target,
            target_hash=target_hash,
            source_snapshot=str(snapshot),
            source_snapshot_sha256=sha256_file(snapshot),
        )

        ah = apply_hwm(cfg)
        if ah is not None and ah > target:
            raise EngineFailure(
                f"TARGET_BEHIND_APPLY_HWM target={target} apply_hwm={ah}; automatic rollback forbidden",
                EXIT_PREFIX,
            )

        _update(cfg, current, phase="SOURCE_STAGE")
        if service_state() != "inactive":
            _log(log, "Stopping bitcoind for physical SOURCE + STAGE")
            core_stop()
        rc = _engine_cmd(
            cfg,
            cfg.build_stage,
            [
                *_build_stage_common_args(cfg),
                "build",
                "--snapshot", str(snapshot),
                "--cores", str(cores),
                "--memory", memory,
                "--window-size", "1000",
            ],
            log,
        )
        if rc == EXIT_CONTROLLED_STOP:
            _update(
                cfg,
                current,
                status="STOPPED_CLEAN",
                phase="SOURCE_STAGE",
                owner_pid=None,
                exit_code=EXIT_CONTROLLED_STOP,
            )
            return EXIT_CONTROLLED_STOP
        if rc != 0:
            raise EngineFailure(f"SOURCE_STAGE_FAILED rc={rc}", EXIT_SOURCE)

        release = _stage_release_for_target(cfg, target)
        _update(
            cfg,
            current,
            stage_release=str(release),
            stage_release_sha256=sha256_file(release),
            phase="CORE_REVALIDATION",
        )

        # Stage is immutable now; release the raw-source freeze and revalidate
        # the immutable target against live Bitcoin Core before any DB mutation.
        core_start()
        wait_rpc(cfg.bitcoin_cli, cfg.datadir)
        observed = bitcoin_cli(cfg.bitcoin_cli, cfg.datadir, "getblockhash", str(target)).strip().lower()
        if observed != target_hash.lower():
            raise EngineFailure(
                f"REORG_DETECTED target={target} stage={target_hash} core={observed}", EXIT_SOURCE
            )

        contract = Path(current.get("run_contract") or (run_path / "run_contract.json"))
        if not contract.exists():
            contract = _make_contract(cfg, current, snapshot, release, initial_core)
        else:
            # Resume may only reuse the exact immutable contract already bound
            # to this run.  Verify both bytes and the target/stage bindings.
            contract_obj = _read_json_verified(contract)
            if str(contract_obj.get("run_id")) != run_id:
                raise EngineFailure("existing run contract run_id mismatch")
            if int((contract_obj.get("target") or {}).get("height", -1)) != target:
                raise EngineFailure("existing run contract target mismatch")
            if str((contract_obj.get("stage") or {}).get("release_sha256", "")) != sha256_file(release):
                raise EngineFailure("existing run contract Stage release mismatch")
        _update(
            cfg,
            current,
            run_contract=str(contract),
            run_contract_sha256=sha256_file(contract),
            phase="APPLY",
        )

        env = {
            "UTXO_MODE": "CORE_STAGE2_REBUILD",
            "UTXO_CORE_REBUILD_RESUME": "1" if cfg.db.exists() else "0",
            "UTXO_CORE_STAGE2_RELEASE_MANIFEST": str(release),
            "UTXO_CORE_END_HEIGHT": str(target),
            "UTXO_CORE_DB_PATH": str(cfg.db),
            "UTXO_CORE_WORK_ROOT": str(cfg.apply_work_root),
            "UTXO_CORE_WORKER_ROOT": str(cfg.worker_root),
            "DUCKDB_TMPDIR": str(cfg.tmpdir),
            "UTXO_STOP_FILE": str(cfg.stop_file),
            "UTXO_STAGE_THREADS": str(cores),
            "UTXO_STAGE_MEMORY_LIMIT": memory,
            "UTXO_APPLY_THREADS": "1",
            "UTXO_APPLY_MEMORY_LIMIT": memory,
            "UTXO_CORE_APPLY_BLOCK_WINDOW": str(window),
            "UTXO_CORE_MIN_BLOCK_WINDOW": str(cfg.min_window),
            "UTXO_CORE_OOM_MAX_RETRIES": str(cfg.oom_retries),
            "UTXO_CORE_OOM_BACKOFF_DIVISOR": str(cfg.backoff_divisor),
            "UTXO_CORE_CHECKPOINT_EVERY_WINDOWS": str(cfg.checkpoint_every_windows),
            "UTXO_CORE_STICKY_WINDOW": "1",
            "UTXO_CORE_ADAPTIVE_GROW": "0",
            "UTXO_CORE_V41_DEEP_LEGACY_PARQUET_SHA": "0",
        }
        rc = _engine_cmd(cfg, cfg.calculator, ["--mode", "CORE_STAGE2_REBUILD"], log, env)
        if rc == EXIT_CONTROLLED_STOP:
            _update(
                cfg,
                current,
                status="STOPPED_CLEAN",
                phase="APPLY",
                owner_pid=None,
                exit_code=EXIT_CONTROLLED_STOP,
            )
            return EXIT_CONTROLLED_STOP
        if rc != 0:
            raise EngineFailure(f"APPLY_FAILED rc={rc}")

        _update(cfg, current, phase="AUDIT")
        audit_args = [
            "--db", str(cfg.db),
            "--stage-release", str(release),
            "--source-catalog", str(cfg.source_catalog),
            "--calculator", str(cfg.calculator),
            "--run-contract", str(contract),
            "--bitcoin-cli", str(cfg.bitcoin_cli),
            "--datadir", str(cfg.datadir),
            "--lock-root", str(cfg.lock_root),
            "--output-dir", str(cfg.v2_base / "audit"),
            "--stop-file", str(cfg.stop_file),
        ]
        rc = _engine_cmd(cfg, cfg.auditor, audit_args, log)
        if rc == EXIT_CONTROLLED_STOP:
            _update(
                cfg,
                current,
                status="STOPPED_CLEAN_AUDIT",
                phase="AUDIT",
                owner_pid=None,
                exit_code=EXIT_CONTROLLED_STOP,
            )
            return EXIT_CONTROLLED_STOP
        if rc != 0:
            raise EngineFailure(f"AUDIT_FAILED rc={rc}", EXIT_AUDIT)

        _update(
            cfg,
            current,
            status="COMPLETE_AUDIT_GREEN_MUHASH_PENDING",
            phase="AUDIT_GREEN_MUHASH_PENDING",
            owner_pid=None,
            exit_code=EXIT_OK,
            finished_utc=utc_now().isoformat(),
        )
        write_last(cfg, current)
        clear_current(cfg)
        terminal = True
        _log(
            log,
            event(
                "GREEN",
                "✓",
                "AUDIT GREEN",
                [
                    f"Target: {target} {target_hash}",
                    f"DB: {cfg.db}",
                    "MuHash certification: PENDING separate exact auditor",
                ],
            ),
        )
        exit_code = EXIT_OK
        return EXIT_OK

    except EngineFailure as exc:
        exit_code = _fail_state(cfg, current, log, exc, exc.exit_code)
        terminal = True
        return exit_code
    except RuntimeError as exc:
        msg = str(exc)
        if "DISK_GUARD" in msg:
            code = EXIT_DISK
        elif "MEMORY" in msg or "OOM" in msg:
            code = EXIT_MEMORY
        elif "PREFIX" in msg:
            code = EXIT_PREFIX
        elif "LEDGER" in msg:
            code = EXIT_LEDGER
        else:
            code = EXIT_GENERAL
        exit_code = _fail_state(cfg, current, log, exc, code)
        terminal = True
        return exit_code
    finally:
        if initial_core in {"active", "inactive"}:
            try:
                _restore_core(cfg, initial_core, log)
                final_core_state = service_state()
                if final_core_state != initial_core:
                    raise RuntimeError(
                        f"bitcoind restore state mismatch initial={initial_core} final={final_core_state}"
                    )
                _log(log, f"CORE_RESTORED initial={initial_core} final={final_core_state}")
                current["core_restore_status"] = "OK"
                current["core_final_state"] = final_core_state
                current["updated_utc"] = utc_now().isoformat()
                if terminal:
                    write_last(cfg, current)
                else:
                    write_current(cfg, current)
            except Exception as exc:
                restore_error = f"{type(exc).__name__}:{exc}"
                _log(log, f"CORE_RESTORE_FAILED {restore_error}")
                current["core_restore_status"] = "FAILED"
                current["core_restore_error"] = restore_error
                current["updated_utc"] = utc_now().isoformat()
                # Semantic calculation state and service-restoration state are
                # separate. A completed/audited DB is never rolled back here.
                # Nevertheless a successful `utxo run` must not return success
                # when the operator failed to restore the service state it found.
                if terminal:
                    if exit_code == EXIT_OK:
                        current["status"] = "COMPLETE_CORE_RESTORE_FAILED"
                        current["phase"] = "CORE_RESTORE_FAILED"
                        current["exit_code"] = EXIT_CORE_RESTORE
                    try:
                        write_last(cfg, current)
                    except Exception:
                        pass
                else:
                    try:
                        _update(
                            cfg,
                            current,
                            status="CORE_RESTORE_FAILED",
                            owner_pid=None,
                            error=restore_error,
                        )
                    except Exception:
                        pass
                if exit_code == EXIT_OK:
                    exit_code = EXIT_CORE_RESTORE
        try:
            lock.release()
        except Exception as exc:
            lock_error = f"{type(exc).__name__}:{exc}"
            _log(log, f"OPERATOR_LOCK_RELEASE_FAILED {lock_error}")
            current["operator_lock_release_status"] = "FAILED"
            current["operator_lock_release_error"] = lock_error
            current["updated_utc"] = utc_now().isoformat()
            if terminal and exit_code == EXIT_OK:
                current["status"] = "COMPLETE_OPERATOR_LOCK_RELEASE_FAILED"
                current["phase"] = "OPERATOR_LOCK_RELEASE_FAILED"
                current["exit_code"] = EXIT_LOCK_RELEASE
                try:
                    write_last(cfg, current)
                except Exception:
                    pass
                exit_code = EXIT_LOCK_RELEASE
        # Conditional returns in finally are intentional only for successful
        # semantic runs followed by an operational cleanup failure. They never
        # mask an earlier calculator/audit/source error.
        if exit_code in {EXIT_CORE_RESTORE, EXIT_LOCK_RELEASE}:
            return exit_code
