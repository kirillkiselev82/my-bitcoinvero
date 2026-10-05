#!/usr/bin/env python3
# MyBot / UTXO Core v2
# SOURCE + STAGE incremental engine.
#
# Architecture contract:
#   Bitcoin Core RPC snapshot (Core running)
#       -> immutable target snapshot
#   physical blk*.dat scan (Core stopped + datadir lock)
#       -> source_catalog.duckdb
#   exact frozen decoder/extractor helpers
#       -> immutable Stage windows
#       -> immutable full-coverage Stage release manifest
#
# This file deliberately reuses the reviewed Stage2 decoder/extractor helpers
# by exact SHA256 instead of reimplementing Bitcoin transaction semantics.

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


VERSION = "utxo-core-v2-build-stage-rc2.5"
SOURCE_CATALOG_SCHEMA = "utxo-source-catalog-v2"
SOURCE_SNAPSHOT_SCHEMA = "utxo-source-snapshot-v2"
SOURCE_SNAPSHOT_CHAIN_MODE = "physical-prevhash-v1"
SOURCE_LEDGER_CONTRACT = "utxo-source-catalog-ledger-v2"
LEGACY_PHYSICAL_BACKFILL_META_KEY = "legacy_inventory_physical_backfill_v1"
STAGE_WINDOW_SCHEMA = "utxo-stage-window-v2"
STAGE_GENERATION_SCHEMA = "utxo-stage-generation-v2"
STAGE_RELEASE_SCHEMA = "mybot-stage2-release-v2"
STAGE_RELEASE_TSV_SCHEMA = "mybot-stage2-release-windows-v2"

BASELINE_END_HEIGHT = 617698
BASELINE_END_HASH = "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
BASELINE_CANONICAL_MANIFEST_SHA256 = "5227507e9b38fbdb63040c1e197cdfb9b39cc2d054c6744722113206c4847161"
BASELINE_LOCATOR_SHA256 = "0e045ecee898095f1a35789c2d21efccc737b390e998c2a0c79c6bf659c516ed"
BASELINE_INVENTORY_SHA256 = "e14cd67e47492c32e0f796782744878ab2c02c2b5b89b05dd0c339a27aee041c"
BASELINE_STAGE2_GLOBAL_SHA256 = "3dc4e285947651d0c36bf5564c6f424d620947d29f36154ffa1cbb1dbe94860a"
BASELINE_EXTRACTOR_SHA256 = "7309d10a509d518738c94e9604e2a9f8dba1cc7e190a5f21f3a8df01146f5730"
BASELINE_DECODER_SHA256 = "a981378473ea41f157eaf94c7de233ddbdab1985a4a618fd3962696c6cfa3ec9"
BASELINE_LOCATOR_SCRIPT_SHA256 = "d80ac36c2eb6490aa7aabdb70ebf4eee45f18160946e8e3812256a8c6669522b"
EXPECTED_DUCKDB_VERSION = "1.4.4"
EXPECTED_XOR_HEX = "2af1c3e24315d54b"
EXPECTED_XOR_SHA256 = "b5e50a9b6a79fce708c9fcfb62a76c512aec637192961c94fd99ffe051b9d6e7"
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MIN_BLOCK_SERIALIZED_SIZE = 81
BLK_RE = re.compile(r"^blk([0-9]{5})\.dat$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_BASE = Path("/opt/mybot_data/etl/utxo_core_v2")
DEFAULT_LEGACY_BASE = Path("/opt/mybot_data/etl/utxo_core_v1")
DEFAULT_DATADIR = Path("/opt/mybot_data/bitcoin")
DEFAULT_TMP = Path("/opt/mybot_tmp/utxo_core_v2")
DEFAULT_EXTRACTOR = Path("/root/mybot/build_canonical_transactions.py")
DEFAULT_DECODER = Path("/root/mybot/stage2_decoder_preflight.py")
DEFAULT_LOCATOR_REFERENCE = Path("/root/mybot/build_block_locator.py")
DEFAULT_BITCOIN_CLI = Path("/usr/local/bin/bitcoin-cli")
DEFAULT_STOP_FILE = Path("/opt/mybot_data/etl/utxo/control/STOP")


class ControlledStop(RuntimeError):
    pass


@dataclass(frozen=True)
class Paths:
    base: Path
    legacy_base: Path
    datadir: Path
    tmp_root: Path
    extractor: Path
    decoder: Path
    locator_reference: Path
    bitcoin_cli: Path
    stop_file: Path

    @property
    def blocks_dir(self) -> Path:
        return self.datadir / "blocks"

    @property
    def xor_file(self) -> Path:
        return self.blocks_dir / "xor.dat"

    @property
    def datadir_lock(self) -> Path:
        return self.datadir / ".lock"

    @property
    def source_dir(self) -> Path:
        return self.base / "source"

    @property
    def source_catalog(self) -> Path:
        return self.source_dir / "source_catalog.duckdb"

    @property
    def source_lock(self) -> Path:
        return self.source_dir / ".source_writer.lock"

    @property
    def build_lock(self) -> Path:
        # Serializes one complete physical SOURCE + STAGE publication.
        # The Bitcoin Core datadir lock is held for the same whole interval.
        return self.base / ".build_stage.lock"

    @property
    def stage_dir(self) -> Path:
        return self.base / "stage"

    @property
    def stage_windows(self) -> Path:
        return self.stage_dir / "windows"

    @property
    def stage_generations(self) -> Path:
        return self.stage_dir / "generations"

    @property
    def stage_releases(self) -> Path:
        return self.stage_dir / "manifests" / "releases"

    @property
    def stage_index(self) -> Path:
        return self.stage_dir / "stage_index.duckdb"

    @property
    def stage_lock(self) -> Path:
        return self.stage_dir / ".stage_writer.lock"

    @property
    def legacy_manifest(self) -> Path:
        return self.legacy_base / "manifests" / "canonical_chain_0_617698.tsv"

    @property
    def legacy_locator(self) -> Path:
        return self.legacy_base / "stage" / "block_locator_0_617698.tsv"

    @property
    def legacy_inventory(self) -> Path:
        return self.legacy_base / "stage" / "block_files_inventory.tsv"

    @property
    def legacy_stage2(self) -> Path:
        return self.legacy_base / "stage2"

    @property
    def legacy_stage2_global(self) -> Path:
        return self.legacy_stage2 / "manifests" / "canonical_transactions_0_617698.json"

    @property
    def legacy_stage2_windows_tsv(self) -> Path:
        return self.legacy_stage2 / "manifests" / "canonical_transactions_0_617698.windows.tsv"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path, limit: Optional[int] = None) -> str:
    h = hashlib.sha256()
    remaining = limit
    with path.open("rb") as f:
        while True:
            want = 16 * 1024 * 1024 if remaining is None else min(16 * 1024 * 1024, remaining)
            if want <= 0:
                break
            b = f.read(want)
            if not b:
                break
            h.update(b)
            if remaining is not None:
                remaining -= len(b)
    if limit is not None and remaining != 0:
        raise RuntimeError(f"short prefix hash read path={path} limit={limit} remaining={remaining}")
    return h.hexdigest()


def canonical_json_hash(payload: Dict[str, Any], exclude: Sequence[str] = ()) -> str:
    skip = set(exclude)
    body = {str(k): v for k, v in payload.items() if str(k) not in skip}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sql_quote(value: str) -> str:
    """Return one DuckDB SQL string literal without relying on parameter coercion."""
    return "'" + str(value).replace("'", "''") + "'"


def fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o640, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(str(tmp), flags, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            # Atomic no-clobber publication. A path.exists()+os.replace() pair
            # has a TOCTOU overwrite window; hard-linking a same-directory temp
            # file makes EEXIST an atomic guard.
            try:
                os.link(tmp, path)
            except FileExistsError as exc:
                raise FileExistsError(path) from exc
            tmp.unlink()
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


def fsync_file(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish_stage_window_directory(source_dir: Path, final_dir: Path) -> None:
    """Durably publish one immutable Stage window across filesystems.

    The window may be built under ``tmp_root`` on a different filesystem from
    ``stage/windows``.  A direct rename(2) across those mounts fails with EXDEV.
    Copy first into a hidden sibling of the final directory, fully verify and
    fsync that sibling, then atomically rename it within the destination
    filesystem.  The build lock serializes publishers, so the final rename is
    also the immutable no-clobber commit point.
    """
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise RuntimeError(f"unsafe Stage publish source directory: {source_dir}")
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(final_dir):
        raise RuntimeError(f"immutable Stage window already exists unexpectedly: {final_dir}")

    publish_tmp = final_dir.parent / f".{final_dir.name}.publish.{uuid.uuid4().hex}"
    if os.path.lexists(publish_tmp):
        raise RuntimeError(f"Stage publish staging path already exists unexpectedly: {publish_tmp}")
    publish_tmp.mkdir(mode=0o750)
    try:
        source_names = []
        for src in sorted(source_dir.iterdir(), key=lambda x: x.name):
            if src.is_symlink() or not src.is_file():
                raise RuntimeError(f"unsafe Stage publish payload entry: {src}")
            source_names.append(src.name)
            dst = publish_tmp / src.name
            shutil.copy2(src, dst, follow_symlinks=False)
            fsync_file(dst)

        # Verify the destination copy from its own bytes before publication.
        manifest_path = publish_tmp / "manifest.json"
        sidecar = publish_tmp / "manifest.json.sha256"
        verify_file(manifest_path, sidecar=sidecar)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        declared = manifest.get("files") or {}
        payload_sidecars = []
        for name, meta in declared.items():
            dst = publish_tmp / str(name)
            if dst.is_symlink() or not dst.is_file():
                raise RuntimeError(f"Stage publish copied payload missing/unsafe: {dst}")
            expected_sha = str((meta or {}).get("sha256") or "")
            expected_size = int((meta or {}).get("size_bytes") or -1)
            if expected_size < 0 or dst.stat().st_size != expected_size:
                raise RuntimeError(f"Stage publish copied size mismatch: {dst}")
            payload_sidecar = Path(str(dst) + ".sha256")
            verify_file(dst, expected_sha, payload_sidecar)
            payload_sidecars.append(payload_sidecar.name)

        expected_names = sorted([
            "manifest.json", "manifest.json.sha256", *declared.keys(), *payload_sidecars,
        ])
        actual_names = sorted(x.name for x in publish_tmp.iterdir())
        if actual_names != expected_names or sorted(source_names) != expected_names:
            raise RuntimeError(
                f"Stage publish payload set mismatch source={sorted(source_names)} copied={actual_names} expected={expected_names}"
            )

        fsync_dir(publish_tmp)
        # publish_tmp and final_dir share one parent, hence one filesystem.
        os.rename(publish_tmp, final_dir)
        fsync_dir(final_dir.parent)
    except BaseException:
        try:
            if publish_tmp.exists() and not publish_tmp.is_symlink():
                shutil.rmtree(publish_tmp)
        except Exception:
            pass
        raise


def atomic_write_json(path: Path, payload: Dict[str, Any], overwrite: bool = False) -> None:
    atomic_write_bytes(
        path,
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        overwrite=overwrite,
    )


def write_sha_sidecar(path: Path, overwrite: bool = False, digest: Optional[str] = None) -> Path:
    digest = sha256_file(path) if digest is None else str(digest).lower()
    if not HASH_RE.fullmatch(digest):
        raise RuntimeError(f"invalid SHA256 for sidecar publication: {digest!r}")
    sidecar = Path(str(path) + ".sha256")
    atomic_write_bytes(sidecar, f"{digest}  {path.name}\n".encode("ascii"), overwrite=overwrite)
    return sidecar


def sidecar_value(path: Path) -> str:
    parts = path.read_text(encoding="ascii").strip().split()
    if not parts:
        raise RuntimeError(f"empty SHA sidecar: {path}")
    return parts[0].lower()


def verify_file(path: Path, expected: Optional[str] = None, sidecar: Optional[Path] = None) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"missing/not-regular/symlink artifact: {path}")
    actual = sha256_file(path)
    expected_sha = None if expected is None else str(expected).strip().lower()
    if expected_sha == "":
        # An empty manifest/index SHA is operator-visible technical debt, not a
        # reason to silently skip integrity verification.  Continue only when
        # an independent detached seal is present; the full payload bytes are
        # still hashed below and must match that seal.
        print(
            f"WARN EMPTY_EXPECTED_SHA path={path} fallback=detached_sidecar",
            file=sys.stderr,
            flush=True,
        )
        if sidecar is None:
            raise RuntimeError(f"empty expected SHA without detached sidecar: {path}")
    elif expected_sha is not None:
        if not HASH_RE.fullmatch(expected_sha):
            raise RuntimeError(f"invalid expected SHA256 path={path}: {expected!r}")
        if actual != expected_sha:
            raise RuntimeError(f"SHA mismatch path={path} expected={expected_sha} actual={actual}")
    if sidecar:
        if not sidecar.is_file() or sidecar.is_symlink():
            raise RuntimeError(f"missing/bad SHA sidecar: {sidecar}")
        recorded = sidecar_value(sidecar)
        if recorded != actual:
            raise RuntimeError(f"sidecar mismatch path={path} recorded={recorded} actual={actual}")
    return actual


def valid_hash(value: Any, label: str) -> str:
    s = str(value or "").lower()
    if not HASH_RE.fullmatch(s):
        raise RuntimeError(f"invalid hash {label}: {value!r}")
    return s


def load_module(path: Path, expected_sha: str, name: str):
    actual = verify_file(path, expected_sha)
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, actual


def require_duckdb():
    try:
        import duckdb
    except Exception as exc:
        raise RuntimeError("duckdb Python package is required") from exc
    if getattr(duckdb, "__version__", None) != EXPECTED_DUCKDB_VERSION:
        raise RuntimeError(
            f"DuckDB version mismatch expected={EXPECTED_DUCKDB_VERSION} actual={getattr(duckdb, '__version__', None)}"
        )
    return duckdb


def consume_stop_if_requested(stop_file: Path, phase: str, payload: Optional[Dict[str, Any]] = None) -> None:
    if not stop_file.exists():
        return
    if stop_file.is_symlink() or not stop_file.is_file():
        raise RuntimeError(f"controlled STOP is not a regular file: {stop_file}")
    stamp = utc_stamp()
    consumed = stop_file.with_name(f"{stop_file.name}.consumed.{stamp}.{os.getpid()}")
    os.replace(stop_file, consumed)
    fsync_dir(consumed.parent)
    detail = {"phase": phase, "consumed": str(consumed), "payload": payload or {}}
    raise ControlledStop(json.dumps(detail, sort_keys=True))


def acquire_file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open("a+", encoding="ascii")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        raise RuntimeError(f"writer lock already held: {path}")
    return f


def require_core_active() -> None:
    p = subprocess.run(
        ["systemctl", "is-active", "bitcoind"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    state = p.stdout.strip()
    if state != "active":
        raise RuntimeError(f"bitcoind must be active for SOURCE snapshot, got {state!r}")


def require_core_stopped_and_lock(paths: Paths) -> int:
    p = subprocess.run(
        ["systemctl", "is-active", "bitcoind"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    state = p.stdout.strip()
    if state != "inactive":
        raise RuntimeError(f"bitcoind must be inactive for physical SOURCE/STAGE, got {state!r}")
    pgrep = subprocess.run(["pgrep", "-x", "bitcoind"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if pgrep.returncode == 0:
        raise RuntimeError("bitcoind process exists while service is inactive")
    if pgrep.returncode not in (0, 1):
        raise RuntimeError(f"pgrep bitcoind failed rc={pgrep.returncode}")
    if not paths.datadir_lock.is_file():
        raise RuntimeError(f"Bitcoin Core datadir lock file missing: {paths.datadir_lock}")
    fd = os.open(str(paths.datadir_lock), os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        raise RuntimeError(f"Bitcoin Core datadir lock is busy: {paths.datadir_lock}")
    pgrep2 = subprocess.run(["pgrep", "-x", "bitcoind"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if pgrep2.returncode == 0:
        os.close(fd)
        raise RuntimeError("bitcoind appeared while acquiring datadir lock")
    return fd


def bitcoin_cli(paths: Paths, *args: str) -> str:
    cmd = [str(paths.bitcoin_cli), f"-datadir={paths.datadir}"] + [str(a) for a in args]
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError(f"bitcoin-cli failed rc={p.returncode} cmd={' '.join(cmd)} stderr={p.stderr.strip()}")
    return p.stdout.strip()


def rpc_json(paths: Paths, *args: str) -> Dict[str, Any]:
    out = bitcoin_cli(paths, *args)
    try:
        obj = json.loads(out)
    except Exception as exc:
        raise RuntimeError(f"invalid bitcoin-cli JSON for {args}: {out[:500]!r}") from exc
    if not isinstance(obj, dict):
        raise RuntimeError(f"unexpected bitcoin-cli JSON type for {args}: {type(obj).__name__}")
    return obj


def rpc_header_at_height(paths: Paths, height: int) -> Dict[str, Any]:
    block_hash = valid_hash(bitcoin_cli(paths, "getblockhash", str(int(height))), f"height={height}")
    header = rpc_json(paths, "getblockheader", block_hash, "true")
    if int(header.get("height", -1)) != int(height):
        raise RuntimeError(f"Core header height mismatch requested={height} actual={header.get('height')}")
    if valid_hash(header.get("hash"), f"header height={height}") != block_hash:
        raise RuntimeError(f"Core header hash mismatch height={height}")
    prev = "0" * 64 if height == 0 else valid_hash(header.get("previousblockhash"), f"prev height={height}")
    return {
        "height": int(height),
        "block_hash": block_hash,
        "prev_hash": prev,
        "block_time": int(header["time"]),
        "median_time_past": int(header["mediantime"]),
    }


def source_cutoff_epoch(day: date) -> int:
    end = datetime.combine(day, dt_time(23, 59, 59), tzinfo=timezone.utc)
    return int(end.timestamp())


def catalog_connect(paths: Paths, read_only: bool = False):
    duckdb = require_duckdb()
    if read_only:
        return duckdb.connect(str(paths.source_catalog), read_only=True)
    paths.source_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(paths.source_catalog))
    con.execute("SET TimeZone='UTC'")
    return con


def ensure_catalog_schema(con) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS catalog_meta(
            key VARCHAR PRIMARY KEY,
            value VARCHAR,
            updated_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS physical_blocks(
            block_hash VARCHAR PRIMARY KEY,
            prev_hash VARCHAR NOT NULL,
            header_time BIGINT NOT NULL,
            blk_file VARCHAR NOT NULL,
            file_number INTEGER NOT NULL,
            record_offset BIGINT NOT NULL,
            block_offset BIGINT NOT NULL,
            block_size BIGINT NOT NULL,
            record_size BIGINT NOT NULL,
            first_scanned_at TIMESTAMP NOT NULL DEFAULT now(),
            UNIQUE(file_number, record_offset)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS canonical_blocks(
            height BIGINT PRIMARY KEY,
            block_hash VARCHAR NOT NULL UNIQUE,
            prev_hash VARCHAR NOT NULL,
            block_time BIGINT NOT NULL,
            median_time_past BIGINT NOT NULL,
            blk_file VARCHAR NOT NULL,
            file_number INTEGER NOT NULL,
            record_offset BIGINT NOT NULL,
            block_offset BIGINT NOT NULL,
            block_size BIGINT NOT NULL,
            record_size BIGINT NOT NULL,
            source_generation_id VARCHAR NOT NULL,
            source_snapshot_sha256 VARCHAR NOT NULL,
            verified_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS source_files(
            file_number INTEGER PRIMARY KEY,
            blk_file VARCHAR NOT NULL UNIQUE,
            device BIGINT NOT NULL,
            inode BIGINT NOT NULL,
            size_bytes BIGINT NOT NULL,
            mtime_ns BIGINT NOT NULL,
            ctime_ns BIGINT NOT NULL,
            verified_prefix_end BIGINT NOT NULL,
            verified_prefix_sha256 VARCHAR,
            sealed BOOLEAN NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS catalog_ledger(
            record_no BIGINT PRIMARY KEY,
            generation_id VARCHAR NOT NULL UNIQUE,
            h1 BIGINT NOT NULL,
            h2 BIGINT NOT NULL,
            target_hash VARCHAR NOT NULL,
            target_mtp BIGINT NOT NULL,
            source_snapshot_sha256 VARCHAR NOT NULL,
            source_range_fingerprint_sha256 VARCHAR NOT NULL,
            previous_record_sha256 VARCHAR,
            record_sha256 VARCHAR NOT NULL UNIQUE,
            created_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )


def set_meta(con, key: str, value: Any) -> None:
    con.execute(
        "INSERT INTO catalog_meta(key,value,updated_at) VALUES (?,?,now()) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
        [str(key), str(value)],
    )


def get_meta(con) -> Dict[str, str]:
    if not con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name='catalog_meta'").fetchone()[0]:
        return {}
    return {str(k): str(v) for k, v in con.execute("SELECT key,value FROM catalog_meta").fetchall()}


def catalog_hwm(con) -> Tuple[int, Optional[str], Optional[int]]:
    row = con.execute("SELECT max(height) FROM canonical_blocks").fetchone()
    if row[0] is None:
        return -1, None, None
    h = int(row[0])
    r = con.execute("SELECT block_hash,median_time_past FROM canonical_blocks WHERE height=?", [h]).fetchone()
    return h, str(r[0]), int(r[1])


def verify_baseline_artifacts(paths: Paths) -> None:
    verify_file(paths.legacy_manifest, BASELINE_CANONICAL_MANIFEST_SHA256, Path(str(paths.legacy_manifest) + ".sha256"))
    verify_file(paths.legacy_locator, BASELINE_LOCATOR_SHA256, Path(str(paths.legacy_locator) + ".sha256"))
    verify_file(paths.legacy_inventory, BASELINE_INVENTORY_SHA256, Path(str(paths.legacy_inventory) + ".sha256"))
    verify_file(paths.legacy_stage2_global, BASELINE_STAGE2_GLOBAL_SHA256, Path(str(paths.legacy_stage2_global) + ".sha256"))
    verify_file(paths.extractor, BASELINE_EXTRACTOR_SHA256)
    verify_file(paths.decoder, BASELINE_DECODER_SHA256)
    verify_file(paths.locator_reference, BASELINE_LOCATOR_SCRIPT_SHA256)
    verify_file(paths.xor_file, EXPECTED_XOR_SHA256)
    if paths.xor_file.read_bytes().hex() != EXPECTED_XOR_HEX:
        raise RuntimeError("xor.dat key mismatch")


def baseline_block_times(paths: Paths) -> List[Tuple[int, int]]:
    duckdb = require_duckdb()
    block_paths = sorted((paths.legacy_stage2 / "windows").glob("window_*/blocks.parquet"))
    if len(block_paths) != 618:
        raise RuntimeError(f"baseline Stage2 blocks.parquet count mismatch: {len(block_paths)}")
    con = duckdb.connect(":memory:")
    try:
        qpaths = [str(x) for x in block_paths]
        # DuckDB 1.4.4 accepts a list literal reliably across Python bindings;
        # do not depend on list-valued parameter coercion here.
        qlist = "[" + ",".join(sql_quote(x) for x in qpaths) + "]"
        rows = con.execute(
            f"SELECT height, block_time FROM read_parquet({qlist}, union_by_name=true) ORDER BY height"
        ).fetchall()
    finally:
        con.close()
    if len(rows) != BASELINE_END_HEIGHT + 1:
        raise RuntimeError(f"baseline block time rows mismatch: {len(rows)}")
    return [(int(h), int(t)) for h, t in rows]


def compute_mtp_series(times: Sequence[Tuple[int, int]]) -> Dict[int, int]:
    window: List[int] = []
    out: Dict[int, int] = {}
    expected = 0
    for h, ts in times:
        if h != expected:
            raise RuntimeError(f"block-time height gap expected={expected} actual={h}")
        window.append(int(ts))
        if len(window) > 11:
            window.pop(0)
        out[h] = int(statistics.median(window))
        expected += 1
    return out


def bootstrap_catalog(paths: Paths) -> Dict[str, Any]:
    if paths.source_catalog.exists():
        con = catalog_connect(paths, read_only=True)
        try:
            tables = {str(r[0]) for r in con.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='main'"
            ).fetchall()}
            required = {"catalog_meta", "physical_blocks", "canonical_blocks", "source_files", "catalog_ledger"}
            if not required.issubset(tables):
                raise RuntimeError(
                    f"existing Source Catalog is incomplete/corrupt; missing tables={sorted(required-tables)} path={paths.source_catalog}"
                )
            h, hh, _ = catalog_hwm(con)
            if h < BASELINE_END_HEIGHT:
                raise RuntimeError(
                    f"existing Source Catalog is below frozen baseline hwm={h} required={BASELINE_END_HEIGHT}; "
                    "automatic rebuild/rollback is forbidden"
                )
            anchor = con.execute(
                "SELECT lower(block_hash) FROM canonical_blocks WHERE height=?", [BASELINE_END_HEIGHT]
            ).fetchone()
            if anchor != (BASELINE_END_HASH,):
                raise RuntimeError(
                    f"existing Source Catalog baseline anchor mismatch actual={anchor} expected={BASELINE_END_HASH}"
                )
            meta = get_meta(con)
            if meta.get("schema") != SOURCE_CATALOG_SCHEMA:
                raise RuntimeError(
                    f"existing Source Catalog schema mismatch actual={meta.get('schema')!r} expected={SOURCE_CATALOG_SCHEMA!r}"
                )
            return {"status": "ALREADY_BOOTSTRAPPED", "source_hwm": h, "source_hash": hh}
        finally:
            con.close()
    verify_baseline_artifacts(paths)
    times = baseline_block_times(paths)
    time_map = {h: ts for h, ts in times}
    mtp_map = compute_mtp_series(times)

    loc_rows: List[Tuple[Any, ...]] = []
    with paths.legacy_locator.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            h = int(row["height"])
            if h < 0 or h > BASELINE_END_HEIGHT:
                raise RuntimeError(f"baseline locator height out of range: {h}")
            bh = valid_hash(row["block_hash"], f"baseline locator {h}")
            prev = valid_hash(row["prev_hash"], f"baseline locator prev {h}")
            loc_rows.append(
                (
                    h, bh, prev, int(time_map[h]), int(mtp_map[h]), row["blk_file"], int(row["file_number"]),
                    int(row["record_offset"]), int(row["block_offset"]), int(row["block_size"]), int(row["record_size"]),
                )
            )
    if len(loc_rows) != BASELINE_END_HEIGHT + 1 or loc_rows[-1][1] != BASELINE_END_HASH:
        raise RuntimeError("baseline locator completeness/end anchor failure")

    inventory: List[Dict[str, Any]] = []
    with paths.legacy_inventory.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            inventory.append({k: row[k] for k in reader.fieldnames or []})
    if not inventory:
        raise RuntimeError("empty baseline inventory")
    last_file_number = max(int(r["file_number"]) for r in inventory)
    last_entry = next(r for r in inventory if int(r["file_number"]) == last_file_number)
    last_cursor = int(last_entry["size_bytes"]) - int(last_entry.get("padding_bytes") or 0)
    last_path = paths.blocks_dir / last_entry["blk_file"]
    last_prefix_sha = sha256_file(last_path, limit=last_cursor)

    generation_id = "legacy-0-617698"
    source_snapshot_sha = BASELINE_CANONICAL_MANIFEST_SHA256
    range_fp = canonical_json_hash(
        {
            "contract": "legacy-source-bootstrap-v1",
            "manifest_sha256": BASELINE_CANONICAL_MANIFEST_SHA256,
            "locator_sha256": BASELINE_LOCATOR_SHA256,
            "inventory_sha256": BASELINE_INVENTORY_SHA256,
            "stage2_global_sha256": BASELINE_STAGE2_GLOBAL_SHA256,
        }
    )
    ledger_payload = {
        "contract": SOURCE_LEDGER_CONTRACT,
        "record_no": 1,
        "generation_id": generation_id,
        "h1": 0,
        "h2": BASELINE_END_HEIGHT,
        "target_hash": BASELINE_END_HASH,
        "target_mtp": int(mtp_map[BASELINE_END_HEIGHT]),
        "source_snapshot_sha256": source_snapshot_sha,
        "source_range_fingerprint_sha256": range_fp,
        "previous_record_sha256": None,
    }
    ledger_sha = canonical_json_hash(ledger_payload)

    con = catalog_connect(paths)
    try:
        ensure_catalog_schema(con)
        con.execute("BEGIN TRANSACTION")
        try:
            con.executemany(
                """
                INSERT INTO physical_blocks(
                    block_hash,prev_hash,header_time,blk_file,file_number,record_offset,block_offset,block_size,record_size
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                [(r[1], r[2], r[3], r[5], r[6], r[7], r[8], r[9], r[10]) for r in loc_rows],
            )
            con.executemany(
                """
                INSERT INTO canonical_blocks(
                    height,block_hash,prev_hash,block_time,median_time_past,blk_file,file_number,
                    record_offset,block_offset,block_size,record_size,source_generation_id,source_snapshot_sha256
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [r + (generation_id, source_snapshot_sha) for r in loc_rows],
            )
            for row in inventory:
                num = int(row["file_number"])
                size = int(row["size_bytes"])
                padding = int(row.get("padding_bytes") or 0)
                cursor = size - padding
                prefix_sha = last_prefix_sha if num == last_file_number else None
                con.execute(
                    """
                    INSERT INTO source_files(
                        file_number,blk_file,device,inode,size_bytes,mtime_ns,ctime_ns,
                        verified_prefix_end,verified_prefix_sha256,sealed
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    [
                        num, row["blk_file"], int(row["device"]), int(row["inode"]), size,
                        int(row["mtime_ns"]), int(row["ctime_ns"]), cursor, prefix_sha, num != last_file_number,
                    ],
                )
            con.execute(
                """
                INSERT INTO catalog_ledger(
                    record_no,generation_id,h1,h2,target_hash,target_mtp,source_snapshot_sha256,
                    source_range_fingerprint_sha256,previous_record_sha256,record_sha256
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                [1, generation_id, 0, BASELINE_END_HEIGHT, BASELINE_END_HASH, int(mtp_map[BASELINE_END_HEIGHT]), source_snapshot_sha, range_fp, None, ledger_sha],
            )
            set_meta(con, "schema", SOURCE_CATALOG_SCHEMA)
            set_meta(con, "source_hwm", BASELINE_END_HEIGHT)
            set_meta(con, "source_hwm_hash", BASELINE_END_HASH)
            set_meta(con, "catalog_ledger_tail_sha256", ledger_sha)
            set_meta(con, "baseline_manifest_sha256", BASELINE_CANONICAL_MANIFEST_SHA256)
            set_meta(con, "baseline_locator_sha256", BASELINE_LOCATOR_SHA256)
            set_meta(con, "baseline_inventory_sha256", BASELINE_INVENTORY_SHA256)
            set_meta(con, "baseline_stage2_global_sha256", BASELINE_STAGE2_GLOBAL_SHA256)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        con.execute("CHECKPOINT")
    finally:
        con.close()
    return {
        "status": "BOOTSTRAPPED",
        "source_hwm": BASELINE_END_HEIGHT,
        "source_hash": BASELINE_END_HASH,
        "ledger_tail_sha256": ledger_sha,
    }


def read_catalog_tip(paths: Paths) -> Tuple[int, str, int]:
    if not paths.source_catalog.exists():
        return BASELINE_END_HEIGHT, BASELINE_END_HASH, -1
    con = catalog_connect(paths, read_only=True)
    try:
        tables = {str(r[0]) for r in con.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='main'"
        ).fetchall()}
        if "canonical_blocks" not in tables:
            raise RuntimeError(
                f"existing Source Catalog has no canonical_blocks table: {paths.source_catalog}"
            )
        h, bh, mtp = catalog_hwm(con)
    finally:
        con.close()
    if h < BASELINE_END_HEIGHT or bh is None or mtp is None:
        raise RuntimeError(
            f"existing Source Catalog is incomplete hwm={h} path={paths.source_catalog}; automatic fallback is forbidden"
        )
    return h, bh, mtp


def resolve_target_snapshot(
    paths: Paths,
    to_day: date,
    confirmations: int,
    allow_incomplete_day: bool = False,
) -> Dict[str, Any]:
    """Freeze an immutable canonical target with O(log N) Bitcoin Core RPCs.

    The v2 snapshot deliberately does *not* enumerate every height in the suffix.
    Enumerating a multi-year catch-up through getblockhash/getblockheader would turn
    the first incremental run into hundreds of thousands of RPC round-trips.

    Canonical ancestry for base+1..target is instead proven after Core is stopped:
    physical blk*.dat headers are indexed, then the target is walked backwards by
    prev_hash until the already-proven Source Catalog base anchor is reached.  The
    final physical target header and computed MTP are required to match this RPC
    target exactly before any canonical Source Catalog rows are committed.
    """
    require_core_active()
    today = datetime.now(timezone.utc).date()
    if to_day >= today and not allow_incomplete_day:
        raise RuntimeError(
            f"requested UTC day is not complete: {to_day}; use an explicit through-now policy instead"
        )
    info = rpc_json(paths, "getblockchaininfo")
    if str(info.get("chain")) != "main":
        raise RuntimeError(f"Bitcoin Core is not mainnet: chain={info.get('chain')!r}")
    tip = int(info.get("blocks", -1))
    headers = int(info.get("headers", -1))
    if tip < 0 or headers < tip:
        raise RuntimeError(f"invalid Core chain state blocks={tip} headers={headers}")
    stable = tip - max(0, int(confirmations))
    if stable < 0:
        raise RuntimeError(f"stable height below genesis tip={tip} confirmations={confirmations}")

    base_h, base_hash, base_mtp = read_catalog_tip(paths)
    if base_h > stable:
        raise RuntimeError(
            f"SOURCE_HWM is above stable Core height: source_hwm={base_h} stable={stable}; lower confirmations only explicitly"
        )
    core_base_hash = valid_hash(bitcoin_cli(paths, "getblockhash", str(base_h)), "catalog tip reorg guard")
    if core_base_hash != base_hash:
        raise RuntimeError(
            f"REORG_DETECTED_BELOW_SOURCE_HWM height={base_h} catalog={base_hash} core={core_base_hash}"
        )

    cutoff = source_cutoff_epoch(to_day)
    header_cache: Dict[int, Dict[str, Any]] = {}
    # To prove the end-of-day cut, the stable chain must already extend past
    # the requested MTP cutoff. Otherwise max(MTP <= cutoff) would silently
    # resolve to the current stable tip and produce a partial day.
    stable_header = rpc_header_at_height(paths, stable)
    header_cache[stable] = stable_header
    if int(stable_header["median_time_past"]) <= cutoff:
        raise RuntimeError(
            f"TARGET_NOT_YET_STABLE requested_day={to_day} cutoff={cutoff} "
            f"stable_height={stable} stable_mtp={stable_header['median_time_past']} confirmations={confirmations}"
        )

    # Bitcoin Core MTP is monotonic for the active chain. Binary search gives
    # the last stable block whose MTP belongs to the requested UTC day.
    lo, hi = 0, stable
    resolved = -1
    while lo <= hi:
        mid = (lo + hi) // 2
        hdr = header_cache.get(mid)
        if hdr is None:
            hdr = rpc_header_at_height(paths, mid)
            header_cache[mid] = hdr
        if int(hdr["median_time_past"]) <= cutoff:
            resolved = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if resolved < 0:
        raise RuntimeError(f"cannot resolve target for {to_day}: no canonical MTP <= cutoff")
    if resolved > stable:
        raise RuntimeError(f"resolved target exceeds stable height: {resolved}>{stable}")
    if resolved < base_h:
        raise RuntimeError(
            f"requested target is behind SOURCE_HWM: target={resolved} source_hwm={base_h}; "
            "v2 normal operation is append-only and never rolls back automatically"
        )

    target_header = header_cache.get(resolved) or rpc_header_at_height(paths, resolved)
    if resolved == base_h and target_header["block_hash"] != base_hash:
        raise RuntimeError("resolved target/base hash mismatch")

    payload: Dict[str, Any] = {
        "schema": SOURCE_SNAPSHOT_SCHEMA,
        "version": VERSION,
        "chain_mode": SOURCE_SNAPSHOT_CHAIN_MODE,
        "created_utc": utc_now_iso(),
        "requested_utc_day": to_day.isoformat(),
        "cutoff_utc": datetime.fromtimestamp(cutoff, timezone.utc).isoformat(),
        "confirmations": int(confirmations),
        "core_tip_height": tip,
        "core_headers_height": headers,
        "stable_height": stable,
        "base_height": base_h,
        "base_hash": base_hash,
        "base_median_time_past": int(base_mtp),
        "target": target_header,
        # Kept as an explicit empty list so older inspection tooling fails
        # obviously rather than mistaking absence for a truncated snapshot.
        "rows": [],
        "canonical_suffix_proof": {
            "method": SOURCE_SNAPSHOT_CHAIN_MODE,
            "authority": "bitcoin-core-active-chain-target-plus-physical-prevhash-chain",
            "rpc_suffix_enumeration": False,
            "physical_reconstruction_required": bool(resolved > base_h),
        },
    }
    payload["snapshot_sha256"] = canonical_json_hash(payload, exclude=("snapshot_sha256",))
    return payload

def verify_snapshot(snapshot: Dict[str, Any]) -> None:
    if snapshot.get("schema") != SOURCE_SNAPSHOT_SCHEMA:
        raise RuntimeError(f"source snapshot schema mismatch: {snapshot.get('schema')!r}")
    if snapshot.get("chain_mode") != SOURCE_SNAPSHOT_CHAIN_MODE:
        raise RuntimeError(
            f"source snapshot chain_mode mismatch: {snapshot.get('chain_mode')!r} "
            f"expected={SOURCE_SNAPSHOT_CHAIN_MODE!r}"
        )
    expected = canonical_json_hash(snapshot, exclude=("snapshot_sha256",))
    if snapshot.get("snapshot_sha256") != expected:
        raise RuntimeError(f"source snapshot hash mismatch expected={expected} actual={snapshot.get('snapshot_sha256')}")
    target = snapshot.get("target") if isinstance(snapshot.get("target"), dict) else None
    if target is None:
        raise RuntimeError("source snapshot target missing")
    target_h = int(target.get("height", -1))
    target_hash = valid_hash(target.get("block_hash"), "snapshot target")
    base_h = int(snapshot.get("base_height", -1))
    base_hash = valid_hash(snapshot.get("base_hash"), "snapshot base")
    if base_h < 0 or target_h < base_h:
        raise RuntimeError(f"source snapshot height range invalid base={base_h} target={target_h}")
    if target_h == base_h and target_hash != base_hash:
        raise RuntimeError("source snapshot target/base hash mismatch")
    rows = snapshot.get("rows")
    if rows != []:
        raise RuntimeError(
            "v2 physical-prevhash snapshot must not carry an RPC-enumerated suffix; "
            f"rows_type={type(rows).__name__} rows_len={len(rows) if isinstance(rows, list) else 'n/a'}"
        )
    proof = snapshot.get("canonical_suffix_proof")
    if not isinstance(proof, dict) or proof.get("method") != SOURCE_SNAPSHOT_CHAIN_MODE:
        raise RuntimeError("source snapshot canonical_suffix_proof missing or invalid")
    if proof.get("rpc_suffix_enumeration") is not False:
        raise RuntimeError("source snapshot unexpectedly claims RPC suffix enumeration")


def reconstruct_physical_canonical_suffix(
    con,
    *,
    base_height: int,
    base_hash: str,
    target: Dict[str, Any],
    physical_cache: Optional[Dict[str, Tuple[Any, ...]]] = None,
) -> List[Dict[str, Any]]:
    """Reconstruct one exact canonical suffix from the frozen RPC target backwards.

    This is the large-catch-up optimization and also a stronger source boundary:
    every suffix block must physically exist in indexed blk*.dat and the complete
    prev_hash chain must land on the already-proven catalog base anchor.
    """
    target_h = int(target["height"])
    target_hash = valid_hash(target["block_hash"], "physical target")
    if target_h < base_height:
        raise RuntimeError(f"physical reconstruction target below base {target_h}<{base_height}")
    if target_h == base_height:
        if target_hash != base_hash:
            raise RuntimeError("physical reconstruction target/base hash mismatch")
        return []

    backwards: List[Dict[str, Any]] = []
    current_hash = target_hash
    h = target_h
    while h > base_height:
        phys = (physical_cache or {}).get(current_hash)
        if phys is None:
            phys = con.execute(
                """
                SELECT prev_hash,header_time,blk_file,file_number,record_offset,block_offset,block_size,record_size
                FROM physical_blocks WHERE block_hash=?
                """,
                [current_hash],
            ).fetchone()
        if phys is None:
            raise RuntimeError(
                f"canonical target ancestry missing from physical source height={h} hash={current_hash}"
            )
        prev_hash = valid_hash(phys[0], f"physical prev height={h}")
        backwards.append({
            "height": h,
            "block_hash": current_hash,
            "prev_hash": prev_hash,
            "block_time": int(phys[1]),
            "blk_file": str(phys[2]),
            "file_number": int(phys[3]),
            "record_offset": int(phys[4]),
            "block_offset": int(phys[5]),
            "block_size": int(phys[6]),
            "record_size": int(phys[7]),
        })
        current_hash = prev_hash
        h -= 1
    if current_hash != base_hash:
        raise RuntimeError(
            f"physical canonical chain does not anchor at Source HWM height={base_height} "
            f"expected={base_hash} observed={current_hash}"
        )
    rows = list(reversed(backwards))
    expected_h = base_height + 1
    prev = base_hash
    for row in rows:
        if int(row["height"]) != expected_h or row["prev_hash"] != prev:
            raise RuntimeError(f"physical canonical chain discontinuity height={row['height']}")
        prev = row["block_hash"]
        expected_h += 1
    if rows[-1]["block_hash"] != target_hash:
        raise RuntimeError("physical canonical reconstruction final target mismatch")
    return rows


def build_physical_suffix_cache(
    con,
    scan_rows: Sequence[Tuple[Any, ...]],
    *,
    expected_suffix_blocks: int,
) -> Dict[str, Tuple[Any, ...]]:
    """Build an O(1) header lookup cache for large catch-up reconstruction.

    Newly scanned records are already in Python memory.  If the requested suffix
    is large but some records were pre-indexed by an earlier run (which may scan
    physical files past that run's canonical target), fetch only physical rows
    that are not yet canonical.  This avoids one DuckDB round-trip per block.
    """
    cache: Dict[str, Tuple[Any, ...]] = {}
    for row in scan_rows:
        cache[str(row[0])] = (
            str(row[1]), int(row[2]), str(row[3]), int(row[4]),
            int(row[5]), int(row[6]), int(row[7]), int(row[8]),
        )
    if int(expected_suffix_blocks) > 4096:
        rows = con.execute(
            """
            SELECT p.block_hash,p.prev_hash,p.header_time,p.blk_file,p.file_number,
                   p.record_offset,p.block_offset,p.block_size,p.record_size
            FROM physical_blocks p
            LEFT JOIN canonical_blocks c ON c.block_hash=p.block_hash
            WHERE c.block_hash IS NULL
            """
        ).fetchall()
        for row in rows:
            cache.setdefault(str(row[0]), (
                str(row[1]), int(row[2]), str(row[3]), int(row[4]),
                int(row[5]), int(row[6]), int(row[7]), int(row[8]),
            ))
    return cache


def attach_mtp_and_verify_rpc_target(
    con,
    *,
    base_height: int,
    rows: List[Dict[str, Any]],
    target: Dict[str, Any],
) -> None:
    """Compute exact Core-style MTP from physical header times and cross-check target."""
    if not rows:
        return
    start = max(0, int(base_height) - 9)
    prior = con.execute(
        "SELECT height,block_time FROM canonical_blocks WHERE height BETWEEN ? AND ? ORDER BY height",
        [start, int(base_height)],
    ).fetchall()
    expected_prior = int(base_height) - start + 1
    if len(prior) != expected_prior:
        raise RuntimeError(
            f"cannot seed MTP window from Source Catalog rows={len(prior)} expected={expected_prior}"
        )
    window = [int(r[1]) for r in prior]
    if len(window) > 10:
        window = window[-10:]
    for row in rows:
        window.append(int(row["block_time"]))
        if len(window) > 11:
            window.pop(0)
        row["median_time_past"] = int(statistics.median(window))
    last = rows[-1]
    checks = {
        "height": (int(last["height"]), int(target["height"])),
        "block_hash": (str(last["block_hash"]), str(target["block_hash"])),
        "prev_hash": (str(last["prev_hash"]), str(target["prev_hash"])),
        "block_time": (int(last["block_time"]), int(target["block_time"])),
        "median_time_past": (int(last["median_time_past"]), int(target["median_time_past"])),
    }
    bad = {k: v for k, v in checks.items() if v[0] != v[1]}
    if bad:
        raise RuntimeError(f"physical target does not match frozen Bitcoin Core RPC target: {bad}")

def scan_block_file_entries(paths: Paths) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for p in paths.blocks_dir.iterdir():
        if not p.is_file() or p.is_symlink():
            continue
        m = BLK_RE.fullmatch(p.name)
        if not m:
            continue
        st = p.stat()
        entries.append(
            {
                "file_number": int(m.group(1)), "blk_file": p.name, "path": p,
                "size_bytes": int(st.st_size), "mtime_ns": int(st.st_mtime_ns), "ctime_ns": int(st.st_ctime_ns),
                "inode": int(st.st_ino), "device": int(st.st_dev),
            }
        )
    entries.sort(key=lambda x: x["file_number"])
    if not entries or entries[0]["file_number"] != 0:
        raise RuntimeError("blk file set missing blk00000.dat")
    for i, row in enumerate(entries):
        if int(row["file_number"]) != i:
            raise RuntimeError(f"blk file numbering gap expected={i} actual={row['file_number']}")
    return entries


def read_catalog_source_files(con) -> Dict[int, Dict[str, Any]]:
    rows = con.execute(
        "SELECT file_number,blk_file,device,inode,size_bytes,mtime_ns,ctime_ns,verified_prefix_end,verified_prefix_sha256,sealed "
        "FROM source_files ORDER BY file_number"
    ).fetchall()
    return {
        int(r[0]): {
            "file_number": int(r[0]), "blk_file": str(r[1]), "device": int(r[2]), "inode": int(r[3]),
            "size_bytes": int(r[4]), "mtime_ns": int(r[5]), "ctime_ns": int(r[6]), "verified_prefix_end": int(r[7]),
            "verified_prefix_sha256": None if r[8] is None else str(r[8]), "sealed": bool(r[9]),
        }
        for r in rows
    }


def xor_at(raw: bytes, absolute_offset: int, key: bytes) -> bytes:
    return bytes(value ^ key[(absolute_offset + i) % len(key)] for i, value in enumerate(raw))


def sha256d_display(header: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def scan_legacy_inventory_physical_backfill(
    paths: Paths,
    con,
    current_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """One-time physical-header backfill for the frozen legacy Stage1 inventory.

    The legacy Stage1 locator scanned every physical record in every blk*.dat
    that existed at baseline creation, but its locator intentionally published
    only canonical heights 0..617698.  The original v2 bootstrap imported the
    complete Stage1 file inventory/cursors into source_files while importing
    only those canonical locator rows into physical_blocks.  Marking the old
    files sealed then made the incremental scanner skip already-existing
    post-baseline records forever.

    Under the Bitcoin Core datadir lock, re-read only storage headers + 80-byte
    block headers through the exact SHA-pinned legacy inventory prefix.  No
    transaction payload is decoded and no canonical/source HWM is changed here.
    Publication happens later in the caller's single SOURCE transaction.
    """
    meta = get_meta(con)
    if meta.get(LEGACY_PHYSICAL_BACKFILL_META_KEY) == "COMPLETE":
        return {
            "needed": False,
            "status": "ALREADY_COMPLETE",
            "physical_rows": [],
            "records_scanned": 0,
            "files_scanned": 0,
        }
    if meta.get("baseline_inventory_sha256") != BASELINE_INVENTORY_SHA256:
        raise RuntimeError(
            "legacy physical backfill refused: Source Catalog baseline inventory pin mismatch "
            f"actual={meta.get('baseline_inventory_sha256')!r} expected={BASELINE_INVENTORY_SHA256}"
        )
    verify_file(
        paths.legacy_inventory,
        BASELINE_INVENTORY_SHA256,
        Path(str(paths.legacy_inventory) + ".sha256"),
    )
    verify_file(paths.xor_file, EXPECTED_XOR_SHA256)
    xor_key = paths.xor_file.read_bytes()
    if len(xor_key) != 8 or xor_key.hex() != EXPECTED_XOR_HEX:
        raise RuntimeError("legacy physical backfill refused: xor.dat changed")

    inventory: List[Dict[str, Any]] = []
    with paths.legacy_inventory.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")
        required = {
            "file_number", "blk_file", "size_bytes", "mtime_ns", "ctime_ns",
            "inode", "device", "padding_bytes",
        }
        if not required.issubset(set(reader.fieldnames or [])):
            raise RuntimeError(
                f"legacy physical backfill inventory schema missing={sorted(required-set(reader.fieldnames or []))}"
            )
        for row in reader:
            inventory.append({k: row[k] for k in reader.fieldnames or []})
    if not inventory:
        raise RuntimeError("legacy physical backfill inventory is empty")

    inventory.sort(key=lambda r: int(r["file_number"]))
    for expected, row in enumerate(inventory):
        if int(row["file_number"]) != expected or row["blk_file"] != f"blk{expected:05d}.dat":
            raise RuntimeError(
                "legacy physical backfill inventory file numbering/name mismatch "
                f"expected=blk{expected:05d}.dat actual={row.get('blk_file')} number={row.get('file_number')}"
            )

    stored = read_catalog_source_files(con)
    current_by_num = {int(x["file_number"]): x for x in current_entries}
    physical_rows: List[Tuple[Any, ...]] = []
    total_records = 0

    for file_index, row in enumerate(inventory, start=1):
        num = int(row["file_number"])
        cur = current_by_num.get(num)
        old = stored.get(num)
        if cur is None or old is None:
            raise RuntimeError(
                f"legacy physical backfill missing file/catalog row number={num} file={row['blk_file']}"
            )
        if str(old["blk_file"]) != str(row["blk_file"]) or str(cur["blk_file"]) != str(row["blk_file"]):
            raise RuntimeError(f"legacy physical backfill blk filename mismatch number={num}")
        # source_files is the already-validated bootstrap binding.  Its cursor
        # must cover at least the immutable Stage1 record prefix we are about to
        # index; it may be ahead only if a newer successful scan already ran.
        limit = int(row["size_bytes"]) - int(row.get("padding_bytes") or 0)
        if limit < 0 or int(old["verified_prefix_end"]) < limit:
            raise RuntimeError(
                f"legacy physical backfill cursor contract invalid file={row['blk_file']} "
                f"inventory_limit={limit} catalog_cursor={old['verified_prefix_end']}"
            )
        # For files Stage1 classified as sealed, the exact historical identity
        # must still match.  The former open tail may have legitimately grown;
        # scan_new_physical_records already verifies its old prefix hash.
        if bool(old["sealed"]):
            for k in ("device", "inode", "size_bytes", "mtime_ns", "ctime_ns"):
                if int(cur[k]) != int(row[k]):
                    raise RuntimeError(
                        f"legacy physical backfill sealed identity changed file={row['blk_file']} field={k} "
                        f"current={cur[k]} inventory={row[k]}"
                    )
        else:
            for k in ("device", "inode"):
                if int(cur[k]) != int(row[k]):
                    raise RuntimeError(
                        f"legacy physical backfill open-tail identity changed file={row['blk_file']} field={k}"
                    )
            if int(cur["size_bytes"]) < limit:
                raise RuntimeError(
                    f"legacy physical backfill open tail shrank file={row['blk_file']} "
                    f"current={cur['size_bytes']} inventory_limit={limit}"
                )

        pos = 0
        fd = os.open(str(cur["path"]), os.O_RDONLY)
        try:
            while pos < limit:
                remaining = limit - pos
                if remaining < 8:
                    raise RuntimeError(
                        f"legacy physical backfill short record area file={row['blk_file']} offset={pos} remaining={remaining}"
                    )
                raw8 = os.pread(fd, 8, pos)
                if len(raw8) != 8:
                    raise RuntimeError(f"legacy physical backfill short storage header file={row['blk_file']} offset={pos}")
                if raw8 == b"\x00" * 8:
                    raise RuntimeError(
                        f"legacy physical backfill encountered zero padding before inventory cursor "
                        f"file={row['blk_file']} offset={pos} limit={limit}"
                    )
                decoded8 = xor_at(raw8, pos, xor_key)
                if decoded8[:4] != MAINNET_MAGIC:
                    raise RuntimeError(f"legacy physical backfill mainnet magic mismatch file={row['blk_file']} offset={pos}")
                block_size = struct.unpack("<I", decoded8[4:8])[0]
                if not (MIN_BLOCK_SERIALIZED_SIZE <= block_size <= MAX_BLOCK_SERIALIZED_SIZE):
                    raise RuntimeError(
                        f"legacy physical backfill implausible block size={block_size} file={row['blk_file']} offset={pos}"
                    )
                end = pos + 8 + block_size
                if end > limit:
                    raise RuntimeError(
                        f"legacy physical backfill record crosses pinned inventory cursor file={row['blk_file']} "
                        f"offset={pos} end={end} limit={limit}"
                    )
                raw_header = os.pread(fd, 80, pos + 8)
                if len(raw_header) != 80:
                    raise RuntimeError(f"legacy physical backfill short block header file={row['blk_file']} offset={pos+8}")
                header = xor_at(raw_header, pos + 8, xor_key)
                bh = sha256d_display(header)
                prev = header[4:36][::-1].hex()
                header_time = int(struct.unpack("<I", header[68:72])[0])
                physical_rows.append(
                    (bh, prev, header_time, row["blk_file"], num, pos, pos + 8, block_size, block_size + 8)
                )
                total_records += 1
                pos = end
        finally:
            os.close(fd)
        if pos != limit:
            raise RuntimeError(
                f"legacy physical backfill did not end exactly at inventory cursor file={row['blk_file']} pos={pos} limit={limit}"
            )
        if file_index == 1 or file_index % 250 == 0 or file_index == len(inventory):
            print(
                f"SOURCE_BACKFILL files={file_index}/{len(inventory)} records={total_records} "
                f"file={row['blk_file']}",
                file=sys.stderr,
                flush=True,
            )

    return {
        "needed": True,
        "status": "SCANNED",
        "physical_rows": physical_rows,
        "records_scanned": total_records,
        "files_scanned": len(inventory),
    }


def scan_new_physical_records(
    paths: Paths,
    con,
    current_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    stored = read_catalog_source_files(con)
    xor_key = paths.xor_file.read_bytes()
    if len(xor_key) != 8 or xor_key.hex() != EXPECTED_XOR_HEX:
        raise RuntimeError("xor.dat changed")
    current_by_num = {int(x["file_number"]): x for x in current_entries}
    if stored:
        max_stored = max(stored)
        for num, old in stored.items():
            cur = current_by_num.get(num)
            if cur is None:
                raise RuntimeError(f"previous blk file disappeared: {old['blk_file']}")
            if cur["inode"] != old["inode"] or cur["device"] != old["device"]:
                raise RuntimeError(f"blk file inode/device changed: {old['blk_file']}")
            if old["sealed"]:
                for k in ("size_bytes", "mtime_ns", "ctime_ns"):
                    if int(cur[k]) != int(old[k]):
                        raise RuntimeError(f"sealed blk file changed field={k} file={old['blk_file']}")
            else:
                cursor = int(old["verified_prefix_end"])
                if int(cur["size_bytes"]) < cursor:
                    raise RuntimeError(f"open tail shrank below verified prefix: {old['blk_file']}")
                expected_prefix = old.get("verified_prefix_sha256")
                if expected_prefix:
                    actual_prefix = sha256_file(Path(cur["path"]), limit=cursor)
                    if actual_prefix != expected_prefix:
                        raise RuntimeError(
                            f"open tail verified prefix changed file={old['blk_file']} expected={expected_prefix} actual={actual_prefix}"
                        )
        if max(current_by_num) < max_stored:
            raise RuntimeError("current blk file set is shorter than catalog")

    physical_rows: List[Tuple[Any, ...]] = []
    file_updates: List[Dict[str, Any]] = []
    total_records = 0
    for cur in current_entries:
        num = int(cur["file_number"])
        old = stored.get(num)
        if old and old["sealed"]:
            continue
        pos = int(old["verified_prefix_end"]) if old else 0
        file_size = int(cur["size_bytes"])
        fd = os.open(str(cur["path"]), os.O_RDONLY)
        try:
            while pos < file_size:
                remaining = file_size - pos
                if remaining < 8:
                    tail = os.pread(fd, remaining, pos)
                    if any(tail):
                        raise RuntimeError(f"nonzero short blk tail file={cur['blk_file']} offset={pos}")
                    break
                raw8 = os.pread(fd, 8, pos)
                if raw8 == b"\x00" * 8:
                    break
                if len(raw8) != 8:
                    raise RuntimeError(f"short blk storage header file={cur['blk_file']} offset={pos}")
                decoded8 = xor_at(raw8, pos, xor_key)
                if decoded8[:4] != MAINNET_MAGIC:
                    raise RuntimeError(f"mainnet magic mismatch file={cur['blk_file']} offset={pos}")
                block_size = struct.unpack("<I", decoded8[4:8])[0]
                if not (MIN_BLOCK_SERIALIZED_SIZE <= block_size <= MAX_BLOCK_SERIALIZED_SIZE):
                    raise RuntimeError(f"implausible block size={block_size} file={cur['blk_file']} offset={pos}")
                end = pos + 8 + block_size
                if end > file_size:
                    raise RuntimeError(f"block record beyond EOF file={cur['blk_file']} offset={pos} size={block_size}")
                raw_header = os.pread(fd, 80, pos + 8)
                if len(raw_header) != 80:
                    raise RuntimeError(f"short block header file={cur['blk_file']} offset={pos+8}")
                header = xor_at(raw_header, pos + 8, xor_key)
                bh = sha256d_display(header)
                prev = header[4:36][::-1].hex()
                header_time = int(struct.unpack("<I", header[68:72])[0])
                physical_rows.append(
                    (bh, prev, header_time, cur["blk_file"], num, pos, pos + 8, block_size, block_size + 8)
                )
                total_records += 1
                pos = end
        finally:
            os.close(fd)
        # Only bytes through pos are authoritative; bytes after pos may be zero preallocation.
        prefix_sha = sha256_file(Path(cur["path"]), limit=pos)
        sealed = num < max(current_by_num)
        file_updates.append(
            {
                "file_number": num, "blk_file": cur["blk_file"], "device": cur["device"], "inode": cur["inode"],
                "size_bytes": cur["size_bytes"], "mtime_ns": cur["mtime_ns"], "ctime_ns": cur["ctime_ns"],
                "verified_prefix_end": pos, "verified_prefix_sha256": prefix_sha, "sealed": sealed,
            }
        )
    return {"physical_rows": physical_rows, "file_updates": file_updates, "records_scanned": total_records}


def commit_source_snapshot(
    paths: Paths,
    snapshot: Dict[str, Any],
    *,
    datadir_lock_held: bool = False,
) -> Dict[str, Any]:
    verify_snapshot(snapshot)
    # cmd_build() normally holds the Bitcoin Core datadir lock across the whole
    # SOURCE+STAGE operation.  Standalone/internal callers remain fail-closed.
    core_lock_fd: Optional[int] = None
    if not datadir_lock_held:
        core_lock_fd = require_core_stopped_and_lock(paths)
    try:
        bootstrap_catalog(paths)
        consume_stop_if_requested(paths.stop_file, "before_source_catalog_mutation")
        lock = acquire_file_lock(paths.source_lock)
        try:
            con = catalog_connect(paths)
            try:
                ensure_catalog_schema(con)
                hwm, hwm_hash, _ = catalog_hwm(con)
                snapshot_base_h = int(snapshot["base_height"])
                snapshot_base_hash = str(snapshot["base_hash"])
                snapshot_sha = str(snapshot["snapshot_sha256"])
                target = snapshot["target"]
                target_h = int(target["height"])
                target_hash = str(target["block_hash"])

                # Resume must be idempotent.  SOURCE publication is one DuckDB
                # transaction, so after a controlled stop we can only observe
                # either the snapshot base or the complete snapshot target.
                # A target-complete catalog is accepted only after exact row
                # reconciliation; an intermediate HWM is a hard invariant break.
                source_already_green = False
                if hwm == target_h and hwm_hash == target_hash:
                    if target_h < snapshot_base_h:
                        raise RuntimeError(
                            f"source catalog target precedes snapshot base target={target_h} base={snapshot_base_h}"
                        )
                    expected_count = target_h - snapshot_base_h
                    observed_rows = con.execute(
                        """
                        SELECT height,block_hash,prev_hash,block_time,median_time_past,source_snapshot_sha256
                        FROM canonical_blocks WHERE height>? AND height<=? ORDER BY height
                        """,
                        [snapshot_base_h, target_h],
                    ).fetchall()
                    if len(observed_rows) != expected_count:
                        raise RuntimeError(
                            f"SOURCE resume row-count mismatch observed={len(observed_rows)} expected={expected_count}"
                        )
                    prev = snapshot_base_hash
                    expected_h = snapshot_base_h + 1
                    for observed_row in observed_rows:
                        h = int(observed_row[0])
                        bh = str(observed_row[1])
                        ph = str(observed_row[2])
                        if h != expected_h or ph != prev:
                            raise RuntimeError(
                                f"SOURCE resume canonical chain mismatch height={h} expected_height={expected_h} "
                                f"prev={ph} expected_prev={prev}"
                            )
                        if str(observed_row[5]) != snapshot_sha:
                            raise RuntimeError(
                                f"SOURCE resume snapshot binding mismatch height={h} "
                                f"observed={observed_row[5]} expected={snapshot_sha}"
                            )
                        prev = bh
                        expected_h += 1
                    if observed_rows:
                        if prev != target_hash:
                            raise RuntimeError(
                                f"SOURCE resume final hash mismatch observed={prev} expected={target_hash}"
                            )
                        if int(observed_rows[-1][4]) != int(target["median_time_past"]):
                            raise RuntimeError(
                                "SOURCE resume target MTP mismatch "
                                f"observed={observed_rows[-1][4]} expected={target['median_time_past']}"
                            )
                    elif target_h != snapshot_base_h:
                        raise RuntimeError("SOURCE resume unexpectedly empty suffix")
                    source_already_green = True
                elif hwm == snapshot_base_h and hwm_hash == snapshot_base_hash:
                    source_already_green = False
                elif snapshot_base_h < hwm < target_h:
                    raise RuntimeError(
                        f"SOURCE catalog is partially advanced inside an atomic snapshot range: "
                        f"base={snapshot_base_h} hwm={hwm} target={target_h}"
                    )
                elif hwm > target_h:
                    raise RuntimeError(
                        f"SOURCE catalog is ahead of immutable target hwm={hwm} target={target_h}; automatic rollback forbidden"
                    )
                else:
                    raise RuntimeError(
                        f"source snapshot base no longer matches catalog hwm={hwm}/{hwm_hash} "
                        f"snapshot={snapshot_base_h}/{snapshot_base_hash}"
                    )

                entries = scan_block_file_entries(paths)
                # Validate current files/cursors first, then repair the one-time
                # rc2 bootstrap omission: the legacy Stage1 inventory covered
                # physical records beyond 617698 but physical_blocks did not.
                scan = scan_new_physical_records(paths, con, entries)
                legacy_backfill = scan_legacy_inventory_physical_backfill(paths, con, entries)
                physical_rows = list(legacy_backfill["physical_rows"]) + list(scan["physical_rows"])
                generation_id = f"source-{utc_stamp()}-{uuid.uuid4().hex[:12]}"

                con.execute("BEGIN TRANSACTION")
                try:
                    # Reconcile the potentially large one-time backfill in bulk.
                    # A per-row SELECT would turn ~1M header records into ~1M
                    # DuckDB round-trips.  Read the existing physical index once,
                    # validate exact hash/location identity in memory, then insert
                    # only genuinely new rows with one executemany batch.
                    existing_rows = con.execute(
                        "SELECT block_hash,prev_hash,header_time,blk_file,file_number,"
                        "record_offset,block_offset,block_size,record_size FROM physical_blocks"
                    ).fetchall()
                    by_hash: Dict[str, Tuple[Any, ...]] = {}
                    by_location: Dict[Tuple[int, int], str] = {}
                    for existing in existing_rows:
                        eh = str(existing[0])
                        payload = (
                            str(existing[1]), int(existing[2]), str(existing[3]), int(existing[4]),
                            int(existing[5]), int(existing[6]), int(existing[7]), int(existing[8]),
                        )
                        loc = (int(existing[4]), int(existing[5]))
                        if eh in by_hash or loc in by_location:
                            raise RuntimeError(f"physical_blocks existing uniqueness invariant failed hash={eh} location={loc}")
                        by_hash[eh] = payload
                        by_location[loc] = eh

                    new_physical_rows: List[Tuple[Any, ...]] = []
                    for row in physical_rows:
                        rh = str(row[0])
                        expected = (
                            str(row[1]), int(row[2]), str(row[3]), int(row[4]),
                            int(row[5]), int(row[6]), int(row[7]), int(row[8]),
                        )
                        loc = (int(row[4]), int(row[5]))
                        existing = by_hash.get(rh)
                        if existing is not None:
                            if existing != expected:
                                raise RuntimeError(
                                    f"physical block re-scan identity mismatch hash={rh} observed={existing} expected={expected}"
                                )
                            if by_location.get(loc) != rh:
                                raise RuntimeError(
                                    f"physical block hash/location cross-index mismatch hash={rh} location={loc}"
                                )
                            continue
                        other_hash = by_location.get(loc)
                        if other_hash is not None:
                            raise RuntimeError(
                                f"physical location already bound to different block hash file={row[3]} "
                                f"offset={row[5]} existing={other_hash} scanned={rh}"
                            )
                        new_physical_rows.append(tuple(row))
                        by_hash[rh] = expected
                        by_location[loc] = rh

                    if new_physical_rows:
                        con.executemany(
                            """
                            INSERT INTO physical_blocks(
                                block_hash,prev_hash,header_time,blk_file,file_number,record_offset,block_offset,block_size,record_size
                            ) VALUES (?,?,?,?,?,?,?,?,?)
                            """,
                            new_physical_rows,
                        )
                    for frow in scan["file_updates"]:
                        con.execute(
                            """
                            INSERT INTO source_files(
                                file_number,blk_file,device,inode,size_bytes,mtime_ns,ctime_ns,
                                verified_prefix_end,verified_prefix_sha256,sealed,updated_at
                            ) VALUES (?,?,?,?,?,?,?,?,?,?,now())
                            ON CONFLICT(file_number) DO UPDATE SET
                                blk_file=excluded.blk_file,device=excluded.device,inode=excluded.inode,
                                size_bytes=excluded.size_bytes,mtime_ns=excluded.mtime_ns,ctime_ns=excluded.ctime_ns,
                                verified_prefix_end=excluded.verified_prefix_end,
                                verified_prefix_sha256=excluded.verified_prefix_sha256,sealed=excluded.sealed,updated_at=now()
                            """,
                            [
                                frow["file_number"], frow["blk_file"], frow["device"], frow["inode"], frow["size_bytes"],
                                frow["mtime_ns"], frow["ctime_ns"], frow["verified_prefix_end"], frow["verified_prefix_sha256"], frow["sealed"],
                            ],
                        )
    
                    if legacy_backfill["needed"]:
                        set_meta(con, LEGACY_PHYSICAL_BACKFILL_META_KEY, "COMPLETE")
                        set_meta(con, "legacy_inventory_physical_backfill_inventory_sha256", BASELINE_INVENTORY_SHA256)
                        set_meta(con, "legacy_inventory_physical_backfill_files", int(legacy_backfill["files_scanned"]))
                        set_meta(con, "legacy_inventory_physical_backfill_records", int(legacy_backfill["records_scanned"]))
                        set_meta(con, "legacy_inventory_physical_backfill_completed_utc", utc_now_iso())

                    suffix_rows: List[Dict[str, Any]] = []
                    if not source_already_green:
                        expected_count = target_h - snapshot_base_h
                        physical_cache = build_physical_suffix_cache(
                            con,
                            physical_rows,
                            expected_suffix_blocks=expected_count,
                        )
                        suffix_rows = reconstruct_physical_canonical_suffix(
                            con,
                            base_height=snapshot_base_h,
                            base_hash=snapshot_base_hash,
                            target=target,
                            physical_cache=physical_cache,
                        )
                        attach_mtp_and_verify_rpc_target(
                            con,
                            base_height=snapshot_base_h,
                            rows=suffix_rows,
                            target=target,
                        )
                        if len(suffix_rows) != expected_count:
                            raise RuntimeError(
                                f"physical canonical suffix row-count mismatch rows={len(suffix_rows)} expected={expected_count}"
                            )

                    expected_h = snapshot_base_h + 1
                    prev = snapshot_base_hash
                    fp_rows: List[Dict[str, Any]] = []
                    for row in suffix_rows:
                        h = int(row["height"])
                        bh = valid_hash(row["block_hash"], f"source row {h}")
                        if h != expected_h or row["prev_hash"] != prev:
                            raise RuntimeError(f"physical source chain discontinuity at height={h}")
                        con.execute(
                            """
                            INSERT INTO canonical_blocks(
                                height,block_hash,prev_hash,block_time,median_time_past,blk_file,file_number,
                                record_offset,block_offset,block_size,record_size,source_generation_id,source_snapshot_sha256
                            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                            """,
                            [
                                h, bh, row["prev_hash"], int(row["block_time"]), int(row["median_time_past"]),
                                str(row["blk_file"]), int(row["file_number"]), int(row["record_offset"]),
                                int(row["block_offset"]), int(row["block_size"]), int(row["record_size"]),
                                generation_id, snapshot_sha,
                            ],
                        )
                        fp_rows.append({
                            "height": h, "block_hash": bh, "prev_hash": row["prev_hash"],
                            "block_time": int(row["block_time"]), "median_time_past": int(row["median_time_past"]),
                            "blk_file": str(row["blk_file"]), "record_offset": int(row["record_offset"]),
                            "block_size": int(row["block_size"]),
                        })
                        prev = bh
                        expected_h += 1

                    if suffix_rows and not source_already_green:
                        prev_record = con.execute("SELECT record_no,record_sha256 FROM catalog_ledger ORDER BY record_no DESC LIMIT 1").fetchone()
                        record_no = int(prev_record[0]) + 1 if prev_record else 1
                        previous_sha = str(prev_record[1]) if prev_record else None
                        range_fp = canonical_json_hash({"schema": SOURCE_CATALOG_SCHEMA, "rows": fp_rows})
                        ledger_payload = {
                            "contract": SOURCE_LEDGER_CONTRACT,
                            "record_no": record_no,
                            "generation_id": generation_id,
                            "h1": int(suffix_rows[0]["height"]),
                            "h2": int(suffix_rows[-1]["height"]),
                            "target_hash": str(target["block_hash"]),
                            "target_mtp": int(target["median_time_past"]),
                            "source_snapshot_sha256": snapshot_sha,
                            "source_range_fingerprint_sha256": range_fp,
                            "previous_record_sha256": previous_sha,
                        }
                        ledger_sha = canonical_json_hash(ledger_payload)
                        con.execute(
                            """
                            INSERT INTO catalog_ledger(
                                record_no,generation_id,h1,h2,target_hash,target_mtp,source_snapshot_sha256,
                                source_range_fingerprint_sha256,previous_record_sha256,record_sha256
                            ) VALUES (?,?,?,?,?,?,?,?,?,?)
                            """,
                            [
                                record_no, generation_id, int(suffix_rows[0]["height"]), int(suffix_rows[-1]["height"]),
                                str(target["block_hash"]), int(target["median_time_past"]), snapshot_sha, range_fp, previous_sha, ledger_sha,
                            ],
                        )
                        set_meta(con, "catalog_ledger_tail_sha256", ledger_sha)
                        set_meta(con, "source_hwm", int(suffix_rows[-1]["height"]))
                        set_meta(con, "source_hwm_hash", str(suffix_rows[-1]["block_hash"]))
                    con.execute("COMMIT")
                except BaseException:
                    con.execute("ROLLBACK")
                    raise
                con.execute("CHECKPOINT")
                final_h, final_hash, final_mtp = catalog_hwm(con)
            finally:
                con.close()
            consume_stop_if_requested(
                paths.stop_file,
                "after_source_catalog_commit",
                {"source_hwm": final_h, "source_hash": final_hash},
            )
            return {
                "status": "SOURCE_ALREADY_GREEN" if source_already_green else "SOURCE_GREEN",
                "source_hwm": final_h,
                "source_hash": final_hash,
                "source_mtp": final_mtp,
                "records_scanned": scan["records_scanned"],
                "legacy_inventory_backfill": {
                    "status": "COMPLETE" if legacy_backfill["needed"] else "ALREADY_COMPLETE",
                    "files_scanned": int(legacy_backfill["files_scanned"]),
                    "records_scanned": int(legacy_backfill["records_scanned"]),
                },
                "generation_id": None if source_already_green or final_h == snapshot_base_h else generation_id,
                "snapshot_sha256": snapshot_sha,
            }
        finally:
            lock.close()
    finally:
        if core_lock_fd is not None:
            os.close(core_lock_fd)

def stage_index_connect(paths: Paths, read_only: bool = False):
    duckdb = require_duckdb()
    if read_only:
        return duckdb.connect(str(paths.stage_index), read_only=True)
    paths.stage_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(paths.stage_index))
    con.execute("SET TimeZone='UTC'")
    return con


def ensure_stage_index_schema(con) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS stage_meta(
            key VARCHAR PRIMARY KEY,value VARCHAR,updated_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS stage_windows(
            start_height BIGINT PRIMARY KEY,
            end_height BIGINT NOT NULL UNIQUE,
            window_dir VARCHAR NOT NULL UNIQUE,
            manifest_path VARCHAR NOT NULL UNIQUE,
            manifest_sha256 VARCHAR NOT NULL UNIQUE,
            generation_id VARCHAR NOT NULL,
            blocks_sha256 VARCHAR NOT NULL,
            transactions_sha256 VARCHAR NOT NULL,
            inputs_sha256 VARCHAR NOT NULL,
            outputs_sha256 VARCHAR NOT NULL,
            blocks BIGINT NOT NULL,
            transactions BIGINT NOT NULL,
            inputs BIGINT NOT NULL,
            outputs BIGINT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS stage_generations(
            generation_id VARCHAR PRIMARY KEY,
            h1 BIGINT NOT NULL,
            h2 BIGINT NOT NULL,
            manifest_path VARCHAR NOT NULL UNIQUE,
            manifest_sha256 VARCHAR NOT NULL UNIQUE,
            source_snapshot_sha256 VARCHAR NOT NULL,
            source_ledger_tail_sha256 VARCHAR NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT now()
        )
        """
    )


def stage_hwm(paths: Paths) -> int:
    if not paths.stage_index.exists():
        return BASELINE_END_HEIGHT
    con = stage_index_connect(paths, read_only=True)
    try:
        ensure = con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name='stage_windows'").fetchone()[0]
        if not ensure:
            return BASELINE_END_HEIGHT
        row = con.execute("SELECT max(end_height) FROM stage_windows").fetchone()[0]
        if row is None:
            return BASELINE_END_HEIGHT
        # Prove contiguous v2 suffix starting immediately after baseline.
        rows = con.execute("SELECT start_height,end_height FROM stage_windows ORDER BY start_height").fetchall()
        nxt = BASELINE_END_HEIGHT + 1
        for h1, h2 in rows:
            if int(h1) != nxt or int(h2) < int(h1):
                raise RuntimeError(f"Stage index gap/overlap expected_start={nxt} actual={h1}..{h2}")
            nxt = int(h2) + 1
        return nxt - 1
    finally:
        con.close()


def configure_extractor_helpers(paths: Paths, cores: int, memory: str):
    extractor, extractor_sha = load_module(paths.extractor, BASELINE_EXTRACTOR_SHA256, "utxo_v2_frozen_extractor")
    decoder, decoder_sha = load_module(paths.decoder, BASELINE_DECODER_SHA256, "utxo_v2_frozen_decoder")
    extractor.BLOCKS_DIR = paths.blocks_dir
    extractor.TMP_ROOT = paths.tmp_root / "stage" / "extractor"
    extractor.DUCKDB_TMP = paths.tmp_root / "stage" / "duckdb"
    extractor.DUCKDB_THREADS = max(1, int(cores))
    extractor.DUCKDB_MEMORY_LIMIT = str(memory)
    extractor.TMP_ROOT.mkdir(parents=True, exist_ok=True)
    extractor.DUCKDB_TMP.mkdir(parents=True, exist_ok=True)
    return extractor, decoder, extractor_sha, decoder_sha


def catalog_rows_for_range(paths: Paths, h1: int, h2: int) -> List[Dict[str, Any]]:
    con = catalog_connect(paths, read_only=True)
    try:
        rows = con.execute(
            """
            SELECT height,block_hash,prev_hash,block_time,median_time_past,blk_file,file_number,
                   record_offset,block_offset,block_size,record_size,source_generation_id,source_snapshot_sha256
            FROM canonical_blocks WHERE height BETWEEN ? AND ? ORDER BY height
            """,
            [int(h1), int(h2)],
        ).fetchall()
    finally:
        con.close()
    if len(rows) != h2 - h1 + 1:
        raise RuntimeError(f"catalog range incomplete h1={h1} h2={h2} rows={len(rows)}")
    out: List[Dict[str, Any]] = []
    expected = h1
    for r in rows:
        if int(r[0]) != expected:
            raise RuntimeError(f"catalog height gap expected={expected} actual={r[0]}")
        out.append(
            {
                "height": int(r[0]), "block_hash": str(r[1]), "prev_hash": str(r[2]), "block_time": int(r[3]),
                "median_time_past": int(r[4]), "blk_file": str(r[5]), "file_number": int(r[6]),
                "record_offset": int(r[7]), "block_offset": int(r[8]), "block_size": int(r[9]), "record_size": int(r[10]),
                "source_generation_id": str(r[11]), "source_snapshot_sha256": str(r[12]),
            }
        )
        expected += 1
    return out


def build_one_stage_window(
    paths: Paths,
    h1: int,
    h2: int,
    generation_id: str,
    cores: int,
    memory: str,
) -> Dict[str, Any]:
    duckdb = require_duckdb()
    extractor, decoder, extractor_sha, decoder_sha = configure_extractor_helpers(paths, cores, memory)
    rows = catalog_rows_for_range(paths, h1, h2)
    final_dir = paths.stage_windows / f"window_{h1:06d}_{h2:06d}"
    output_tmp = paths.tmp_root / "stage" / f"window_{h1:06d}_{h2:06d}.publish.{uuid.uuid4().hex}"
    stage_tmp = paths.tmp_root / "stage" / f"window_{h1:06d}_{h2:06d}.tsv.{uuid.uuid4().hex}"
    if final_dir.exists():
        raise RuntimeError(f"immutable Stage window already exists unexpectedly: {final_dir}")
    output_tmp.mkdir(parents=True, exist_ok=False)
    stage_tmp.mkdir(parents=True, exist_ok=False)
    counters = {
        "blocks": 0, "transactions": 0, "inputs": 0, "outputs": 0,
        "witness_transactions": 0, "txid_wtxid_differences": 0,
        "block_bytes": 0, "stripped_block_bytes": 0, "block_weight": 0,
    }
    stage_paths = None
    files = None
    started = time.time()
    try:
        stage_paths, files = extractor.open_staging_files(stage_tmp)
        xor_key = paths.xor_file.read_bytes()
        with extractor.BlockFileReader(xor_key, decoder, max_open=32) as reader:
            for row in rows:
                block = reader.read(row)
                decoded = extractor.decode_block_full(
                    block, row["height"], row["block_hash"], row["prev_hash"], decoder
                )
                if int(decoded["time"]) != int(row["block_time"]):
                    raise RuntimeError(f"catalog/header time mismatch height={row['height']}")
                extractor.write_decoded_block(decoded, row, block, files, decoder, counters)
        extractor.close_fsync_staging(files)
        files = None
        extractor.convert_tsv_to_parquet(duckdb, stage_paths, output_tmp)
        validated = extractor.validate_parquets(duckdb, output_tmp, h1, h2, counters)
        file_info: Dict[str, Dict[str, Any]] = {}
        for name in ("blocks.parquet", "transactions.parquet", "inputs.parquet", "outputs.parquet"):
            p = output_tmp / name
            file_info[name] = {"sha256": sha256_file(p), "size_bytes": p.stat().st_size}
            # R12.9 deliberately requires a detached seal in addition to the
            # hashes embedded in the window manifest and release TSV.  Publish
            # the seal before the immutable directory commit so a GREEN window
            # is directly consumable by the certified calculator.
            write_sha_sidecar(p, digest=file_info[name]["sha256"])
        source_rows_fp = canonical_json_hash(
            {
                "schema": SOURCE_CATALOG_SCHEMA,
                "rows": [
                    {
                        "height": r["height"], "block_hash": r["block_hash"], "prev_hash": r["prev_hash"],
                        "block_time": r["block_time"], "median_time_past": r["median_time_past"],
                        "blk_file": r["blk_file"], "record_offset": r["record_offset"], "block_size": r["block_size"],
                    }
                    for r in rows
                ],
            }
        )
        manifest = {
            "schema": STAGE_WINDOW_SCHEMA,
            "release_complete": True,
            "created_utc": utc_now_iso(),
            "start_height": h1,
            "end_height": h2,
            "block_rows": h2 - h1 + 1,
            "generation_id": generation_id,
            "duckdb_version": EXPECTED_DUCKDB_VERSION,
            "extractor_reference_sha256": extractor_sha,
            "decoder_script_sha256": decoder_sha,
            "build_stage_script_sha256": sha256_file(Path(__file__).resolve()),
            "source_catalog_range_fingerprint_sha256": source_rows_fp,
            "source_generation_ids": sorted({r["source_generation_id"] for r in rows}),
            "source_snapshot_sha256": sorted({r["source_snapshot_sha256"] for r in rows}),
            "counts": counters,
            "validated_parquet_counts": validated,
            "files": file_info,
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
        manifest_path = output_tmp / "manifest.json"
        atomic_write_json(manifest_path, manifest)
        manifest_sha = sha256_file(manifest_path)
        atomic_write_bytes(
            output_tmp / "manifest.json.sha256", f"{manifest_sha}  manifest.json\n".encode("ascii")
        )
        fsync_dir(output_tmp)
        publish_stage_window_directory(output_tmp, final_dir)
        shutil.rmtree(output_tmp)
        shutil.rmtree(stage_tmp)
        return {
            "start_height": h1,
            "end_height": h2,
            "window_dir": str(final_dir.resolve()),
            "manifest_path": str((final_dir / "manifest.json").resolve()),
            "manifest_sha256": manifest_sha,
            "blocks_sha256": file_info["blocks.parquet"]["sha256"],
            "transactions_sha256": file_info["transactions.parquet"]["sha256"],
            "inputs_sha256": file_info["inputs.parquet"]["sha256"],
            "outputs_sha256": file_info["outputs.parquet"]["sha256"],
            "blocks": int(counters["blocks"]),
            "transactions": int(counters["transactions"]),
            "inputs": int(counters["inputs"]),
            "outputs": int(counters["outputs"]),
        }
    except BaseException:
        if files is not None:
            try:
                extractor.close_fsync_staging(files)
            except Exception:
                pass
        # Current-run scratch is never authoritative.  Immutable destination
        # windows, if already published, are deliberately left untouched so
        # validate_existing_stage_window() can adopt them after a crash.
        for scratch in (output_tmp, stage_tmp):
            try:
                if scratch.exists() and not scratch.is_symlink():
                    shutil.rmtree(scratch)
            except Exception:
                pass
        raise


def validate_existing_stage_window(paths: Paths, h1: int, h2: int) -> Dict[str, Any]:
    """Validate and adopt a fully published window left before index commit.

    Publication is intentionally filesystem-first and index-second. A process
    death in that tiny interval must be resumable without deleting or rewriting
    an immutable GREEN directory.
    """
    final_dir = paths.stage_windows / f"window_{h1:06d}_{h2:06d}"
    if final_dir.is_symlink() or not final_dir.is_dir():
        raise RuntimeError(f"existing Stage window is not a real directory: {final_dir}")
    manifest_path = final_dir / "manifest.json"
    sidecar = final_dir / "manifest.json.sha256"
    verify_file(manifest_path, sidecar=sidecar)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"Stage window manifest is not an object: {manifest_path}")
    checks = {
        "schema": obj.get("schema") == STAGE_WINDOW_SCHEMA,
        "release_complete": obj.get("release_complete") is True,
        "start_height": int(obj.get("start_height", -1)) == int(h1),
        "end_height": int(obj.get("end_height", -1)) == int(h2),
        "block_rows": int(obj.get("block_rows", -1)) == int(h2 - h1 + 1),
        "extractor": obj.get("extractor_reference_sha256") == BASELINE_EXTRACTOR_SHA256,
        "decoder": obj.get("decoder_script_sha256") == BASELINE_DECODER_SHA256,
        "duckdb": obj.get("duckdb_version") == EXPECTED_DUCKDB_VERSION,
        "builder": obj.get("build_stage_script_sha256") == sha256_file(Path(__file__).resolve()),
    }
    bad = [k for k, ok in checks.items() if not ok]
    if bad:
        raise RuntimeError(f"existing immutable Stage window contract mismatch {final_dir}: {bad}")
    generation_id = str(obj.get("generation_id") or "")
    if not generation_id:
        raise RuntimeError(f"existing Stage window generation_id missing: {manifest_path}")
    files = obj.get("files") if isinstance(obj.get("files"), dict) else {}
    file_hashes: Dict[str, str] = {}
    for name in ("blocks.parquet", "transactions.parquet", "inputs.parquet", "outputs.parquet"):
        info = files.get(name) if isinstance(files.get(name), dict) else None
        if info is None:
            raise RuntimeError(f"existing Stage manifest file metadata missing: {name}")
        fp = final_dir / name
        if fp.is_symlink() or not fp.is_file():
            raise RuntimeError(f"existing Stage parquet missing/not regular: {fp}")
        expected_sha = str(info.get("sha256") or "")
        actual_sha = verify_file(fp, expected_sha, Path(str(fp) + ".sha256"))
        if int(info.get("size_bytes", -1)) != int(fp.stat().st_size):
            raise RuntimeError(f"existing Stage parquet size mismatch: {fp}")
        file_hashes[name] = actual_sha
    counts = obj.get("counts") if isinstance(obj.get("counts"), dict) else {}
    for key in ("blocks", "transactions", "inputs", "outputs"):
        if key not in counts or int(counts[key]) < 0:
            raise RuntimeError(f"existing Stage count missing/invalid key={key}")
    if int(counts["blocks"]) != int(h2 - h1 + 1):
        raise RuntimeError(f"existing Stage block count mismatch {counts['blocks']}!={h2-h1+1}")
    return {
        "start_height": int(h1),
        "end_height": int(h2),
        "window_dir": str(final_dir.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_file(manifest_path),
        "generation_id": generation_id,
        "blocks_sha256": file_hashes["blocks.parquet"],
        "transactions_sha256": file_hashes["transactions.parquet"],
        "inputs_sha256": file_hashes["inputs.parquet"],
        "outputs_sha256": file_hashes["outputs.parquet"],
        "blocks": int(counts["blocks"]),
        "transactions": int(counts["transactions"]),
        "inputs": int(counts["inputs"]),
        "outputs": int(counts["outputs"]),
        "adopted_after_crash": True,
    }


def source_ledger_sha_for_target(paths: Paths, target_height: int) -> str:
    """Return the immutable Source Catalog ledger anchor ending at target_height."""
    con = catalog_connect(paths, read_only=True)
    try:
        rows = con.execute(
            "SELECT record_sha256 FROM catalog_ledger WHERE h2=? ORDER BY record_no",
            [int(target_height)],
        ).fetchall()
    finally:
        con.close()
    if len(rows) != 1:
        raise RuntimeError(
            f"Source Catalog must have exactly one ledger record ending at target={target_height}; rows={len(rows)}"
        )
    return str(rows[0][0])


def source_ledger_tail(paths: Paths) -> str:
    con = catalog_connect(paths, read_only=True)
    try:
        row = con.execute("SELECT record_sha256 FROM catalog_ledger ORDER BY record_no DESC LIMIT 1").fetchone()
        if not row:
            raise RuntimeError("source catalog ledger empty")
        return str(row[0])
    finally:
        con.close()


def build_stage_suffix(paths: Paths, target_height: int, cores: int, memory: str, window_size: int) -> Dict[str, Any]:
    bootstrap_catalog(paths)
    shwm = stage_hwm(paths)
    if target_height <= shwm:
        return {"status": "STAGE_ALREADY_GREEN", "stage_hwm": shwm, "generation_id": None, "windows": []}
    con_catalog = catalog_connect(paths, read_only=True)
    try:
        source_h, _, _ = catalog_hwm(con_catalog)
    finally:
        con_catalog.close()
    if target_height > source_h:
        raise RuntimeError(f"cannot build Stage beyond SOURCE_HWM target={target_height} source_hwm={source_h}")
    if shwm < BASELINE_END_HEIGHT:
        raise RuntimeError(f"v2 Stage HWM cannot be below frozen legacy baseline: {shwm}")
    consume_stop_if_requested(paths.stop_file, "before_stage_build", {"stage_hwm": shwm, "target": target_height})
    lock = acquire_file_lock(paths.stage_lock)
    try:
        gen_id = f"stage-{utc_stamp()}-{uuid.uuid4().hex[:12]}"
        h1 = shwm + 1
        windows: List[Dict[str, Any]] = []
        while h1 <= target_height:
            h2 = min(h1 + max(1, int(window_size)) - 1, target_height)
            final_dir = paths.stage_windows / f"window_{h1:06d}_{h2:06d}"
            if final_dir.exists() or final_dir.is_symlink():
                row = validate_existing_stage_window(paths, h1, h2)
                if not windows:
                    # At most one unindexed published window can exist because
                    # each window is indexed before the next one starts. Reuse
                    # its immutable generation id and continue that generation.
                    gen_id = str(row["generation_id"])
                elif str(row["generation_id"]) != gen_id:
                    raise RuntimeError(
                        f"orphan Stage window generation mismatch {row['generation_id']}!={gen_id}"
                    )
            else:
                row = build_one_stage_window(paths, h1, h2, gen_id, cores, memory)
                row["generation_id"] = gen_id
            windows.append(row)
            # Index only after immutable publication.
            con = stage_index_connect(paths)
            try:
                ensure_stage_index_schema(con)
                con.execute("BEGIN TRANSACTION")
                try:
                    con.execute(
                        """
                        INSERT INTO stage_windows(
                            start_height,end_height,window_dir,manifest_path,manifest_sha256,generation_id,
                            blocks_sha256,transactions_sha256,inputs_sha256,outputs_sha256,blocks,transactions,inputs,outputs
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        [
                            row["start_height"], row["end_height"], row["window_dir"], row["manifest_path"], row["manifest_sha256"], row["generation_id"],
                            row["blocks_sha256"], row["transactions_sha256"], row["inputs_sha256"], row["outputs_sha256"],
                            row["blocks"], row["transactions"], row["inputs"], row["outputs"],
                        ],
                    )
                    con.execute(
                        "INSERT INTO stage_meta(key,value,updated_at) VALUES ('stage_hwm',?,now()) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                        [str(h2)],
                    )
                    con.execute("COMMIT")
                except BaseException:
                    con.execute("ROLLBACK")
                    raise
                con.execute("CHECKPOINT")
            finally:
                con.close()
            consume_stop_if_requested(paths.stop_file, "after_stage_window", {"h1": h1, "h2": h2})
            h1 = h2 + 1

        ledger_tail = source_ledger_tail(paths)
        snapshot_shas = sorted({
            x for row in catalog_rows_for_range(paths, windows[0]["start_height"], windows[-1]["end_height"])
            for x in [row["source_snapshot_sha256"]]
        })
        generation_manifest = {
            "schema": STAGE_GENERATION_SCHEMA,
            "release_complete": True,
            "generation_id": gen_id,
            "created_utc": utc_now_iso(),
            "h1": windows[0]["start_height"],
            "h2": windows[-1]["end_height"],
            "source_snapshot_sha256_set": snapshot_shas,
            "source_ledger_tail_sha256": ledger_tail,
            "windows": [
                {k: w[k] for k in ("start_height", "end_height", "manifest_path", "manifest_sha256")}
                for w in windows
            ],
        }
        gen_path = paths.stage_generations / f"generation_{gen_id}.json"
        atomic_write_json(gen_path, generation_manifest)
        gen_sha = sha256_file(gen_path)
        write_sha_sidecar(gen_path)
        con = stage_index_connect(paths)
        try:
            ensure_stage_index_schema(con)
            con.execute(
                "INSERT INTO stage_generations(generation_id,h1,h2,manifest_path,manifest_sha256,source_snapshot_sha256,source_ledger_tail_sha256) "
                "VALUES (?,?,?,?,?,?,?)",
                [gen_id, windows[0]["start_height"], windows[-1]["end_height"], str(gen_path.resolve()), gen_sha, ",".join(snapshot_shas), ledger_tail],
            )
            con.execute("CHECKPOINT")
        finally:
            con.close()
        return {"status": "STAGE_GREEN", "stage_hwm": windows[-1]["end_height"], "generation_id": gen_id, "generation_manifest": str(gen_path), "generation_manifest_sha256": gen_sha, "windows": windows}
    finally:
        lock.close()


def parse_legacy_windows(paths: Paths) -> List[Dict[str, Any]]:
    verify_baseline_artifacts(paths)
    global_obj = json.loads(paths.legacy_stage2_global.read_text(encoding="utf-8"))
    rows: List[Dict[str, Any]] = []
    with paths.legacy_stage2_windows_tsv.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            h1, h2 = int(r["window_start"]), int(r["window_end"])
            d = paths.legacy_stage2 / "windows" / f"window_{h1:06d}_{h2:06d}"
            rows.append(
                {
                    "window_start": h1,
                    "window_end": h2,
                    "producer_contract": "legacy_stage2_v1",
                    "window_manifest_path": str((d / "manifest.json").resolve()),
                    "window_manifest_sha256": str(r["window_manifest_sha256"]),
                    "blocks_path": str((d / "blocks.parquet").resolve()),
                    "blocks_sha256": str(r["blocks_sha256"]),
                    "transactions_path": str((d / "transactions.parquet").resolve()),
                    "transactions_sha256": str(r["transactions_sha256"]),
                    "inputs_path": str((d / "inputs.parquet").resolve()),
                    "inputs_sha256": str(r["inputs_sha256"]),
                    "outputs_path": str((d / "outputs.parquet").resolve()),
                    "outputs_sha256": str(r["outputs_sha256"]),
                    "blocks": int(r["blocks"]), "transactions": int(r["transactions"]), "inputs": int(r["inputs"]), "outputs": int(r["outputs"]),
                }
            )
    if len(rows) != 618 or rows[-1]["window_end"] != BASELINE_END_HEIGHT:
        raise RuntimeError("legacy Stage2 windows coverage mismatch")
    if int(global_obj.get("end_height", -1)) != BASELINE_END_HEIGHT:
        raise RuntimeError("legacy Stage2 global end mismatch")
    return rows


def parse_v2_windows(paths: Paths, target_height: int) -> List[Dict[str, Any]]:
    if target_height <= BASELINE_END_HEIGHT:
        return []
    if not paths.stage_index.exists():
        raise RuntimeError("v2 Stage index missing")
    con = stage_index_connect(paths, read_only=True)
    try:
        rows = con.execute(
            """
            SELECT start_height,end_height,manifest_path,manifest_sha256,
                   blocks_sha256,transactions_sha256,inputs_sha256,outputs_sha256,
                   blocks,transactions,inputs,outputs
            FROM stage_windows WHERE start_height<=? ORDER BY start_height
            """,
            [int(target_height)],
        ).fetchall()
    finally:
        con.close()
    out: List[Dict[str, Any]] = []
    expected = BASELINE_END_HEIGHT + 1
    for r in rows:
        h1, h2 = int(r[0]), int(r[1])
        if h1 != expected or h2 > target_height:
            raise RuntimeError(f"v2 Stage window coverage mismatch expected={expected} actual={h1}..{h2} target={target_height}")
        d = Path(str(r[2])).parent
        payloads = (
            ("blocks", d / "blocks.parquet", str(r[4])),
            ("transactions", d / "transactions.parquet", str(r[5])),
            ("inputs", d / "inputs.parquet", str(r[6])),
            ("outputs", d / "outputs.parquet", str(r[7])),
        )
        verified_payload_sha: Dict[str, str] = {}
        for role, payload_path, payload_sha in payloads:
            verified_payload_sha[role] = verify_file(
                payload_path, payload_sha, Path(str(payload_path) + ".sha256")
            )
        out.append(
            {
                "window_start": h1, "window_end": h2, "producer_contract": STAGE_WINDOW_SCHEMA,
                "window_manifest_path": str(Path(str(r[2])).resolve()), "window_manifest_sha256": str(r[3]),
                "blocks_path": str((d / "blocks.parquet").resolve()), "blocks_sha256": verified_payload_sha["blocks"],
                "transactions_path": str((d / "transactions.parquet").resolve()), "transactions_sha256": verified_payload_sha["transactions"],
                "inputs_path": str((d / "inputs.parquet").resolve()), "inputs_sha256": verified_payload_sha["inputs"],
                "outputs_path": str((d / "outputs.parquet").resolve()), "outputs_sha256": verified_payload_sha["outputs"],
                "blocks": int(r[8]), "transactions": int(r[9]), "inputs": int(r[10]), "outputs": int(r[11]),
            }
        )
        expected = h2 + 1
    if expected != target_height + 1:
        raise RuntimeError(f"v2 Stage incomplete target={target_height} next={expected}")
    return out


def release_windows_fingerprint(rows: Sequence[Dict[str, Any]]) -> str:
    return canonical_json_hash(
        {
            "schema": STAGE_RELEASE_TSV_SCHEMA,
            "windows": [
                {
                    "window_start": r["window_start"], "window_end": r["window_end"],
                    "producer_contract": r["producer_contract"], "window_manifest_sha256": r["window_manifest_sha256"],
                    "blocks_sha256": r["blocks_sha256"], "transactions_sha256": r["transactions_sha256"],
                    "inputs_sha256": r["inputs_sha256"], "outputs_sha256": r["outputs_sha256"],
                }
                for r in rows
            ],
        }
    )


def _ensure_immutable_bytes(path: Path, expected: bytes) -> None:
    """Publish bytes once, or prove an interrupted prior publication is identical."""
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"immutable artifact exists but is not a regular file: {path}")
        actual = path.read_bytes()
        if actual != expected:
            raise RuntimeError(f"existing immutable artifact conflicts with expected bytes: {path}")
        return
    atomic_write_bytes(path, expected)


def _ensure_sha_sidecar(path: Path) -> Path:
    sidecar = Path(str(path) + ".sha256")
    digest = sha256_file(path)
    expected = f"{digest}  {path.name}\n".encode("ascii")
    _ensure_immutable_bytes(sidecar, expected)
    verify_file(path, sidecar=sidecar)
    return sidecar


def publish_stage_release(paths: Paths, target_height: int) -> Dict[str, Any]:
    """Publish the immutable full-coverage Stage release with crash adoption.

    TSV and JSON are no-clobber immutable artifacts. If the process dies between
    either file and its SHA sidecar, the next run only adopts byte-identical
    artifacts; conflicting partial publication is a hard failure.
    """
    if target_height < 0:
        raise RuntimeError("negative target height")
    legacy = parse_legacy_windows(paths)
    if target_height < BASELINE_END_HEIGHT:
        raise RuntimeError("v2 Stage release publication supports target >= frozen baseline only")
    v2 = parse_v2_windows(paths, target_height)
    rows = legacy + v2
    expected = 0
    for r in rows:
        if int(r["window_start"]) != expected:
            raise RuntimeError(f"release window gap expected={expected} actual={r['window_start']}")
        expected = int(r["window_end"]) + 1
    if expected != target_height + 1:
        raise RuntimeError(f"release coverage incomplete target={target_height} next={expected}")

    con = catalog_connect(paths, read_only=True)
    try:
        target = con.execute(
            "SELECT block_hash,block_time,median_time_past FROM canonical_blocks WHERE height=?", [int(target_height)]
        ).fetchone()
    finally:
        con.close()
    if target is None:
        raise RuntimeError(f"target not present in Source Catalog: {target_height}")

    release_base = f"stage_release_0_{target_height}"
    tsv_path = paths.stage_releases / f"{release_base}.windows.tsv"
    json_path = paths.stage_releases / f"{release_base}.json"
    paths.stage_releases.mkdir(parents=True, exist_ok=True)
    fingerprint = release_windows_fingerprint(rows)

    columns = [
        "window_start", "window_end", "producer_contract", "window_manifest_path", "window_manifest_sha256",
        "blocks_path", "blocks_sha256", "transactions_path", "transactions_sha256", "inputs_path", "inputs_sha256",
        "outputs_path", "outputs_sha256", "blocks", "transactions", "inputs", "outputs",
    ]
    lines = ["\t".join(columns)]
    for r in rows:
        fields = [str(r[c]) for c in columns]
        if any("\t" in x or "\n" in x or "\r" in x for x in fields):
            raise RuntimeError("unsafe Stage release TSV field")
        lines.append("\t".join(fields))
    tsv_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    _ensure_immutable_bytes(tsv_path, tsv_bytes)
    tsv_sha = sha256_file(tsv_path)
    _ensure_sha_sidecar(tsv_path)

    totals = {k: sum(int(r[k]) for r in rows) for k in ("blocks", "transactions", "inputs", "outputs")}
    source_tail = source_ledger_sha_for_target(paths, target_height)
    payload = {
        "schema": STAGE_RELEASE_SCHEMA,
        "release_complete": True,
        "created_utc": None,
        "start_height": 0,
        "end_height": int(target_height),
        "end_hash": str(target[0]),
        "end_block_time": int(target[1]),
        "end_median_time_past": int(target[2]),
        "window_count": len(rows),
        "windows_tsv": {"path": str(tsv_path.resolve()), "sha256": tsv_sha},
        "windows_fingerprint_sha256": fingerprint,
        "totals": totals,
        "legacy_baseline": {
            "end_height": BASELINE_END_HEIGHT,
            "end_hash": BASELINE_END_HASH,
            "global_manifest_sha256": BASELINE_STAGE2_GLOBAL_SHA256,
        },
        "source_catalog": {
            "path": str(paths.source_catalog.resolve()),
            "ledger_tail_sha256": source_tail,
        },
        "producer": {
            "build_stage_script_sha256": sha256_file(Path(__file__).resolve()),
            "extractor_reference_sha256": BASELINE_EXTRACTOR_SHA256,
            "decoder_script_sha256": BASELINE_DECODER_SHA256,
            "duckdb_version": EXPECTED_DUCKDB_VERSION,
        },
        "validation": {
            "height_coverage_contiguous": True,
            "all_windows_release_complete": True,
            "window_manifest_sha256_bound": True,
            "parquet_content_sha256_bound": True,
            "legacy_plus_v2_boundary_exact": True,
        },
    }

    # created_utc cannot participate in deterministic crash adoption. If JSON
    # already exists, preserve and validate its recorded timestamp. Otherwise
    # freeze one now before the no-clobber publication.
    if json_path.exists() or json_path.is_symlink():
        if json_path.is_symlink() or not json_path.is_file():
            raise RuntimeError(f"existing Stage release JSON is not regular: {json_path}")
        existing = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise RuntimeError(f"existing Stage release JSON is not object: {json_path}")
        payload["created_utc"] = existing.get("created_utc")
    else:
        payload["created_utc"] = utc_now_iso()
    json_bytes = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _ensure_immutable_bytes(json_path, json_bytes)
    digest = sha256_file(json_path)
    _ensure_sha_sidecar(json_path)

    # Re-read and validate the immutable release identity after complete publish.
    obj = json.loads(json_path.read_text(encoding="utf-8"))
    if (
        obj.get("schema") != STAGE_RELEASE_SCHEMA
        or obj.get("release_complete") is not True
        or obj.get("windows_fingerprint_sha256") != fingerprint
        or int(obj.get("end_height", -1)) != int(target_height)
        or str(obj.get("end_hash") or "") != str(target[0])
        or str((obj.get("source_catalog") or {}).get("ledger_tail_sha256") or "") != source_tail
    ):
        raise RuntimeError(f"published Stage release post-verification failed: {json_path}")
    return {
        "status": "STAGE_RELEASE_GREEN",
        "path": str(json_path),
        "sha256": digest,
        "windows_tsv": str(tsv_path),
        "windows_fingerprint_sha256": fingerprint,
    }

def cmd_snapshot(args, paths: Paths) -> int:
    payload = resolve_target_snapshot(paths, date.fromisoformat(args.to), args.confirmations, args.allow_incomplete_day)
    if args.output:
        out = Path(args.output)
        atomic_write_json(out, payload, overwrite=args.overwrite)
        write_sha_sidecar(out, overwrite=args.overwrite)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def load_snapshot_path(path: Path) -> Dict[str, Any]:
    verify_file(path, sidecar=Path(str(path) + ".sha256"))
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError("snapshot JSON is not object")
    verify_snapshot(obj)
    return obj


def cmd_build(args, paths: Paths) -> int:
    snapshot = load_snapshot_path(Path(args.snapshot))
    target_h = int(snapshot["target"]["height"])
    # One process-level build lock plus the real Bitcoin Core datadir lock span
    # bootstrap, physical SOURCE scan, Stage decode and Stage release publication.
    # This closes the old lock gap where Core could theoretically restart
    # between SOURCE_GREEN and STAGE_GREEN.
    build_lock = acquire_file_lock(paths.build_lock)
    core_lock_fd: Optional[int] = None
    try:
        core_lock_fd = require_core_stopped_and_lock(paths)
        source_report = commit_source_snapshot(paths, snapshot, datadir_lock_held=True)
        stage_report = build_stage_suffix(paths, target_h, args.cores, args.memory, args.window_size)
        release = publish_stage_release(paths, target_h)
        consume_stop_if_requested(
            paths.stop_file,
            "after_stage_release",
            {"target_height": target_h, "stage_release": release.get("path")},
        )
        result = {
            "status": "STAGE_GREEN",
            "target": snapshot["target"],
            "source": source_report,
            "stage": stage_report,
            "release": release,
            "datadir_lock_held_across_source_and_stage": True,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    finally:
        if core_lock_fd is not None:
            os.close(core_lock_fd)
        build_lock.close()


def cmd_status(args, paths: Paths) -> int:
    source_h, source_hash, source_mtp = read_catalog_tip(paths)
    try:
        st_h = stage_hwm(paths)
    except Exception as exc:
        st_h = None
        stage_error = f"{type(exc).__name__}: {exc}"
    else:
        stage_error = None
    result = {
        "version": VERSION,
        "source_catalog": str(paths.source_catalog),
        "source_hwm": source_h,
        "source_hash": source_hash,
        "source_mtp": source_mtp,
        "stage_hwm": st_h,
        "stage_error": stage_error,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_paths(args) -> Paths:
    return Paths(
        base=Path(args.base), legacy_base=Path(args.legacy_base), datadir=Path(args.datadir), tmp_root=Path(args.tmp_root),
        extractor=Path(args.extractor), decoder=Path(args.decoder), locator_reference=Path(args.locator_reference),
        bitcoin_cli=Path(args.bitcoin_cli), stop_file=Path(args.stop_file),
    )


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="UTXO Core v2 incremental SOURCE + STAGE builder")
    ap.add_argument("--base", default=str(DEFAULT_BASE))
    ap.add_argument("--legacy-base", default=str(DEFAULT_LEGACY_BASE))
    ap.add_argument("--datadir", default=str(DEFAULT_DATADIR))
    ap.add_argument("--tmp-root", default=str(DEFAULT_TMP))
    ap.add_argument("--extractor", default=str(DEFAULT_EXTRACTOR))
    ap.add_argument("--decoder", default=str(DEFAULT_DECODER))
    ap.add_argument("--locator-reference", default=str(DEFAULT_LOCATOR_REFERENCE))
    ap.add_argument("--bitcoin-cli", default=str(DEFAULT_BITCOIN_CLI))
    ap.add_argument("--stop-file", default=str(DEFAULT_STOP_FILE))
    sp = ap.add_subparsers(dest="command", required=True)

    p = sp.add_parser("snapshot", help="resolve immutable UTC/MTP target while Bitcoin Core is running")
    p.add_argument("--to", required=True, help="YYYY-MM-DD UTC day, through end of day")
    p.add_argument("--confirmations", type=int, default=100)
    p.add_argument("--allow-incomplete-day", action="store_true")
    p.add_argument("--output")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_snapshot)

    p = sp.add_parser("build", help="commit SOURCE and build immutable Stage while Bitcoin Core is stopped")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--cores", type=int, default=10)
    p.add_argument("--memory", default="80GB")
    p.add_argument("--window-size", type=int, default=1000)
    p.set_defaults(func=cmd_build)

    p = sp.add_parser("status")
    p.set_defaults(func=cmd_status)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    os.umask(0o027)
    args = parser().parse_args(argv)
    paths = build_paths(args)
    try:
        return int(args.func(args, paths))
    except ControlledStop as exc:
        print(f"CONTROLLED_STOP {exc}", file=sys.stderr, flush=True)
        return 75
    except Exception as exc:
        print(f"FATAL {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
