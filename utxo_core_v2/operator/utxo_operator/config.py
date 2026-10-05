from __future__ import annotations
import configparser
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass(frozen=True)
class Config:
    path: Path
    python: Path
    root: Path
    build_stage: Path
    calculator: Path
    auditor: Path
    frozen_v40: Path
    parent_v30: Path
    extractor: Path
    decoder: Path
    locator_reference: Path
    v2_base: Path
    legacy_base: Path
    db: Path
    source_catalog: Path
    stage_release_dir: Path
    run_dir: Path
    log_dir: Path
    apply_work_root: Path
    worker_root: Path
    tmpdir: Path
    datadir: Path
    bitcoin_cli: Path
    stop_file: Path
    lock_root: Path
    operator_lock: Path
    release_manifest: Path
    expected_release_manifest_sha: str
    expected_build_stage_sha: str
    expected_v41_sha: str
    expected_n41_sha: str
    expected_v40_sha: str
    expected_v30_sha: str
    expected_extractor_sha: str
    expected_decoder_sha: str
    expected_locator_sha: str
    stage_cores: int
    memory: str
    apply_window: int
    min_window: int
    oom_retries: int
    backoff_divisor: int
    checkpoint_every_windows: int
    confirmations: int
    min_free_data_gib: int
    min_free_tmp_gib: int
    min_available_memory_gib: int


def _s(cp,sec,key,default): return cp.get(sec,key,fallback=default).strip()
def _i(cp,sec,key,default): return cp.getint(sec,key,fallback=default)

def load_config(path: Optional[str]=None) -> Config:
    p=Path(path or "/etc/mybot/utxo.ini")
    cp=configparser.ConfigParser()
    if p.exists(): cp.read(p)
    root=Path(_s(cp,"paths","root","/root/mybot"))
    v2=Path(_s(cp,"paths","v2_base","/opt/mybot_data/etl/utxo_core_v2"))
    legacy=Path(_s(cp,"paths","legacy_base","/opt/mybot_data/etl/utxo_core_v1"))
    control=Path(_s(cp,"paths","control_dir","/opt/mybot_data/etl/utxo/control"))
    return Config(
      path=p, python=Path(_s(cp,"paths","python","/root/mybot/.venv/bin/python3")), root=root,
      build_stage=Path(_s(cp,"paths","build_stage",str(root/"utxo_core_v2/build_stage.py"))),
      calculator=Path(_s(cp,"paths","calculator",str(root/"utxo_pipeline_v41.py"))),
      auditor=Path(_s(cp,"paths","auditor",str(root/"utxo_pipeline_audit_n41.py"))),
      frozen_v40=Path(_s(cp,"paths","frozen_v40",str(root/"utxo_pipeline_v40.py"))),
      parent_v30=Path(_s(cp,"paths","parent_v30",str(root/"utxo_pipeline_v30.py"))),
      extractor=Path(_s(cp,"paths","extractor",str(root/"build_canonical_transactions.py"))),
      decoder=Path(_s(cp,"paths","decoder",str(root/"stage2_decoder_preflight.py"))),
      locator_reference=Path(_s(cp,"paths","locator_reference",str(root/"build_block_locator.py"))),
      v2_base=v2, legacy_base=legacy,
      db=Path(_s(cp,"paths","db",str(legacy/"output/utxo_core_v40_0_617698.duckdb"))),
      source_catalog=Path(_s(cp,"paths","source_catalog",str(v2/"source/source_catalog.duckdb"))),
      stage_release_dir=Path(_s(cp,"paths","stage_release_dir",str(v2/"stage/manifests/releases"))),
      run_dir=Path(_s(cp,"paths","run_dir",str(v2/"run"))), log_dir=Path(_s(cp,"paths","log_dir",str(v2/"logs"))),
      apply_work_root=Path(_s(cp,"paths","apply_work_root",str(v2/"apply"))),
      worker_root=Path(_s(cp,"paths","worker_root","/opt/mybot_tmp/utxo_core_v2_workers")),
      tmpdir=Path(_s(cp,"paths","tmpdir","/opt/mybot_tmp/utxo_core_v2_duckdb")),
      datadir=Path(_s(cp,"paths","datadir","/opt/mybot_data/bitcoin")),
      bitcoin_cli=Path(_s(cp,"paths","bitcoin_cli","/usr/local/bin/bitcoin-cli")),
      stop_file=Path(_s(cp,"paths","stop_file",str(control/"STOP"))), lock_root=Path(_s(cp,"paths","lock_root","/root/mybot/lock")),
      operator_lock=Path(_s(cp,"paths","operator_lock",str(v2/"run/operator.lock"))),
      release_manifest=Path(_s(cp,"paths","release_manifest",str(root/"utxo_core_v2/release/RELEASE_MANIFEST.json"))),
      expected_release_manifest_sha=_s(cp,"provenance","release_manifest_sha256",""),
      expected_build_stage_sha=_s(cp,"provenance","build_stage_sha256",""), expected_v41_sha=_s(cp,"provenance","v41_sha256",""),
      expected_n41_sha=_s(cp,"provenance","n41_sha256",""), expected_v40_sha=_s(cp,"provenance","v40_sha256","08b376031ccf73f0292574c45dc50b1ce358b31a9abe6ddc6cf7f04cb6cda46c"),
      expected_v30_sha=_s(cp,"provenance","v30_sha256","d8bd57a9702ef0a93afd0b51f9232306645827a93fea0253fb64e4d87f63921a"),
      expected_extractor_sha=_s(cp,"provenance","extractor_sha256","7309d10a509d518738c94e9604e2a9f8dba1cc7e190a5f21f3a8df01146f5730"),
      expected_decoder_sha=_s(cp,"provenance","decoder_sha256","a981378473ea41f157eaf94c7de233ddbdab1985a4a618fd3962696c6cfa3ec9"),
      expected_locator_sha=_s(cp,"provenance","locator_sha256","d80ac36c2eb6490aa7aabdb70ebf4eee45f18160946e8e3812256a8c6669522b"),
      stage_cores=_i(cp,"defaults","stage_cores",10), memory=_s(cp,"defaults","memory","80GB"),
      apply_window=_i(cp,"defaults","apply_window",1000), min_window=_i(cp,"defaults","min_window",1),
      oom_retries=_i(cp,"defaults","oom_retries",16), backoff_divisor=_i(cp,"defaults","backoff_divisor",2),
      checkpoint_every_windows=_i(cp,"defaults","checkpoint_every_windows",25), confirmations=_i(cp,"defaults","confirmations",100),
      min_free_data_gib=_i(cp,"safety","min_free_data_gib",300), min_free_tmp_gib=_i(cp,"safety","min_free_tmp_gib",200),
      min_available_memory_gib=_i(cp,"safety","min_available_memory_gib",15),
    )
