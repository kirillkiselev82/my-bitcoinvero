from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any, Dict
from .config import Config
from .util import sha256_file

RELEASE = "2.0.0-rc2.1"
RELEASE_MANIFEST_SCHEMA = "utxo-core-v2-release-manifest-v1"

def verify_one(path: Path, expected: str, label: str) -> Dict[str,Any]:
    if not path.is_file() or path.is_symlink():
        return {'label':label,'path':str(path),'status':'BAD','reason':'missing/not-regular/symlink'}
    actual=sha256_file(path)
    if not expected:
        return {'label':label,'path':str(path),'status':'BAD','actual':actual,'reason':'expected SHA not configured'}
    return {'label':label,'path':str(path),'status':'OK' if actual==expected else 'BAD','expected':expected,'actual':actual}

def _installed_manifest_mapping(cfg: Config, public_cli_path: Path = Path('/usr/local/bin/utxo')) -> Dict[str, Path]:
    operator_dir = cfg.root / 'utxo_core_v2' / 'operator' / 'utxo_operator'
    mapping = {
        'build_stage.py': cfg.build_stage,
        'utxo_pipeline_v41.py': cfg.calculator,
        'utxo_pipeline_audit_n41.py': cfg.auditor,
        'verify_utxo_pipeline_v41_static.py': cfg.root / 'utxo_core_v2' / 'verify_utxo_pipeline_v41_static.py',
        'utxo': public_cli_path,
    }
    for name in ('__init__.py','cli.py','config.py','core.py','legacy.py','orchestrator.py','renderer.py','safety.py','state.py','util.py','verify.py'):
        mapping[f'utxo_operator/{name}'] = operator_dir / name
    return mapping


def verify_operator_release(cfg: Config, public_cli_path: Path = Path('/usr/local/bin/utxo')) -> Dict[str, Any]:
    manifest = cfg.release_manifest
    identity = verify_one(manifest, cfg.expected_release_manifest_sha, 'release_manifest')
    if identity['status'] != 'OK':
        return {'status':'BAD','identity':identity,'files':[]}
    try:
        obj=json.loads(manifest.read_text(encoding='utf-8'))
    except Exception as exc:
        return {'status':'BAD','identity':identity,'files':[],'reason':f'manifest JSON: {type(exc).__name__}:{exc}'}
    if not isinstance(obj,dict) or obj.get('schema')!=RELEASE_MANIFEST_SCHEMA or obj.get('release')!=RELEASE:
        return {'status':'BAD','identity':identity,'files':[],'reason':'manifest schema/release mismatch'}
    files=obj.get('files') if isinstance(obj.get('files'),dict) else {}
    rows=[]
    for key,path in _installed_manifest_mapping(cfg, public_cli_path=public_cli_path).items():
        expected=str(files.get(key) or '')
        rows.append(verify_one(path, expected, key))
    ok=all(r['status']=='OK' for r in rows)
    return {'status':'OK' if ok else 'BAD','identity':identity,'files':rows}

def verify_release(cfg: Config, public_cli_path: Path = Path('/usr/local/bin/utxo')) -> Dict[str,Any]:
    rows=[
      verify_one(cfg.build_stage,cfg.expected_build_stage_sha,'build_stage'),
      verify_one(cfg.calculator,cfg.expected_v41_sha,'calculator_v41'),
      verify_one(cfg.auditor,cfg.expected_n41_sha,'auditor_n41'),
      verify_one(cfg.frozen_v40,cfg.expected_v40_sha,'frozen_v40'),
      verify_one(cfg.parent_v30,cfg.expected_v30_sha,'parent_v30'),
      verify_one(cfg.extractor,cfg.expected_extractor_sha,'extractor'),
      verify_one(cfg.decoder,cfg.expected_decoder_sha,'decoder'),
      verify_one(cfg.locator_reference,cfg.expected_locator_sha,'locator_reference'),
    ]
    operator_release=verify_operator_release(cfg, public_cli_path=public_cli_path)
    runtime: Dict[str,Any] = {'status':'BAD','python':str(cfg.python),'python_expected':'3.9.x','duckdb_expected':'1.4.4'}
    if cfg.python.is_file() and not cfg.python.is_symlink():
        p=subprocess.run(
            [str(cfg.python),'-c','import sys,duckdb; print(sys.version.split()[0]); print(duckdb.__version__)'],
            text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
        )
        lines=[x.strip() for x in p.stdout.splitlines() if x.strip()]
        runtime.update({
            'returncode':int(p.returncode),
            'python_version':lines[0] if len(lines)>0 else None,
            'duckdb_version':lines[1] if len(lines)>1 else None,
            'stderr':p.stderr.strip() or None,
        })
        if p.returncode==0 and len(lines)>1 and lines[0].startswith('3.9.') and lines[1]=='1.4.4':
            runtime['status']='OK'
    else:
        runtime['reason']='python missing/not-regular/symlink'
    ok=(all(r['status']=='OK' for r in rows) and operator_release['status']=='OK' and runtime['status']=='OK')
    return {'status':'GREEN' if ok else 'BAD','artifacts':rows,'operator_release':operator_release,'runtime':runtime}
