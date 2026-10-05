from __future__ import annotations
import json,subprocess,time
from pathlib import Path
from typing import Any,Dict

def service_state() -> str:
    p=subprocess.run(['systemctl','is-active','bitcoind'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    return p.stdout.strip()

def wait_state(want: str, timeout: int=120) -> None:
    deadline=time.time()+timeout
    while time.time()<deadline:
        if service_state()==want: return
        time.sleep(1)
    raise RuntimeError(f"bitcoind did not reach state={want} within {timeout}s; current={service_state()}")

def start(timeout: int=120) -> None:
    p=subprocess.run(['systemctl','start','bitcoind'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode!=0: raise RuntimeError(f"systemctl start bitcoind failed: {p.stdout.strip()}")
    wait_state('active',timeout)

def stop(timeout: int=120) -> None:
    p=subprocess.run(['systemctl','stop','bitcoind'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if p.returncode!=0: raise RuntimeError(f"systemctl stop bitcoind failed: {p.stdout.strip()}")
    wait_state('inactive',timeout)

def cli(bitcoin_cli: Path, datadir: Path, *args: str) -> str:
    p=subprocess.run([str(bitcoin_cli),f'-datadir={datadir}',*map(str,args)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode!=0: raise RuntimeError(f"bitcoin-cli failed rc={p.returncode}: {p.stderr.strip()}")
    return p.stdout.strip()

def wait_rpc(bitcoin_cli: Path, datadir: Path, timeout: int=180) -> Dict[str,Any]:
    deadline=time.time()+timeout; last=''
    while time.time()<deadline:
        try:
            obj=json.loads(cli(bitcoin_cli,datadir,'getblockchaininfo'))
            if isinstance(obj,dict): return obj
        except Exception as e: last=str(e)
        time.sleep(2)
    raise RuntimeError(f"Bitcoin Core RPC not ready after {timeout}s: {last}")
