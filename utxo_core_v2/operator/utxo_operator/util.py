from __future__ import annotations
import hashlib, json, os, subprocess, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_stamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b=f.read(16*1024*1024)
            if not b: break
            h.update(b)
    return h.hexdigest()


def fsync_dir(path: Path) -> None:
    fd=os.open(str(path),os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic_bytes(path: Path, data: bytes, mode: int=0o640, overwrite: bool=True) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}")
    fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
    try:
        with os.fdopen(fd,"wb") as f:
            fd=-1; f.write(data); f.flush(); os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            # Atomic no-clobber publication.  A pre-check followed by
            # os.replace() has a TOCTOU window and can overwrite another
            # operator's STOP/contract.  tmp and path live in the same
            # directory/filesystem, so link() gives an atomic EEXIST guard.
            try:
                os.link(tmp, path)
            except FileExistsError as exc:
                raise RuntimeError(f"refuse overwrite: {path}") from exc
            tmp.unlink()
        fsync_dir(path.parent)
    except BaseException:
        if fd>=0:
            try: os.close(fd)
            except OSError: pass
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        raise


def atomic_json(path: Path, obj: Dict[str,Any], overwrite: bool=True) -> None:
    atomic_bytes(path,(json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode(),overwrite=overwrite)


def write_sha_sidecar(path: Path, overwrite: bool=True) -> str:
    d=sha256_file(path)
    atomic_bytes(Path(str(path)+".sha256"),f"{d}  {path.name}\n".encode("ascii"),overwrite=overwrite)
    return d


def verify_sidecar(path: Path) -> str:
    if path.is_symlink() or not path.is_file(): raise RuntimeError(f"artifact missing/not regular: {path}")
    side=Path(str(path)+".sha256")
    if side.is_symlink() or not side.is_file(): raise RuntimeError(f"sidecar missing/not regular: {side}")
    actual=sha256_file(path); parts=side.read_text(encoding="ascii").strip().split()
    if not parts or parts[0].lower()!=actual: raise RuntimeError(f"SHA sidecar mismatch: {path}")
    return actual


def run(cmd: Sequence[str], *, env: Optional[Dict[str,str]]=None, log: Optional[Path]=None, check: bool=False) -> subprocess.CompletedProcess:
    merged=os.environ.copy()
    if env: merged.update({str(k):str(v) for k,v in env.items()})
    if log is None:
        p=subprocess.run(list(map(str,cmd)),env=merged,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    else:
        log.parent.mkdir(parents=True,exist_ok=True)
        with log.open("a",encoding="utf-8") as f:
            f.write(f"{utc_now().isoformat()} EXEC {' '.join(map(str,cmd))}\n"); f.flush()
            p=subprocess.run(list(map(str,cmd)),env=merged,text=True,stdout=f,stderr=subprocess.STDOUT)
            f.write(f"{utc_now().isoformat()} EXEC_RC {p.returncode}\n"); f.flush()
    if check and p.returncode!=0:
        raise RuntimeError(f"command failed rc={p.returncode}: {' '.join(map(str,cmd))}")
    return p


def pid_alive(pid: int) -> bool:
    try:
        if int(pid)<=0: return False
        os.kill(int(pid),0); return True
    except ProcessLookupError: return False
    except PermissionError: return True
    except Exception: return False


def iter_cmdlines() -> Iterable[tuple[int,str]]:
    proc=Path('/proc')
    if not proc.exists(): return []
    out=[]
    for p in proc.iterdir():
        if not p.name.isdigit(): continue
        try: cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode('utf-8','replace').strip()
        except Exception: continue
        if cmd: out.append((int(p.name),cmd))
    return out


def parse_last_json_from_text(text: str) -> Optional[Dict[str,Any]]:
    dec=json.JSONDecoder(); best=None
    for i,ch in enumerate(text):
        if ch!='{': continue
        try: obj,end=dec.raw_decode(text[i:])
        except Exception: continue
        if isinstance(obj,dict): best=obj
    return best
