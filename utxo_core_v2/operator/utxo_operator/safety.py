from __future__ import annotations
import json,os
from dataclasses import dataclass
from pathlib import Path
from .util import atomic_json,fsync_dir,pid_alive,utc_now

@dataclass
class OperatorLock:
    path: Path
    run_id: str
    command: str
    acquired: bool=False
    def acquire(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        try: self.path.mkdir(mode=0o700)
        except FileExistsError:
            owner={}
            try: owner=json.loads((self.path/'owner.json').read_text())
            except Exception: pass
            pid=int(owner.get('pid') or 0)
            if pid_alive(pid): raise RuntimeError(f"operator lock active pid={pid} run_id={owner.get('run_id')} path={self.path}")
            raise RuntimeError(f"stale operator lock exists: {self.path}; doctor must verify it before removal")
        fsync_dir(self.path.parent)
        try:
            atomic_json(self.path/'owner.json',{'pid':os.getpid(),'run_id':self.run_id,'command':self.command,'created_utc':utc_now().isoformat()})
        except BaseException:
            try:
                self.path.rmdir()
                fsync_dir(self.path.parent)
            except Exception:
                pass
            raise
        self.acquired=True
    def release(self):
        if not self.acquired:
            return
        owner_path = self.path / 'owner.json'
        try:
            try:
                owner = json.loads(owner_path.read_text(encoding='utf-8'))
            except Exception as exc:
                raise RuntimeError(f"cannot verify operator-lock ownership before release: {self.path}: {exc}") from exc
            if int(owner.get('pid') or 0) != os.getpid() or str(owner.get('run_id') or '') != str(self.run_id):
                raise RuntimeError(
                    f"operator-lock ownership changed; refuse release: path={self.path} "
                    f"owner_pid={owner.get('pid')} owner_run_id={owner.get('run_id')!r} "
                    f"expected_pid={os.getpid()} expected_run_id={self.run_id!r}"
                )
            owner_path.unlink()
            self.path.rmdir()
            fsync_dir(self.path.parent)
        finally:
            self.acquired=False
