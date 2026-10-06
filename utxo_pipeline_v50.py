#!/root/mybot/.venv/bin/python3
"""MyBot UTXO V50 dense calculator driver.

Independent calculator.  Reads frozen canonical Stage only; never writes V40/V41
state.  The C++ dense core is embedded and auto-built; it owns V50 state and commit/recovery semantics.
"""
from __future__ import annotations

import argparse, base64, concurrent.futures, csv, ctypes, fcntl, gzip, hashlib, json, multiprocessing, os, re, shutil, signal, struct, subprocess, sys, tempfile, time, uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "v50-dense-r11-buffered-script-append-singlefile-prod"
DUCKDB_VERSION = "1.4.4"
LEGACY_STAGE_BASE = Path("/opt/mybot_data/etl/utxo_core_v1/stage2")
DEFAULT_STATE = Path("/opt/mybot_data/etl/utxo_v50/state")
DEFAULT_TMP = Path("/opt/mybot_tmp/utxo_v50")
DEFAULT_CONTROL = Path("/opt/mybot_data/etl/utxo_v50/control")
DEFAULT_CORE = Path("/opt/mybot_data/etl/utxo_v50/runtime/utxo_v50_dense_core")
LEGACY_GLOBAL_SHA = "3dc4e285947651d0c36bf5564c6f424d620947d29f36154ffa1cbb1dbe94860a"
LEGACY_END = 617698
LEGACY_END_HASH = "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
LEGACY_TOTALS = {"blocks":617699,"transactions":503813853,"inputs":1231768826,"outputs":1337956664}
FROZEN_LIVE_COUNT = 65419258
FROZEN_LIVE_VALUE = 1822105482121089
MAX_MONEY = 21_000_000 * 100_000_000
MAX_SCRIPT_SIZE = 10_000
BIP30_LATER = (91842, 91880)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

SPOOL_HDR = struct.Struct("<8sIIIIQ32s8s")
BLOCK_ROW = struct.Struct("<I32s32sqI")
TX_ROW = struct.Struct("<II32sIII")
INPUT_ROW = struct.Struct("<II32sII32sQ")
OUTPUT_PREFIX = struct.Struct("<II32sQqI")
SPOOL_MAGIC = b"V50SPL01"
SPOOL_VERSION = 3
SPOOL_KIND = {"blocks":1,"transactions":2,"inputs":3,"outputs":4}

STOP_REQUESTED = False


def _arm_pdeathsig(expected_parent: int) -> None:
    """Linux fail-closed parent-death guard for PREPARE processes/workers."""
    expected_parent=int(expected_parent)
    if expected_parent <= 1:
        die(f"invalid parent pid for PDEATHSIG: {expected_parent}")
    if os.getppid() != expected_parent:
        die(f"parent pid mismatch before PDEATHSIG expected={expected_parent} actual={os.getppid()}")
    libc=ctypes.CDLL(None,use_errno=True)
    PR_SET_PDEATHSIG=1
    rc=libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    if rc != 0:
        err=ctypes.get_errno()
        die(f"PR_SET_PDEATHSIG failed errno={err}")
    if os.getppid() != expected_parent:
        os.kill(os.getpid(), signal.SIGKILL)

# Dense core is embedded in this single operator file.  It is compiled automatically
# into the private V50 runtime directory on first use.  No installer or manual SHA
# verification is required.  The authoritative V50 state still binds itself to the
# exact Python driver bytes and exact compiled core binary bytes.
EMBEDDED_CORE_SOURCE_SHA256 = "cb689d72992419378568d11617c8203115a7af8105adaf6dcdfbf5e972211dbf"
EXPECTED_CORE_ID = "v50-dense-core-r11-buffered-script-append"
EMBEDDED_CORE_GZIP_B64 = "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"
CORE_BUILD_FLAGS = (
    "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-D_GLIBCXX_ASSERTIONS",
    "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
)


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)


def die(msg: str) -> None:
    raise RuntimeError(msg)


def sha256_file(path: Path, block: int = 8 << 20) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b=f.read(block)
            if not b: break
            h.update(b)
    return h.hexdigest()


def driver_sha256() -> str:
    # Bind every state open/mutation to the exact Python driver bytes.
    return sha256_file(Path(__file__).resolve())


def read_sidecar(path: Path) -> str:
    if path.is_symlink() or not path.is_file(): die(f"missing/invalid SHA sidecar: {path}")
    toks=path.read_text(encoding="ascii").strip().split()
    if not toks or not HASH_RE.fullmatch(toks[0].lower()): die(f"invalid SHA sidecar: {path}")
    return toks[0].lower()


def regular(path: Path) -> Path:
    if path.is_symlink() or not path.is_file(): die(f"required regular non-symlink file missing: {path}")
    return path.resolve(strict=True)


def verify_manifest_file(path: Path, expected: Optional[str]=None, full: bool=True) -> str:
    path=regular(path); side=Path(str(path)+".sha256")
    rec=read_sidecar(side)
    if expected and rec != expected.lower(): die(f"recorded SHA mismatch path={path} recorded={rec} expected={expected}")
    if full:
        got=sha256_file(path)
        if got != rec: die(f"content SHA mismatch path={path} actual={got} expected={rec}")
    return rec


def load_json(path: Path) -> Dict[str,Any]:
    x=json.loads(regular(path).read_text(encoding="utf-8"))
    if not isinstance(x,dict): die(f"JSON object required: {path}")
    return x


def file_ref(path: Path, expected_sha: str, rows: int) -> Dict[str,Any]:
    p=regular(path); s=read_sidecar(Path(str(p)+".sha256"))
    if s != expected_sha.lower(): die(f"Stage sidecar mismatch path={p} recorded={s} expected={expected_sha}")
    return {"path":str(p),"sha256":s,"rows":int(rows)}


def load_legacy_source(base: Path) -> Dict[str,Any]:
    base=base.resolve(strict=True)
    gm=base/"manifests"/"canonical_transactions_0_617698.json"
    gsha=verify_manifest_file(gm, LEGACY_GLOBAL_SHA, True)
    obj=load_json(gm)
    if obj.get("schema") != "mybot_stage2_canonical_transactions_v1" or obj.get("release_complete") is not True: die("legacy Stage global contract mismatch")
    if int(obj.get("start_height",-1))!=0 or int(obj.get("end_height",-1))!=LEGACY_END: die("legacy Stage range mismatch")
    if str(obj.get("end_hash") or LEGACY_END_HASH).lower()!=LEGACY_END_HASH: die("legacy Stage end hash mismatch")
    totals=obj.get("totals") or {}
    for k,v in LEGACY_TOTALS.items():
        if int(totals.get(k,-1))!=v: die(f"legacy Stage total mismatch {k}")
    needed={"all_windows_release_complete","all_window_file_sha256_verified","height_coverage_contiguous","canonical_block_hash_all","canonical_prevhash_all","exact_block_boundary_all","context_free_tx_checks_all","txid_wtxid_all","merkle_root_all","witness_commitment_all","parquet_cross_table_counts_all"}
    val=obj.get("validation") or {}
    bad=sorted(k for k in needed if val.get(k) is not True)
    if bad: die(f"legacy Stage validation not GREEN: {bad}")
    w=base/"manifests"/"canonical_transactions_0_617698.windows.tsv"
    wsha=verify_manifest_file(w, str((obj.get("windows_tsv") or {}).get("sha256") or ""), True)
    with w.open("r",encoding="ascii",newline="") as f:
        r=csv.DictReader(f,delimiter="\t"); rows=list(r); fields=list(r.fieldnames or [])
    expect=["window_start","window_end","window_manifest_sha256","blocks_sha256","transactions_sha256","inputs_sha256","outputs_sha256","blocks","transactions","inputs","outputs"]
    if fields!=expect: die(f"legacy Stage windows.tsv schema mismatch: {fields}")
    entries=[]; nxt=0; agg={k:0 for k in LEGACY_TOTALS}
    for row in rows:
        h1,h2=int(row["window_start"]),int(row["window_end"])
        if h1!=nxt or h2<h1: die(f"legacy Stage window continuity failure expected={nxt} actual={h1}..{h2}")
        nxt=h2+1; wd=base/"windows"/f"window_{h1:06d}_{h2:06d}"
        mp=wd/"manifest.json"; msha=verify_manifest_file(mp,row["window_manifest_sha256"],True); mo=load_json(mp)
        if mo.get("schema")!="mybot_stage2_window_v1" or mo.get("release_complete") is not True: die(f"legacy Stage window contract mismatch: {mp}")
        if int(mo.get("start_height",-1))!=h1 or int(mo.get("end_height",-1))!=h2: die(f"legacy window range mismatch: {mp}")
        e={"h1":h1,"h2":h2,"producer":"legacy_stage2_v1","manifest_path":str(mp.resolve()),"manifest_sha256":msha}
        for role in ("blocks","transactions","inputs","outputs"):
            n=int(row[role]); agg[role]+=n
            e[role]=file_ref(wd/f"{role}.parquet",row[f"{role}_sha256"],n)
        entries.append(e)
    if nxt!=LEGACY_END+1 or agg!=LEGACY_TOTALS: die("legacy Stage aggregate/coverage mismatch")
    return {"kind":"legacy","sha256":gsha,"path":str(gm.resolve()),"start_height":0,"end_height":LEGACY_END,"end_hash":LEGACY_END_HASH,"totals":agg,"entries":entries,"windows_sha256":wsha}


def load_v41_release(path: Path) -> Dict[str,Any]:
    path=regular(path); gsha=verify_manifest_file(path,None,True); obj=load_json(path)
    if obj.get("schema")!="mybot-stage2-release-v2" or obj.get("release_complete") is not True: die("V41 Stage release contract mismatch")
    start,end=int(obj.get("start_height",-1)),int(obj.get("end_height",-1))
    if start!=0 or end<LEGACY_END: die("V41 Stage release range invalid")
    eh=str(obj.get("end_hash") or "").lower()
    if not HASH_RE.fullmatch(eh): die("V41 Stage release end_hash invalid")
    wo=obj.get("windows_tsv") or {}; wp=Path(str(wo.get("path") or ""))
    if not wp.is_absolute(): die("V41 Stage release windows_tsv path must be absolute")
    wsha=verify_manifest_file(wp,str(wo.get("sha256") or ""),True)
    with wp.open("r",encoding="utf-8",newline="") as f:
        r=csv.DictReader(f,delimiter="\t"); rows=list(r); fields=list(r.fieldnames or [])
    expect=["window_start","window_end","producer_contract","window_manifest_path","window_manifest_sha256","blocks_path","blocks_sha256","transactions_path","transactions_sha256","inputs_path","inputs_sha256","outputs_path","outputs_sha256","blocks","transactions","inputs","outputs"]
    if fields!=expect: die(f"V41 Stage release TSV schema mismatch: {fields}")
    entries=[]; nxt=0; agg={k:0 for k in LEGACY_TOTALS}
    required_v2={"canonical_block_hash_all","canonical_prevhash_all","exact_block_boundary_all","context_free_tx_checks_all","txid_wtxid_all","merkle_root_all","witness_commitment_all","parquet_cross_table_counts","parquet_output_script_blob_lengths"}
    for row in rows:
        h1,h2=int(row["window_start"]),int(row["window_end"])
        if h1!=nxt or h2<h1 or h2>end: die(f"V41 Stage continuity failure expected={nxt} actual={h1}..{h2}")
        nxt=h2+1; prod=row["producer_contract"]; mp=Path(row["window_manifest_path"])
        msha=verify_manifest_file(mp,row["window_manifest_sha256"],True); mo=load_json(mp)
        if prod=="legacy_stage2_v1":
            if mo.get("schema")!="mybot_stage2_window_v1" or mo.get("release_complete") is not True: die(f"bad legacy window under V41 release: {mp}")
        elif prod=="utxo-stage-window-v2":
            if mo.get("schema")!="utxo-stage-window-v2" or mo.get("release_complete") is not True: die(f"bad V41 window: {mp}")
            bad=sorted(k for k in required_v2 if (mo.get("validation") or {}).get(k) is not True)
            if bad: die(f"V41 window validation not GREEN path={mp}: {bad}")
        else: die(f"unknown V41 Stage producer: {prod}")
        e={"h1":h1,"h2":h2,"producer":prod,"manifest_path":str(mp.resolve()),"manifest_sha256":msha}
        for role in ("blocks","transactions","inputs","outputs"):
            n=int(row[role]); agg[role]+=n
            e[role]=file_ref(Path(row[f"{role}_path"]),row[f"{role}_sha256"],n)
        entries.append(e)
    if nxt!=end+1: die("V41 Stage terminal coverage mismatch")
    declared=obj.get("totals") or {}
    for k,v in agg.items():
        if int(declared.get(k,-1))!=v: die(f"V41 Stage total mismatch {k}")
    return {"kind":"v41_release","sha256":gsha,"path":str(path),"start_height":0,"end_height":end,"end_hash":eh,"totals":agg,"entries":entries,"windows_sha256":wsha}


def load_source(args) -> Dict[str,Any]:
    return load_v41_release(Path(args.stage_release)) if getattr(args,"stage_release",None) else load_legacy_source(Path(args.stage_base))


def require_duckdb():
    try: import duckdb
    except Exception as e: die(f"duckdb Python package {DUCKDB_VERSION} required: {e}")
    if getattr(duckdb,"__version__",None)!=DUCKDB_VERSION: die(f"DuckDB version mismatch expected={DUCKDB_VERSION} actual={getattr(duckdb,'__version__',None)}")
    return duckdb


def find_entry(source: Dict[str,Any], h: int) -> Dict[str,Any]:
    for e in source["entries"]:
        if e["h1"]<=h<=e["h2"]: return e
    die(f"height outside Stage release: {h}")


def stage_segments(source: Dict[str,Any], h1:int, h2:int) -> List[Dict[str,Any]]:
    """Return contiguous physical Stage shards covering one logical APPLY window."""
    if h2 < h1: die(f"invalid Stage range: {h1}..{h2}")
    out=[]; expect=h1
    for e in source["entries"]:
        if int(e["h2"]) < expect: continue
        if int(e["h1"]) > h2: break
        if not (int(e["h1"]) <= expect <= int(e["h2"])):
            die(f"Stage shard gap while building logical window expected={expect} entry={e['h1']}..{e['h2']}")
        s1=expect; s2=min(h2,int(e["h2"]))
        out.append({"h1":s1,"h2":s2,"entry":e})
        expect=s2+1
        if expect>h2: break
    if expect!=h2+1: die(f"Stage shards do not cover logical window {h1}..{h2}; next={expect}")
    return out


def adjust_bip30(h1:int,h2:int)->int:
    for x in BIP30_LATER:
        if h1 < x <= h2: return x-1
    return h2


def hx(s: Any, what: str) -> bytes:
    q=str(s).lower()
    if not HASH_RE.fullmatch(q): die(f"invalid {what}: {s!r}")
    return bytes.fromhex(q)


def entry_stamps(e:Dict[str,Any])->Tuple[Tuple[str,int,int,int,int,int],...]:
    out=[]
    for role in ("blocks","transactions","inputs","outputs"):
        p=regular(Path(e[role]["path"])); st=p.stat()
        out.append((role,int(st.st_dev),int(st.st_ino),int(st.st_size),int(st.st_mtime_ns),int(st.st_ctime_ns)))
    return tuple(out)


def assert_entry_stamp(e:Dict[str,Any], expected)->None:
    got=entry_stamps(e)
    if got!=expected: die(f"Stage parquet changed after SHA verification manifest={e['manifest_sha256']}")


def full_verify_entry(e:Dict[str,Any], cache:dict)->None:
    """Full content SHA verification, parallel across the four immutable Parquet files."""
    key=e["manifest_sha256"]
    if key in cache:
        assert_entry_stamp(e,cache[key]); return
    before=entry_stamps(e)
    roles=("blocks","transactions","inputs","outputs")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4,thread_name_prefix="v50-sha") as ex:
        fut={role:ex.submit(sha256_file,Path(e[role]["path"])) for role in roles}
        for role in roles:
            got=fut[role].result()
            if got!=e[role]["sha256"]:
                die(f"Stage parquet content SHA mismatch role={role} path={e[role]['path']}")
    after=entry_stamps(e)
    if before!=after: die(f"Stage parquet changed while hashing manifest={key}")
    cache[key]=after


def spool_file(path: Path, kind:int, h1:int,h2:int,source_sha:str, rows:Iterable[bytes], *, sidecar:bool=True) -> int:
    """Write an ephemeral PREPARE spool.

    PREPARE spools are disposable derivations of frozen Stage, so they are intentionally
    *not* fsync'd.  Authoritative durability belongs to the dense-core checkpoint/state.
    A final spool still gets a SHA sidecar so APPLY can reject post-build corruption.
    """
    path.parent.mkdir(parents=True,exist_ok=True)
    zero=SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,0,bytes.fromhex(source_sha),b"\0"*8)
    count=0
    with path.open("xb") as f:
        f.write(zero)
        for b in rows:
            f.write(b); count+=1
        f.seek(0)
        f.write(SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,count,bytes.fromhex(source_sha),b"\0"*8))
        f.flush()
    if sidecar:
        digest=sha256_file(path)
        side=Path(str(path)+".sha256")
        with side.open("x",encoding="ascii") as f:
            f.write(f"{digest}  {path.name}\n")
            f.flush()
    return count


def _spool_part_file(path:Path, kind:int, h1:int, h2:int, source_sha:str, rows:Iterable[bytes])->Tuple[int,str]:
    """Write a disposable part spool and hash its body without an extra read pass."""
    path.parent.mkdir(parents=True,exist_ok=True)
    zero=SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,0,bytes.fromhex(source_sha),b"\0"*8)
    count=0; body_hash=hashlib.sha256()
    with path.open("xb") as f:
        f.write(zero)
        for b in rows:
            body_hash.update(b); f.write(b); count+=1
        f.seek(0)
        f.write(SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,count,bytes.fromhex(source_sha),b"\0"*8))
        f.flush()
    return count,body_hash.hexdigest()


def _merge_spool_parts(path:Path, kind:int, h1:int, h2:int, source_sha:str, parts:List[Dict[str,Any]]) -> int:
    if not parts: die(f"no spool parts to merge kind={kind}")
    path.parent.mkdir(parents=True,exist_ok=True)
    total=0; expect=h1
    zero=SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,0,bytes.fromhex(source_sha),b"\0"*8)
    with path.open("xb") as out:
        out.write(zero)
        for r in sorted(parts,key=lambda x:int(x["part_idx"])):
            ph1,ph2=int(r["h1"]),int(r["h2"])
            if ph1!=expect or ph2<ph1: die(f"non-contiguous spool parts expected={expect} actual={ph1}..{ph2}")
            pp=regular(Path(r["path"]))
            with pp.open("rb") as src:
                raw=src.read(SPOOL_HDR.size)
                if len(raw)!=SPOOL_HDR.size: die(f"short part spool header: {pp}")
                magic,version,pkind,hh1,hh2,count,ssha,reserved=SPOOL_HDR.unpack(raw)
                if magic!=SPOOL_MAGIC or version!=SPOOL_VERSION or pkind!=kind or hh1!=ph1 or hh2!=ph2 or reserved!=b"\0"*8:
                    die(f"part spool header mismatch: {pp}")
                if ssha!=bytes.fromhex(source_sha): die(f"part spool source SHA mismatch: {pp}")
                if int(count)!=int(r["rows"]): die(f"part spool row-count mismatch: {pp}")
                expected_body=str(r.get("body_sha256") or "")
                if not HASH_RE.fullmatch(expected_body): die(f"part spool missing body SHA: {pp}")
                bh=hashlib.sha256()
                while True:
                    b=src.read(8<<20)
                    if not b: break
                    bh.update(b); out.write(b)
                if bh.hexdigest()!=expected_body: die(f"part spool body SHA mismatch: {pp}")
            total+=int(count); expect=ph2+1
        if expect!=h2+1: die(f"merged spool does not reach h2={h2}, next={expect}")
        out.seek(0)
        out.write(SPOOL_HDR.pack(SPOOL_MAGIC,SPOOL_VERSION,kind,h1,h2,total,bytes.fromhex(source_sha),b"\0"*8))
        out.flush()
    digest=sha256_file(path)
    side=Path(str(path)+".sha256")
    with side.open("x",encoding="ascii") as f:
        f.write(f"{digest}  {path.name}\n")
        f.flush()
    return total


def query_batches(con,sql:str,params:Sequence[Any],batch:int=65536):
    cur=con.execute(sql,params)
    while True:
        rows=cur.fetchmany(batch)
        if not rows: break
        for r in rows: yield r


def _file_stamp(path:Path)->Tuple[int,int,int,int,int]:
    p=regular(path); st=p.stat()
    return (int(st.st_dev),int(st.st_ino),int(st.st_size),int(st.st_mtime_ns),int(st.st_ctime_ns))


def _parse_memory_bytes(value:str)->int:
    m=re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)\s*",str(value),re.I)
    if not m: die(f"unsupported --stage-memory value: {value!r}")
    n=float(m.group(1)); u=m.group(2).upper()
    mul={"B":1,"KB":1000,"MB":1000**2,"GB":1000**3,"TB":1000**4,"KIB":1024,"MIB":1024**2,"GIB":1024**3,"TIB":1024**4}[u]
    b=int(n*mul)
    if b < 256*(1<<20): die("--stage-memory must be at least 256MiB")
    return b


def _split_memory(value:str,workers:int)->str:
    total=_parse_memory_bytes(value)
    each=max(256*(1<<20),total//max(1,workers))
    return f"{each//(1<<20)}MiB"


def _role_spool_worker(payload:Tuple[str,List[Dict[str,Any]],int,int,str,str,int,str,str,int,bool,int])->Dict[str,Any]:
    role,segments,h1,h2,source_sha,out_s,threads,memory,tmp_s,parent_pid,make_sidecar,part_idx=payload
    _arm_pdeathsig(int(parent_pid))
    out=Path(out_s); tmp=Path(tmp_s)
    if not segments: die(f"empty Stage segment list for role={role}")
    expect=h1
    for s in segments:
        if int(s["h1"])!=expect or int(s["h2"])<int(s["h1"]):
            die(f"non-contiguous role segments role={role} expected={expect} actual={s.get('h1')}..{s.get('h2')}")
        expect=int(s["h2"])+1
    if expect!=h2+1: die(f"role segments do not reach logical h2 role={role} next={expect} h2={h2}")
    duckdb=require_duckdb(); tmp.mkdir(parents=True,exist_ok=True)
    con=duckdb.connect(":memory:")
    con.execute(f"PRAGMA threads={max(1,int(threads))}")
    con.execute(f"PRAGMA memory_limit='{memory}'")
    con.execute("PRAGMA preserve_insertion_order=true")
    con.execute(f"PRAGMA temp_directory='{str(tmp)}'")
    try:
        def rows():
            if role=="blocks":
                last=h1-1
                for seg in segments:
                    p=Path(seg["path"]); s1,s2=int(seg["h1"]),int(seg["h2"]); before=_file_stamp(p)
                    for height,bh,ph,bt,tc in query_batches(con,"SELECT height, lower(block_hash), lower(prev_hash), block_time, tx_count FROM read_parquet(?) WHERE height BETWEEN ? AND ?",[str(p),s1,s2]):
                        height=int(height)
                        if height!=last+1: die(f"blocks physical order/non-contiguous: expected={last+1} actual={height}")
                        last=height; yield BLOCK_ROW.pack(height,hx(bh,"block_hash"),hx(ph,"prev_hash"),int(bt),int(tc))
                    if before!=_file_stamp(p): die(f"Stage parquet changed while reading role={role} path={p}")
                if last!=h2: die(f"blocks spool did not reach h2={h2}, last={last}")
            elif role=="transactions":
                prev=(-1,-1)
                for seg in segments:
                    p=Path(seg["path"]); s1,s2=int(seg["h1"]),int(seg["h2"]); before=_file_stamp(p)
                    for h,ti,txid,cb,vin,vout in query_batches(con,"SELECT height, tx_index, lower(txid), is_coinbase, vin_count, vout_count FROM read_parquet(?) WHERE height BETWEEN ? AND ?",[str(p),s1,s2]):
                        h,ti=int(h),int(ti); key=(h,ti)
                        if key<=prev: die(f"transactions physical order failure {key} after {prev}")
                        prev=key; flags=1 if bool(cb) else 0
                        yield TX_ROW.pack(h,ti,hx(txid,"txid"),flags,int(vin),int(vout))
                    if before!=_file_stamp(p): die(f"Stage parquet changed while reading role={role} path={p}")
            elif role=="inputs":
                prev=(-1,-1,-1)
                for seg in segments:
                    p=Path(seg["path"]); s1,s2=int(seg["h1"]),int(seg["h2"]); before=_file_stamp(p)
                    for h,ti,txid,vi,pt,pv in query_batches(con,"SELECT height, tx_index, lower(txid), vin_index, lower(prev_txid), prev_vout FROM read_parquet(?) WHERE height BETWEEN ? AND ?",[str(p),s1,s2]):
                        h,ti,vi=int(h),int(ti),int(vi); key=(h,ti,vi)
                        if key<=prev: die(f"inputs physical order failure {key} after {prev}")
                        prev=key; pb=hx(pt,"prev_txid"); pv=int(pv); has_prev=0 if pb==b"\0"*32 and pv==0xFFFFFFFF else 1
                        yield INPUT_ROW.pack(h,ti,hx(txid,"input txid"),vi,has_prev,pb,pv)
                    if before!=_file_stamp(p): die(f"Stage parquet changed while reading role={role} path={p}")
            elif role=="outputs":
                prev=(-1,-1,-1)
                for seg in segments:
                    p=Path(seg["path"]); s1,s2=int(seg["h1"]),int(seg["h2"]); before=_file_stamp(p)
                    for h,ti,txid,vout,val,script,slen in query_batches(con,"SELECT height, tx_index, lower(txid), vout, value_sats, script_pubkey, script_pubkey_size FROM read_parquet(?) WHERE height BETWEEN ? AND ?",[str(p),s1,s2]):
                        h,ti,vout=int(h),int(ti),int(vout); key=(h,ti,vout)
                        if key<=prev: die(f"outputs physical order failure {key} after {prev}")
                        prev=key; sb=bytes(script); slen=int(slen); val=int(val)
                        if len(sb)!=slen: die(f"script BLOB length mismatch height={h} tx={ti} vout={vout}")
                        if val<0 or val>MAX_MONEY: die(f"MoneyRange violation height={h} tx={ti} vout={vout}")
                        yield OUTPUT_PREFIX.pack(h,ti,hx(txid,"output txid"),vout,val,slen)+sb
                    if before!=_file_stamp(p): die(f"Stage parquet changed while reading role={role} path={p}")
            else: die(f"unknown spool role: {role}")
        if make_sidecar:
            n=spool_file(out,SPOOL_KIND[role],h1,h2,source_sha,rows(),sidecar=True); body_sha=None
        else:
            n,body_sha=_spool_part_file(out,SPOOL_KIND[role],h1,h2,source_sha,rows())
    finally:
        con.close()
    return {"role":role,"path":str(out),"rows":n,"h1":h1,"h2":h2,"part_idx":int(part_idx),"body_sha256":body_sha}


def _split_segments_contiguous(segments:List[Dict[str,Any]], parts:int)->List[List[Dict[str,Any]]]:
    parts=max(1,min(int(parts),len(segments)))
    q,r=divmod(len(segments),parts)
    out=[]; pos=0
    for i in range(parts):
        n=q+(1 if i<r else 0)
        out.append(segments[pos:pos+n]); pos+=n
    return [x for x in out if x]


def _role_partition_count(role:str, threads:int, nshards:int)->int:
    if role=="blocks": want=max(1,min(2,threads//4 or 1))
    elif role=="transactions": want=max(1,threads//2)
    else: want=max(1,threads)  # inputs/outputs dominate real-chain PREPARE cost
    return min(nshards,want)


def build_spools(segments:List[Dict[str,Any]],h1:int,h2:int,source_sha:str,tmp_root:Path,threads:int,memory:str,integrity:str="manifest")->Dict[str,Path]:
    """Build one logical spool set with shard-parallel Stage reads.

    `threads` is a hard upper bound on concurrently active PREPARE worker processes.
    Every worker runs DuckDB with threads=1, preventing the old N-workers × N-DuckDB-threads
    oversubscription.  Each role is partitioned into contiguous shard groups and merged in
    original chain order before APPLY.
    """
    if integrity not in ("manifest","full"): die(f"invalid Stage integrity mode: {integrity}")
    if not segments: die("cannot build spools from empty Stage segment list")
    threads=max(1,int(threads))
    work=tmp_root/f"window_{h1:06d}_{h2:06d}_{uuid.uuid4().hex}"
    parts_root=work/"parts"
    work.mkdir(parents=True,exist_ok=False); parts_root.mkdir(parents=True,exist_ok=False)
    unique=[]; seen=set()
    for seg in segments:
        e=seg["entry"]; key=e["manifest_sha256"]
        if key not in seen: seen.add(key); unique.append(e)
    before={e["manifest_sha256"]:entry_stamps(e) for e in unique}
    for e in unique:
        for role in ("blocks","transactions","inputs","outputs"):
            rec=read_sidecar(Path(str(e[role]["path"])+".sha256"))
            if rec!=e[role]["sha256"]: die(f"Stage sidecar changed role={role} path={e[role]['path']}")
    if integrity=="full":
        cache={}
        for e in unique: full_verify_entry(e,cache)
    max_workers=min(threads, max(1,len(segments)*4))
    worker_memory=_split_memory(memory,max_workers)
    role_chunks:Dict[str,List[List[Dict[str,Any]]]]={}
    for role in ("blocks","transactions","inputs","outputs"):
        logical=[]
        for seg in segments:
            e=seg["entry"]
            logical.append({"path":e[role]["path"],"h1":int(seg["h1"]),"h2":int(seg["h2"])})
        role_chunks[role]=_split_segments_contiguous(logical,_role_partition_count(role,threads,len(logical)))
    tasks=[]
    # Round-robin roles so the first wave contains a mix instead of only blocks.
    max_parts=max(len(v) for v in role_chunks.values())
    for part_idx in range(max_parts):
        for role in ("outputs","inputs","transactions","blocks"):
            chunks=role_chunks[role]
            if part_idx>=len(chunks): continue
            chunk=chunks[part_idx]; ch1=int(chunk[0]["h1"]); ch2=int(chunk[-1]["h2"])
            out=parts_root/f"{role}_{part_idx:03d}.spool"
            tasks.append((role,chunk,ch1,ch2,source_sha,str(out),1,worker_memory,str(tmp_root/"duckdb"/work.name/f"{role}_{part_idx:03d}"),os.getpid(),False,part_idx))
    try:
        ctx=multiprocessing.get_context("fork")
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers,mp_context=ctx) as ex:
            futs=[ex.submit(_role_spool_worker,x) for x in tasks]
            results=[f.result() for f in futs]
        for e in unique:
            if entry_stamps(e)!=before[e["manifest_sha256"]]: die(f"Stage parquet changed during shard-parallel PREPARE manifest={e['manifest_sha256']}")
        paths={"work":work}
        for role in ("blocks","transactions","inputs","outputs"):
            rparts=[r for r in results if r["role"]==role]
            final=work/f"{role}.spool"
            _merge_spool_parts(final,SPOOL_KIND[role],h1,h2,source_sha,rparts)
            paths[role]=final
        shutil.rmtree(parts_root,ignore_errors=True)
        return paths
    except Exception:
        log(f"V50 spool preserved after failure: {work}")
        raise

def _prepare_request_write(tmp_root:Path,segments:List[Dict[str,Any]],h1:int,h2:int,source_sha:str,threads:int,memory:str,integrity:str)->Path:
    ctl=tmp_root/"prepare"; ctl.mkdir(parents=True,exist_ok=True)
    req=ctl/f"req_{h1:06d}_{h2:06d}_{uuid.uuid4().hex}.json"
    obj={"schema":"v50-prepare-request-v2","driver_sha256":driver_sha256(),"source_sha256":source_sha,"segments":segments,"h1":h1,"h2":h2,"stage_threads":threads,"stage_memory":memory,"integrity":integrity}
    data=(json.dumps(obj,separators=(",",":"),sort_keys=True)+"\n").encode("utf-8")
    fd=os.open(str(req),os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC,0o600)
    try:
        os.write(fd,data); os.fsync(fd)
    finally: os.close(fd)
    return req


def _launch_prepare(args,segments:List[Dict[str,Any]],h1:int,h2:int,source_sha:str)->Dict[str,Any]:
    tmp=Path(args.tmp); req=_prepare_request_write(tmp,segments,h1,h2,source_sha,int(args.stage_threads),args.stage_memory,args.parquet_sha)
    cmd=[sys.executable,str(Path(__file__).resolve()),"--tmp",str(tmp),"_prepare-window","--request",str(req),"--parent-pid",str(os.getpid())]
    p=subprocess.Popen(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    return {"proc":p,"request":req,"h1":h1,"h2":h2,"shards":len(segments)}


def _wait_prepare(job:Dict[str,Any])->Dict[str,Any]:
    p=job["proc"]; out,err=p.communicate()
    try: Path(job["request"]).unlink(missing_ok=True)
    except Exception: pass
    if p.returncode!=0: die(f"V50 PREPARE failed {job['h1']}..{job['h2']} rc={p.returncode}: {err.strip() or out.strip()}")
    lines=[x for x in out.splitlines() if x.strip()]
    if not lines: die(f"V50 PREPARE returned no JSON {job['h1']}..{job['h2']}")
    try: obj=json.loads(lines[-1])
    except Exception: die(f"V50 PREPARE invalid JSON {job['h1']}..{job['h2']}: {out!r}")
    if obj.get("status")!="GREEN" or int(obj.get("h1",-1))!=job["h1"] or int(obj.get("h2",-1))!=job["h2"]: die(f"V50 PREPARE acknowledgement mismatch: {obj}")
    if int(obj.get("shards",-1))!=int(job.get("shards",-2)): die(f"V50 PREPARE shard acknowledgement mismatch: {obj}")
    return {"h1":job["h1"],"h2":job["h2"],"shards":job["shards"],"work":Path(obj["work"]),"blocks":Path(obj["blocks"]),"transactions":Path(obj["transactions"]),"inputs":Path(obj["inputs"]),"outputs":Path(obj["outputs"])}


def _cancel_prepare(job:Optional[Dict[str,Any]])->None:
    if not job: return
    p=job.get("proc")
    if p and p.poll() is None:
        try: os.killpg(p.pid,signal.SIGTERM)
        except ProcessLookupError: pass
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try: os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            p.wait()
    try: Path(job["request"]).unlink(missing_ok=True)
    except Exception: pass


def _cleanup_ephemeral(tmp:Path)->None:
    if not tmp.exists(): return
    for p in tmp.glob("window_*"):
        if p.is_dir() and not p.is_symlink(): shutil.rmtree(p,ignore_errors=True)
    prep=tmp/"prepare"
    if prep.exists():
        for p in prep.glob("req_*.json"):
            try: p.unlink()
            except Exception: pass


def core_json(core:Path,args:Sequence[str],env:Optional[Dict[str,str]]=None)->Dict[str,Any]:
    cp=subprocess.run([str(core),*map(str,args)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    if cp.returncode!=0: die(f"dense core failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    lines=[x for x in cp.stdout.splitlines() if x.strip()]
    if not lines: die("dense core returned no JSON")
    try: obj=json.loads(lines[-1])
    except Exception: die(f"dense core invalid JSON: {cp.stdout!r}")
    if obj.get("status")!="GREEN": die(f"dense core not GREEN: {obj}")
    return obj


def _embedded_core_source() -> bytes:
    try:
        src=gzip.decompress(base64.b64decode(EMBEDDED_CORE_GZIP_B64.encode("ascii"),validate=True))
    except Exception as exc:
        die(f"embedded dense core decode failure: {exc}")
    got=hashlib.sha256(src).hexdigest()
    if got!=EMBEDDED_CORE_SOURCE_SHA256:
        die(f"embedded dense core SHA mismatch actual={got} expected={EMBEDDED_CORE_SOURCE_SHA256}")
    return src


def _fsync_dir(path:Path)->None:
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def _verify_core_identity(p:Path)->Path:
    p=regular(p)
    if not os.access(p,os.X_OK): die(f"dense core not executable: {p}")
    cp=subprocess.run([str(p),"identity"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if cp.returncode!=0:
        die(f"dense core identity probe failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    try:
        obj=json.loads([x for x in cp.stdout.splitlines() if x.strip()][-1])
    except Exception:
        die(f"dense core identity probe returned invalid JSON: {cp.stdout!r}")
    if obj.get("status")!="GREEN" or obj.get("core_id")!=EXPECTED_CORE_ID:
        die(f"dense core identity mismatch expected={EXPECTED_CORE_ID} actual={obj}")
    return p


def ensure_core(path:Path)->Path:
    """Return the private dense-core binary, compiling embedded C++ on first use."""
    p=Path(path)
    if p.exists():
        return _verify_core_identity(p)
    if p.is_symlink(): die(f"refuse symlink dense core path: {p}")
    cxx=shutil.which("g++")
    if not cxx: die("g++ not found; install the system C++ compiler before first V50 use")
    p.parent.mkdir(parents=True,exist_ok=True)
    try: os.chmod(p.parent,0o700)
    except PermissionError: pass
    lock_path=p.parent/".core-build.lock"
    lfd=os.open(str(lock_path),os.O_CREAT|os.O_RDWR|os.O_CLOEXEC,0o600)
    try:
        fcntl.flock(lfd,fcntl.LOCK_EX)
        if p.exists():
            return _verify_core_identity(p)
        src=_embedded_core_source()
        with tempfile.TemporaryDirectory(prefix=".v50-core-build-",dir=str(p.parent)) as td:
            td=Path(td); cpp=td/"v50_dense_core.cpp"; out=td/"utxo_v50_dense_core"
            with cpp.open("xb") as f:
                f.write(src); f.flush(); os.fsync(f.fileno())
            cmd=[cxx,*CORE_BUILD_FLAGS,str(cpp),"-o",str(out)]
            cp=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if cp.returncode!=0:
                die(f"automatic dense-core build failed rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
            os.chmod(out,0o700)
            with out.open("rb") as f: os.fsync(f.fileno())
            _verify_core_identity(out)
            os.replace(out,p)
            _fsync_dir(p.parent)
        log(f"V50 dense core auto-built: {p}")
        return _verify_core_identity(p)
    finally:
        try: fcntl.flock(lfd,fcntl.LOCK_UN)
        finally: os.close(lfd)


def active_old_engines()->List[str]:
    hits=[]
    proc=Path("/proc")
    if not proc.is_dir(): return hits
    me=os.getpid()
    for d in proc.iterdir():
        if not d.name.isdigit() or int(d.name)==me: continue
        try: raw=(d/"cmdline").read_bytes().replace(b"\0",b" ").decode("utf-8","replace")
        except Exception: continue
        if "utxo_pipeline_v40.py" in raw or "utxo_pipeline_v41.py" in raw: hits.append(f"pid={d.name} {raw.strip()}")
    return hits


def signal_handler(signum,frame):
    global STOP_REQUESTED; STOP_REQUESTED=True; log(f"V50 stop requested signal={signum}; current window will finish if APPLY has already started")


def consume_stop(stopfile: Path, committed_height: int) -> bool:
    if not STOP_REQUESTED and not stopfile.exists():
        return False
    if stopfile.exists():
        consumed=stopfile.with_name(f"STOP.consumed.{int(time.time())}.{os.getpid()}")
        os.replace(stopfile,consumed)
    log(f"V50 CONTROLLED STOP at committed height={committed_height}")
    return True


def parse_apply_green(cp: subprocess.CompletedProcess, expected_height: int) -> Dict[str,Any]:
    if cp.returncode != 0:
        die(f"V50 APPLY failed expected_height={expected_height} rc={cp.returncode}: {cp.stderr.strip() or cp.stdout.strip()}")
    lines=[x for x in cp.stdout.splitlines() if x.strip()]
    if not lines:
        die(f"V50 APPLY returned no JSON expected_height={expected_height}")
    try:
        obj=json.loads(lines[-1])
    except Exception:
        die(f"V50 APPLY returned invalid JSON expected_height={expected_height}: {cp.stdout!r}")
    if obj.get("status") != "GREEN" or int(obj.get("height",-2)) != int(expected_height):
        die(f"V50 APPLY acknowledgement mismatch expected_height={expected_height}: {obj}")
    return obj


def _session_fail(proc: subprocess.Popen, msg: str) -> None:
    err=""
    try:
        if proc.stderr is not None:
            err=proc.stderr.read().strip()
    except Exception:
        pass
    die(f"{msg}; core_rc={proc.poll()} stderr={err!r}")


def _start_core_session(core: Path, state: Path) -> subprocess.Popen:
    cmd=[str(core),"session","--state",str(state),"--driver-sha256",driver_sha256(),"--parent-pid",str(os.getpid())]
    proc=subprocess.Popen(cmd,text=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=1)
    if proc.stdin is None or proc.stdout is None:
        _session_fail(proc,"V50 core session pipe setup failed")
    line=proc.stdout.readline()
    if not line:
        _session_fail(proc,"V50 core session exited before READY")
    try: obj=json.loads(line)
    except Exception: _session_fail(proc,f"V50 core session invalid READY JSON: {line!r}")
    if obj.get("status")!="GREEN" or obj.get("session")!="READY":
        _session_fail(proc,f"V50 core session READY mismatch: {obj}")
    log(f"V50 APPLY SESSION READY height={obj.get('height')} derived_indexes=RAM")
    return proc


def _session_apply(proc: subprocess.Popen, current: Dict[str,Any], expected_height: int) -> Dict[str,Any]:
    if proc.poll() is not None:
        _session_fail(proc,"V50 core session is not running before APPLY")
    fields=[str(current[k]) for k in ("blocks","transactions","inputs","outputs")]
    if any((not x) or "\t" in x or "\n" in x or "\r" in x for x in fields):
        die("invalid internal spool path for V50 session protocol")
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write("APPLY\t"+"\t".join(fields)+"\n");proc.stdin.flush()
        line=proc.stdout.readline()
    except Exception as exc:
        _session_fail(proc,f"V50 core session I/O failure: {exc}")
    if not line:
        _session_fail(proc,f"V50 core session exited during APPLY expected_height={expected_height}")
    try: obj=json.loads(line)
    except Exception: _session_fail(proc,f"V50 core session invalid APPLY JSON expected_height={expected_height}: {line!r}")
    if obj.get("status")!="GREEN" or int(obj.get("height",-2))!=int(expected_height):
        _session_fail(proc,f"V50 core session APPLY acknowledgement mismatch expected_height={expected_height}: {obj}")
    return obj


def _close_core_session(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:return
    if proc.poll() is not None:return
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write("QUIT\n");proc.stdin.flush()
        line=proc.stdout.readline()
        if line:
            try:
                obj=json.loads(line)
                if obj.get("status")!="GREEN" or obj.get("session")!="CLOSED":
                    log(f"V50 WARNING: core session close acknowledgement unexpected: {obj}")
            except Exception:
                log(f"V50 WARNING: core session close returned invalid JSON: {line!r}")
        proc.wait(timeout=30)
    except Exception as exc:
        log(f"V50 WARNING: graceful core session close failed: {exc}")


def cmd_doctor(args):
    source=load_source(args); core=ensure_core(Path(args.core)); duckdb=require_duckdb()
    # Schema/reader smoke on first and last release entries, no payload mutation.
    con=duckdb.connect(":memory:")
    try:
        for e in {source["entries"][0]["manifest_sha256"]:source["entries"][0],source["entries"][-1]["manifest_sha256"]:source["entries"][-1]}.values():
            checks={
              "blocks":"SELECT height,block_hash,prev_hash,block_time,tx_count FROM read_parquet(?) LIMIT 0",
              "transactions":"SELECT height,tx_index,txid,is_coinbase,vin_count,vout_count FROM read_parquet(?) LIMIT 0",
              "inputs":"SELECT height,tx_index,txid,vin_index,prev_txid,prev_vout FROM read_parquet(?) LIMIT 0",
              "outputs":"SELECT height,tx_index,txid,vout,value_sats,script_pubkey,script_pubkey_size FROM read_parquet(?) LIMIT 0"}
            for role,q in checks.items(): con.execute(q,[e[role]["path"]]).fetchall()
    finally: con.close()
    free=shutil.disk_usage(Path(args.state).parent if Path(args.state).parent.exists() else Path("/opt/mybot_data")).free
    tmpfree=shutil.disk_usage(Path(args.tmp) if Path(args.tmp).exists() else Path(args.tmp).parent).free
    result={"status":"GREEN","version":VERSION,"source_kind":source["kind"],"source_sha256":source["sha256"],"source_end":source["end_height"],"duckdb":DUCKDB_VERSION,"core":str(core),"state_free_gib":round(free/(1<<30),1),"tmp_free_gib":round(tmpfree/(1<<30),1),"old_engines":active_old_engines(),"prepare_engine":"shard-parallel PREPARE + persistent APPLY session + volatile derived indexes + 32MiB buffered scripts","default_stage_threads":8,"default_stage_memory":"32GB","derived_index_mode":"volatile RAM; rebuilt from authoritative checkpoint prefix on session start","script_append_mode":"bounded 32MiB sequential buffer; flushed before authoritative durability barrier"}
    print(json.dumps(result,indent=2))


def cmd_init(args):
    old=active_old_engines()
    if old and not args.allow_old_engines: die("V40/V41 processes are active; V50 init is blocked by production policy. Use only --allow-old-engines for isolated lab state.")
    source=load_source(args); core=ensure_core(Path(args.core)); state=Path(args.state)
    if state.exists(): die(f"V50 state already exists: {state}")
    state.parent.mkdir(parents=True,exist_ok=True)
    totals=source["totals"]
    # Inputs include coinbase inputs, so this is a conservative close capacity.
    obj=core_json(core,["init","--state",state,"--source-sha256",source["sha256"],"--driver-sha256",driver_sha256(),"--expected-tx",totals["transactions"],"--expected-outs",totals["outputs"],"--expected-closes",int(totals["inputs"])+4096])
    print(json.dumps(obj,indent=2))


def cmd_status(args):
    obj=core_json(ensure_core(Path(args.core)),["status","--state",Path(args.state),"--driver-sha256",driver_sha256()])
    obj["driver_version"]=VERSION
    obj["prepare_engine"]="shard-parallel PREPARE + persistent APPLY session + volatile derived indexes + 32MiB buffered scripts"
    print(json.dumps(obj,indent=2))

def cmd_verify(args):
    a=["verify","--state",Path(args.state),"--driver-sha256",driver_sha256()]
    if args.deep:a.append("--deep")
    if args.full_hash:a.append("--full-hash")
    print(json.dumps(core_json(ensure_core(Path(args.core)),a),indent=2))

def cmd_fingerprint(args): print(json.dumps(core_json(ensure_core(Path(args.core)),["fingerprint","--state",Path(args.state),"--driver-sha256",driver_sha256()]),indent=2))


def _window_spec(source:Dict[str,Any],h1:int,target:int,window:int)->Tuple[List[Dict[str,Any]],int]:
    h2=min(h1+window-1,target)
    h2=adjust_bip30(h1,h2)
    if h2<h1: die(f"invalid V50 window after BIP30 split: {h1}..{h2}")
    return stage_segments(source,h1,h2),h2


def cmd__prepare_window(args):
    _arm_pdeathsig(int(args.parent_pid))
    reqp=regular(Path(args.request)); obj=load_json(reqp)
    if obj.get("schema")!="v50-prepare-request-v2": die("invalid internal prepare request schema")
    if str(obj.get("driver_sha256"))!=driver_sha256(): die("internal prepare request/driver SHA mismatch")
    source_sha=str(obj.get("source_sha256") or "").lower()
    if not HASH_RE.fullmatch(source_sha): die("internal prepare source SHA invalid")
    segs=obj.get("segments")
    if not isinstance(segs,list) or not segs: die("internal prepare segment list invalid")
    h1,h2=int(obj["h1"]),int(obj["h2"]); expect=h1
    for seg in segs:
        if not isinstance(seg,dict) or not isinstance(seg.get("entry"),dict): die("internal prepare segment invalid")
        e=seg["entry"]; s1,s2=int(seg["h1"]),int(seg["h2"])
        if s1!=expect or not (int(e["h1"])<=s1<=s2<=int(e["h2"])): die("internal prepare segment coverage invalid")
        expect=s2+1
    if expect!=h2+1: die("internal prepare segments do not cover logical window")
    threads=int(obj["stage_threads"]); memory=str(obj["stage_memory"]); integrity=str(obj["integrity"])
    sp=build_spools(segs,h1,h2,source_sha,Path(args.tmp),threads,memory,integrity)
    print(json.dumps({"status":"GREEN","h1":h1,"h2":h2,"shards":len(segs),"work":str(sp["work"]),"blocks":str(sp["blocks"]),"transactions":str(sp["transactions"]),"inputs":str(sp["inputs"]),"outputs":str(sp["outputs"])},separators=(",",":")))


def cmd_run(args):
    if args.parquet_sha not in ("manifest","full"): die("invalid --parquet-sha")
    target=int(args.target_height); window=int(args.window); stage_threads=int(args.stage_threads)
    if target < 0: die("--target-height must be >=0")
    if window < 1: die("--window must be >=1")
    if stage_threads < 1: die("--stage-threads must be >=1")
    _parse_memory_bytes(args.stage_memory)
    old=active_old_engines()
    if old and not args.allow_old_engines: die("V40/V41 are active. Full V50 APPLY is intentionally blocked to avoid RAM/I/O contention. Stop them safely first.")
    source=load_source(args); core=ensure_core(Path(args.core)); state=Path(args.state); tmp=Path(args.tmp); tmp.mkdir(parents=True,exist_ok=True)
    st=core_json(core,["status","--state",state,"--driver-sha256",driver_sha256()])
    if st["source_sha256"]!=source["sha256"]: die("V50 state/source SHA mismatch")
    if target>source["end_height"]: die("target exceeds Stage release")
    committed=int(st["height"])
    if committed>=target: log(f"already at height {committed} >= target {target}"); return
    signal.signal(signal.SIGTERM,signal_handler); signal.signal(signal.SIGINT,signal_handler)
    stopfile=Path(args.control)/"STOP"; Path(args.control).mkdir(parents=True,exist_ok=True)
    if consume_stop(stopfile,committed): return
    _cleanup_ephemeral(tmp)
    h1=committed+1; segs,h2=_window_spec(source,h1,target,window)
    log(f"V50 PREPARE {h1}..{h2} StageShards={len(segs)} mode={args.parquet_sha} workers={stage_threads} threads={stage_threads}")
    current=_wait_prepare(_launch_prepare(args,segs,h1,h2,source["sha256"]))
    next_job=None
    core_session=_start_core_session(core,state)
    try:
        while True:
            h1,h2=int(current["h1"]),int(current["h2"])
            if STOP_REQUESTED or consume_stop(stopfile,h1-1):
                try: shutil.rmtree(current["work"])
                except Exception as exc: log(f"V50 WARNING: stopped spool cleanup failed path={current['work']}: {exc}")
                return
            next_h1=h2+1
            next_job=None
            if next_h1<=target and not STOP_REQUESTED and not stopfile.exists():
                nsegs,nh2=_window_spec(source,next_h1,target,window)
                log(f"V50 PIPELINE PREPARE {next_h1}..{nh2} StageShards={len(nsegs)}")
                next_job=_launch_prepare(args,nsegs,next_h1,nh2,source["sha256"])
            if not args.allow_old_engines and active_old_engines():
                _cancel_prepare(next_job); die("V40/V41 became active during V50 run; refusing APPLY")
            try: obj=_session_apply(core_session,current,h2)
            except Exception as exc:
                _cancel_prepare(next_job); die(f"{exc}; current spool preserved={current['work']}")
            log(f"V50 COMMIT height={obj.get('height')} live={obj.get('live_count')} value={obj.get('live_value_sats')}")
            try: shutil.rmtree(current["work"])
            except Exception as exc: log(f"V50 WARNING: committed spool cleanup failed path={current['work']}: {exc}")
            if STOP_REQUESTED or consume_stop(stopfile,h2):
                _cancel_prepare(next_job); return
            if h2>=target:
                _cancel_prepare(next_job); break
            if next_job is None: die("internal pipeline error: missing next PREPARE")
            log(f"V50 WAIT PREPARE {next_job['h1']}..{next_job['h2']}")
            current=_wait_prepare(next_job); next_job=None
    finally:
        _cancel_prepare(next_job)
        _close_core_session(core_session)
    log(f"V50 TARGET GREEN height={target}")


def fp_update(h,txid:str,vout:int,value:int,script:bytes,height:int,tx_index:int,coinbase:bool):
    h.update(bytes.fromhex(txid.lower())); h.update(struct.pack("<I",int(vout))); h.update(struct.pack("<q",int(value))); h.update(struct.pack("<I",len(script))); h.update(script); h.update(struct.pack("<I",int(height))); h.update(struct.pack("<I",int(tx_index))); h.update(bytes([1 if coinbase else 0]))


def cmd_compare(args):
    core=ensure_core(Path(args.core)); v=core_json(core,["fingerprint","--state",Path(args.state),"--driver-sha256",driver_sha256()])
    db=regular(Path(args.reference_db)); wal=Path(str(db)+".wal")
    if wal.exists(): die(f"reference DuckDB has WAL; use a clean stopped snapshot: {wal}")
    old=active_old_engines()
    if old and not args.allow_live_reference: die("live V40/V41 process detected; reference comparison requires a stopped/immutable DB snapshot")
    duckdb=require_duckdb(); con=duckdb.connect(str(db),read_only=True)
    try:
        maxh=con.execute("SELECT max(block_number) FROM block_meta").fetchone()[0]
        if maxh is None: die("reference block_meta empty")
        if int(maxh)!=int(v["height"]): die(f"reference/V50 height mismatch reference={maxh} v50={v['height']}")
        if args.expected_height is not None and int(maxh)!=int(args.expected_height): die(f"reference height != expected {args.expected_height}")
        tip=con.execute("SELECT lower(block_hash) FROM block_meta WHERE block_number=?",[int(maxh)]).fetchone()
        if not tip or str(tip[0]).lower()!=str(v["block_hash"]).lower(): die(f"reference/V50 tip block_hash mismatch reference={None if not tip else tip[0]} v50={v['block_hash']}")
        src=con.execute("SELECT value FROM pipeline_meta WHERE key='stage2_global_manifest_sha256'").fetchone()
        if src is not None and str(src[0]).lower()!=str(v["source_sha256"]).lower(): die(f"reference/V50 source SHA mismatch reference={src[0]} v50={v['source_sha256']}")
        h=hashlib.sha256(); count=0; value=0
        q="""SELECT lower(txid),vout,value_sats,script_pubkey,created_height,created_tx_index,is_coinbase
             FROM utxo
             WHERE spent_height IS NULL AND bip30_overwritten_height IS NULL
             ORDER BY created_height,created_tx_index,vout"""
        cur=con.execute(q)
        while True:
            rows=cur.fetchmany(32768)
            if not rows:break
            for txid,vout,val,script,ch,ti,cb in rows:
                sb=bytes(script); fp_update(h,str(txid),int(vout),int(val),sb,int(ch),int(ti),bool(cb)); count+=1; value+=int(val)
    finally: con.close()
    ref=h.hexdigest(); ok=count==int(v["live_count"]) and value==int(v["live_value_sats"]) and ref==v["fingerprint_sha256"]
    report={"status":"GREEN" if ok else "RED","height":int(v["height"]),"block_hash":v["block_hash"],"source_sha256":v["source_sha256"],"v50":{"count":v["live_count"],"value_sats":v["live_value_sats"],"fingerprint":v["fingerprint_sha256"]},"reference":{"count":count,"value_sats":value,"fingerprint":ref,"db":str(db)}}
    print(json.dumps(report,indent=2));
    if not ok: raise SystemExit(3)


def cmd_anchor(args):
    v=core_json(ensure_core(Path(args.core)),["fingerprint","--state",Path(args.state),"--driver-sha256",driver_sha256()])
    ok=int(v["height"])==LEGACY_END and str(v["block_hash"]).lower()==LEGACY_END_HASH and int(v["live_count"])==FROZEN_LIVE_COUNT and int(v["live_value_sats"])==FROZEN_LIVE_VALUE
    r={"status":"GREEN" if ok else "RED","expected_height":LEGACY_END,"actual_height":v["height"],"expected_block_hash":LEGACY_END_HASH,"actual_block_hash":v["block_hash"],"expected_live_count":FROZEN_LIVE_COUNT,"actual_live_count":v["live_count"],"expected_live_value_sats":FROZEN_LIVE_VALUE,"actual_live_value_sats":v["live_value_sats"],"fingerprint_sha256":v["fingerprint_sha256"]}
    print(json.dumps(r,indent=2));
    if not ok: raise SystemExit(3)


def spool_rows(path: Path) -> int:
    with path.open("rb") as f:
        raw=f.read(SPOOL_HDR.size)
    if len(raw)!=SPOOL_HDR.size: die(f"short spool header: {path}")
    magic,version,kind,h1,h2,rows,sha,res=SPOOL_HDR.unpack(raw)
    if magic!=SPOOL_MAGIC or version!=SPOOL_VERSION: die(f"invalid spool header: {path}")
    return int(rows)


def cmd_stage_smoke(args):
    source=load_source(args); core=ensure_core(Path(args.core)); end=int(args.end_height)
    if int(args.stage_threads) < 1: die("stage-smoke --stage-threads must be >=1")
    if end<0 or end>min(source["end_height"],5000): die("stage-smoke end-height must be within 0..5000")
    segs=stage_segments(source,0,end)
    base=Path(args.tmp); base.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix="v50-stage-smoke-",dir=str(base)))
    try:
        sp=build_spools(segs,0,end,source["sha256"],work,int(args.stage_threads),args.stage_memory,args.parquet_sha)
        state=work/"state"
        txc=spool_rows(sp["transactions"])+32; outc=spool_rows(sp["outputs"])+32; closec=spool_rows(sp["inputs"])+32
        core_json(core,["init","--state",state,"--source-sha256",source["sha256"],"--driver-sha256",driver_sha256(),"--expected-tx",txc,"--expected-outs",outc,"--expected-closes",closec])
        cp=subprocess.run([str(core),"apply","--state",str(state),"--driver-sha256",driver_sha256(),"--blocks",str(sp["blocks"]),"--txs",str(sp["transactions"]),"--inputs",str(sp["inputs"]),"--outputs",str(sp["outputs"]),"--parent-pid",str(os.getpid())],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        parse_apply_green(cp,end)
        ver=core_json(core,["verify","--state",state,"--driver-sha256",driver_sha256(),"--deep","--full-hash"]); fpv=core_json(core,["fingerprint","--state",state,"--driver-sha256",driver_sha256()])
        print(json.dumps({"status":"GREEN","source_sha256":source["sha256"],"range":[0,end],"verify":ver,"fingerprint":fpv},indent=2))
    finally:
        if not args.keep: shutil.rmtree(work,ignore_errors=True)


def cmd_stop(args):
    control=Path(args.control); control.mkdir(parents=True,exist_ok=True)
    stop=control/"STOP"
    if stop.exists():
        print(json.dumps({"status":"GREEN","requested":True,"already_present":True,"path":str(stop)},indent=2)); return
    tmp=control/f".STOP.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    with tmp.open("x",encoding="ascii") as f:
        f.write(f"requested_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}\npid={os.getpid()}\n")
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp,stop); _fsync_dir(control)
    print(json.dumps({"status":"GREEN","requested":True,"already_present":False,"path":str(stop)},indent=2))


def cmd_recover(args):
    state=Path(args.state); core=ensure_core(Path(args.core)); dirty=state/"dirty.bin"
    before=dirty.exists()
    st=core_json(core,["status","--state",state,"--driver-sha256",driver_sha256()])
    ver=core_json(core,["verify","--state",state,"--driver-sha256",driver_sha256(),"--deep","--full-hash"])
    print(json.dumps({"status":"GREEN","dirty_before":before,"dirty_after":dirty.exists(),"state":st,"verify":ver},indent=2))


class _DriverLease:
    def __init__(self,state:Path):
        self.path=Path(state).parent/".v50-driver.lock"; self.fd=-1
    def __enter__(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.fd=os.open(str(self.path),os.O_CREAT|os.O_RDWR|os.O_CLOEXEC,0o600)
        try:
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd); self.fd=-1
            die(f"another V50 mutating driver is active: {self.path}")
        os.ftruncate(self.fd,0); os.write(self.fd,f"pid={os.getpid()}\n".encode("ascii")); os.fsync(self.fd)
        return self
    def __exit__(self,exc_type,exc,tb):
        if self.fd>=0:
            try: fcntl.flock(self.fd,fcntl.LOCK_UN)
            finally: os.close(self.fd); self.fd=-1


_cmd_init_impl=cmd_init
_cmd_run_impl=cmd_run
_cmd_recover_impl=cmd_recover

def cmd_init(args):
    with _DriverLease(Path(args.state)):
        return _cmd_init_impl(args)

def cmd_run(args):
    with _DriverLease(Path(args.state)):
        return _cmd_run_impl(args)

def cmd_recover(args):
    with _DriverLease(Path(args.state)):
        return _cmd_recover_impl(args)


def parser():
    p=argparse.ArgumentParser(description="MyBot UTXO V50 dense independent calculator")
    p.add_argument("--stage-base",default=str(LEGACY_STAGE_BASE)); p.add_argument("--stage-release")
    p.add_argument("--state",default=str(DEFAULT_STATE)); p.add_argument("--tmp",default=str(DEFAULT_TMP)); p.add_argument("--control",default=str(DEFAULT_CONTROL)); p.add_argument("--core",default=str(DEFAULT_CORE),help=argparse.SUPPRESS)
    sp=p.add_subparsers(dest="cmd",required=True,metavar="{doctor,stage-smoke,init,run,status,stop,recover,verify,fingerprint,compare,anchor}")
    sp.add_parser("doctor")
    q=sp.add_parser("stage-smoke"); q.add_argument("--end-height",type=int,default=100); q.add_argument("--parquet-sha",choices=("full","manifest"),default="full"); q.add_argument("--stage-threads",type=int,default=8); q.add_argument("--stage-memory",default="8GB"); q.add_argument("--keep",action="store_true")
    q=sp.add_parser("init"); q.add_argument("--allow-old-engines",action="store_true")
    q=sp.add_parser("run"); q.add_argument("--target-height",type=int,required=True); q.add_argument("--window",type=int,default=1000); q.add_argument("--parquet-sha",choices=("manifest","full"),default="manifest",help="manifest=verified release + sidecars + immutable stat guards; full=rehash every Parquet before reading"); q.add_argument("--stage-threads",type=int,default=8); q.add_argument("--stage-memory",default="32GB",help="total PREPARE memory budget, divided across shard-parallel workers"); q.add_argument("--allow-old-engines",action="store_true")
    sp.add_parser("status")
    sp.add_parser("stop")
    sp.add_parser("recover")
    q=sp.add_parser("verify"); q.add_argument("--deep",action="store_true"); q.add_argument("--full-hash",action="store_true")
    sp.add_parser("fingerprint")
    q=sp.add_parser("compare"); q.add_argument("--reference-db",required=True); q.add_argument("--expected-height",type=int); q.add_argument("--allow-live-reference",action="store_true")
    sp.add_parser("anchor")
    q=sp.add_parser("_prepare-window",help=argparse.SUPPRESS); q.add_argument("--request",required=True); q.add_argument("--parent-pid",type=int,required=True)
    sp._choices_actions=[a for a in sp._choices_actions if getattr(a,"dest",None)!="_prepare-window"]
    return p


def main():
    a=parser().parse_args(); fn=globals()["cmd_"+a.cmd.replace("-","_")]; fn(a)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print("V50_FATAL: interrupted",file=sys.stderr); sys.exit(130)
    except Exception as e: print(f"V50_FATAL: {e}",file=sys.stderr); sys.exit(2)
