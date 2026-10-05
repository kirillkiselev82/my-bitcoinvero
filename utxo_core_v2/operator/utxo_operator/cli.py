from __future__ import annotations
import argparse,json,os,re,subprocess,sys,time
from pathlib import Path
from . import __version__
from .config import load_config,Config
from .core import service_state,start as core_start,stop as core_stop,wait_rpc
from .orchestrator import run_pipeline
from .renderer import event
from .safety import OperatorLock
from .state import apply_hwm,apply_tip_time,latest_stage_release,latest_audit_hwm,source_stage_hwm,read_current
from .legacy import live_status as legacy_live_status
from .util import atomic_bytes,fsync_dir,iter_cmdlines,pid_alive,sha256_file,utc_now,verify_sidecar
from .verify import verify_release


def cfg(args): return load_config(args.config)
def disk_free(path:Path):
    p=path
    while not p.exists() and p!=p.parent: p=p.parent
    s=os.statvfs(str(p)); return s.f_bavail*s.f_frsize/1024**3

def host_memory():
    vals={}
    try:
        for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
            if ':' not in line: continue
            k,raw=line.split(':',1); parts=raw.strip().split()
            if parts and parts[0].isdigit(): vals[k]=int(parts[0])*1024
    except Exception: return {'total_gib':None,'available_gib':None}
    return {'total_gib':round(vals.get('MemTotal',0)/1024**3,1),'available_gib':round(vals.get('MemAvailable',0)/1024**3,1)}

def create_stop(c:Config,reason:str):
    c.stop_file.parent.mkdir(parents=True,exist_ok=True)
    if c.stop_file.exists(): raise RuntimeError(f'STOP already exists: {c.stop_file}')
    body=f"controlled_stop_requested_utc={utc_now().isoformat()}\nreason={reason}\nrequested_by=utxo-operator-v{__version__}\n"
    atomic_bytes(c.stop_file,body.encode(),mode=0o600,overwrite=False)

def active_engines(c:Config):
    needles=[str(c.build_stage),str(c.calculator),str(c.auditor),str(c.frozen_v40)]
    return [(p,x) for p,x in iter_cmdlines() if any(n in x for n in needles)]

def cmd_verify(args):
    r=verify_release(cfg(args)); print(json.dumps(r,indent=2,sort_keys=True)); return 0 if r['status']=='GREEN' else 1

def cmd_status(args):
    c=cfg(args); cur=read_current(c); engines=active_engines(c)
    legacy=legacy_live_status(c) if not cur else {'running':False}
    legacy_last=(legacy.get('last_commit') or {}).get('h2') if legacy.get('running') else None
    ah=legacy_last if legacy_last is not None else apply_hwm(c)
    sr=latest_stage_release(c); ss=source_stage_hwm(c); audit_h=latest_audit_hwm(c)
    state = cur.get('status') if cur else ('LEGACY_RUNNING' if legacy.get('running') else ('BUSY_EXTERNAL' if engines else 'IDLE'))
    print('UTXO CORE v2'); print('─'*64)
    print(f"State           {state}")
    print(f"Phase           {cur.get('phase') if cur else ('LEGACY_APPLY' if legacy.get('running') else '-')}")
    if cur:
        print(f"Run ID          {cur.get('run_id')}"); print(f"Requested UTC   {cur.get('requested_utc_day')}"); print(f"Target height   {cur.get('target_height','-')}"); print(f"Log             {cur.get('log_path')}")
    elif legacy.get('running'):
        print(f"Calculator      {c.frozen_v40}")
        if legacy.get('info'): print(f"Run info        {legacy.get('info')}")
        if legacy.get('source_green'): print('Source          GREEN')
        current=legacy.get('current') or {}
        if current:
            h1,h2=int(current['h1']),int(current['h2'])
            print(f"Current window  {h1}..{h2}  size={current.get('size')} attempt={current.get('attempt')}")
            times=legacy.get('times') or {}
            if times.get(h1) or times.get(h2): print(f"  UTXO date: {times.get(h1,'UNKNOWN')} → {times.get(h2,'UNKNOWN')}")
            print(f"  Blocks:    {h1} → {h2}")
        last=legacy.get('last_commit') or {}
        if last:
            h=int(last['h2']); target=int(legacy.get('target') or 617698)
            progress=((h+1)/(target+1)*100.0) if target >= 0 else 0.0
            print(f"Last commit     {h}"); print(f"Progress        {progress:.2f}%"); print(f"OOM events      {legacy.get('oom_count',0)}")
        writer=legacy.get('writer') or {}
        if writer:
            print(f"Writer PID      {writer.get('pid')}")
            if writer.get('rss_gib') is not None: print(f"Writer RSS      {writer.get('rss_gib'):.1f} GiB")
            if writer.get('hwm_gib') is not None: print(f"Writer HWM      {writer.get('hwm_gib'):.1f} GiB")
            print('Writer threads  1 CPU execution thread [LOCKED by policy]')
    print(f"Core            {service_state()}")
    print(f"SOURCE HWM      {ss.get('source_hwm','UNKNOWN') if ss.get('status')=='OK' else 'UNKNOWN'}")
    print(f"STAGE HWM       {ss.get('stage_hwm','UNKNOWN') if ss.get('status')=='OK' else 'UNKNOWN'}")
    print(f"Stage release   {sr or '-'}")
    print(f"APPLY HWM       {ah if ah is not None else 'UNKNOWN'}")
    print(f"AUDIT HWM       {audit_h if audit_h is not None else 'UNKNOWN'}")
    if not legacy.get('running'):
        print(f"APPLY date      {apply_tip_time(c) or 'UNKNOWN'}")
    print(f"Writer policy   1 CPU [LOCKED]")
    print(f"Memory          {cur.get('memory') if cur else c.memory}")
    print(f"Configured win  {cur.get('apply_window') if cur else c.apply_window} (sticky-down)")
    print(f"Active engines  {len(engines)}")
    for pid,cmd in engines[:6]: print(f"  {pid} {cmd[:140]}")
    if ss.get('status')!='OK': print(f"Source/Stage    UNKNOWN ({ss.get('error','status unavailable')})")
    print(f"DB              {c.db}"); print(f"WAL             {'PRESENT' if Path(str(c.db)+'.wal').exists() else 'absent'}")
    return 0

def cmd_date(args):
    c=cfg(args); legacy=legacy_live_status(c)
    if legacy.get('running'):
        item=legacy.get('current') or legacy.get('last_commit') or {}
        if item:
            h1,h2=int(item['h1']),int(item['h2']); times=legacy.get('times') or {}
            print(f"Current legacy APPLY: heights={h1}..{h2} UTC={times.get(h1,'UNKNOWN')} → {times.get(h2,'UNKNOWN')}")
            return 0
    h=apply_hwm(c); t=apply_tip_time(c); print(f"Last committed: height={h} UTC={t or 'UNKNOWN'}"); return 0

def cmd_stop(args):
    c=cfg(args); cur=read_current(c); engines=active_engines(c)
    state=str((cur or {}).get('status') or '')
    stoppable_state = state.startswith('RUNNING')
    if not engines and not stoppable_state:
        print(f'No active UTXO engine; STOP not created. state={state or "IDLE"}'); return 0
    create_stop(c,args.reason); print(event('YELLOW','⚠','CONTROLLED STOP REQUESTED',[f'STOP: {c.stop_file}','No signal was sent; engine will stop at a safe boundary.']))
    if not args.wait: return 0
    deadline=time.time()+args.timeout
    while time.time()<deadline:
        if not active_engines(c): return 0
        time.sleep(2)
    return 1

def cmd_run(args):
    c=cfg(args); return run_pipeline(c,to_day=args.to,confirmations=c.confirmations if args.confirmations is None else args.confirmations,cores=c.stage_cores if args.cores is None else args.cores,memory=c.memory if args.memory is None else args.memory,window=c.apply_window if args.window is None else args.window,resume=False)

def cmd_resume(args):
    c=cfg(args); return run_pipeline(c,to_day='1970-01-01',confirmations=c.confirmations,cores=c.stage_cores,memory=c.memory,window=c.apply_window,resume=True)

def cmd_plan(args):
    c=cfg(args); conf=c.confirmations if args.confirmations is None else args.confirmations; vr=verify_release(c); ss=source_stage_hwm(c); print(f"Release          {vr['status']}"); print(f"Core             {service_state()}"); print(f"Current SOURCE   {ss.get('source_hwm','UNKNOWN')}"); print(f"Current STAGE    {ss.get('stage_hwm','UNKNOWN')}"); print(f"Current APPLY    {apply_hwm(c)}"); print(f"Current AUDIT    {latest_audit_hwm(c)}"); print(f"Requested        {args.to} UTC"); print(f"Confirmations    {conf}")
    if service_state()!='active':
        print('Target           NOT_RESOLVED (plan is read-only; Bitcoin Core is inactive)'); print('Action           run will temporarily start Core, freeze target, stop Core for SOURCE+STAGE, then APPLY+AUDIT'); return 0 if vr['status']=='GREEN' else 1
    p=subprocess.run([str(c.python),str(c.build_stage),'--base',str(c.v2_base),'--legacy-base',str(c.legacy_base),'--datadir',str(c.datadir),'--tmp-root',str(c.tmpdir.parent/'utxo_core_v2_stage'),'--extractor',str(c.extractor),'--decoder',str(c.decoder),'--locator-reference',str(c.locator_reference),'--bitcoin-cli',str(c.bitcoin_cli),'--stop-file',str(c.stop_file),'snapshot','--to',args.to,'--confirmations',str(conf)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(p.stdout.rstrip()); return p.returncode

def cmd_doctor(args):
    c=cfg(args); vr=verify_release(c); errs=[]
    if vr['status']!='GREEN': errs.append('release identity')
    if Path(str(c.db)+'.wal').exists(): errs.append('DB WAL present')
    if c.operator_lock.exists():
        owner={}
        try: owner=json.loads((c.operator_lock/'owner.json').read_text())
        except Exception: owner={}
        pid=int(owner.get('pid') or 0)
        if not pid_alive(pid): errs.append(f'stale operator lock pid={pid} path={c.operator_lock}')
    data=disk_free(c.v2_base); tmp=disk_free(c.tmpdir); mem=host_memory()
    if data<c.min_free_data_gib: errs.append(f'data free {data:.1f}<min {c.min_free_data_gib}')
    if tmp<c.min_free_tmp_gib: errs.append(f'tmp free {tmp:.1f}<min {c.min_free_tmp_gib}')
    if mem.get('available_gib') is None: errs.append('cannot read host memory')
    elif float(mem['available_gib'])<c.min_available_memory_gib: errs.append(f"memory available {mem['available_gib']}<min {c.min_available_memory_gib}")
    print(json.dumps({'status':'GREEN' if not errs else 'BAD','core':service_state(),'data_free_gib':round(data,1),'tmp_free_gib':round(tmp,1),'memory':mem,'release':vr,'errors':errs},indent=2,sort_keys=True)); return 0 if not errs else 1

def cmd_log(args):
    c=cfg(args); cur=read_current(c)
    p=Path(args.path) if args.path else Path(cur['log_path']) if cur and cur.get('log_path') else None
    if not p or not p.exists(): print('No run log',file=sys.stderr); return 1
    if not args.follow: print(p.read_text(errors='replace'),end=''); return 0
    with p.open('r',errors='replace') as f:
        f.seek(0,2)
        try:
            while True:
                line=f.readline()
                if line: print(line,end='',flush=True)
                else: time.sleep(.5)
        except KeyboardInterrupt: return 0

def cmd_perf(args):
    c=cfg(args); cur=read_current(c); p=Path(cur['log_path']) if cur and cur.get('log_path') else None
    if not p or not p.exists(): print('No current run log'); return 1
    rx=re.compile(r"CORE V41 APPLY COMMITTED range=(\d+)-(\d+).*?elapsed=([0-9.]+)s")
    rows=[]
    for line in p.read_text(errors='replace').splitlines():
        m=rx.search(line)
        if m: rows.append((int(m.group(1)),int(m.group(2)),float(m.group(3))))
    rows=rows[-args.windows:]
    if not rows: print('No v41 commit samples'); return 0
    blocks=sum(b-a+1 for a,b,_ in rows); sec=sum(x for *_,x in rows); speed=blocks/sec*3600 if sec else 0
    print(f'Windows sampled {len(rows)}'); print(f'Blocks          {blocks}'); print(f'Elapsed         {sec:.1f}s'); print(f'Speed           {speed:.1f} blocks/hour'); return 0

def cmd_audit(args):
    c=cfg(args)
    vr=verify_release(c)
    if vr['status']!='GREEN':
        raise RuntimeError(f"release identity is not GREEN: {vr}")
    audited_hwm=apply_hwm(c)
    if audited_hwm is None or audited_hwm < 0:
        raise RuntimeError(f'cannot resolve APPLY HWM for standalone audit: {audited_hwm}')
    release=c.stage_release_dir/f'stage_release_0_{audited_hwm}.json'
    if release.is_symlink() or not release.is_file() or not Path(str(release)+'.sha256').is_file():
        raise RuntimeError(f'no immutable Stage release bound to APPLY HWM={audited_hwm}: {release}')
    verify_sidecar(release)
    initial=service_state()
    if initial not in {'active','inactive'}:
        raise RuntimeError(f'unsupported initial bitcoind state: {initial}')
    lock=OperatorLock(c.operator_lock,f'audit-{int(time.time())}-{os.getpid()}','audit')
    lock.acquire()
    try:
        engines=active_engines(c)
        if engines:
            raise RuntimeError('active UTXO engine(s) block standalone audit: '+ ' | '.join(f'{pid}:{cmd[:160]}' for pid,cmd in engines[:8]))
        if service_state()!='active':
            core_start(); wait_rpc(c.bitcoin_cli,c.datadir)
        cmd=[
            str(c.python),str(c.auditor),
            '--db',str(c.db),
            '--stage-release',str(release),
            '--source-catalog',str(c.source_catalog),
            '--calculator',str(c.calculator),
            '--bitcoin-cli',str(c.bitcoin_cli),
            '--datadir',str(c.datadir),
            '--lock-root',str(c.lock_root),
            '--output-dir',str(c.v2_base/'audit'),
            '--stop-file',str(c.stop_file),
        ]
        last_path=c.run_dir/'last_run.json'
        try:
            release_target=int(json.loads(release.read_text(encoding='utf-8')).get('end_height',-1))
        except Exception:
            release_target=-1
        if last_path.is_file() and not last_path.is_symlink():
            try:
                last=json.loads(last_path.read_text(encoding='utf-8'))
            except Exception:
                last={}
            contract_raw=str(last.get('run_contract') or '') if isinstance(last,dict) else ''
            if contract_raw and int(last.get('target_height',-2))==release_target:
                contract=Path(contract_raw)
                if contract.is_file() and not contract.is_symlink() and Path(str(contract)+'.sha256').is_file():
                    cmd += ['--run-contract',str(contract)]
        if args.deep_stage_sha:
            cmd.append('--deep-stage-sha')
        return int(subprocess.call(cmd))
    finally:
        try:
            if initial=='inactive' and service_state()!='inactive': core_stop()
            elif initial=='active' and service_state()!='active': core_start(); wait_rpc(c.bitcoin_cli,c.datadir)
        finally:
            lock.release()

def cmd_config(args):
    c=cfg(args)
    payload={}
    for key,value in vars(c).items():
        payload[key]=str(value) if isinstance(value,Path) else value
    print(json.dumps(payload,indent=2,sort_keys=True))
    return 0

def cmd_explain(args):
    print('UTXO Core v2 policy')
    print('  SOURCE+STAGE : build_stage.py; Core stopped + datadir lock for physical source access')
    print('  APPLY        : utxo_pipeline_v41.py; exactly 1 CPU execution thread [LOCKED]')
    print('  AUDIT        : utxo_pipeline_audit_n41.py; independent read-only checks')
    print('  Target       : immutable height/hash after UTC/MTP snapshot')
    print('  Reorg        : fail closed; no automatic destructive rollback')
    print('  Scheduler    : sticky-down after OOM; automatic grow OFF')
    print('  Main command : utxo run --to YYYY-MM-DD')
    return 0

def main(argv=None):
    ap=argparse.ArgumentParser(prog='utxo',description='UTXO Core v2 operator'); ap.add_argument('--config',default='/etc/mybot/utxo.ini'); ap.add_argument('--version',action='version',version=f'utxo-operator {__version__}')
    sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('run'); p.add_argument('--to',required=True); p.add_argument('--confirmations',type=int); p.add_argument('--cores',type=int); p.add_argument('--memory'); p.add_argument('--window',type=int); p.set_defaults(fn=cmd_run)
    p=sp.add_parser('resume'); p.set_defaults(fn=cmd_resume)
    p=sp.add_parser('plan'); p.add_argument('--to',required=True); p.add_argument('--confirmations',type=int); p.set_defaults(fn=cmd_plan)
    p=sp.add_parser('status'); p.set_defaults(fn=cmd_status)
    p=sp.add_parser('date'); p.set_defaults(fn=cmd_date)
    p=sp.add_parser('stop'); p.add_argument('--reason',default='operator request'); p.add_argument('--wait',action='store_true'); p.add_argument('--timeout',type=int,default=3600); p.set_defaults(fn=cmd_stop)
    p=sp.add_parser('doctor'); p.set_defaults(fn=cmd_doctor)
    p=sp.add_parser('verify-release'); p.set_defaults(fn=cmd_verify)
    p=sp.add_parser('log'); p.add_argument('-f','--follow',action='store_true'); p.add_argument('--path'); p.set_defaults(fn=cmd_log)
    p=sp.add_parser('perf'); p.add_argument('--windows',type=int,default=10); p.set_defaults(fn=cmd_perf)
    p=sp.add_parser('audit'); p.add_argument('--deep-stage-sha',action='store_true'); p.set_defaults(fn=cmd_audit)
    p=sp.add_parser('config'); p.set_defaults(fn=cmd_config)
    p=sp.add_parser('explain'); p.set_defaults(fn=cmd_explain)
    args=ap.parse_args(argv)
    try: return int(args.fn(args))
    except Exception as e: print(f'ERROR {type(e).__name__}: {e}',file=sys.stderr); return 1
