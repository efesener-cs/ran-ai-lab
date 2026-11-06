"""Immutable, resumable four-core DEVELOPMENT pilots across IP and RF tracks.

This does not declare a scientifically validated release or expose blind test
seeds. Failed attempts remain in place. No shared SDK rebuild or uploader.
"""
import argparse
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time

from labcore.paths import ROOT
from labcore.provenance import source_hashes
from labcore.runtime_bundle import copy_runtime
from scenario.source import build_native

STORE=Path('/mnt/onetb/ran-ai-lab')


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def save(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');temporary.replace(path)


def cores(count):
    selected=[];seen=set()
    for cpu in sorted(os.sched_getaffinity(0)):
        p=Path('/sys/devices/system/cpu')/('cpu'+str(cpu))/'topology'
        pair=((p/'physical_package_id').read_text(),(p/'core_id').read_text())
        if pair not in seen:seen.add(pair);selected.append(cpu)
        if len(selected)==count:return selected
    raise ValueError('Insufficient distinct physical cores')


def recipes(development_seeds=(),expanded_only=False):
    jobs=[]
    # Identical development workloads at three concurrency levels. No blind test.
    modes=('none','udp_flood','tcp_connection_churn','udp_port_scan','icmp_flood','mixed')
    for workers in (1,2,4):
        for index,mode in enumerate(modes):
            jobs.append(dict(id=f'ip-w{workers}-{mode}',kind='ip',phase='pilot-'+str(workers),
                 capacity=workers,seed=910101,attack=mode,environment='id',regime='low',sim_time=40,warmup=5))
    for task,index in (('sensing',1),('amc',2),('channel',3)):
        for repeat in range(2):
            jobs.append(dict(id=f'rf-{task}-development-{repeat}',kind='rf',phase='rf-development',capacity=4,
                             task=task,seed=920000+index*100+repeat,samples=480,split='development'))
    if expanded_only:jobs=[]
    for index,seed in enumerate(development_seeds):
        for mode in ('none','udp_flood','udp_ddos','pulsed_udp','udp_port_scan','tcp_connection_churn','icmp_flood','mixed'):
            jobs.append(dict(id=f'ip-dev-{seed}-{mode}',kind='ip',phase='ip-expanded-development',capacity=4,
                seed=seed,attack=mode,environment='ood_network' if index==len(development_seeds)-1 else 'id',
                regime=('low','overlap','high','overlap','low')[index%5],sim_time=70,warmup=10))
    for j in jobs:j.update(state='pending',attempts=[])
    return jobs


def environment(root):
    return dict(os.environ,OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',
                NUMEXPR_NUM_THREADS='1',VECLIB_MAXIMUM_THREADS='1',PYTHONUNBUFFERED='1',
                PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root/'runtime'))


def prepare(args):
    base=args.output_root.resolve()
    if not base.is_relative_to(STORE.resolve()):raise ValueError('New bulk outputs must be under '+str(STORE))
    base.mkdir(parents=True,exist_ok=True)
    root=base/(('collection-' if args.collection else 'development-')+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));root.mkdir()
    copy_runtime(ROOT,root/'runtime');(root/'inputs').mkdir()
    scenario=Path(args.scenario).resolve(strict=True);shutil.copyfile(scenario,root/'inputs/ip-workload.cc')
    sdk=Path(args.ns3).resolve(strict=True)
    binary=build_native(root/'inputs/ip-workload.cc',ns3=sdk,build_root=STORE/'build-cache/research-campaign')
    if args.collection:
        from simulation.research_plan import collection_recipes
        jobs,partition=collection_recipes()
        for name in ('rf-ai-frames.cc','training-data-attacks.cc'):shutil.copyfile(ROOT/'examples/scenarios'/name,root/'inputs'/name)
        (root/'protocol').mkdir()
        for name in ('DATASET_RESEARCH_PROTOCOL.md','ATTACK_COVERAGE.md','OFFLINE_CAMPAIGN.md','RF_RESEARCH.md','IP_RESEARCH.md','RAN_RESEARCH_READINESS.md'):
            shutil.copyfile(ROOT/'docs'/name,root/'protocol'/name)
    else:jobs,partition=recipes(args.development_seeds,args.expanded_only),{}
    plan=dict(format='research-development-v1',stage='development',scientific_status='unvalidated-development',
              state='prepared',created_utc=datetime.now(timezone.utc).isoformat(),workers=args.workers,cpus=cores(args.workers),
              runtime_sha256=source_hashes(root/'runtime'),scenario_sha256=sha(root/'inputs/ip-workload.cc'),
              binary=str(binary),binary_sha256=sha(binary),sdk=str(sdk),
              sdk_libraries={p.name:sha(p) for p in (sdk/'build/lib').glob('*.so')},
              minimum_free_gib=50,minimum_available_ram_gib=3,maximum_aggregate_rss_gib=6,jobs=jobs,sessions=[],
              time_limit_removed_by_user=True,publication_approved=False,
              scope='Synthetic wired transport/session workloads and separate analytical RF tasks; no RIC/OTA acceptance',source_git_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
    if args.collection:
        plan.update(stage='research_collection',scientific_status='preregistered-synthetic-not-externally-validated',seed_partition=partition,output_root=str(root),maximum_output_gib=100,primary_prediction_target='categorical/multilabel attack family',input_sha256={p.name:sha(p) for p in (root/'inputs').iterdir()},protocol_sha256={p.name:sha(p) for p in (root/'protocol').iterdir()})
    save(root/'campaign.json',plan)
    print('Campaign',root,flush=True)
    return root


def verify(root,plan):
    if source_hashes(root/'runtime')!=plan['runtime_sha256'] or sha(root/'inputs/ip-workload.cc')!=plan['scenario_sha256']:
        raise ValueError('Frozen research source changed')
    for name,value in plan.get('input_sha256',{}).items():
        if sha(root/'inputs'/name)!=value:raise ValueError('Frozen reference input changed')
    for name,value in plan.get('protocol_sha256',{}).items():
        if sha(root/'protocol'/name)!=value:raise ValueError('Frozen protocol changed')
    if sha(plan['binary'])!=plan['binary_sha256']:raise ValueError('Frozen binary changed')
    for name,value in plan['sdk_libraries'].items():
        if sha(Path(plan['sdk'])/'build/lib'/name)!=value:raise ValueError('SDK library changed')


def work(root,job_id,attempt):
    root=root.resolve();plan=json.loads((root/'campaign.json').read_text());verify(root,plan)
    job=next(j for j in plan['jobs'] if j['id']==job_id);attempt=attempt.resolve()
    if not attempt.is_relative_to(root/'jobs'/job_id):raise ValueError('Attempt path escapes its job')
    result=attempt/'result';result.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if job['kind']=='ip':
        command=[plan['binary'],'--simTime='+str(job['sim_time']),'--warmup='+str(job['warmup']),
                 '--RngSeed='+str(job['seed']),'--attack='+job['attack'],'--environment='+job['environment'],'--regime='+job['regime'],'--pcap='+str(job.get('pcap_audit',False)).lower()]
    elif job['kind']=='rf':
        command=[sys.executable,'-m','datasets.generate_rf_research','--task',job['task'],'--seed',str(job['seed']),
                 '--samples',str(job['samples']),'--split',job['split'],'--output',str(result),*job.get('generator_args',[])]
        result.rmdir() # RF generator atomically refuses existing output directories.
    elif job['kind']=='rf_attack':
        result.rmdir()
        command=[sys.executable,str(root/'runtime/lab.py'),'run_rf','--scenario',str(root/'inputs/rf-ai-frames.cc'),'--output',str(result),'--rf-profile',job['profile'],'--snr-db',str(job['snr_db']),'--train-samples','3000','--eval-samples','1000','--length','128','--epochs','80','--steps','30','--seeds',*map(str,job['seeds']),'--psr-db','-20','-10','-6']
    elif job['kind']=='training_attack':
        parent=next(j for j in plan['jobs'] if j['id']==job['parent'])
        if parent['state']!='complete':raise ValueError('Verified parent must complete first')
        result.rmdir()
        command=[sys.executable,str(root/'runtime/lab.py'),'run_training_attacks','--rf-run',str(root/parent['attempts'][-1]['path']/'result'),'--scenario',str(root/'inputs/training-data-attacks.cc'),'--output',str(result),'--epochs','80','--attack-seed',str(job['attack_seed'])]
    else:raise ValueError('Unknown research job kind')
    started=time.monotonic()
    with (attempt/'execution.log').open('w') as log:
        subprocess.run(command,cwd=result if job['kind']=='ip' else attempt,env=environment(root),stdout=log,stderr=subprocess.STDOUT,check=True)
    usage=resource.getrusage(resource.RUSAGE_CHILDREN)
    save(attempt/'resources.json',dict(wall_seconds=time.monotonic()-started,child_peak_rss_kib=usage.ru_maxrss,child_user_seconds=usage.ru_utime,child_system_seconds=usage.ru_stime))
    if job['kind']=='ip':
        from checks.check_ip_research import check
        evidence=check(result)
        if job.get('pcap_audit'):
            from checks.audit_ip_pcap import audit
            evidence['independent_pcap']=audit(result)
    elif job['kind']=='rf':
        from checks.check_rf_research import check
        evidence=check(result)
    elif job['kind']=='rf_attack':
        from checks.check_rf import verify as check
        evidence=check(result)
        from datasets.export_rf_detection import export
        export(result,attempt/'attack-family-data',fraction=.2,modes=('fgsm','pgd'),psr_db=-10.,steps=30,seed=job['seeds'][0]+5000000)
        save(attempt/'attack-family-data/prediction-contract.json',dict(primary_target='attack_type',classes=['none','fgsm','pgd'],binary_label_is_secondary=True,victim_task_is_not_attack_type=True,scope='Receiver-input reference only; known victim models/methods; not unseen-model or OTA proof'))
    else:
        from checks.check_training_attacks import verify as check
        evidence=check(result)
    save(attempt/'verification.json',evidence)
    files={p.relative_to(attempt).as_posix():sha(p) for p in sorted(attempt.rglob('*')) if p.is_file() and p not in (attempt/'worker.log',attempt/'receipt.json')}
    save(attempt/'receipt.json',dict(format='research-receipt-v2',files=files,job=job_id,excluded_live_log='worker.log'))
    print('CHECKED',job_id,flush=True)


def recover_owned(root,job):
    if not job['attempts']:return
    pid=job['attempts'][-1].get('pid')
    if not pid:return
    try:
        cmd=Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')
        if str(root).encode() in cmd and job['id'].encode() in cmd and b'--job' in cmd and os.getpgid(pid)==pid:
            os.killpg(pid,signal.SIGTERM)
            until=time.monotonic()+3
            while Path('/proc',str(pid)).exists() and time.monotonic()<until:time.sleep(.1)
            if Path('/proc',str(pid)).exists():os.killpg(pid,signal.SIGKILL)
    except (FileNotFoundError,ProcessLookupError):pass


def verify_receipt(root,job):
    attempt=root/job['attempts'][-1]['path'];receipt=attempt/'receipt.json'
    if sha(receipt)!=job['attempts'][-1]['receipt_sha256']:raise ValueError('Receipt changed')
    for name,value in json.loads(receipt.read_text())['files'].items():
        path=(attempt/name).resolve()
        if not path.is_relative_to(attempt):raise ValueError('Attempt output escapes root')
        if sha(path)!=value:
            # The first development receipt accidentally covered stdout before its
            # final CHECKED line. Accept only this exact known transition; every
            # data file and the original receipt hash must still match.
            legacy=json.loads(receipt.read_text())
            if (name=='worker.log' and 'format' not in legacy and value==hashlib.sha256(b'').hexdigest()
                    and path.read_bytes()==('CHECKED '+job['id']+'\n').encode()):continue
            raise ValueError('Attempt output changed')


def resources_ok(plan):
    values={line.split(':')[0]:line.split(':')[1].strip() for line in Path('/proc/meminfo').read_text().splitlines()}
    if int(values['MemAvailable'].split()[0])*1024<plan['minimum_available_ram_gib']*1024**3:return 'available_ram'
    if shutil.disk_usage(STORE).free<plan['minimum_free_gib']*1024**3:return 'free_disk'
    if plan.get('maximum_output_gib'):
        if time.time()-plan.get('last_growth_check_epoch',0)>30:
            plan['measured_output_bytes']=sum(p.stat().st_size for p in Path(plan['output_root']).rglob('*') if p.is_file() and not p.is_symlink())
            plan['last_growth_check_epoch']=time.time()
        if plan.get('measured_output_bytes',0)>plan['maximum_output_gib']*1024**3:return 'campaign_growth'
    return None


def agreement(root,plan):
    report={}
    for mode in ('none','udp_flood','tcp_connection_churn','udp_port_scan','icmp_flood','mixed'):
        hashes=[]
        for n in (1,2,4):
            job=next(j for j in plan['jobs'] if j['id']==f'ip-w{n}-{mode}')
            if job['state']!='complete':raise ValueError('Pilot incomplete')
            hashes.append(sha(root/job['attempts'][-1]['path']/'result/ip_windows.csv'))
        if len(set(hashes))!=1:raise ValueError('Concurrency changed simulator output: '+mode)
        report[mode]=hashes[0]
    save(root/'concurrency-agreement.json',dict(verified=True,hashes=report,scope='Development determinism, not statistical quality'))



def process_rss(pid,seen=None):
    seen=set() if seen is None else seen
    if pid in seen:return 0
    seen.add(pid)
    try:
        status=Path('/proc',str(pid),'status').read_text()
        own=next((int(line.split()[1])*1024 for line in status.splitlines() if line.startswith('VmRSS:')),0)
        children=Path('/proc',str(pid),'task',str(pid),'children').read_text().split()
        return own+sum(process_rss(int(child),seen) for child in children)
    except (FileNotFoundError,ProcessLookupError):return 0


def run(root):
    plan=json.loads((root/'campaign.json').read_text());verify(root,plan)
    with (root/'.controller.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise ValueError('Controller already running') from e
        for job in plan['jobs']:
            if job['state']=='complete':verify_receipt(root,job)
            elif job['state']=='running':
                recover_owned(root,job);job['attempts'][-1]['state']='interrupted';job['state']='pending'
        os.sched_setaffinity(0,set(plan['cpus']))
        session=dict(started_utc=datetime.now(timezone.utc).isoformat(),pid=os.getpid(),state='running');plan['sessions'].append(session)
        active={};attempted=set();plan['state']='running';save(root/'campaign.json',plan)
        old=signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
        stop='interrupted'
        try:
            while True:
                for cpu,item in list(active.items()):
                    code=item['process'].poll()
                    if code is None:continue
                    item['log'].close();job=item['job'];a=job['attempts'][-1]
                    a.update(exit_code=code,elapsed_seconds=time.monotonic()-item['start'])
                    receipt=root/a['path']/'receipt.json'
                    if code==0 and receipt.is_file():
                        job['state']=a['state']='complete';a['receipt_sha256']=sha(receipt)
                    else:job['state']=a['state']='failed'
                    print(job['state'].upper(),job['id'],flush=True);del active[cpu];save(root/'campaign.json',plan)
                rss=sum(process_rss(item['process'].pid) for item in active.values())
                session['peak_aggregate_rss_bytes']=max(session.get('peak_aggregate_rss_bytes',0),rss)
                reason='aggregate_rss' if rss>plan.get('maximum_aggregate_rss_gib',6)*1024**3 else resources_ok(plan)
                if reason:plan['stop_reason']=reason;stop='resource_limited';break
                pending=[j for j in plan['jobs'] if j['state']!='complete' and j['id'] not in attempted]
                if not pending and not active:
                    stop='complete' if all(j['state']=='complete' for j in plan['jobs']) else 'incomplete';break
                phases=('pilot-1','pilot-2','pilot-4','rf-development','ip-expanded-development','collection')
                unfinished=[j for j in plan['jobs'] if j['state']!='complete']
                phase=next((p for p in phases if any(j['phase']==p for j in unfinished)),None)
                if phase and any(j['state']=='failed' and j['phase']==phase and j['id'] in attempted for j in plan['jobs']) and not active:
                    stop='incomplete';break
                complete_ids={j['id'] for j in plan['jobs'] if j['state']=='complete'}
                candidates=[j for j in pending if j['phase']==phase and set(j.get('depends',[])).issubset(complete_ids)]
                if not candidates and not active and pending:stop='dependency_blocked';break
                capacity=min(plan['workers'],candidates[0]['capacity']) if candidates else plan['workers']
                for cpu in plan['cpus']:
                    if cpu in active or len(active)>=capacity or not candidates:continue
                    verify(root,plan);job=candidates.pop(0);attempted.add(job['id'])
                    dest=root/'jobs'/job['id']/('attempt-'+str(len(job['attempts'])+1));dest.mkdir(parents=True)
                    a=dict(path=dest.relative_to(root).as_posix(),cpu=cpu,state='running',started_utc=datetime.now(timezone.utc).isoformat());job['attempts'].append(a);job['state']='running';save(root/'campaign.json',plan)
                    command=['taskset','-c',str(cpu),sys.executable,str(root/'runtime/lab.py'),'run_research_campaign','--resume',str(root),'--job',job['id'],'--attempt',str(dest)]
                    log=(dest/'worker.log').open('w');proc=subprocess.Popen(command,env=environment(root),cwd=dest,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);a['pid']=proc.pid
                    active[cpu]=dict(process=proc,log=log,job=job,start=time.monotonic());save(root/'campaign.json',plan);print('RUN',job['id'],'CPU',cpu,flush=True)
                session['elapsed_seconds']=time.time()-datetime.fromisoformat(session['started_utc']).timestamp();save(root/'campaign.json',plan);time.sleep(.5)
            if stop=='complete' and any(j['phase']=='pilot-1' for j in plan['jobs']):agreement(root,plan)
        except KeyboardInterrupt:stop='interrupted'
        except BaseException:
            stop='failed';raise
        finally:
            for item in active.values():
                try:os.killpg(item['process'].pid,signal.SIGTERM)
                except ProcessLookupError:pass
            until=time.monotonic()+5
            while any(i['process'].poll() is None for i in active.values()) and time.monotonic()<until:time.sleep(.1)
            for item in active.values():
                if item['process'].poll() is None:
                    try:os.killpg(item['process'].pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                item['log'].close();item['job']['state']=item['job']['attempts'][-1]['state']=stop
            session['state']=plan['state']=stop;session['ended_utc']=datetime.now(timezone.utc).isoformat();save(root/'campaign.json',plan);signal.signal(signal.SIGTERM,old)
        return 0 if stop=='complete' else 2


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resume',type=Path);p.add_argument('--scenario',type=Path);p.add_argument('--ns3',type=Path)
    p.add_argument('--output-root',type=Path,default=STORE/'results/research-campaigns');p.add_argument('--workers',type=int,choices=(1,2,4),default=4);p.add_argument('--prepare-only',action='store_true');p.add_argument('--job');p.add_argument('--attempt',type=Path);p.add_argument('--development-seeds',nargs='*',type=int,default=[]);p.add_argument('--expanded-only',action='store_true');p.add_argument('--collection',action='store_true')
    args=p.parse_args(argv)
    if len(set(args.development_seeds))!=len(args.development_seeds) or any(s<=0 or s>2147483647 for s in args.development_seeds):p.error('Distinct positive development seeds required')
    if args.expanded_only and not args.development_seeds:p.error('--expanded-only needs development seeds')
    if args.resume:
        root=args.resume.resolve()
        if Path(__file__).resolve()!=root/'runtime/simulation/run_research_campaign.py':
            cmd=[sys.executable,str(root/'runtime/lab.py'),'run_research_campaign','--resume',str(root)]
            if args.job:cmd+=['--job',args.job,'--attempt',str(args.attempt)]
            if args.prepare_only:cmd+=['--prepare-only']
            os.execve(sys.executable,cmd,environment(root))
    else:
        if not args.scenario or not args.ns3:p.error('Explicit --scenario and --ns3 are required for preparation')
        root=prepare(args)
    if args.job:
        if not args.attempt:p.error('--attempt required with --job')
        work(root,args.job,args.attempt);return 0
    if args.prepare_only:return 0
    return run(root)


if __name__=='__main__':raise SystemExit(main())
