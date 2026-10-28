#!/usr/bin/env python3
"""Run a near-RT RIC, KPM monitor, and supplied ns-3 scenario directly on the host."""
from labcore.commands import command as cli_command
from labcore.paths import ROOT
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from simulation.build_live import build_runtime
from scenario.source import read_source, snapshot_source
from simulation.native_runner import write_status
from labcore.ric_address import reserve_address
from labcore.discover_sources import discover


def cache_values(path):
    result={}
    for line in path.read_text().splitlines():
        if line and not line.startswith(('#','//')) and '=' in line and ':' in line.split('=')[0]:
            key,value=line.split('=',1);result[key.split(':')[0]]=value
    return result


def wait_for(predicate,timeout,processes,message):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        for name,proc in processes:
            if proc.poll() is not None:
                raise RuntimeError(f'{name} exited early ({proc.returncode}): inspect logs')
        if predicate():return
        time.sleep(0.2)
    raise TimeoutError(message)


def parse_args(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scenario', type=Path, required=True)
    p.add_argument('--output', type=Path, help='New host result directory')
    p.add_argument('--e2-nodes', type=int, default=5)
    p.add_argument('--duration',type=float,default=10)
    p.add_argument('--ues',type=int,default=12)
    p.add_argument('--seed',type=int,default=7)
    p.add_argument('--run',type=int,default=1)
    p.add_argument('--load-scale',type=float,default=1)
    p.add_argument('--min-speed',type=float,default=1)
    p.add_argument('--max-speed',type=float,default=15)
    p.add_argument('--wall-timeout',type=int,default=1800)
    p.add_argument('--flexric',type=Path,default=None)
    p.add_argument('--ns3',type=Path,default=None)
    p.add_argument('--ai-model', '--shadow-model', dest='shadow_model', type=Path)
    p.add_argument('--evasion-config',type=Path)
    p.add_argument('--apply-ai-control',action='store_true')
    p.add_argument('--ric-ip',default=None)
    p.add_argument('--search-root',type=Path,action='append',default=[])
    args=p.parse_args(argv)
    if args.apply_ai_control and args.shadow_model is None:p.error('AI control requires a model')
    if args.duration<=1.2 or not 3<=args.ues<=120:
        p.error('duration must exceed 1.2 s; ues must be 3..120')
    if args.e2_nodes < 1:
        p.error('--e2-nodes must be positive')
    read_source(args.scenario)
    if args.shadow_model is not None:
        from ai.runtime import RuntimeForecaster
        RuntimeForecaster.load(args.shadow_model)
    return args


def main(argv=None):
    args = parse_args(argv)
    result = args.output.resolve() if args.output else ROOT / 'results' / ('live-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    result.mkdir(parents=True, exist_ok=False)
    raw = result / 'raw'
    raw.mkdir()
    lab = result / 'work'
    lab.mkdir()
    (lab / 'controller.pid').write_text(str(os.getpid()))
    selected = snapshot_source(args.scenario, result)
    status={'status':'preflight','live_ric_verified':False,'configuration':vars(args).copy(),
            'attack_present':False,'ai_controller_installed':False,
            'non_rt_ric_installed':False, 'scenario': selected.metadata()}
    status['configuration']={k:str(v) if isinstance(v,Path) else [str(x) for x in v] if isinstance(v,list) else v for k,v in status['configuration'].items()}
    def save(): write_status(result, status)
    save()
    procs=[];streams=[];address_lease=None
    previous_handler = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit('Live supervisor terminated'))
        address_lease=reserve_address(lab.name,args.ric_ip)
        ric_ip=address_lease.address
        status['ric_endpoint']={'address':ric_ip,'e2_port':36421,'xapp_port':36422};save()
        print('Reserved isolated RIC endpoint:',ric_ip,flush=True)
        print('Discovering compatible FlexRIC and ns-3 source trees...',flush=True)
        fr=discover('flexric', args.flexric, args.search_root)
        ns=discover('ns3', args.ns3, args.search_root)
        status['resolved_sources']={'flexric':str(fr),'ns3':str(ns)}
        save()
        print('FlexRIC:',fr,'ns-3:',ns,flush=True)
        cache=fr/'build/CMakeCache.txt'
        if not cache.exists():raise RuntimeError(f'Missing FlexRIC build cache: {cache}; pass --flexric PATH')
        values=cache_values(cache)
        if values.get('E2AP_VERSION')!='E2AP_V1' or values.get('KPM_VERSION')!='KPM_V3_00':
            raise RuntimeError('This experiment requires FlexRIC E2AP_V1 + KPM_V3_00; refusing version mismatch')
        if not (ns/'contrib/oran-interface/model/oran-interface.cc').exists():
            raise RuntimeError(f'Compatible ns-O-RAN source not found: {ns}')
        if 'ActionDefinition-Format4' not in (ns/'contrib/oran-interface/model/oran-interface.cc').read_text():
            raise RuntimeError('Selected ns-3 tree does not have the expected newer KPM integration')
        artifacts = build_runtime(lab, raw, fr, ns, selected.path)
        status['kpm_sender_override']=str(artifacts.override);save()
        config=lab/'flexric.conf'
        config.write_text('[NEAR-RIC]\nNEAR_RIC_IP = '+ric_ip+'\n\n[XAPP]\nDB_DIR = '+str(raw)+'/\n')
        def launch(name,cmd,env=None):
            log=(raw/(name+'.log')).open('w');streams.append(log)
            proc=subprocess.Popen(['stdbuf','-oL','-eL',*cmd],cwd=raw,stdout=log,
                                  stderr=subprocess.STDOUT,start_new_session=True,env=env)
            procs.append((name,proc));return proc
        common=['-c',str(config),'-p',str(artifacts.plugins)+'/' ]
        ricproc=launch('ric',[str(artifacts.ric),*common])
        time.sleep(1)
        if ricproc.poll() is not None:raise RuntimeError('RIC did not start; inspect ric.log')
        print('Starting E2 agents; waiting for', args.e2_nodes, 'E2 nodes...', flush=True)
        scenario=[str(artifacts.binary),'--liveRic=true','--simTime='+str(args.duration),
                  '--ueCount='+str(args.ues),'--warmup=1','--loadScale='+str(args.load_scale),
                  '--minSpeed='+str(args.min_speed),'--maxSpeed='+str(args.max_speed),
                  '--e2TermIp='+ric_ip,'--RngSeed='+str(args.seed),'--RngRun='+str(args.run),
                  '--indicationPeriodicity=0.1','--enableTraces=true','--reducedPmValues=false']
        if args.apply_ai_control:scenario+=['--applyAiControl=true']
        sim_env=os.environ.copy()
        sim_env['LD_PRELOAD']=str(artifacts.override)
        simproc=launch('simulation',scenario,sim_env)
        riclog=raw/'ric.log'
        wait_for(lambda:len(set(re.findall(r'E2 SETUP-REQUEST rx[^\n]*Node ID (\d+) RAN type (\S+)', riclog.read_text(errors='replace')))) >= args.e2_nodes,
                 50,procs,'Expected E2 nodes did not register')
        print('Expected E2 nodes registered. Starting KPM monitoring xApp...',flush=True)
        xproc=launch('xapp',[str(artifacts.xapp),*common,'-d',str(raw)+'/', '-n','kpm.sqlite'])
        xlog=raw/'xapp.log'
        wait_for(lambda:any(int(n) >= args.e2_nodes for n in re.findall(r'Connected E2 nodes = (\d+)', xlog.read_text(errors='replace'))),
                 30,procs,'xApp did not discover all E2 nodes')
        shadowproc=None
        shadow_stop=raw/'ai_shadow.stop'
        if args.shadow_model:
            shadowproc=launch('ai-shadow',[*cli_command('shadow_stream', ROOT),
                '--model',str(args.shadow_model),'--raw-dir',str(raw),'--output',str(result/'csv'),
                '--run-id',result.name,'--ues',str(args.ues),
                '--stop-file',str(shadow_stop)]+(['--apply-control'] if args.apply_ai_control else [])+(['--evasion-config',str(args.evasion_config)] if args.evasion_config else []))
            status['ai_shadow_enabled']=True;status['ai_control_enabled']=args.apply_ai_control
            status['ai_controller_installed']=args.apply_ai_control
            status['ai_controller_kind']='external file bridge' if args.apply_ai_control else 'shadow only'
            status['e2_rc_control_used']=False
            if args.apply_ai_control:
                status['control_network_mode']={'handover':'NoAuto','outage_threshold_db':-1000}
            status['network_actions_applied']=0;save()
        (raw/'ric.ready').touch()
        print('RIC/xApp readiness passed; running mixed traffic...',flush=True)
        end=time.monotonic()+args.wall_timeout
        while simproc.poll() is None:
            if ricproc.poll() is not None or xproc.poll() is not None:
                raise RuntimeError(f'Process exited: RIC={ricproc.poll()}, xApp={xproc.poll()}, simulation={simproc.poll()}')
            if shadowproc is not None and shadowproc.poll() is not None:
                raise RuntimeError(f'AI shadow process exited early: {shadowproc.returncode}')
            if time.monotonic()>end:raise TimeoutError('Simulation wall timeout exceeded')
            time.sleep(0.5)
        if simproc.returncode!=0:raise RuntimeError(f'ns-3 exited with {simproc.returncode}')
        if shadowproc is not None:
            shadow_stop.touch()
            if shadowproc.wait(timeout=15)!=0:raise RuntimeError('AI shadow process failed')
            ai_status=json.loads((result/'csv/ai_shadow_status.json').read_text())
            if ai_status.get('decision_count',0)<=0:raise RuntimeError('No AI shadow decisions')
            status['ai_shadow_status']=ai_status
            status['network_actions_applied']=ai_status['network_actions_applied'];save()
        indications=xlog.read_text(errors='replace').count('KPM ind_msg latency')
        if indications==0:raise RuntimeError('No decoded KPM indications: refusing to report successful RIC integration')
        sim_text=(raw/'simulation.log').read_text(errors='replace')
        xapp_text=xlog.read_text(errors='replace')
        if '[KPM FIX] patched message constructor' not in sim_text:
            raise RuntimeError('KPM sender override was not executed; refusing to accept stale sender layout')
        if '[KPM VALID]' not in xapp_text:
            raise RuntimeError('No non-placeholder numeric KPM measurement received')
        status['numeric_kpm_measurement_count']=xapp_text.count('[KPM VALID]')
        status['placeholder_kpm_count']=xapp_text.count('[KPM PLACEHOLDER]')
        status['missing_kpm_count']=xapp_text.count('[KPM MISSING]')
        status.update(status='e2_verified',live_ric_verified=True,simulation_exit_code=0,kpm_indication_count=indications,
                      e2_setup_request_count=riclog.read_text(errors='replace').count('E2 SETUP-REQUEST rx'))
        save()
        subprocess.run([*cli_command('export_dataset', ROOT),str(result),'--duration',str(args.duration)],check=True)
        status['status']='complete';save()
        if args.apply_ai_control:
            from checks.check_control import verify
            control_result=verify(result,require_live=True)
            if not control_result['infrastructure_valid']:
                raise RuntimeError('Control evidence is malformed or infrastructure-invalid; inspect control_verification.json')
            status['ai_control_infrastructure_valid']=True
            status['control_outcomes']=control_result['control_outcomes']
            # A later connected-target event is a timestamped outcome, not whole-window application.
            status['ai_control_verified']=bool(control_result['submitted']) and control_result['confirmed']==control_result['submitted']
            save()
        print('E2 setup + decoded KPM indications verified; CSV exported.',flush=True)
    except BaseException as exc:
        status.update(status='failed',error=str(exc));save()
        status['process_exit_codes_before_cleanup']={name:proc.poll() for name,proc in procs};save()
        for name in ['xapp','ric','simulation','ai-shadow']:
            path=raw/(name+'.log')
            if path.exists():
                print('Runtime log:',path,flush=True)
                print('\n'.join(path.read_text(errors='replace').splitlines()[-20:]),flush=True)
        logs=sorted(raw.glob('*build.log'),key=lambda path:path.stat().st_mtime)
        logs+=sorted(raw.glob('*configure.log'),key=lambda path:path.stat().st_mtime)
        if logs:
            latest=max(logs,key=lambda path:path.stat().st_mtime)
            print('Diagnostic log:',latest,flush=True)
            print('\n'.join(latest.read_text(errors='replace').splitlines()[-25:]),flush=True)
        raise
    finally:
        for _,proc in reversed(procs):
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        for stream in streams:stream.close()
        if address_lease is not None:address_lease.close()
        signal.signal(signal.SIGTERM, previous_handler)

if __name__=='__main__':main()
