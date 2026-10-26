#!/usr/bin/env python3
"""Run a real near-RT RIC + KPM monitoring xApp + ns-3 E2 agents in one container."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import socket
import subprocess
import sys
import time
from kpm_fixes import sender_override, patch_monitor
from ric_address import reserve_address
from discover_sources import discover
from portable_build import configure_flexric, relocate_headers, select_compilers, shared_library_args


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


def main():
    p=argparse.ArgumentParser()
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
    p.add_argument('--shadow-model',type=Path)
    p.add_argument('--evasion-config',type=Path)
    p.add_argument('--apply-ai-control',action='store_true')
    p.add_argument('--ric-ip',default=None)
    p.add_argument('--search-root',type=Path,action='append',default=[])
    args=p.parse_args()
    if args.apply_ai_control and args.shadow_model is None:p.error('AI control requires a model')
    if args.duration<=1.2 or not 3<=args.ues<=120:
        p.error('duration must exceed 1.2 s; ues must be 3..120')
    lab=Path(__file__).resolve().parent
    (lab/'controller.pid').write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit('Controller terminated'))
    result=lab/'result';raw=result/'raw';raw.mkdir(parents=True,exist_ok=True)
    status={'status':'preflight','live_ric_verified':False,'configuration':vars(args).copy(),
            'attack_present':False,'ai_controller_installed':False,
            'non_rt_ric_installed':False}
    status['configuration']={k:str(v) if isinstance(v,Path) else [str(x) for x in v] if isinstance(v,list) else v for k,v in status['configuration'].items()}
    def save(): (result/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
    save()
    procs=[];streams=[];address_lease=None
    try:
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
        print('Configuring a fresh, isolated FlexRIC build...',flush=True)
        with (raw/'flexric-configure.log').open('w') as log:
            frbuild=configure_flexric(fr, lab/'flexric-build', log)
        print('Building FlexRIC near-RT RIC and KPM monitor...',flush=True)
        with (raw/'flexric-build.log').open('w') as log:
            subprocess.run(['cmake','--build',str(frbuild.parent),'--target','nearRT-RIC','xapp_kpm_moni','kpm_sm','rc_sm','-j','2'],
                           check=True,stdout=log,stderr=subprocess.STDOUT)
        ric=frbuild/'examples/ric/nearRT-RIC'
        monitor_dir=fr/'examples/xApp/c/monitor'
        monitor_build=frbuild/'examples/xApp/c/monitor'
        # Compile a run-local 100ms variant; do not edit the upstream monitor.
        monitor_source=(monitor_dir/'xapp_kpm_moni.c').read_text()
        monitor_source=patch_monitor(monitor_source)
        monitor_source=monitor_source.replace('period_ms = 1000;', 'period_ms = 100;')
        monitor_source=re.sub(r'#include "([^"\n]+)"',
            lambda m: '#include "'+str((monitor_dir/m.group(1)).resolve())+'"',monitor_source)
        custom=lab/'kpm-monitor.c';custom.write_text(monitor_source)
        flags_text=(monitor_build/'CMakeFiles/xapp_kpm_moni.dir/flags.make').read_text()
        flags=[]
        for key in ['C_DEFINES','C_INCLUDES','C_FLAGS']:
            match=re.search('^'+key+r' = (.*)$',flags_text,re.M)
            if match:flags+=shlex.split(match.group(1))
        link=shlex.split((monitor_build/'CMakeFiles/xapp_kpm_moni.dir/link.txt').read_text())
        obj=lab/'kpm-monitor.o';xapp=lab/'kpm-monitor'
        with (raw/'xapp-build.log').open('w') as log:
            subprocess.run([link[0],*flags,'-c',str(custom),'-o',str(obj)],
                cwd=monitor_build,check=True,stdout=log,stderr=subprocess.STDOUT)
            link[link.index('-o')+1]=str(xapp)
            original='CMakeFiles/xapp_kpm_moni.dir/xapp_kpm_moni.c.o'
            if original not in link:raise RuntimeError('Unexpected xApp linker layout')
            link[link.index(original)]=str(obj)
            subprocess.run(link,cwd=monitor_build,check=True,stdout=log,stderr=subprocess.STDOUT)
        # Consolidate plugin libraries in a run-local directory, no system installation.
        plugins=lab/'plugins';plugins.mkdir(exist_ok=True)
        for lib in (frbuild/'src/sm').rglob('*.so'):
            dest=plugins/lib.name
            if dest.exists() or dest.is_symlink():dest.unlink()
            dest.symlink_to(lib)
        if not (plugins/'libkpm_sm.so').exists():raise RuntimeError('KPM plugin was not built')
        print('Compiling mixed-traffic ns-3 scenario against KPM v3 tree...',flush=True)
        binary=lab/'ran-ai-live'
        libs=sorted((ns/'build/lib').glob('*.so'))
        if not libs:raise RuntimeError('No ns-3 shared libraries found')
        relocate_headers(ns,lab/'ns3-headers/ns3')
        _,cxx=select_compilers()
        cmd=[cxx,'-std=c++20','-O1','-DNS3_LOG_ENABLE','-DNS3_ASSERT_ENABLE',
             '-I'+str(lab/'ns3-headers'),'-I/usr/local/include/e2sim',str(lab/'ran-ai-scenario.cc'),
             '-o',str(binary),'-Wl,-rpath,'+str(ns/'build/lib')]
        cmd += shared_library_args(libs)
        with (raw/'ns3-build.log').open('w') as log:
            subprocess.run(cmd,check=True,stdout=log,stderr=subprocess.STDOUT)
        # Run-local interposition library; upstream ns-3 sources and binaries stay intact.
        patched=lab/'kpm-indication-fixed.cc'
        patched.write_text(sender_override((ns/'contrib/oran-interface/model/kpm-indication.cc').read_text()))
        override=lab/'libkpm_indication_fixed.so'
        override_cmd=[cxx,'-std=c++20','-O1','-fPIC','-shared','-DNS3_LOG_ENABLE','-DNS3_ASSERT_ENABLE',
                      '-I'+str(lab/'ns3-headers'),'-I/usr/local/include/e2sim',str(patched),
                      '-o',str(override),'-Wl,--no-undefined','-Wl,-rpath,'+str(ns/'build/lib')]
        override_cmd+=shared_library_args(libs)
        with (raw/'kpm-fix-build.log').open('w') as log:
            subprocess.run(override_cmd,check=True,stdout=log,stderr=subprocess.STDOUT)
        status['kpm_sender_override']=str(override);save()
        config=lab/'flexric.conf'
        config.write_text('[NEAR-RIC]\nNEAR_RIC_IP = '+ric_ip+'\n\n[XAPP]\nDB_DIR = '+str(raw)+'/\n')
        def launch(name,cmd,env=None):
            log=(raw/(name+'.log')).open('w');streams.append(log)
            proc=subprocess.Popen(['stdbuf','-oL','-eL',*cmd],cwd=raw,stdout=log,
                                  stderr=subprocess.STDOUT,start_new_session=True,env=env)
            procs.append((name,proc));return proc
        common=['-c',str(config),'-p',str(plugins)+'/' ]
        ricproc=launch('ric',[str(ric),*common])
        time.sleep(1)
        if ricproc.poll() is not None:raise RuntimeError('RIC did not start; inspect ric.log')
        print('Starting E2 agents; waiting for five E2 setup requests...',flush=True)
        scenario=[str(binary),'--liveRic=true','--simTime='+str(args.duration),
                  '--ueCount='+str(args.ues),'--warmup=1','--loadScale='+str(args.load_scale),
                  '--minSpeed='+str(args.min_speed),'--maxSpeed='+str(args.max_speed),
                  '--e2TermIp='+ric_ip,'--RngSeed='+str(args.seed),'--RngRun='+str(args.run),
                  '--indicationPeriodicity=0.1','--enableTraces=true','--reducedPmValues=false']
        if args.apply_ai_control:scenario+=['--applyAiControl=true']
        sim_env=os.environ.copy()
        sim_env['LD_PRELOAD']=str(override)
        simproc=launch('simulation',scenario,sim_env)
        riclog=raw/'ric.log'
        wait_for(lambda:riclog.read_text(errors='replace').count('E2 SETUP-REQUEST rx')>=5,
                 50,procs,'Five E2 nodes did not register')
        print('Five E2 nodes registered. Starting KPM monitoring xApp...',flush=True)
        xproc=launch('xapp',[str(xapp),*common,'-d',str(raw)+'/', '-n','kpm.sqlite'])
        xlog=raw/'xapp.log'
        wait_for(lambda:bool(re.search(r'Connected E2 nodes = [5-9]|Connected E2 nodes = \d{2,}',
                                      xlog.read_text(errors='replace'))),
                 30,procs,'xApp did not discover all E2 nodes')
        shadowproc=None
        shadow_stop=raw/'ai_shadow.stop'
        if args.shadow_model:
            shadowproc=launch('ai-shadow',[sys.executable,str(lab/'shadow_stream.py'),
                '--model',str(args.shadow_model),'--raw-dir',str(raw),'--output',str(result/'csv'),
                '--run-id',lab.name.removeprefix('ran-ai-'),'--ues',str(args.ues),
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
        subprocess.run([sys.executable,str(lab/'export_dataset.py'),str(result),'--duration',str(args.duration)],check=True)
        status['status']='complete';save()
        if args.apply_ai_control:
            from check_control import verify
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

if __name__=='__main__':main()
