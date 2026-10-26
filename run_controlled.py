#!/usr/bin/env python3
"""Host integration test: model -> atomic commands -> ns-3 RRC; no E2 RC claim."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--duration',type=float,default=3)
p.add_argument('--ues',type=int,default=6)
p.add_argument('--model',type=Path)
p.add_argument('--warmup',type=float,default=1.0)
p.add_argument('--seed',type=int,default=7)
p.add_argument('--run',type=int,default=1)
p.add_argument('--evasion-config',type=Path)
p.add_argument('--output',type=Path,help='Run output directory (must not already exist)')
a=p.parse_args();lab=Path(__file__).resolve().parent
model=a.model or lab/'ai/artifacts/pilot/model.json'
root=a.output.resolve() if a.output else lab/'results'/('control-native-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
if a.output:
    root.mkdir(parents=True,exist_ok=False)
raw=root/'raw';raw.mkdir(parents=True,exist_ok=False)
stop=raw/'ai_shadow.stop'
status=dict(status='running',live_ric_verified=False,ai_control_enabled=True,
            control_transport='atomic CSV to ns-3 RRC API; no E2 RC',
            configuration=dict(duration=a.duration,ues=a.ues,seed=a.seed,run=a.run,warmup=a.warmup))
(root/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
print('Results:',root,flush=True)
shadow_log=(raw/'ai-shadow.log').open('w')
controller=subprocess.Popen([sys.executable,str(lab/'shadow_stream.py'),'--model',str(model),
    '--raw-dir',str(raw),'--output',str(root/'csv'),'--run-id',root.name,'--ues',str(a.ues),
    '--stop-file',str(stop),'--apply-control']+(['--evasion-config',str(a.evasion_config.resolve())] if a.evasion_config else []),stdout=shadow_log,stderr=subprocess.STDOUT)
try:
    with (raw/'simulation.log').open('w') as log:
        subprocess.run([str(lab/'ran-ai-offline'),'--liveRic=false','--applyAiControl=true',
            '--simTime='+str(a.duration),'--ueCount='+str(a.ues),'--warmup='+str(a.warmup),
            '--RngSeed='+str(a.seed),'--RngRun='+str(a.run)],cwd=raw,stdout=log,stderr=subprocess.STDOUT,check=True)
    stop.touch()
    if controller.wait(timeout=15)!=0:raise RuntimeError('AI controller failed')
    subprocess.run([sys.executable,str(lab/'export_dataset.py'),str(root),'--duration',str(a.duration)],check=True)
    status.update(status='complete',simulation_exit_code=0)
    (root/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
    from check_control import verify
    result=verify(root,require_live=False)
    if not result['infrastructure_valid']:raise RuntimeError('Control evidence is malformed or infrastructure-invalid')
    status['ai_control_infrastructure_valid']=True
    status['control_outcomes']=result['control_outcomes']
    # A run may be healthy with no submissions or with an unconfirmed handover.
    # Never record those scientific outcomes as verified control success.
    status['ai_control_verified_native']=bool(result['submitted']) and result['confirmed']==result['submitted']
except BaseException as exc:
    status.update(status='failed',error=str(exc));raise
finally:
    if controller.poll() is None:controller.terminate();controller.wait(timeout=5)
    shadow_log.close()
    (root/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
