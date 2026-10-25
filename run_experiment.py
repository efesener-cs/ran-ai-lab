#!/usr/bin/env python3
"""Host-only stochastic RAN experiment; UDP attack packets stay inside ns-3."""
import argparse
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from experiment_plan import make_plan

p=argparse.ArgumentParser()
p.add_argument('--duration',type=float,default=3)
p.add_argument('--ues',type=int,default=24)
p.add_argument('--warmup',type=float,default=0.5)
p.add_argument('--attacks',type=int,default=3)
p.add_argument('--seed',type=int,default=17)
p.add_argument('--run',type=int,default=1)
a=p.parse_args()
if not 3<=a.ues<=120:p.error('UE count must be 3..120')
lab=Path(__file__).resolve().parent
binary=lab/'ran-ai-offline'
source=lab/'ran-ai-scenario.cc'
if not binary.exists() or source.stat().st_mtime>binary.stat().st_mtime:
    subprocess.run([sys.executable,str(lab/'build_offline.py')],check=True)
root=lab/'results'/('stochastic-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
raw=root/'raw';raw.mkdir(parents=True)
attack_seed=a.seed*100003+a.run
plan=make_plan(raw/'attack_plan.csv',a.duration,a.ues,a.warmup,attack_seed,a.attacks)
status={'configuration':vars(a),'attack_seed':attack_seed,'live_ric_verified':False,
        'mode':'host ns-3, offline E2 logging','ai_controller_installed':False,
        'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'status':'running'}
(root/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
print('Results:',root,flush=True)
print(f'{a.ues} UEs; {len(plan)} stochastic UDP events, seed {attack_seed}',flush=True)
command=[str(binary),'--liveRic=false','--simTime='+str(a.duration),'--ueCount='+str(a.ues),
         '--warmup='+str(a.warmup),'--attackPlan='+str(raw/'attack_plan.csv'),
         '--RngSeed='+str(a.seed),'--RngRun='+str(a.run)]
try:
    with (raw/'simulation.log').open('w') as log:
        subprocess.run(command,cwd=raw,check=True,stdout=log,stderr=subprocess.STDOUT)
    subprocess.run([sys.executable,str(lab/'export_dataset.py'),str(root),'--duration',str(a.duration)],check=True)
    status['status']='complete'
except BaseException as exc:
    status.update(status='failed',error=str(exc));raise
finally:
    (root/'run_status.json').write_text(json.dumps(status,indent=2)+'\n')
