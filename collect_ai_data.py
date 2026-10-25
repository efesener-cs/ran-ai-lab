#!/usr/bin/env python3
"""Collect independent clean live runs, then train with the last run held out."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from check_live import check

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runs',type=int,default=3)
p.add_argument('--duration',type=float,default=10)
p.add_argument('--ues',type=int,default=12)
p.add_argument('--seed',type=int,default=11)
a=p.parse_args()
if a.runs<2:p.error('At least two runs are needed for held-out-run evaluation')
lab=Path(__file__).resolve().parent
roots=[]
for index in range(a.runs):
    before=set((lab/'results').glob('live-*'))
    subprocess.run([sys.executable,str(lab/'run_live.py'),'--duration',str(a.duration),
        '--ues',str(a.ues),'--seed',str(a.seed+index),'--run',str(index+1)],check=True)
    added=set((lab/'results').glob('live-*'))-before
    if len(added)!=1:raise RuntimeError('Cannot uniquely identify new run; avoid concurrent live collectors')
    root=added.pop()
    if not check(root)['passed']:raise RuntimeError('Live verification failed: '+str(root))
    roots.append(root)
out=lab/'ai/artifacts/independent-runs'
command=[sys.executable,str(lab/'train_ai.py'),'--output',str(out)]
for root in roots[:-1]:command+=['--run-dir',str(root)]
command+=['--test-run-dir',str(roots[-1])]
subprocess.run(command,check=True)
(out/'collection.json').write_text(json.dumps(dict(training_runs=[r.name for r in roots[:-1]],
    test_run=roots[-1].name,command_parameters=vars(a)),indent=2)+'\n')
