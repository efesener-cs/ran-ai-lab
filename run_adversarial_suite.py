#!/usr/bin/env python3
"""Matched local control experiments: clean, random, targeted FGSM and PGD."""
import argparse
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from ai.evasion import validate
from check_evasion import verify


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path)
    p.add_argument('--attack-seed',type=int,default=311)
    p.add_argument('--backend',choices=['native','live'],default='native')
    p.add_argument('--duration',type=float,default=3);p.add_argument('--ues',type=int,default=6)
    p.add_argument('--seed',type=int,default=7);p.add_argument('--run',type=int,default=1)
    p.add_argument('--epsilon',type=float,default=2)
    p.add_argument('--model',type=Path,default=Path('ai/artifacts/pilot/model.json'))
    a=p.parse_args()
    if a.duration<3 or a.ues<2:p.error('Use duration >=3 and ues >=2')
    validate(dict(mode='fgsm',epsilon_db=a.epsilon))
    lab=Path(__file__).resolve().parent;model=a.model.resolve()
    root=a.output.resolve() if a.output else lab/'results'/('adversarial-suite-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True,exist_ok=False)
    snapshot=root/'model.json';snapshot.write_bytes(model.read_bytes());model=snapshot
    rng=random.Random(a.attack_seed);events=[]
    for ue in rng.sample(range(1,a.ues+1),max(1,a.ues//3)):
        start=round(rng.uniform(1.1,a.duration-1.2),2)
        end=round(min(a.duration-.3,start+rng.uniform(.5,1.0)),2)
        events.append(dict(id='sinr-'+str(ue),ue_imsi=ue,start_s=start,end_s=end))
    manifest=dict(configuration=vars(a)|{'model':str(model),'output':str(root)},events=events,model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),runs={})
    manifest['source_sha256']={name:hashlib.sha256((lab/name).read_bytes()).hexdigest() for name in ['ai/evasion.py','ai/runtime.py','ai/policy.py','shadow_stream.py','ran-ai-scenario.cc']}
    if a.backend=='native':manifest['simulation_binary_sha256']=hashlib.sha256((lab/'ran-ai-offline').read_bytes()).hexdigest()
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    summaries=[]
    for mode in ['none','random','fgsm','pgd']:
        config=root/(mode+'.json');config.write_text(json.dumps(dict(mode=mode,epsilon_db=a.epsilon,seed=a.attack_seed,steps=10,events=events),indent=2)+'\n')
        cmd=[sys.executable,str(lab/('run_controlled.py' if a.backend=='native' else 'run_live.py')),
             '--duration',str(a.duration),'--ues',str(a.ues),'--seed',str(a.seed),'--run',str(a.run),
             '--model' if a.backend=='native' else '--ai-model',str(model),'--evasion-config',str(config)]
        if a.backend=='live':cmd+=['--apply-ai-control']
        existing=set((lab/'results').iterdir());print('Running',mode,flush=True)
        subprocess.run(cmd,cwd=lab,check=True)
        created=[d for d in set((lab/'results').iterdir())-existing if (d/'run_status.json').exists()]
        if len(created)!=1:raise RuntimeError('Ambiguous run discovery')
        run=created[0];manifest['runs'][mode]=str(run)
        (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        summary=verify(run)
        if not summary['passed']:raise RuntimeError('Evasion audit failed')
        with (run/'csv/ue_application_100ms.csv').open() as stream:
            apps=list(csv.DictReader(stream))
        control=json.loads((run/'control_verification.json').read_text())
        summary['control_submitted']=control['submitted'];summary['control_confirmed']=control['confirmed']
        summary['application_rx_bytes']=sum(int(r['rx_bytes']) for r in apps if r['is_warmup']=='0')
        summaries.append(summary)
    clean=summaries[0]['application_rx_bytes']
    for row in summaries:row['rx_bytes_change_vs_clean']=row['application_rx_bytes']-clean
    (root/'comparison.json').write_text(json.dumps(summaries,indent=2)+'\n')
    combine(root,manifest)
    print('Suite:',root,flush=True)

def combine(root,manifest):
    rows=[]
    for mode,path in manifest['runs'].items():
        with (Path(path)/'csv/adversarial_dataset.csv').open() as stream:
            rows.extend(dict(row,experiment_condition=mode) for row in csv.DictReader(stream))
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with (root/'dataset.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)

if __name__=='__main__':main()
