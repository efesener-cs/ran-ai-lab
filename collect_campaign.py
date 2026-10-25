#!/usr/bin/env python3
"""Plan and resume sequential matched experiments; failed attempts remain on disk."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

LAB=Path(__file__).resolve().parent


def save_plan(root,plan):
    temporary=root/'.campaign.json.tmp'
    temporary.write_text(json.dumps(plan,indent=2)+'\n')
    temporary.replace(root/'campaign.json')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',choices=['live','native'],default='live')
    p.add_argument('--duration',type=float,default=10);p.add_argument('--ues',type=int,default=24)
    p.add_argument('--seeds',type=int,nargs='+',default=[7,19])
    p.add_argument('--epsilons',type=float,nargs='+',default=[.5,1,2])
    p.add_argument('--model',type=Path,default=LAB/'ai/artifacts/pilot/model.json')
    p.add_argument('--plan-only',action='store_true');p.add_argument('--resume',type=Path)
    a=p.parse_args()
    if a.resume:
        root=a.resume.resolve();plan=json.loads((root/'campaign.json').read_text())
    else:
        if a.duration<3 or a.ues<2 or any(not 0<=v<=5 for v in a.epsilons):p.error('Invalid duration/UE/epsilon')
        root=LAB/'results'/('campaign-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));root.mkdir()
        model=root/'model.json';model.write_bytes(a.model.read_bytes())
        plan=dict(backend=a.backend,duration=a.duration,ues=a.ues,model=str(model),
                  model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),jobs=[])
        for seed in dict.fromkeys(a.seeds):
            for eps in dict.fromkeys(a.epsilons):
                plan['jobs'].append(dict(seed=seed,epsilon=eps,run=1,attack_seed=311+seed,status='pending',attempts=[]))
        save_plan(root,plan)
    print('Campaign:',root,' suites:',len(plan['jobs']),' runs:',4*len(plan['jobs']),flush=True)
    if a.plan_only:
        print('Execute/resume: python3 collect_campaign.py --resume '+str(root));return
    if hashlib.sha256(Path(plan['model']).read_bytes()).hexdigest()!=plan['model_sha256']:raise ValueError('Campaign model changed')
    for index,job in enumerate(plan['jobs']):
        if job['status']=='complete':continue
        destination=root/f"suite-{index:02d}-attempt-{len(job['attempts'])+1}"
        job['attempts'].append(str(destination));job['status']='running'
        save_plan(root,plan)
        command=[sys.executable,str(LAB/'run_adversarial_suite.py'),'--backend',plan['backend'],
                 '--duration',str(plan['duration']),'--ues',str(plan['ues']),'--seed',str(job['seed']),
                 '--run',str(job['run']),'--epsilon',str(job['epsilon']),'--attack-seed',str(job['attack_seed']),
                 '--model',plan['model'],'--output',str(destination)]
        print('Job',index+1,'/',len(plan['jobs']),flush=True)
        try:
            with (root/f'job-{index:02d}-attempt-{len(job["attempts"])}.log').open('w') as log:
                subprocess.run(command,cwd=LAB,stdout=log,stderr=subprocess.STDOUT,check=True)
            job.update(status='complete',suite=str(destination))
        except BaseException:
            job['status']='failed';raise
        finally:save_plan(root,plan)
    suites=[job['suite'] for job in plan['jobs'] if job['status']=='complete']
    subprocess.run([sys.executable,str(LAB/'analyze_experiments.py'),*suites,'--output',str(root/'analysis')],check=True)

if __name__=='__main__':main()
