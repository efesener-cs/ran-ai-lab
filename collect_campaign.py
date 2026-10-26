#!/usr/bin/env python3
"""Plan and resume sequential matched experiments; failed attempts remain on disk."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import math
from ai.evasion import MODES, ACCESS, validate
import subprocess
import sys

LAB=Path(__file__).resolve().parent


def save_plan(root,plan):
    temporary=root/'.campaign.json.tmp'
    temporary.write_text(json.dumps(plan,indent=2)+'\n')
    temporary.replace(root/'campaign.json')


def execution_hashes():
    files=list(LAB.glob('*.py'))+list((LAB/'ai').glob('*.py'))+[LAB/'ran-ai-scenario.cc']
    return {str(path.relative_to(LAB)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(files)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',choices=['live','native'],default='live')
    p.add_argument('--duration',type=float,default=10);p.add_argument('--ues',type=int,default=24)
    p.add_argument('--seeds',type=int,nargs='+',default=[41,53,67])
    p.add_argument('--epsilons',type=float,nargs='+',default=[0,.5,1,2])
    p.add_argument('--model',type=Path,default=LAB/'ai/artifacts/pilot/model.json')
    p.add_argument('--modes',nargs='+',choices=sorted(MODES),default=['none','random','bias','fgsm','pgd','exact'])
    p.add_argument('--predictors',nargs='+',choices=['ridge','persistence'],default=['ridge'])
    p.add_argument('--robust-budgets-db',nargs='+',default=['off'],help='off or budgets in dB; each is a separate matched suite')
    p.add_argument('--access',choices=sorted(ACCESS),default='two_cell')
    p.add_argument('--max-step-db',type=float)
    p.add_argument('--steps',type=int,default=10)
    p.add_argument('--restarts',type=int,default=5)
    p.add_argument('--plan-only',action='store_true');p.add_argument('--resume',type=Path)
    p.add_argument('--allow-code-change',action='store_true',help='Record an explicit source revision boundary before resuming')
    a=p.parse_args()
    if a.resume:
        root=a.resume.resolve();plan=json.loads((root/'campaign.json').read_text())
    else:
        if not math.isfinite(a.duration) or a.duration<3 or not 3<=a.ues<=120 or any(not math.isfinite(v) or not 0<=v<=5 for v in a.epsilons):p.error('Invalid duration/UE/epsilon')
        if len(set(a.modes))!=len(a.modes) or 'none' not in a.modes:p.error('Modes must be distinct and include none')
        budgets=[]
        for value in a.robust_budgets_db:
            budget=None if value=='off' else float(value)
            if budget is not None and (not math.isfinite(budget) or not 0<=budget<=5):p.error('Invalid robust budget')
            if budget not in budgets:budgets.append(budget)
        config=dict(mode='pgd',steps=a.steps,restarts=a.restarts)
        if a.max_step_db is not None:config['max_step_db']=a.max_step_db
        validate(config)
        root=LAB/'results'/('campaign-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));root.mkdir()
        model=root/'model.json';model.write_bytes(a.model.read_bytes())
        plan=dict(backend=a.backend,duration=a.duration,ues=a.ues,model=str(model),
                  model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),modes=a.modes,access=a.access,
                  steps=a.steps,restarts=a.restarts,max_step_db=a.max_step_db,jobs=[])
        for seed in dict.fromkeys(a.seeds):
            for eps in dict.fromkeys(a.epsilons):
                for predictor in dict.fromkeys(a.predictors):
                    for budget in budgets:
                        plan['jobs'].append(dict(seed=seed,epsilon=eps,run=1,attack_seed=311+seed,
                            predictor=predictor,robust_budget_db=budget,status='pending',attempts=[]))
        save_plan(root,plan)
    current_sources=execution_hashes()
    previous_sources=plan.get('execution_source_sha256')
    if previous_sources and previous_sources!=current_sources:
        if not a.allow_code_change:raise ValueError('Sources changed since campaign start; review changes and use --allow-code-change to record a revision boundary')
        plan.setdefault('source_revision_history',[]).append(previous_sources)
    plan['execution_source_sha256']=current_sources
    save_plan(root,plan)
    print('Campaign:',root,' suites:',len(plan['jobs']),' runs:',len(plan.get('modes',['none','random','fgsm','pgd']))*len(plan['jobs']),flush=True)
    if a.plan_only:
        print('Execute/resume: python3 collect_campaign.py --resume '+str(root));return
    if hashlib.sha256(Path(plan['model']).read_bytes()).hexdigest()!=plan['model_sha256']:raise ValueError('Campaign model changed')
    for index,job in enumerate(plan['jobs']):
        if execution_hashes()!=current_sources:raise RuntimeError('Source files changed during campaign; stop editing before resuming')
        if job['status']=='complete':continue
        destination=root/f"suite-{index:02d}-attempt-{len(job['attempts'])+1}"
        job['attempts'].append(str(destination));job['status']='running'
        save_plan(root,plan)
        command=[sys.executable,str(LAB/'run_adversarial_suite.py'),'--backend',plan['backend'],
                 '--duration',str(plan['duration']),'--ues',str(plan['ues']),'--seed',str(job['seed']),
                 '--run',str(job['run']),'--epsilon',str(job['epsilon']),'--attack-seed',str(job['attack_seed']),
                 '--model',plan['model'],'--output',str(destination)]
        command+=['--modes',*plan.get('modes',['none','random','fgsm','pgd']),
                  '--predictor',job.get('predictor','ridge'),'--access',plan.get('access','two_cell'),
                  '--steps',str(plan.get('steps',10)),'--restarts',str(plan.get('restarts',5))]
        if job.get('robust_budget_db') is not None:command+=['--robust-budget-db',str(job['robust_budget_db'])]
        if plan.get('max_step_db') is not None:command+=['--max-step-db',str(plan['max_step_db'])]
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
    subprocess.run([sys.executable,str(LAB/'summarize_campaign.py'),str(root/'analysis/run_summary.csv'),
                    '--output',str(root/'statistics')],check=True)

if __name__=='__main__':main()
