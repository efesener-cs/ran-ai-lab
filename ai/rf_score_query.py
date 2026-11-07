"""Budgeted score-only targeted RF evasion with antithetic query estimates.

No victim parameter/gradient access in the attack. Fixed global target1,
PSR=-10dB, budgets64/256/1024; first128 test frames are prespecified.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import numpy as np
from ai.rf import RFModel, features, normalize, project
from simulation.run_rf import load_frames


def probabilities(logits):
    z=logits-logits.max(axis=1,keepdims=True)
    e=np.exp(z)
    return e/e.sum(axis=1,keepdims=True)


def score_only(victim, x, budget, seed):
    rng=np.random.default_rng(seed); n,d=x.shape
    radius=np.sqrt(.1)*np.linalg.norm(x,axis=1,keepdims=True)
    delta=np.zeros_like(x); used=0
    # Reserve the final query for reporting the returned target posterior.
    while used+2 <= budget-1:
        directions=min(16,(budget-1-used)//2)
        u=normalize(rng.normal(size=(n*directions,d))).reshape(n,directions,d)
        sigma=.02*radius[:,None,:]
        plus=x[:,None,:]+delta[:,None,:]+sigma*u
        minus=x[:,None,:]+delta[:,None,:]-sigma*u
        qp=probabilities(victim.forward(plus.reshape(-1,d))[0])[:,1].reshape(n,directions)
        qm=probabilities(victim.forward(minus.reshape(-1,d))[0])[:,1].reshape(n,directions)
        grad=np.mean((np.log(np.maximum(qp,1e-15))-np.log(np.maximum(qm,1e-15)))[:,:,None]*u,axis=1)
        delta=project(delta+.2*radius*normalize(grad),radius)
        used+=2*directions
    posterior=probabilities(victim.forward(x+delta)[0])
    return delta,posterior,used+1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);state=dict(state='running',conditions=0)
    def save():
        tmp=a.output/'status.tmp';tmp.write_text(json.dumps(state,indent=2)+'\n');tmp.replace(a.output/'status.json')
    save();plan=json.loads((a.campaign/'campaign.json').read_text()); sources={}
    try:
        with (a.output/'observations.csv').open('w',newline='') as f:
            header=['source_job','task','frame_id','split','attack_family','attack_applied','query_budget','actual_queries','true_class_audit','clean_correct_eligible','target_hit','target_posterior','power_ratio']+['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']+[v+str(i) for i in range(128) for v in ('i','q')]
            w=csv.writer(f);w.writerow(header)
            for job in plan['jobs']:
                if job['kind']!='rf_attack' or job['profile']!='diverse':continue
                source=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((source/'manifest.json').read_text());c=m['configuration']
                data=source/'test.csv';sha=hashlib.sha256(data.read_bytes()).hexdigest();assert sha==m['inputs']['test']['sha256'];sources[str(data)]=sha
                xs,ys=load_frames(data,c['eval_samples'],c['length']);seed=m['inputs']['train']['seed']
                for task in ('sensing','amc'):
                    x=xs[task][:128];y=ys[task][:128];assert x.shape[1]==256
                    victim=RFModel.load(source/(task+'-model.npz'));clean=victim.forward(x)[0].argmax(1);eligible=(clean==y)&(y!=1)
                    for budget in (64,256,1024):
                        delta,posterior,queries=score_only(victim,x,budget,seed+budget)
                        ratio=np.sum(delta*delta,axis=1)/np.maximum(np.sum(x*x,axis=1),1e-30)
                        assert queries<=budget and np.max(ratio)<=.1+1e-10
                        feats=features(x+delta);pred=posterior.argmax(1)
                        for i in range(len(x)):w.writerow([job['id'],task,i,'test','score_query_antithetic',int(np.any(delta[i])),budget,queries,int(y[i]),int(eligible[i]),int(pred[i]==1),posterior[i,1],ratio[i],*feats[i],*(x+delta)[i]])
                        np.savez_compressed(a.output/f"{job['id']}-{task}-{budget}.npz",delta=delta,posterior=posterior,frame_ids=np.arange(len(x)))
                        f.flush();state['conditions']+=1;state['current']=f"{job['id']}/{task}/{budget}";save()
            (a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state['state']='complete';save()
    except BaseException as exc:
        state.update(state='failed',error=str(exc));save();raise


if __name__=='__main__':main()
