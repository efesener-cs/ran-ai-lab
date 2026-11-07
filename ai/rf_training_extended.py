"""Declared single-level clean-label/availability poison and dynamic IQ backdoor."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import train,project,normalize
from ai.training_attacks import classification
from simulation.run_rf import load_frames


def trigger(x,seed,random_control=False):
 rng=np.random.default_rng(seed);out=x.copy();length=x.shape[1]//2
 for i in range(len(x)):
  start=int(rng.integers(0,length-16+1));phase=rng.uniform(-np.pi,np.pi)
  d=np.zeros(32);d[0::2]=np.cos(phase);d[1::2]=np.sin(phase)
  if random_control:
   d=rng.normal(size=32);d*=4/max(np.linalg.norm(d),1e-30)
  out[i,2*start:2*(start+16)]+=d
 return out


def main():
 p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 state={'state':'running'}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save();plan=json.loads((a.campaign/'campaign.json').read_text());sources={};condition_count=0
 try:
  with (a.output/'model_outcomes.csv').open('w',newline='') as outf,(a.output/'training_rows.csv').open('w',newline='') as auditf,(a.output/'evaluation_predictions.csv').open('w',newline='') as pf:
   w=csv.writer(outf);w.writerow(['condition_id','source_job','task','method','fraction','selected','reference_accuracy','clean_accuracy','clean_macro_f1','eligible_reference_clean_correct_nontarget','clean_target_hits','triggered_target_hits','random_patch_target_hits','reference_triggered_target_hits','selected_epoch'])
   aw=csv.writer(auditf);aw.writerow(['condition_id','frame_id','selected','true_label','training_label','iq_changed','power_ratio','dataset_role'])
   pw=csv.writer(pf);pw.writerow(['condition_id','frame_id','true_label','reference_clean','model_clean','model_triggered','model_random_patch'])
   for job in plan['jobs']:
    if job['kind']!='rf_attack' or job['profile']!='diverse':continue
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data={}
    for split in ('train','validation','test'):
     source=root/(split+'.csv');digest=hashlib.sha256(source.read_bytes()).hexdigest()
     if digest!=m['inputs'][split]['sha256']:raise ValueError('Changed RF input')
     sources[str(source)]=digest;data[split]=load_frames(source,c['train_samples'] if split=='train' else c['eval_samples'],c['length'])
    for task in ('sensing','amc'):
     x,y=data['train'][0][task],data['train'][1][task];vx,vy=data['validation'][0][task],data['validation'][1][task];tx,ty=data['test'][0][task],data['test'][1][task];seed=m['inputs']['train']['seed']
     reference,ref_fit=train(x,y,vx,vy,False,seed,80);reference.save(a.output/(job['id']+'-'+task+'-reference.npz'))
     cleanref=reference.forward(tx)[0].argmax(1);eligible=(cleanref==ty)&(ty!=1);triggered=trigger(tx,seed+55000);random=trigger(tx,seed+55000,True);ref_trigger=reference.forward(triggered)[0].argmax(1)
     orders={}
     for method in ('clean_label_targeted_input_poison','availability_loss_poison','dynamic_backdoor'):
      eligible_train=np.flatnonzero(y==1) if method=='clean_label_targeted_input_poison' else (np.flatnonzero(y!=1) if method=='dynamic_backdoor' else np.arange(len(x)))
      orders[method]=np.random.default_rng(seed+44000).permutation(eligible_train)
      for fraction in (.01,.05,.1,.2):
       n=int(np.floor(len(x)*fraction+.5));indices=orders[method][:n]
       if len(indices)!=n:raise ValueError('Infeasible poisoning fraction')
       px=x.copy();py=y.copy();delta=np.zeros_like(x[indices]);radius=np.sqrt(10**(-6/10))*np.linalg.norm(x[indices],axis=1,keepdims=True)
       if method=='dynamic_backdoor':px[indices]=trigger(x[indices],seed+66000);py[indices]=1
       else:
        for step in range(30):
         target=np.zeros(n,dtype=int) if method=='clean_label_targeted_input_poison' else y[indices]
         gradient=reference.loss_gradient(x[indices]+delta,target,False)[1];direction=-1 if method=='clean_label_targeted_input_poison' else 1
         delta=project(delta+direction*.15*radius*normalize(gradient),radius)
        px[indices]+=delta
       selected=np.zeros(len(x),dtype=bool);selected[indices]=True;changed=np.any(px!=x,axis=1);ratio=np.sum((px-x)**2,axis=1)/np.maximum(np.sum(x*x,axis=1),1e-30)
       if method!='dynamic_backdoor' and (not np.array_equal(py,y) or np.any(ratio>10**(-6/10)+1e-10)):raise ValueError('Clean-label/budget invariant')
       if np.any(px[~selected]!=x[~selected]) or np.any(py[~selected]!=y[~selected]):raise ValueError('Unselected row changed')
       name=job['id']+'-'+task+'-'+method+'-'+str(fraction)
       victim,fit=train(px,py,vx,vy,False,seed,80);victim.save(a.output/(name+'-model.npz'))
       clean=victim.forward(tx)[0].argmax(1);tr=victim.forward(triggered)[0].argmax(1);rd=victim.forward(random)[0].argmax(1);metrics=classification(ty,clean,2 if task=='sensing' else 3)
       w.writerow([name,job['id'],task,method,fraction,n,float(np.mean(cleanref==ty)),metrics['accuracy'],metrics['macro_f1'],int(eligible.sum()),int(np.sum(eligible&(clean==1))),int(np.sum(eligible&(tr==1))),int(np.sum(eligible&(rd==1))),int(np.sum(eligible&(ref_trigger==1))),fit['selected_epoch']])
       for i in range(len(x)):aw.writerow([name,i,int(selected[i]),int(y[i]),int(py[i]),int(changed[i]),ratio[i],'training'])
       for i in range(len(tx)):pw.writerow([name,i,int(ty[i]),int(cleanref[i]),int(clean[i]),int(tr[i]),int(rd[i])])
       np.savez_compressed(a.output/(name+'-transform.npz'),indices=indices,delta=px[indices]-x[indices],training_labels=py[indices])
       outf.flush();auditf.flush();pf.flush();condition_count+=1;state.update(conditions=condition_count,current_condition=name);save()
   (a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state.update(state='complete',conditions=condition_count);save()
 except BaseException as e:state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
