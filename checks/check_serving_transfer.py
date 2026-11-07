"""Recompute artifact/output observations and held-out transfer outcomes."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.rf_training_extended import trigger
from simulation.run_rf import load_frames


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('training',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text())
 for name,h in json.loads((a.run/'sources.json').read_text()).items():assert sha(Path(name))==h
 groups={};summary=[]
 with (a.run/'serving_requests.csv').open() as f:
  for row in csv.DictReader(f):groups.setdefault((row['source_job'],row['task'],row['condition']),[]).append(row)
 for job in plan['jobs']:
  if job['kind']!='rf_attack' or job['profile']!='diverse':continue
  root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data,truth=load_frames(root/'test.csv',c['eval_samples'],c['length']);seed=m['inputs']['train']['seed']
  for task in ('sensing','amc'):
   x,y=data[task],truth[task];prefix=job['id']+'-'+task;clean_path=a.training/(prefix+'-reference.npz');shadow=RFModel.load(clean_path).forward(x)[0].argmax(1);eligible=(shadow==y)&(y!=1)
   for condition in ('clean_artifact','replacement_model_artifact','output_label_remap','random_output_control'):
    path=a.run/(prefix+'-'+condition)/'served-model.npz';reported=RFModel.load(path).forward(x)[0].argmax(1);changed=sha(path)!=sha(clean_path)
    if condition=='output_label_remap':reported[:]=1
    if condition=='random_output_control':
     rng=np.random.default_rng(seed+77000);indices=rng.permutation(len(x))[:int(np.sum(shadow!=1))];reported[indices]=rng.integers(0,2 if task=='sensing' else 3,len(indices))
    rows=groups.pop((job['id'],task,condition));assert len(rows)==len(x)
    for i,row in enumerate(rows):assert [int(row[k]) for k in ('frame_id','model_artifact_changed','trusted_hash_check_passed','true_class','trusted_shadow_prediction','reported_prediction','output_changed','eligible_clean_correct_nontarget','target_hit')]==[i,int(changed),int(not changed),int(y[i]),int(shadow[i]),int(reported[i]),int(shadow[i]!=reported[i]),int(eligible[i]),int(reported[i]==1)]
    summary.append(dict(source_job=job['id'],task=task,condition=condition,accuracy=float(np.mean(reported==y)),eligible=int(eligible.sum()),target_hits=int(np.sum(eligible&(reported==1))),artifact_changed=changed))
 transfer=list(csv.DictReader((a.run/'transfer_outcomes.csv').open()));cache={}
 for row in transfer:
  repeat=int(row['source_job'].rsplit('-r',1)[1]);root=a.run/('fresh-target-r'+str(repeat));generation=json.loads((root/'generation.json').read_text())
  for role,meta in generation['inputs'].items():assert sha(root/(role+'.csv'))==meta['sha256'];assert meta['seed']=={'train':1810001,'validation':1820001,'test':1830001}[role]+repeat
  task=row['task'];key=(repeat,task)
  if key not in cache:
   td,ty=load_frames(root/'test.csv',1000,128);vd,vy=load_frames(root/'validation.csv',1000,128);cache[key]=(td[task],ty[task],vd[task],vy[task])
  x,y,vx,vy=cache[key];prefix=row['source_job']+'-'+task;model=RFModel.load(a.run/(prefix+'-'+row['condition']+'.npz'));ref=RFModel.load(a.run/(prefix+'-clean_finetune.npz'));job=next(j for j in plan['jobs'] if j['id']==row['source_job']);source=a.campaign/job['attempts'][-1]['path']/'result';seed=json.loads((source/'manifest.json').read_text())['inputs']['train']['seed'];pred=model.forward(x)[0].argmax(1);rp=ref.forward(x)[0].argmax(1);probe=trigger(x,seed+81000);tr=model.forward(probe)[0].argmax(1);rt=ref.forward(probe)[0].argmax(1);eligible=(rp==y)&(y!=1)
  assert np.isclose(float(row['validation_accuracy']),np.mean(model.forward(vx)[0].argmax(1)==vy));assert np.isclose(float(row['test_accuracy']),np.mean(pred==y));assert int(row['eligible_clean_reference_correct_nontarget'])==int(eligible.sum());assert int(row['triggered_target_hits'])==int(np.sum(eligible&(tr==1)));assert int(row['reference_triggered_hits'])==int(np.sum(eligible&(rt==1)));assert 1<=int(row['selected_epoch'])<=20
 assert not groups and len(summary)==40 and len(transfer)==20
 with (a.run/'serving_outcomes.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'serving_conditions':40,'transfer_conditions':20,'scope':'source and served-artifact hashes, all request outputs and clean/trigger transfer outcomes re-evaluated; fine-tuning optimizer not independently refit'},indent=2)+'\n');print('Verified serving40 transfer20')

if __name__=='__main__':main()
