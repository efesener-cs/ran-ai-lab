"""Small synthetic FedAvg/coordinate-median update poisoning experiment."""
import argparse,csv,json,copy,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.rf_training_extended import trigger
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 state={'state':'running'}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save();plan=json.loads((a.campaign/'campaign.json').read_text());conditions=0;sources={}
 try:
  with (a.output/'client_updates.csv').open('w',newline='') as uf,(a.output/'model_outcomes.csv').open('w',newline='') as of,(a.output/'validation_rounds.csv').open('w',newline='') as vf:
   uw=csv.writer(uf);uw.writerow(['source_job','task','condition','aggregation','round','client','malicious_update','attack_family','update_l2','update_linf','update_mean','update_std'])
   ow=csv.writer(of);ow.writerow(['source_job','task','condition','aggregation','selected_round','clean_accuracy','reference_clean_accuracy','eligible_reference_clean_correct_nontarget','triggered_target_hits','reference_triggered_target_hits'])
   vw=csv.writer(vf);vw.writerow(['source_job','task','condition','aggregation','round','validation_accuracy'])
   for job in plan['jobs']:
    if job['kind']!='rf_attack' or job['profile']!='diverse':continue
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data={}
    for split in ('train','validation','test'):
     path=root/(split+'.csv');h=hashlib.sha256(path.read_bytes()).hexdigest();assert h==m['inputs'][split]['sha256'];sources[str(path)]=h;data[split]=load_frames(path,c['train_samples'] if split=='train' else c['eval_samples'],c['length'])
    for task in ('sensing','amc'):
     x,y=data['train'][0][task],data['train'][1][task];vx,vy=data['validation'][0][task],data['validation'][1][task];tx,ty=data['test'][0][task],data['test'][1][task];seed=m['inputs']['train']['seed'];clients=np.array_split(np.random.default_rng(seed+61000).permutation(len(x)),10)
     initial=RFModel(x,2 if task=='sensing' else 3,seed+62000);references={};probe=trigger(tx,seed+63000)
     for method in ('clean','sign_flip','replacement_backdoor'):
      for aggregation in ('mean','coordinate_median'):
       server=copy.deepcopy(initial);best=None;best_acc=-1;selected_round=0
       for round_id in range(1,21):
        all_updates=[]
        for client,ids in enumerate(clients):
         rng=np.random.default_rng(seed+round_id*100+client);local=copy.deepcopy(server);cx=x[ids].copy();cy=y[ids].copy();malicious=method!='clean' and client<2
         if malicious and method=='replacement_backdoor':
          selected=rng.permutation(len(cx))[:int(.3*len(cx))];cx[selected]=trigger(cx[selected],seed+round_id*100+client);cy[selected]=1
         for step in range(3):
          take=rng.choice(len(cx),min(64,len(cx)),replace=False);grads=local.loss_gradient(cx[take],cy[take],False)[2]
          local.parameters=[v-.03*g for v,g in zip(local.parameters,grads)]
         update=[v-w for v,w in zip(local.parameters,server.parameters)]
         if malicious and method=='sign_flip':update=[-5*v for v in update]
         if malicious and method=='replacement_backdoor':update=[10*v for v in update]
         vector=np.concatenate([v.ravel() for v in update]);assert np.isfinite(vector).all();all_updates.append(update)
         uw.writerow([job['id'],task,method,aggregation,round_id,client,int(malicious),method if malicious else 'none',np.linalg.norm(vector),np.max(np.abs(vector)),vector.mean(),vector.std()])
        for k in range(len(server.parameters)):
         stacked=np.stack([u[k] for u in all_updates]);delta=np.mean(stacked,axis=0) if aggregation=='mean' else np.median(stacked,axis=0);server.parameters[k]+=delta
        acc=float(np.mean(server.forward(vx)[0].argmax(1)==vy));vw.writerow([job['id'],task,method,aggregation,round_id,acc])
        if acc>best_acc:best_acc=acc;best=copy.deepcopy(server);selected_round=round_id
       clean=best.forward(tx)[0].argmax(1);triggered=best.forward(probe)[0].argmax(1)
       if method=='clean':references[aggregation]=(clean,triggered)
       reference,ref_triggered=references[aggregation];eligible=(reference==ty)&(ty!=1)
       ow.writerow([job['id'],task,method,aggregation,selected_round,float(np.mean(clean==ty)),float(np.mean(reference==ty)),int(eligible.sum()),int(np.sum(eligible&(triggered==1))),int(np.sum(eligible&(ref_triggered==1)))])
       best.save(a.output/(job['id']+'-'+task+'-'+method+'-'+aggregation+'.npz'))
       uf.flush();of.flush();vf.flush();conditions+=1;state.update(conditions=conditions,current_job=job['id'],task=task,method=method,aggregation=aggregation);save()
   (a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state.update(state='complete',conditions=conditions);save()
 except BaseException as e:state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
