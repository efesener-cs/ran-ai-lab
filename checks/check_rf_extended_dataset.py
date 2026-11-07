"""Recompute extended split records and exact train-only mixture selection."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel,attack,project,features
from ai.rf_extended_dataset import FIELDS,channel_map
from simulation.run_rf import load_frames


def rowhash(row):return hashlib.sha256('\0'.join(row).encode()).hexdigest()


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text());assert json.loads((a.run/'status.json').read_text())['state']=='complete'
 for name,h in json.loads((a.run/'sources.json').read_text()).items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==h
 handles={};readers={};groups={s:set() for s in ('train','validation','test')};train_hashes={};count=0;conditions=[]
 try:
  for split in groups:
   handles[split]=(a.run/(split+'.csv')).open();readers[split]=csv.reader(handles[split]);assert next(readers[split])==FIELDS
  for job in plan['jobs']:
   if job['kind']!='rf_attack' or job['profile']!='diverse':continue
   root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];seed=m['inputs']['train']['seed']
   for task in ('sensing','amc'):
    model=RFModel.load(root/(task+'-model.npz'))
    with np.load(a.run/(job['id']+'-'+task+'-universal.npz'),allow_pickle=False) as z:u,v=z['universal'],z['shift_universal']
    for split_index,split in enumerate(groups):
     data,truth=load_frames(root/(split+'.csv'),c['train_samples'] if split=='train' else c['eval_samples'],c['length']);x,y=data[task],truth[task];radius=np.sqrt(.1)*np.linalg.norm(x,axis=1,keepdims=True);target=np.ones(len(x),dtype=int);eligible=(model.forward(x)[0].argmax(1)==y)&(y!=1);rng_seed=seed+810000+split_index*1009
     with np.load(a.run/(job['id']+'-'+task+'-'+split+'-perturbations.npz'),allow_pickle=False) as z:
      tx=z['channel_tx'];h=z['channel_h'];deltas={'clean':np.zeros_like(x),'random_control':attack(model,x,target,'random',.1,False,rng_seed),'fgsm':z['fgsm'],'pgd':z['pgd'],'transfer_pgd':z['transfer'],'sparse_8_complex':z['sparse'],'universal':project(np.repeat(u,len(x),axis=0),radius),'shift_eot_universal':project(np.repeat(np.roll(v,8,axis=1),len(x),axis=0),radius),'channel_aware_flat':channel_map(tx,h)}
      assert np.max(np.sum(np.any(z['sparse'].reshape(len(x),-1,2)!=0,axis=2),axis=1))<=8
      for method,delta in deltas.items():
       moments=features(x+delta);pred=model.forward(x+delta)[0].argmax(1);applied=np.any(delta!=0,axis=1)&(method not in ('clean','random_control'));energy=np.maximum(np.sum(x*x,axis=1),1e-30);rp=np.sum(delta**2,axis=1)/energy;tp=np.sum(tx**2,axis=1)/energy if method=='channel_aware_flat' else rp;assert np.max(tp)<=.1+1e-10
       for i in range(len(x)):
        row=next(readers[split]);group='rf-s'+str(m['inputs'][split]['seed'])+'-'+task+'-'+str(i);assert row[:7]==[job['id'],group,task,str(i),split,method,method if applied[i] else 'none'];assert [int(vv) for vv in row[7:10]]==[int(applied[i]),int(eligible[i]),int(pred[i]==1)];assert np.allclose(np.asarray(row[10:],float),np.r_[tp[i],rp[i],moments[i]],rtol=1e-9,atol=1e-12);groups[split].add(group)
        if split=='train':train_hashes[(group,method)]=rowhash(row)
        count+=1
       conditions.append(dict(source_job=job['id'],task=task,split=split,method=method,eligible=int(eligible.sum()),target_hits=int(np.sum(eligible&(pred==1))),applied=int(applied.sum())))
  for reader in readers.values():assert next(reader,None) is None
 finally:
  for f in handles.values():f.close()
 assert count==450000 and not groups['train']&groups['validation'] and not groups['train']&groups['test'] and not groups['validation']&groups['test']
 seen=set();n=0;positive=0;by_task={}
 with (a.run/'train_80_20.csv').open() as f:
  rr=csv.reader(f);assert next(rr)==FIELDS
  for row in rr:
   assert row[1] not in seen;seen.add(row[1]);assert train_hashes[(row[1],row[5])]==rowhash(row);n+=1;positive+=int(row[7]);by_task.setdefault(row[2],[0,0]);by_task[row[2]][0]+=1;by_task[row[2]][1]+=int(row[7])
 assert n==30000 and positive==6000 and all(v==[15000,3000] for v in by_task.values())
 with (a.run/'condition_metrics.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(conditions[0]));w.writeheader();w.writerows(conditions)
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'inventory_rows':count,'conditions':len(conditions),'training_view_rows':n,'training_positive':positive,'scope':'all saved moments/predictions/eligible labels/power/group identities recomputed; exact source-row matches and20percent applied attacks in one-version-per-frame training view; attack optimization not independently rerun'},indent=2)+'\n');print('Extended inventory verified',count,'train',n)

if __name__=='__main__':main()
