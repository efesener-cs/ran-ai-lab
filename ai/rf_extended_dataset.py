"""Extended RF attack inventory for original splits plus 80/20 train-only view."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel,train,attack,normalize,project,features
from simulation.run_rf import load_frames

MOMENTS=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']
FAMILIES=['fgsm','pgd','transfer_pgd','sparse_8_complex','universal','shift_eot_universal','channel_aware_flat']
FIELDS=['source_job','source_group_id','task','frame_id','split','requested_method','attack_family','attack_applied','eligible_clean_correct_nontarget','target_hit','tx_power_ratio','rx_power_ratio']+MOMENTS


def learned_vectors(model,x,seed):
 rng=np.random.default_rng(seed);radius=float(np.sqrt(.1)*np.min(np.linalg.norm(x,axis=1)));u=np.zeros((1,x.shape[1]));v=u.copy()
 for _ in range(30):
  batch=x[rng.choice(len(x),min(128,len(x)),replace=False)];target=np.ones(len(batch),dtype=int);gradient=model.loss_gradient(batch+u,target,False)[1].mean(0,keepdims=True);u=project(u-.15*radius*normalize(gradient),radius);g=np.zeros_like(v)
  for shift in (-4,0,4):g+=np.roll(model.loss_gradient(batch+np.roll(v,2*shift,axis=1),target,False)[1].mean(0,keepdims=True),-2*shift,axis=1)/3
  v=project(v-.15*radius*normalize(g),radius)
 return u,v


def sparse(model,x,target,radius):
 delta=np.zeros_like(x);best=delta.copy();loss=model.loss_gradient(x,target,False)[0]
 for _ in range(30):
  g=model.loss_gradient(x+delta,target,False)[1];power=(g.reshape(len(x),-1,2)**2).sum(2);indices=np.argsort(power,axis=1)[:,-8:];mask=np.zeros_like(power);np.put_along_axis(mask,indices,1,axis=1);mask=np.repeat(mask,2,axis=1);delta=project((delta-.15*radius*normalize(g*mask))*mask,radius);now=model.loss_gradient(x+delta,target,False)[0];take=now<loss;best[take]=delta[take];loss[take]=now[take]
 return best


def channel_map(delta,h):
 z=h[:,None]*(delta[:,0::2]+1j*delta[:,1::2]);out=np.empty_like(delta);out[:,0::2]=z.real;out[:,1::2]=z.imag;return out


def channel_attack(model,x,target,radius,h):
 delta=np.zeros_like(x);best=delta.copy();loss=model.loss_gradient(x,target,False)[0]
 for _ in range(30):
  g=model.loss_gradient(x+channel_map(delta,h),target,False)[1];gradient=channel_map(g,np.conj(h));delta=project(delta-.15*radius*normalize(gradient),radius);now=model.loss_gradient(x+channel_map(delta,h),target,False)[0];take=now<loss;best[take]=delta[take];loss[take]=now[take]
 return best


def balanced_view(rows,count,seed):
 rng=np.random.default_rng(seed);normal={int(r[3]):r for r in rows if r[5]=='clean'};assert len(normal)==count
 candidates={family:[r for r in rows if r[6]==family and r[7]==1] for family in FAMILIES};orders={k:rng.permutation(len(v)).tolist() for k,v in candidates.items()};selected={};total=int(np.floor(count*.2+.5))
 while len(selected)<total:
  family=FAMILIES[len(selected)%len(FAMILIES)];pool=orders[family]
  while pool and int(candidates[family][pool[-1]][3]) in selected:pool.pop()
  if not pool:raise ValueError('Cannot create train-only mixture without duplicate frames')
  row=candidates[family][pool.pop()];selected[int(row[3])]=row
 result=[selected.get(i,normal[i]) for i in range(count)];assert sum(r[7] for r in result)==total
 return [result[i] for i in rng.permutation(count)]


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);plan=json.loads((a.campaign/'campaign.json').read_text());state={'state':'running'};handles={};writers={};counts={};sources={}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save()
 try:
  for split in ('train','validation','test','train_80_20'):
   handles[split]=(a.output/(split+'.csv')).open('w',newline='');writers[split]=csv.writer(handles[split]);writers[split].writerow(FIELDS);counts[split]=0
  for job in plan['jobs']:
   if job['kind']!='rf_attack' or job['profile']!='diverse':continue
   root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data={};seed=m['inputs']['train']['seed']
   for split in ('train','validation','test'):
    path=root/(split+'.csv');h=hashlib.sha256(path.read_bytes()).hexdigest();assert h==m['inputs'][split]['sha256'];sources[str(path)]=h;data[split]=load_frames(path,c['train_samples'] if split=='train' else c['eval_samples'],c['length'])
   for task in ('sensing','amc'):
    path=root/(task+'-model.npz');sources[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest();model=RFModel.load(path);xx,yy=data['train'][0][task],data['train'][1][task];surrogate,fit=train(xx,yy,data['validation'][0][task],data['validation'][1][task],False,seed+700001,80);surrogate.save(a.output/(job['id']+'-'+task+'-surrogate.npz'));u,v=learned_vectors(model,xx,seed+700000);np.savez_compressed(a.output/(job['id']+'-'+task+'-universal.npz'),universal=u,shift_universal=v)
    for split_index,split in enumerate(('train','validation','test')):
     x,y=data[split][0][task],data[split][1][task];target=np.ones(len(x),dtype=int);radius=np.sqrt(.1)*np.linalg.norm(x,axis=1,keepdims=True);rng_seed=seed+810000+split_index*1009;h=.8*np.exp(1j*np.random.default_rng(rng_seed).uniform(-np.pi,np.pi,len(x)));channel_tx=channel_attack(model,x,target,radius,h)
     deltas={'clean':np.zeros_like(x),'random_control':attack(model,x,target,'random',.1,False,rng_seed),'fgsm':attack(model,x,target,'fgsm',.1,False,rng_seed,30),'pgd':attack(model,x,target,'pgd',.1,False,rng_seed,30),'transfer_pgd':attack(surrogate,x,target,'pgd',.1,False,rng_seed,30),'sparse_8_complex':sparse(model,x,target,radius),'universal':project(np.repeat(u,len(x),axis=0),radius),'shift_eot_universal':project(np.repeat(np.roll(v,8,axis=1),len(x),axis=0),radius),'channel_aware_flat':channel_map(channel_tx,h)}
     np.savez_compressed(a.output/(job['id']+'-'+task+'-'+split+'-perturbations.npz'),fgsm=deltas['fgsm'],pgd=deltas['pgd'],transfer=deltas['transfer_pgd'],sparse=deltas['sparse_8_complex'],channel_tx=channel_tx,channel_h=h)
     eligible=(model.forward(x)[0].argmax(1)==y)&(y!=1);energy=np.maximum(np.sum(x*x,axis=1),1e-30);rows=[]
     for method,delta in deltas.items():
      tx=channel_tx if method=='channel_aware_flat' else delta;tp=np.sum(tx*tx,axis=1)/energy;rp=np.sum(delta*delta,axis=1)/energy;assert np.isfinite(delta).all() and np.max(tp)<=.1+1e-10;moments=features(x+delta);pred=model.forward(x+delta)[0].argmax(1);applied=(np.any(delta!=0,axis=1)&(method not in ('clean','random_control')))
      for i in range(len(x)):
       row=[job['id'],'rf-s'+str(m['inputs'][split]['seed'])+'-'+task+'-'+str(i),task,i,split,method,method if applied[i] else 'none',int(applied[i]),int(eligible[i]),int(pred[i]==1),tp[i],rp[i],*moments[i]];writers[split].writerow(row);rows.append(row);counts[split]+=1
     if split=='train':view=balanced_view(rows,len(x),rng_seed+1);writers['train_80_20'].writerows(view);counts['train_80_20']+=len(view)
     handles[split].flush();handles['train_80_20'].flush();state.update(current_job=job['id'],task=task,split=split,rows=counts);save()
  for f in handles.values():f.close()
  assert counts=={'train':270000,'validation':90000,'test':90000,'train_80_20':30000}
  (a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state.update(state='complete',rows=counts);save();print('Extended split dataset',counts)
 except BaseException as e:
  for f in handles.values():f.close()
  state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
