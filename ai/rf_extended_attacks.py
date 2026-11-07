"""Additional receiver-IQ threat models; independently labeled CSV evidence."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel,train,attack,normalize,project,features
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 plan=json.loads((a.campaign/'campaign.json').read_text());a.output.mkdir(parents=True,exist_ok=False)
 state={'state':'running','scope':'synthetic receiver IQ; model-level interventions, not OTA or RAN control'}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save();sources={};count=0
 try:
  with (a.output/'observations.csv').open('w',newline='') as f:
   w=csv.writer(f);w.writerow(['source_job','task','frame_id','method','attack_applied','clean_correct_eligible','target_hit','tx_power_ratio','rx_power_ratio','mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq'])
   for job in plan['jobs']:
    if job['kind']!='rf_attack' or job['profile']!='diverse':continue
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration']
    data={}
    for split in ('train','validation','test'):
     path=root/(split+'.csv');digest=hashlib.sha256(path.read_bytes()).hexdigest()
     if digest!=m['inputs'][split]['sha256']:raise ValueError('Source data changed')
     sources[str(path)]=digest;data[split]=load_frames(path,c['train_samples'] if split=='train' else c['eval_samples'],c['length'])
    for task in ('sensing','amc'):
     x,y=data['test'][0][task],data['test'][1][task];tx,ty=data['train'][0][task],data['train'][1][task]
     vx,vy=data['validation'][0][task],data['validation'][1][task]
     victim=RFModel.load(root/(task+'-model.npz'));seed=m['inputs']['train']['seed'];rng=np.random.default_rng(seed+700000)
     surrogate,fit=train(tx,ty,vx,vy,False,seed+700001,80)
     target=np.ones(len(y),dtype=int);eligible=(victim.forward(x)[0].argmax(1)==y)&(y!=1)
     radius=np.sqrt(.1)*np.linalg.norm(x,axis=1,keepdims=True)
     # Universal perturbations use training inputs only and a fixed global radius.
     radius_global=float(np.sqrt(.1)*np.min(np.linalg.norm(tx,axis=1)))
     universal=np.zeros((1,tx.shape[1]));shift_universal=universal.copy()
     for step in range(30):
      batch=tx[rng.choice(len(tx),min(128,len(tx)),replace=False)];target_batch=np.ones(len(batch),dtype=int)
      g=victim.loss_gradient(batch+universal,target_batch,False)[1].mean(0,keepdims=True)
      universal=project(universal-.15*radius_global*normalize(g),radius_global)
      grad=np.zeros_like(shift_universal)
      for shift in (-4,0,4):
       perturb=np.roll(shift_universal,2*shift,axis=1)
       g=victim.loss_gradient(batch+perturb,target_batch,False)[1].mean(0,keepdims=True)
       grad+=np.roll(g,-2*shift,axis=1)/3
      shift_universal=project(shift_universal-.15*radius_global*normalize(grad),radius_global)
     transfer=attack(surrogate,x,target,'pgd',.1,False,seed+800001,30)
     sparse=np.zeros_like(x)
     for step in range(30):
      g=victim.loss_gradient(x+sparse,target,False)[1]
      pair=(g.reshape(len(x),-1,2)**2).sum(2);support=np.argsort(pair,axis=1)[:,-8:]
      mask=np.zeros_like(pair);np.put_along_axis(mask,support,1,axis=1);g*=np.repeat(mask,2,axis=1)
      sparse=project((sparse-.15*radius*normalize(g))*np.repeat(mask,2,axis=1),radius)
     phase=rng.uniform(-np.pi,np.pi,len(x));h=.8*np.exp(1j*phase)
     def channel(d):
      z=d[:,0::2]+1j*d[:,1::2];v=h[:,None]*z;out=np.empty_like(d);out[:,0::2]=v.real;out[:,1::2]=v.imag;return out
     channel_tx=np.zeros_like(x)
     for step in range(30):
      g=victim.loss_gradient(x+channel(channel_tx),target,False)[1];z=g[:,0::2]+1j*g[:,1::2];z*=np.conj(h[:,None]);grad=np.empty_like(g);grad[:,0::2]=z.real;grad[:,1::2]=z.imag
      channel_tx=project(channel_tx-.15*radius*normalize(grad),radius)
     methods=[('clean',np.zeros_like(x),None),('random_control',attack(victim,x,target,'random',.1,False,seed),None),('transfer_pgd',transfer,None),('universal',project(np.repeat(universal,len(x),axis=0),radius),None),('sparse_8_complex',sparse,None),('shift_eot_universal',project(np.repeat(np.roll(shift_universal,8,axis=1),len(x),axis=0),radius),None),('channel_aware_flat',channel(channel_tx),channel_tx)]
     for method,delta,transmitted in methods:
      rx=(delta*delta).sum(1)/np.maximum((x*x).sum(1),1e-30);td=delta if transmitted is None else transmitted;tp=(td*td).sum(1)/np.maximum((x*x).sum(1),1e-30)
      if np.max(tp)>.1+1e-10 or not np.isfinite(delta).all():raise ValueError('Budget violation')
      moments=features(x+delta);pred=victim.forward(x+delta)[0].argmax(1);malicious=method not in ('clean','random_control')
      for i in range(len(x)):w.writerow([job['id'],task,i,method,int(malicious and np.any(delta[i]!=0)),int(eligible[i]),int(pred[i]==1),tp[i],rx[i],*moments[i]])
      count+=len(x);f.flush();state.update(rows=count,current_job=job['id'],current_task=task,current_method=method);save()
     np.savez_compressed(a.output/(job['id']+'-'+task+'-perturbations.npz'),universal=universal,shift_universal=shift_universal,transfer=transfer,sparse=sparse,channel_tx=channel_tx,channel_h=h)
  (a.output/'sources.json').write_text(json.dumps(sources,indent=2));state.update(state='complete',rows=count);save()
 except BaseException as e:state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
