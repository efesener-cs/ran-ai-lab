"""Recompute extended RF table predictions and moments from frozen source data."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel,attack,project,features
from simulation.run_rf import load_frames
from simulation.run_research_campaign import verify_receipt


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args()
 plan=json.loads((a.campaign/'campaign.json').read_text());groups={};sources={}
 with (a.run/'observations.csv').open() as f:
  for row in csv.DictReader(f):groups.setdefault((row['source_job'],row['task'],row['method']),[]).append(row)
 report=[];n=0
 for job in plan['jobs']:
  if job['kind']!='rf_attack' or job['profile']!='diverse':continue
  verify_receipt(a.campaign,job)
  root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration']
  data,truth=load_frames(root/'test.csv',c['eval_samples'],c['length'])
  for task in ('sensing','amc'):
   x,y=data[task],truth[task];victim=RFModel.load(root/(task+'-model.npz'));seed=m['inputs']['train']['seed'];target=np.ones(len(y),dtype=int)
   eligible=(victim.forward(x)[0].argmax(1)==y)&(y!=1);radius=np.sqrt(.1)*np.linalg.norm(x,axis=1,keepdims=True)
   path=a.run/(job['id']+'-'+task+'-perturbations.npz')
   with np.load(path,allow_pickle=False) as z:
    transmitted=z['channel_tx'];h=z['channel_h'];v=h[:,None]*(transmitted[:,0::2]+1j*transmitted[:,1::2]);channel=np.empty_like(x);channel[:,0::2]=v.real;channel[:,1::2]=v.imag
    delta={'clean':np.zeros_like(x),'random_control':attack(victim,x,target,'random',.1,False,seed),'transfer_pgd':z['transfer'],'sparse_8_complex':z['sparse'],'universal':project(np.repeat(z['universal'],len(x),axis=0),radius),'shift_eot_universal':project(np.repeat(np.roll(z['shift_universal'],8,axis=1),len(x),axis=0),radius),'channel_aware_flat':channel}
    for mode,d in delta.items():
     rows=groups.pop((job['id'],task,mode));assert len(rows)==len(x)
     observed=features(x+d);pred=victim.forward(x+d)[0].argmax(1);energy=np.sum(x*x,axis=1)
     rx=np.sum(d*d,axis=1)/np.maximum(energy,1e-30);tx=np.sum(transmitted**2,axis=1)/np.maximum(energy,1e-30) if mode=='channel_aware_flat' else rx
     for i,row in enumerate(rows):
      assert int(row['frame_id'])==i and int(row['clean_correct_eligible'])==int(eligible[i])
      assert int(row['target_hit'])==int(pred[i]==1)
      assert np.isclose(float(row['tx_power_ratio']),tx[i],rtol=1e-9,atol=1e-12)
      assert np.isclose(float(row['rx_power_ratio']),rx[i],rtol=1e-9,atol=1e-12)
      assert np.allclose([float(row[k]) for k in ('mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq')],observed[i],rtol=1e-9,atol=1e-12)
     total=int(eligible.sum());hits=int(np.sum(eligible&(pred==1)))
     report.append(dict(source_job=job['id'],task=task,method=mode,eligible=total,hits=hits,conditional_target_rate=hits/total if total else None))
     n+=len(rows)
   for source in (root/'manifest.json',root/(task+'-model.npz'),path):sources[str(source)]=hashlib.sha256(source.read_bytes()).hexdigest()
 assert not groups
 (a.run/'independent-verification.json').write_text(json.dumps(dict(verified=True,rows=n,conditions=report,sources=sources,scope='CSV features, source receipts, model predictions, eligibility and transmitted/received power recomputed'),indent=2)+'\n')
 with (a.run/'condition_metrics.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(report[0]));w.writeheader();w.writerows(report)
 print('Verified',n,'rows',len(report),'conditions')

if __name__=='__main__':main()
