"""Four compact-count CSV tables from verified RF task arrays; no simulation."""
import argparse,csv,json,hashlib,os
from pathlib import Path
import numpy as np
from simulation.run_research_campaign import verify_receipt


def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();stage=a.output.with_name(a.output.name+'.partial');stage.mkdir(parents=True,exist_ok=False);plan=json.loads((a.campaign/'campaign.json').read_text());state={'state':'running','jobs':0};writers={};handles={};counts={};sources={};groups={};seed_roles={}
 def save():
  t=stage/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(stage/'status.json')
 save()
 try:
  pilot= (stage/'channel_pilots.csv').open('w',newline='');pw=csv.writer(pilot);pw.writerow(['source_job','subcarrier','pilot_i','pilot_q']);handles['pilots']=pilot
  for job in plan['jobs']:
   if job['kind']!='rf':continue
   if job['state']!='complete':raise ValueError('Incomplete RF job')
   verify_receipt(a.campaign,job);root=a.campaign/job['attempts'][-1]['path']/'result';task=job['task'];old_role=seed_roles.setdefault(job['seed'],job['role']);assert old_role==job['role'];sources[job['id']]=job['attempts'][-1]['receipt_sha256']
   with np.load(root/'observations.npz',allow_pickle=False) as observations,np.load(root/'labels.npz',allow_pickle=False) as labels,np.load(root/'identities.npz',allow_pickle=False) as identity:
    x=observations['received'];n=len(x);g=identity['group'];frame=identity['frame'];assert len(g)==n and len(frame)==n and np.isfinite(x).all()
    iq_columns=[f'{v}{i}' for i in range(x.shape[-2]) for v in ('i','q')]
    if task not in writers:
     fields=['source_job','source_group','frame_id','split']+(['band','quiet_mean_power'] if task=='sensing' else [])+iq_columns
     fields+= [f'true_h_{v}{i}' for i in range(x.shape[-2]) for v in ('i','q')] if task=='channel' else ['true_task_class']
     handle=(stage/(task+'.csv')).open('w',newline='');handles[task]=handle;writer=csv.writer(handle);writer.writerow(fields);writers[task]=writer;counts[task]=0
    if task=='channel':
     pilots=observations['pilots'];assert pilots.shape==x.shape[1:]
     for i,v in enumerate(pilots):pw.writerow([job['id'],i,*v])
    noise=np.mean(np.sum(observations['quiet_calibration']**2,axis=-1),axis=1) if task=='sensing' else None
    lab=labels['H'] if task=='channel' else labels['class']
    for i in range(n):
     gid=task+':seed'+str(job['seed'])+':group'+str(g[i]);role=job['role'];old=groups.setdefault((task,gid),role)
     if old!=role:raise ValueError('RF source group crosses roles')
     base=[job['id'],gid,int(frame[i]),role]
     if task=='sensing':
      for band in range(x.shape[1]):writers[task].writerow(base+[band,float(noise[i])]+x[i,band].ravel().tolist()+[int(lab[i,band])]);counts[task]+=1
     elif task=='amc':writers[task].writerow(base+x[i].ravel().tolist()+[int(lab[i])]);counts[task]+=1
     else:writers[task].writerow(base+x[i].ravel().tolist()+lab[i].ravel().tolist());counts[task]+=1
   state.update(jobs=state['jobs']+1,current_job=job['id'],rows=counts);save()
  for handle in handles.values():handle.close()
  manifest=dict(scope='RF victim-task CSV views, not adversarial method labels',rows=counts,verified_job_receipts=sources,split_policy='source group stays in recorded role; band variants stay together',lossy_calibration='Quiet-calibration samples reduced to observed mean power; full raw arrays preserved in original archive',channel_pilot_contract='join source_job with channel_pilots; IDs are not numerical features',checksums={p.name:digest(p) for p in stage.glob('*.csv')})
  (stage/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');state.update(state='complete');save()
  if a.output.exists():raise FileExistsError(a.output)
  stage.rename(a.output);print('Exported RF task CSV',counts,flush=True)
 except BaseException as e:
  for handle in handles.values():handle.close()
  state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
