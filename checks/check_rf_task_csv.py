"""Audit all CSV identities/labels and fixed per-job samples against RF arrays."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from datasets.export_rf_task_csv import digest


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text());manifest=json.loads((a.run/'manifest.json').read_text());handles={};readers={};counts={k:0 for k in ('sensing','amc','channel')};sampled=0
 for name,h in manifest['checksums'].items():assert digest(a.run/name)==h
 try:
  for task in counts:handles[task]=(a.run/(task+'.csv')).open(newline='');readers[task]=csv.reader(handles[task]);next(readers[task])
  pilot=(a.run/'channel_pilots.csv').open(newline='');pr=csv.reader(pilot);next(pr);pilot_count=0
  for job in plan['jobs']:
   if job['kind']!='rf':continue
   assert manifest['verified_job_receipts'][job['id']]==job['attempts'][-1]['receipt_sha256'];root=a.campaign/job['attempts'][-1]['path']/'result';task=job['task']
   with np.load(root/'observations.npz',allow_pickle=False) as o,np.load(root/'labels.npz',allow_pickle=False) as l,np.load(root/'identities.npz',allow_pickle=False) as ids:
    x=o['received'];lab=l['H'] if task=='channel' else l['class'];g,frame=ids['group'],ids['frame'];n=len(x);indices={0,n//2,n-1}
    noise=np.mean(np.sum(o['quiet_calibration']**2,axis=-1),axis=1) if task=='sensing' else None
    if task=='channel':
     for k,v in enumerate(o['pilots']):row=next(pr);assert row[0]==job['id'] and int(row[1])==k and np.array_equal(np.asarray(row[2:],float),v);pilot_count+=1
    for i in range(n):
     bands=range(x.shape[1]) if task=='sensing' else (None,)
     for band in bands:
      row=next(readers[task]);assert row[:4]==[job['id'],task+':seed'+str(job['seed'])+':group'+str(g[i]),str(int(frame[i])),job['role']]
      offset=6 if task=='sensing' else 4;length=x.shape[-2]*2;assert len(row)==offset+length+(length if task=='channel' else 1)
      if task=='sensing':assert int(row[4])==band and np.isclose(float(row[5]),noise[i]);assert int(row[-1])==int(lab[i,band])
      elif task=='amc':assert int(row[-1])==int(lab[i])
      if i in indices:
       expected=x[i,band].ravel() if task=='sensing' else x[i].ravel();assert np.array_equal(np.asarray(row[offset:offset+length],float),expected)
       if task=='channel':assert np.array_equal(np.asarray(row[offset+length:],float),lab[i].ravel())
       sampled+=1
      counts[task]+=1
  for task,rr in readers.items():assert next(rr,None) is None
  assert next(pr,None) is None and counts==manifest['rows']
 finally:
  for f in handles.values():f.close()
  if 'pilot' in locals():pilot.close()
 report={'verified':True,'rows':counts,'pilot_rows':pilot_count,'complete_value_sample_rows':sampled,'scope':'all CSV checksums, widths, source/frame/group/role identities and class labels; pilot values fully checked; IQ/H fully compared for first/middle/last frame of every job, not every scalar'}
 (a.run/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('RF CSV audit',counts,'sampled',sampled)

if __name__=='__main__':main()
