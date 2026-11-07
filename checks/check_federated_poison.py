"""Recompute held-out model outcomes, selection and update-table contracts."""
import argparse,csv,json,hashlib,collections
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.rf_training_extended import trigger
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text())
 for name,h in json.loads((a.run/'sources.json').read_text()).items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==h
 rows=list(csv.DictReader((a.run/'model_outcomes.csv').open()));rounds={};updates=collections.Counter();seen=set()
 with (a.run/'validation_rounds.csv').open() as f:
  for v in csv.DictReader(f):rounds.setdefault((v['source_job'],v['task'],v['condition'],v['aggregation']),[]).append(v)
 with (a.run/'client_updates.csv').open() as f:
  for v in csv.DictReader(f):
   key=tuple(v[k] for k in ('source_job','task','condition','aggregation'));identity=key+(int(v['round']),int(v['client']));assert identity not in seen;seen.add(identity);updates[key]+=1
   malignant=v['condition']!='clean' and int(v['client'])<2;assert int(v['malicious_update'])==int(malignant);assert v['attack_family']==(v['condition'] if malignant else 'none')
   vals=[float(v[k]) for k in ('update_l2','update_linf','update_mean','update_std')];assert np.isfinite(vals).all();assert vals[0]>=vals[1]-1e-12 and min(vals[0],vals[1],vals[3])>=0
 for row in rows:
  job=next(j for j in plan['jobs'] if j['id']==row['source_job']);root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());task=row['task'];data,truth=load_frames(root/'test.csv',m['configuration']['eval_samples'],m['configuration']['length']);x,y=data[task],truth[task];seed=m['inputs']['train']['seed'];aggregation=row['aggregation']
  prefix=job['id']+'-'+task+'-';model=RFModel.load(a.run/(prefix+row['condition']+'-'+aggregation+'.npz'));reference=RFModel.load(a.run/(prefix+'clean-'+aggregation+'.npz'));ref=reference.forward(x)[0].argmax(1);clean=model.forward(x)[0].argmax(1);probe=trigger(x,seed+63000);triggered=model.forward(probe)[0].argmax(1);rt=reference.forward(probe)[0].argmax(1);eligible=(ref==y)&(y!=1)
  assert np.isclose(float(row['clean_accuracy']),np.mean(clean==y));assert np.isclose(float(row['reference_clean_accuracy']),np.mean(ref==y));assert int(row['eligible_reference_clean_correct_nontarget'])==int(eligible.sum());assert int(row['triggered_target_hits'])==int(np.sum(eligible&(triggered==1)));assert int(row['reference_triggered_target_hits'])==int(np.sum(eligible&(rt==1)))
  key=tuple(row[k] for k in ('source_job','task','condition','aggregation'));rr=rounds.pop(key);assert len(rr)==20 and updates[key]==200;best=max(rr,key=lambda q:float(q['validation_accuracy']));assert int(best['round'])==int(row['selected_round'])
 assert not rounds and len(rows)==60
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'models':len(rows),'client_updates':len(seen),'scope':'source hashes, update label/count/numeric contracts, validation-only selected round, clean/probe outcome recomputation from saved models; later-round update vectors not independently replayed'},indent=2)+'\n');print('Verified federated outcomes',len(rows))

if __name__=='__main__':main()
