"""Verify representative-inversion outputs and private-record recovery audit."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel,normalize
from ai.rf_model_inversion import nearest_error
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text());rows={};count=0;sources={}
 with (a.run/'inverted_prototypes.csv').open() as f:
  for row in csv.DictReader(f):rows.setdefault((row['source_job'],row['task'],int(row['target_class'])),[]).append(row)
 saved=json.loads((a.run/'metrics.json').read_text())
 for job in plan['jobs']:
  if job['kind']!='rf_attack' or job['profile']!='diverse':continue
  root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];source=root/'train.csv';assert hashlib.sha256(source.read_bytes()).hexdigest()==m['inputs']['train']['sha256'];data,labels=load_frames(source,c['train_samples'],c['length']);seed=m['inputs']['train']['seed'];sources[str(source)]=m['inputs']['train']['sha256']
  for task in ('sensing','amc'):
   path=root/(task+'-model.npz');model=RFModel.load(path);sources[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest();radius=np.sqrt(max(float(model.mean[2]+model.mean[3]),1e-3)*c['length'])
   for target in range(2 if task=='sensing' else 3):
    rr=rows.pop((job['id'],task,target));assert len(rr)==32;prototype=np.array([[float(v[k+str(i)]) for i in range(c['length']) for k in ('i','q')] for v in rr]);random=normalize(np.random.default_rng(seed+82000+target).normal(size=prototype.shape))*radius;out=model.forward(prototype)[0];out-=out.max(1,keepdims=True);prob=np.exp(out);prob/=prob.sum(1,keepdims=True);private=data[task][labels[task]==target];distance=nearest_error(prototype,private);baseline=nearest_error(random,private);metric=next(v for v in saved if v['source_job']==job['id'] and v['task']==task and v['target']==target)
    assert np.max(np.linalg.norm(prototype,axis=1))<=radius+1e-10
    for i,v in enumerate(rr):assert int(v['prototype_id'])==i and int(v['predicted_class'])==int(prob[i].argmax());assert np.isclose(float(v['target_posterior']),prob[i,target]);assert np.isclose(float(v['nearest_member_normalized_mse_audit']),distance[i]);assert np.isclose(float(v['random_nearest_member_normalized_mse_audit']),baseline[i])
    assert np.isclose(metric['mean_nearest_member_normalized_mse'],distance.mean());assert int(metric['approximate_record_recoveries_at_nmse_1e_minus3'])==int(np.sum(distance<1e-3));count+=len(rr)
 assert not rows and count==800
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'prototypes':count,'class_conditions':len(saved),'sources':sources,'scope':'source hashes, output model predictions/posteriors, signal norm and nearest private-member distance; class prototypes are not recovered private waveforms'},indent=2)+'\n');print('Inversion verification',count)

if __name__=='__main__':main()
