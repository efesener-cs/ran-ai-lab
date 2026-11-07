"""Verify membership partitions, query transcripts and feature-inversion errors."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score,roc_auc_score,average_precision_score
from ai.rf import RFModel,features
from ai.rf_query_privacy import probabilities
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text());metrics=json.loads((a.run/'metrics.json').read_text());sources=json.loads((a.run/'sources.json').read_text())
 for name,digest in sources.items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest
 members={};inv={}
 with (a.run/'membership_queries.csv').open() as f:
  for row in csv.DictReader(f):members.setdefault((row['source_job'],row['task'],row['attack_role']),[]).append(row)
 with (a.run/'inversion_predictions.csv').open() as f:
  for row in csv.DictReader(f):inv.setdefault((row['source_job'],row['task']),[]).append(row)
 count=0
 for job in plan['jobs']:
  if job['kind']!='rf_attack' or job['profile']!='diverse':continue
  root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data={s:load_frames(root/(s+'.csv'),c['train_samples'] if s=='train' else c['eval_samples'],c['length']) for s in ('train','validation','test')}
  for task in ('sensing','amc'):
   victim=RFModel.load(root/(task+'-model.npz'));x,y=data['train'][0][task],data['train'][1][task];ex,ey=data['test'][0][task],data['test'][1][task];ep=probabilities(victim,ex);teacher=ep.argmax(1);fx,fe=features(x),features(ex);seed=m['inputs']['train']['seed']
   all_probs={split:probabilities(victim,data[split][0][task]) for split in ('train','validation','test')}
   relevant=[v for v in metrics if v['source_job']==job['id'] and v['task']==task];assert len(relevant)==6
   for budget in (128,512,2048):
    path=a.run/(job['id']+'-'+task+'-queries-'+str(budget)+'.csv');rows=list(csv.DictReader(path.open()));ids=np.array([int(v['training_frame_id']) for v in rows]);labels=np.array([int(v['returned_class']) for v in rows]);assert len(ids)==budget and len(set(ids.tolist()))==budget
    assert np.array_equal(labels,probabilities(victim,x[ids]).argmax(1))
    student=RandomForestClassifier(n_estimators=100,max_depth=16,min_samples_leaf=5,n_jobs=1,random_state=seed+budget);student.fit(fx[ids],labels);pred=student.predict(fe)
    saved=next(v for v in relevant if v['method']=='label_query_extraction' and v['query_budget']==budget)
    assert np.isclose(saved['fidelity'],accuracy_score(teacher,pred)) and np.isclose(saved['student_task_accuracy'],accuracy_score(ey,pred));count+=1
   seen=set()
   for role in ('calibration','evaluation'):
    rows=members.pop((job['id'],task,role));ids={(v['source_split'],int(v['frame_id'])) for v in rows};assert len(ids)==len(rows) and not (seen&ids);seen.update(ids)
    saved=next(v for v in relevant if v['method']=='known_member_loss_inference' and v['role']==role);labels=[];scores=[];class_counts={0:{},1:{}}
    for v in rows:
     split=v['source_split'];i=int(v['frame_id']);member=int(v['member_target']);truth=int(v['true_class']);xx,yy=data[split][0][task],data[split][1][task];assert truth==yy[i] and member==int(split=='train')
     assert split=='train' or split==('validation' if role=='calibration' else 'test')
     score=float(np.log(max(all_probs[split][i,truth],1e-30)));assert np.isclose(score,float(v['score_negative_loss']))
     labels.append(member);scores.append(float(v['score_negative_loss']));class_counts[member][truth]=class_counts[member].get(truth,0)+1
    assert class_counts[0]==class_counts[1]
    labels=np.array(labels);scores=np.array(scores);assert np.isclose(roc_auc_score(labels,scores),saved['roc_auc']);assert np.isclose(average_precision_score(labels,scores),saved['average_precision']);assert np.isclose(accuracy_score(labels,scores>=saved['threshold']),saved['accuracy']);count+=1
   rows=inv.pop((job['id'],task));assert len(rows)==len(ex)*7
   values=np.array([[float(v['true_feature']),float(v['reconstructed_feature']),float(v['class_mean_baseline'])] for v in rows]).reshape(len(ex),7,3);assert np.allclose(values[:,:,0],fe)
   scale=np.maximum(fx.std(0),1e-4);saved=next(v for v in relevant if v['method']=='output_conditioned_feature_inversion')
   assert np.isclose(np.mean(((values[:,:,1]-fe)/scale)**2),saved['normalized_mse']);assert np.isclose(np.mean(((values[:,:,2]-fe)/scale)**2),saved['class_mean_normalized_mse']);count+=1
 assert not members and not inv
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'conditions':count,'scope':'source hashes, deterministic extraction refits, membership disjointness/class matching/scores/metrics, inversion error arithmetic; no raw waveform/privacy generalization claim'},indent=2)+'\n');print('Verified query/privacy conditions',count)

if __name__=='__main__':main()
