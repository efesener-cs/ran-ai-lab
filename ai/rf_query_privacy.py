"""Budgeted local model extraction and explicit output-based privacy experiments."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier,RandomForestRegressor
from sklearn.metrics import accuracy_score,roc_auc_score,roc_curve,average_precision_score
from ai.rf import RFModel,features
from simulation.run_rf import load_frames


def probabilities(model,x):
 z=model.forward(x)[0];z-=z.max(1,keepdims=True);p=np.exp(z);return p/p.sum(1,keepdims=True)


def balanced_indices(y,classes,rng):
 pools=[np.flatnonzero(y==c) for c in classes];n=min(map(len,pools))
 if not n:raise ValueError('Missing class in privacy role')
 return np.concatenate([rng.permutation(v)[:n] for v in pools])


def main():
 p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output.mkdir(parents=True,exist_ok=False);state={'state':'running'}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save();plan=json.loads((a.campaign/'campaign.json').read_text());summary=[];sources={}
 try:
  with (a.output/'membership_queries.csv').open('w',newline='') as mf,(a.output/'inversion_predictions.csv').open('w',newline='') as inf:
   mw=csv.writer(mf);mw.writerow(['source_job','task','attack_role','source_split','frame_id','member_target','true_class','score_negative_loss','membership_prediction'])
   iw=csv.writer(inf);iw.writerow(['source_job','task','frame_id','feature_index','true_feature','reconstructed_feature','class_mean_baseline'])
   for job in plan['jobs']:
    if job['kind']!='rf_attack' or job['profile']!='diverse':continue
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];data={}
    for split in ('train','validation','test'):
     source=root/(split+'.csv');digest=hashlib.sha256(source.read_bytes()).hexdigest()
     if digest!=m['inputs'][split]['sha256']:raise ValueError('Input hash mismatch')
     sources[str(source)]=digest;data[split]=load_frames(source,c['train_samples'] if split=='train' else c['eval_samples'],c['length'])
    for task in ('sensing','amc'):
     model_path=root/(task+'-model.npz');sources[str(model_path)]=hashlib.sha256(model_path.read_bytes()).hexdigest();victim=RFModel.load(model_path)
     seed=m['inputs']['train']['seed'];rng=np.random.default_rng(seed+910000);x,y=data['train'][0][task],data['train'][1][task];vx,vy=data['validation'][0][task],data['validation'][1][task];ex,ey=data['test'][0][task],data['test'][1][task]
     probs=probabilities(victim,x);ep=probabilities(victim,ex);vp=probabilities(victim,vx)
     fx,fe=features(x),features(ex);teacher=ep.argmax(1)
     order=rng.permutation(len(x))
     # The attacker sees query inputs and returned class labels, never victim weights/gradients.
     for budget in (128,512,2048):
      indices=order[:min(budget,len(x))];labels=probs[indices].argmax(1)
      student=RandomForestClassifier(n_estimators=100,max_depth=16,min_samples_leaf=5,n_jobs=1,random_state=seed+budget)
      student.fit(fx[indices],labels);prediction=student.predict(fe)
      summary.append(dict(source_job=job['id'],task=task,method='label_query_extraction',query_budget=len(indices),evaluation_queries=len(ex),fidelity=float(accuracy_score(teacher,prediction)),student_task_accuracy=float(accuracy_score(ey,prediction)),victim_task_accuracy=float(accuracy_score(ey,teacher))))
      with (a.output/(job['id']+'-'+task+'-queries-'+str(budget)+'.csv')).open('w',newline='') as f:
       w=csv.writer(f);w.writerow(['training_frame_id','returned_class']);w.writerows(zip(indices.tolist(),labels.tolist()))
     # Known-member calibration is an explicit attacker capability. Evaluation frames are disjoint.
     classes=np.arange(2 if task=='sensing' else 3);member_order=rng.permutation(len(x));middle=len(x)//2;cal_member=member_order[:middle];eval_member=member_order[middle:]
     roles=[('calibration',cal_member,vy,vp,'validation'),('evaluation',eval_member,ey,ep,'test')];threshold=None
     for role,member_pool,non_y,non_p,non_split in roles:
      per_class=min(min(int(np.sum(y[member_pool]==k)),int(np.sum(non_y==k))) for k in classes)
      if per_class<1:raise ValueError('Missing matched privacy class')
      mi=np.concatenate([rng.permutation(member_pool[y[member_pool]==k])[:per_class] for k in classes]);ni=np.concatenate([rng.permutation(np.flatnonzero(non_y==k))[:per_class] for k in classes]);n=len(mi)
      # Class-matched, balanced member/nonmember scores; true-label access is declared.
      scores=np.r_[np.log(np.maximum(probs[mi,y[mi]],1e-30)),np.log(np.maximum(non_p[ni,non_y[ni]],1e-30))];labels=np.r_[np.ones(n,dtype=int),np.zeros(n,dtype=int)]
      if role=='calibration':
       fpr,tpr,ts=roc_curve(labels,scores);valid=np.flatnonzero(np.isfinite(ts));threshold=float(ts[valid[np.argmax((tpr-fpr)[valid])]])
      prediction=(scores>=threshold).astype(int)
      for index,(src,ids,ys) in enumerate((('train',mi,y),(non_split,ni,non_y))):
       for offset,k in enumerate(ids):
        j=index*n+offset;mw.writerow([job['id'],task,role,src,int(k),int(labels[j]),int(ys[k]),scores[j],int(prediction[j])])
      summary.append(dict(source_job=job['id'],task=task,method='known_member_loss_inference',role=role,rows=2*n,threshold=threshold,roc_auc=float(roc_auc_score(labels,scores)),average_precision=float(average_precision_score(labels,scores)),accuracy=float(accuracy_score(labels,prediction)),capability='known member subset, known nonmember calibration set and true class labels'))
     # Feature inversion, not recovery of a training waveform or membership evidence.
     decoder=RandomForestRegressor(n_estimators=100,max_depth=12,min_samples_leaf=5,n_jobs=1,random_state=seed+30000)
     decoder.fit(probs,fx);reconstruction=decoder.predict(ep);class_means=np.array([fx[probs.argmax(1)==k].mean(0) if np.any(probs.argmax(1)==k) else fx.mean(0) for k in classes]);baseline=class_means[teacher];scale=np.maximum(fx.std(0),1e-4)
     summary.append(dict(source_job=job['id'],task=task,method='output_conditioned_feature_inversion',queries=len(x),evaluation_queries=len(ex),normalized_mse=float(np.mean(((reconstruction-fe)/scale)**2)),class_mean_normalized_mse=float(np.mean(((baseline-fe)/scale)**2)),target='seven receiver IQ moments of held-out frames, not raw RF or private training-record reconstruction'))
     for i in range(len(ex)):
      for k in range(7):iw.writerow([job['id'],task,i,k,fe[i,k],reconstruction[i,k],baseline[i,k]])
     mf.flush();inf.flush();state.update(source_job=job['id'],task=task,conditions=len(summary));save()
  (a.output/'metrics.json').write_text(json.dumps(summary,indent=2,allow_nan=False)+'\n');(a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state.update(state='complete',conditions=len(summary));save()
 except BaseException as e:state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
