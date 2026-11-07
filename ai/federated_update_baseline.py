"""Small fixed Random Forest baseline over held-out federated source seeds."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,balanced_accuracy_score,f1_score
import sklearn,joblib

FEATURES=['update_l2','update_linf','update_mean','update_std']


def main():
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();verification=json.loads((a.run/'verification.json').read_text());assert verification['verified']
 rows=list(csv.DictReader((a.run/'client_updates.csv').open()));parts={k:[] for k in ('train','validation','test')}
 for row in rows:
  repeat=int(row['source_job'].rsplit('-r',1)[1]);role='train' if repeat<3 else ('validation' if repeat==3 else 'test');parts[role].append(row)
 arrays={role:(np.array([[float(r[f]) for f in FEATURES] for r in rr]),np.array([r['attack_family'] for r in rr])) for role,rr in parts.items()}
 model=RandomForestClassifier(n_estimators=100,max_depth=12,min_samples_leaf=5,class_weight='balanced_subsample',random_state=940001,n_jobs=1);model.fit(*arrays['train']);classes=['none','sign_flip','replacement_backdoor'];report={}
 for role,(x,y) in arrays.items():
  pred=model.predict(x);report[role]=dict(rows=len(y),macro_f1=float(f1_score(y,pred,labels=classes,average='macro',zero_division=0)),balanced_accuracy=float(balanced_accuracy_score(y,pred)),confusion_matrix=confusion_matrix(y,pred,labels=classes).tolist(),classification_report=classification_report(y,pred,labels=classes,output_dict=True,zero_division=0),source_groups=sorted(set(r['source_job'] for r in parts[role])))
 a.output.mkdir(parents=True,exist_ok=False);joblib.dump(model,a.output/'model.joblib')
 metadata={'features':FEATURES,'target':'attack_family','classes':classes,'split':'repetitions0/1/2 train;3 validation;4 test; all client/round/aggregation/task variants stay in source group','model_parameters':model.get_params(),'sklearn':sklearn.__version__,'input_sha256':hashlib.sha256((a.run/'client_updates.csv').read_bytes()).hexdigest(),'metrics':report,'caveat':'Fixed synthetic attack strengths and IID-client reference only; not external or real O-RAN FL detection.'}
 (a.output/'metrics.json').write_text(json.dumps(metadata,indent=2)+'\n');print('Federated test macro-F1',report['test']['macro_f1'])

if __name__=='__main__':main()
