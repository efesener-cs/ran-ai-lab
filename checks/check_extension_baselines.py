"""Reload fixed RF baselines and reproduce every recorded split metric."""
import argparse,json,hashlib
from pathlib import Path
import pandas as pd
import joblib
from sklearn.metrics import f1_score,balanced_accuracy_score,confusion_matrix


def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()


def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();r=a.root;reports={}
 path=r/'baselines/training-integrity-family';m=json.loads((path/'metrics.json').read_text());data_path=r/'data/training_integrity_features.csv';assert sha(data_path)==m['input_sha256'];data=pd.read_csv(data_path,usecols=m['features']+['source_group_id','task','detector_split','attack_family']);seen=set()
 for role in ('train','validation','test'):
  groups=set(data.loc[data.detector_split==role,'source_group_id']);assert not seen&groups;seen.update(groups)
 for task,result in m['results'].items():
  model=joblib.load(path/(task+'-model.joblib'))
  for role,saved in result['metrics'].items():
   part=data.loc[(data.task==task)&(data.detector_split==role)];pred=model.predict(part[m['features']]);assert len(part)==saved['rows'];assert abs(float(f1_score(part.attack_family,pred,labels=m['classes'],average='macro',zero_division=0))-saved['macro_f1'])<1e-12;assert confusion_matrix(part.attack_family,pred,labels=m['classes']).tolist()==saved['confusion_matrix']
 reports['training_integrity']='all six task/split metrics and group separation verified'
 path=r/'baselines/federated-update-family';m=json.loads((path/'metrics.json').read_text());data_path=r/'federated-poison/client_updates.csv';assert sha(data_path)==m['input_sha256'];data=pd.read_csv(data_path);repeat=data.source_job.str.rsplit('-r',n=1).str[-1].astype(int);model=joblib.load(path/'model.joblib')
 for role,mask in (('train',repeat<3),('validation',repeat==3),('test',repeat==4)):
  part=data.loc[mask];pred=model.predict(part[m['features']].to_numpy());saved=m['metrics'][role];assert len(part)==saved['rows'];assert abs(float(f1_score(part.attack_family,pred,labels=m['classes'],average='macro',zero_division=0))-saved['macro_f1'])<1e-12;assert confusion_matrix(part.attack_family,pred,labels=m['classes']).tolist()==saved['confusion_matrix']
 reports['federated']='all split metrics verified'
 (r/'baselines/extension-verification.json').write_text(json.dumps({'verified':True,'reports':reports,'scope':'saved model roundtrip, unchanged input hashes, group partitions and stored macro-F1/confusion matrices reproduced'},indent=2)+'\n');print('Baseline roundtrips verified')

if __name__=='__main__':main()
