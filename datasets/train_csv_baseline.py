"""Train the small RF baselines directly from a CSV release, without raw archives."""
import argparse,json
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,f1_score
import joblib


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('.'));p.add_argument('--track',choices=['rf','training','federated'],default='rf');p.add_argument('--task',choices=['sensing','amc'],default='sensing');p.add_argument('--output',type=Path,default=Path('baseline-rerun'));a=p.parse_args();root=a.root
 if a.track=='rf':
  meta=json.loads((root/'baselines/rf-extended-family/metrics.json').read_text());features=meta['features'];classes=meta['classes'];params=meta['results'][a.task]['parameters'];parts={}
  for role,name in (('train','train_80_20'),('validation','validation'),('test','test')):
   dd=pd.read_csv(root/('data/detection/rf_extended_'+name+'.csv'),usecols=features+['task','source_group_id','attack_family']);parts[role]=dd.loc[dd.task==a.task]
 elif a.track=='training':
  meta=json.loads((root/'baselines/training-integrity-family/metrics.json').read_text());features=meta['features'];classes=meta['classes'];params=meta['results'][a.task]['model_parameters'];dd=pd.read_csv(root/'data/detection/training_integrity.csv',usecols=features+['task','detector_split','source_group_id','attack_family']);dd=dd.loc[dd.task==a.task];parts={role:dd.loc[dd.detector_split==role] for role in ('train','validation','test')}
 else:
  meta=json.loads((root/'baselines/federated-update-family/metrics.json').read_text());features=meta['features'];classes=meta['classes'];params=meta['model_parameters'];dd=pd.read_csv(root/'data/detection/federated_updates.csv');repeat=dd.source_job.str.rsplit('-r',n=1).str[-1].astype(int);dd['source_group_id']=dd.source_job;parts={'train':dd.loc[repeat<3],'validation':dd.loc[repeat==3],'test':dd.loc[repeat==4]}
 seen=set()
 for role,part in parts.items():
  groups=set(part.source_group_id);assert groups and not seen&groups;seen.update(groups)
 model=RandomForestClassifier(**params);model.fit(parts['train'][features],parts['train'].attack_family);results={}
 for role,part in parts.items():
  pred=model.predict(part[features]);results[role]={'rows':len(part),'macro_f1':float(f1_score(part.attack_family,pred,labels=classes,average='macro',zero_division=0)),'classification_report':classification_report(part.attack_family,pred,labels=classes,output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix(part.attack_family,pred,labels=classes).tolist()}
 a.output.mkdir(parents=True,exist_ok=False);joblib.dump(model,a.output/'model.joblib');(a.output/'metrics.json').write_text(json.dumps({'features':features,'classes':classes,'parameters':params,'results':results},indent=2)+'\n');print('Test macro-F1',results['test']['macro_f1'])

if __name__=='__main__':main()
