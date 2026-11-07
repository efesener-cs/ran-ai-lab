"""Fixed Random Forest baselines on observed training rows, grouped by source seed."""
import argparse,json,hashlib
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,f1_score,balanced_accuracy_score
import sklearn,joblib

FEATURES=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq','provided_training_label']
CLASSES=['none','label_flip','static_backdoor','clean_label_targeted_input_poison','availability_loss_poison','dynamic_backdoor']


def main():
 p=argparse.ArgumentParser();p.add_argument('csv',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();data=pd.read_csv(a.csv,usecols=FEATURES+['source_group_id','task','detector_split','attack_family']);seen=set()
 for split in ('train','validation','test'):
  groups=set(data.loc[data.detector_split==split,'source_group_id']);assert groups and not seen&groups;seen.update(groups)
 a.output.mkdir(parents=True,exist_ok=False);results={}
 for task in ('sensing','amc'):
  part=data.loc[data.task==task];train=part.loc[part.detector_split=='train'];assert set(train.attack_family)==set(CLASSES)
  model=RandomForestClassifier(n_estimators=100,max_depth=12,max_leaf_nodes=2048,min_samples_leaf=5,max_samples=.7,class_weight='balanced_subsample',random_state=941001,n_jobs=2);model.fit(train[FEATURES],train.attack_family);report={}
  for split in ('train','validation','test'):
   dd=part.loc[part.detector_split==split];pred=model.predict(dd[FEATURES]);report[split]={'rows':len(dd),'source_groups':dd.source_group_id.nunique(),'macro_f1':float(f1_score(dd.attack_family,pred,labels=CLASSES,average='macro',zero_division=0)),'balanced_accuracy':float(balanced_accuracy_score(dd.attack_family,pred)),'classification_report':classification_report(dd.attack_family,pred,labels=CLASSES,output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix(dd.attack_family,pred,labels=CLASSES).tolist()}
  joblib.dump(model,a.output/(task+'-model.joblib'));results[task]={'model_parameters':model.get_params(),'metrics':report};print(task,'test macro-F1',report['test']['macro_f1'],flush=True)
 h=hashlib.sha256()
 with a.csv.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 (a.output/'metrics.json').write_text(json.dumps({'features':FEATURES,'classes':CLASSES,'target':'attack_family','sklearn':sklearn.__version__,'input_sha256':h.hexdigest(),'results':results,'scope':'Training-row integrity references only; provided label is observable input, true class/IDs/selection/condition are excluded. All source-frame variants stay in one split. Random feature corruption is a negative control. Fixed strengths, one held-out repetition; no external/OOD claim.'},indent=2)+'\n')

if __name__=='__main__':main()
