"""Fixed eight-class RF-method detector; original seed splits, train-only80/20."""
import argparse,json,hashlib
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score,classification_report,confusion_matrix
import sklearn,joblib

FEATURES=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']
CLASSES=['none','fgsm','pgd','transfer_pgd','sparse_8_complex','universal','shift_eot_universal','channel_aware_flat']


def main():
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert json.loads((a.run/'verification.json').read_text())['verified'];data={};hashes={};seen=set()
 for role,name in (('train','train_80_20.csv'),('validation','validation.csv'),('test','test.csv')):
  path=a.run/name;hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest();dd=pd.read_csv(path,usecols=FEATURES+['source_group_id','task','attack_family','requested_method']);groups=set(dd.source_group_id);assert not seen&groups;seen.update(groups);data[role]=dd
 a.output.mkdir(parents=True,exist_ok=False);results={}
 for task in ('sensing','amc'):
  train=data['train'].loc[data['train'].task==task];assert set(train.attack_family)==set(CLASSES);model=RandomForestClassifier(n_estimators=100,max_depth=12,max_leaf_nodes=2048,min_samples_leaf=5,max_samples=.8,class_weight='balanced_subsample',random_state=944001,n_jobs=2);model.fit(train[FEATURES],train.attack_family);scores={}
  for role,dd in data.items():
   part=dd.loc[dd.task==task];pred=model.predict(part[FEATURES]);metrics={'rows':len(part),'source_frame_groups':part.source_group_id.nunique(),'macro_f1':float(f1_score(part.attack_family,pred,labels=CLASSES,average='macro',zero_division=0)),'classification_report':classification_report(part.attack_family,pred,labels=CLASSES,output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix(part.attack_family,pred,labels=CLASSES).tolist(),'by_requested_method':{}}
   for method in sorted(part.requested_method.unique()):
    mask=(part.requested_method==method).to_numpy();actual=(part.attack_family.to_numpy()[mask]!='none');reported=(pred[mask]!='none');metrics['by_requested_method'][method]={'rows':int(mask.sum()),'actually_applied_attacks':int(actual.sum()),'binary_detection_rate':float(reported[actual].mean()) if actual.any() else None,'false_alarm_on_unchanged_or_control':float(reported[~actual].mean()) if (~actual).any() else None}
   scores[role]=metrics
  path=a.output/(task+'-model.joblib');joblib.dump(model,path);loaded=joblib.load(path);test=data['test'].loc[data['test'].task==task];again=loaded.predict(test[FEATURES]);assert confusion_matrix(test.attack_family,again,labels=CLASSES).tolist()==scores['test']['confusion_matrix'];results[task]={'parameters':model.get_params(),'metrics':scores};print(task,'extended test macro-F1',scores['test']['macro_f1'],flush=True)
 (a.output/'metrics.json').write_text(json.dumps({'features':FEATURES,'classes':CLASSES,'input_sha256':hashes,'sklearn':sklearn.__version__,'results':results,'roundtrip_verified':True,'scope':'Known victims and fixed budgets, disjoint source frames; no unseen-victim/OOD or attribution guarantee. Training30,000rows exactly80/20; validation/test retain full controlled condition inventory.'},indent=2)+'\n')

if __name__=='__main__':main()
