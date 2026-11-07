"""Observed training-row features with source-group-disjoint detector partitions."""
import argparse,csv,json
from pathlib import Path
import numpy as np
from ai.rf import features
from ai.training_attacks import read_table
from simulation.run_rf import load_frames
from simulation.run_research_campaign import verify_receipt

MOMENTS=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('extended',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert json.loads((a.extended/'verification.json').read_text())['verified'];plan=json.loads((a.campaign/'campaign.json').read_text());a.output.parent.mkdir(parents=True,exist_ok=True)
 if a.output.exists():raise FileExistsError(a.output)
 count=0;source_groups={}
 with a.output.with_suffix('.partial').open('w',newline='') as out:
  w=csv.writer(out);w.writerow(['condition_id','source_group_id','task','frame_id','detector_split','transformation','sample_role','attack_family','true_class_audit','provided_training_label',*MOMENTS])
  def write(condition,reference,task,seed,ids,true,observed,provided,selected,method,control=False):
   nonlocal count
   repeat=int(reference.rsplit('-r',1)[1]);split='train' if repeat<3 else ('validation' if repeat==3 else 'test');moments=features(observed)
   for i in range(len(observed)):
    group='rf-s'+str(seed)+'-'+task+'-'+str(ids[i]);old=source_groups.setdefault(group,split);assert old==split
    family=method if selected[i] and not control else 'none';role='random_corruption_control' if selected[i] and control else ('poisoned_training_row' if selected[i] else 'clean_training_row')
    w.writerow([condition,group,task,int(ids[i]),split,method,role,family,int(true[i]),int(provided[i]),*moments[i]]);count+=1
  for job in plan['jobs']:
   if job['kind']!='training_attack':continue
   verify_receipt(a.campaign,job);root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());reference=job['parent'];seed=m['original_inputs']['train']['seed'];conditions=json.loads((root/'summary.json').read_text())['conditions']
   for row in conditions:
    if row['mode']=='none':continue
    path=root/row['training'];x,provided,ids=read_table(path,row['task']);audit=list(csv.DictReader(Path(str(path)+'.audit.csv').open()));truth=np.array([int(v['clean_label']) for v in audit]);selected=np.array([bool(int(v['selected'])) for v in audit]);assert np.array_equal(ids,[int(v['id']) for v in audit])
    method={'backdoor':'static_backdoor','label_flip':'label_flip','feature_noise':'random_feature_corruption_control'}[row['mode']];condition=job['id']+'-'+row['task']+'-'+row['mode']+'-'+str(row['fraction_requested']);write(condition,reference,row['task'],seed,ids,truth,x,provided,selected,method,row['mode']=='feature_noise')
  cache={}
  for row in csv.DictReader((a.extended/'model_outcomes.csv').open()):
   reference=row['source_job'];task=row['task'];key=(reference,task)
   if key not in cache:
    job=next(j for j in plan['jobs'] if j['id']==reference);root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];xx,yy=load_frames(root/'train.csv',c['train_samples'],c['length']);cache[key]=(xx[task],yy[task],m['inputs']['train']['seed'])
   x,y,seed=cache[key];observed=x.copy();provided=y.copy();selected=np.zeros(len(x),dtype=bool)
   with np.load(a.extended/(row['condition_id']+'-transform.npz'),allow_pickle=False) as z:indices=z['indices'];observed[indices]+=z['delta'];provided[indices]=z['training_labels'];selected[indices]=True
   write(row['condition_id'],reference,task,seed,np.arange(len(x)),y,observed,provided,selected,row['method'])
 assert count==720000
 a.output.with_suffix('.partial').rename(a.output);a.output.with_suffix('.metadata.json').write_text(json.dumps({'rows':count,'features':MOMENTS+['provided_training_label'],'target':'attack_family','split':'All variants of a source frame stay in seed repetition0/1/2 train,3 validation,4 test. These are detector-relative roles, not victim training/validation roles.','controls':'Random feature corruption is an explicit negative control, not automatically malicious.','excluded':'true_class_audit, IDs, transformation, sample_role, condition and partition are never inputs.'},indent=2)+'\n');print('Training integrity feature rows',count)

if __name__=='__main__':main()
