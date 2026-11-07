"""Verify poisoning transforms, immutable labels/budgets and all saved predictions."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.rf_training_extended import trigger
from ai.training_attacks import classification
from simulation.run_rf import load_frames


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('run',type=Path);a=p.parse_args();plan=json.loads((a.campaign/'campaign.json').read_text())
 for name,h in json.loads((a.run/'sources.json').read_text()).items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==h
 outcomes=list(csv.DictReader((a.run/'model_outcomes.csv').open()));cache={};count=0
 with (a.run/'training_rows.csv').open() as audit,(a.run/'evaluation_predictions.csv').open() as predictions:
  ar,pr=csv.DictReader(audit),csv.DictReader(predictions)
  for row in outcomes:
   job=next(j for j in plan['jobs'] if j['id']==row['source_job']);task=row['task'];name=row['condition_id'];key=(job['id'],task)
   if key not in cache:
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];xx,yy=load_frames(root/'train.csv',c['train_samples'],c['length']);tt,tyy=load_frames(root/'test.csv',c['eval_samples'],c['length']);cache[key]=(xx[task],yy[task],tt[task],tyy[task],m['inputs']['train']['seed'])
   x,y,tx,ty,seed=cache[key]
   with np.load(a.run/(name+'-transform.npz'),allow_pickle=False) as z:
    indices,delta,labels=z['indices'],z['delta'],z['training_labels'];n=int(np.floor(len(x)*float(row['fraction'])+.5));assert len(indices)==n==int(row['selected']) and len(set(indices.tolist()))==n
    selected=np.zeros(len(x),dtype=bool);selected[indices]=True;px=x.copy();py=y.copy();px[indices]+=delta;py[indices]=labels;ratio=np.sum((px-x)**2,axis=1)/np.maximum(np.sum(x*x,axis=1),1e-30)
    if row['method']=='dynamic_backdoor':assert np.all(y[indices]!=1) and np.all(labels==1);assert np.allclose(px[indices],trigger(x[indices],seed+66000))
    else:assert np.array_equal(py,y) and np.max(ratio)<=10**(-6/10)+1e-10
    if row['method']=='clean_label_targeted_input_poison':assert np.all(y[indices]==1)
    for i in range(len(x)):
     v=next(ar);assert v['condition_id']==name and int(v['frame_id'])==i and int(v['selected'])==int(selected[i]);assert int(v['true_label'])==y[i] and int(v['training_label'])==py[i];assert int(v['iq_changed'])==int(np.any(px[i]!=x[i]));assert np.isclose(float(v['power_ratio']),ratio[i],rtol=1e-9,atol=1e-12)
   model=RFModel.load(a.run/(name+'-model.npz'));ref=RFModel.load(a.run/(job['id']+'-'+task+'-reference.npz'));clean=model.forward(tx)[0].argmax(1);rc=ref.forward(tx)[0].argmax(1);probe=trigger(tx,seed+55000);random=trigger(tx,seed+55000,True);tr=model.forward(probe)[0].argmax(1);rd=model.forward(random)[0].argmax(1);rt=ref.forward(probe)[0].argmax(1);eligible=(rc==ty)&(ty!=1)
   assert np.isclose(float(row['clean_accuracy']),np.mean(clean==ty));assert np.isclose(float(row['reference_accuracy']),np.mean(rc==ty));assert np.isclose(float(row['clean_macro_f1']),classification(ty,clean,2 if task=='sensing' else 3)['macro_f1']);assert int(row['eligible_reference_clean_correct_nontarget'])==int(eligible.sum())
   for field,pred in (('clean_target_hits',clean),('triggered_target_hits',tr),('random_patch_target_hits',rd),('reference_triggered_target_hits',rt)):assert int(row[field])==int(np.sum(eligible&(pred==1)))
   for i in range(len(tx)):
    v=next(pr);assert v['condition_id']==name and int(v['frame_id'])==i;assert [int(v[k]) for k in ('true_label','reference_clean','model_clean','model_triggered','model_random_patch')]==[int(ty[i]),int(rc[i]),int(clean[i]),int(tr[i]),int(rd[i])]
   count+=1
  assert next(ar,None) is None and next(pr,None) is None
 assert count==120
 (a.run/'verification.json').write_text(json.dumps({'verified':True,'conditions':count,'scope':'source hashes, selected identities/labels/IQ budgets/trigger geometry and all saved test predictions and reported metrics; optimizer training not independently refit'},indent=2)+'\n');print('Verified training conditions',count)

if __name__=='__main__':main()
