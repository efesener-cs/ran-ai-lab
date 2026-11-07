"""Descriptive paired source-seed bootstrap summaries, never frame bootstrap."""
import argparse,csv,json
from pathlib import Path
import numpy as np


def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();groups={}
 def add(track,task,condition,metric,seed,value):
  if value is not None:groups.setdefault((track,task,condition,metric),[]).append((seed,float(value)))
 for row in csv.DictReader((a.root/'extended-rf/condition_metrics.csv').open()):add('rf_evasion',row['task'],row['method'],'conditional_target_rate',row['source_job'],float(row['conditional_target_rate']))
 for row in csv.DictReader((a.root/'extended-training/model_outcomes.csv').open()):
  cond=row['method']+'-'+row['fraction'];seed=row['source_job'];add('training_integrity',row['task'],cond,'accuracy_minus_paired_clean',seed,float(row['clean_accuracy'])-float(row['reference_accuracy']));n=int(row['eligible_reference_clean_correct_nontarget'])
  if n:add('training_integrity',row['task'],cond,'trigger_minus_clean_target_rate',seed,(int(row['triggered_target_hits'])-int(row['clean_target_hits']))/n);add('training_integrity',row['task'],cond,'trigger_minus_reference_trigger_rate',seed,(int(row['triggered_target_hits'])-int(row['reference_triggered_target_hits']))/n)
 for row in csv.DictReader((a.root/'federated-poison/model_outcomes.csv').open()):
  cond=row['condition']+'-'+row['aggregation'];add('federated',row['task'],cond,'accuracy_minus_paired_clean',row['source_job'],float(row['clean_accuracy'])-float(row['reference_clean_accuracy']))
 for row in json.loads((a.root/'query-privacy/metrics.json').read_text()):
  method=row['method']
  if method=='label_query_extraction':add('query_privacy',row['task'],method+'-'+str(row['query_budget']),'fidelity',row['source_job'],row['fidelity'])
  elif method=='known_member_loss_inference' and row['role']=='evaluation':add('query_privacy',row['task'],method,'membership_auc',row['source_job'],row['roc_auc'])
  elif method=='output_conditioned_feature_inversion':add('query_privacy',row['task'],method,'normalized_mse_minus_class_mean_baseline',row['source_job'],row['normalized_mse']-row['class_mean_normalized_mse'])
 transfer=list(csv.DictReader((a.root/'serving-transfer-v2/transfer_outcomes.csv').open()));clean={(r['source_job'],r['task']):r for r in transfer if r['condition']=='clean_finetune'}
 for row in transfer:
  ref=clean[(row['source_job'],row['task'])];add('transfer',row['task'],row['condition'],'accuracy_minus_paired_clean',row['source_job'],float(row['test_accuracy'])-float(ref['test_accuracy']))
 rng=np.random.default_rng(943001);out=[]
 for key,values in sorted(groups.items()):
  seeds=[v[0] for v in values];assert len(seeds)==len(set(seeds))==5;v=np.array([x[1] for x in values]);samples=v[rng.integers(0,len(v),size=(5000,len(v)))].mean(1);lo,hi=np.quantile(samples,[.025,.975]);out.append(dict(track=key[0],task=key[1],condition=key[2],metric=key[3],independent_seed_groups=len(v),mean=float(v.mean()),ci95_low=float(lo),ci95_high=float(hi),minimum=float(v.min()),maximum=float(v.max())))
 with (a.root/'data/paired_seed_summary.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
 (a.root/'paired_summary_method.json').write_text(json.dumps({'bootstrap':'5000 resamples of five independent source-seed groups; paired differences computed before resampling','seed':943001,'interpretation':'descriptive exploratory intervals, small n=5, no multiple-comparison correction, no external paper benchmark equivalence','rows':len(out)},indent=2)+'\n');print('Paired seed summary rows',len(out))

if __name__=='__main__':main()
