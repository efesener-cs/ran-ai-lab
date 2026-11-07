"""Consolidate all accepted original benchmark runs into lossless CSV views."""
import argparse,csv,json,hashlib
from pathlib import Path
import numpy as np
from ai.rf import features
from simulation.run_rf import load_frames
from simulation.run_benchmark import verify_completed


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);plan=json.loads((a.campaign/'campaign.json').read_text());state={'state':'running','jobs':0};writers={};handles={};counts={};receipt_hashes={}
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 def writer(name,header):
  if name not in writers:
   f=(a.output/(name+'.csv')).open('w',newline='');handles[name]=f;w=csv.writer(f);w.writerow(header);writers[name]=(w,header);counts[name]=0
  if writers[name][1]!=header:raise ValueError('Legacy CSV schema changed')
  return writers[name][0]
 save()
 try:
  for job in plan['jobs']:
   if job['phase']!='main' or job['kind'] not in ('rf','ip','training'):continue
   if job['status']!='complete':raise ValueError('Incomplete original job')
   verify_completed(a.campaign,job);receipt_hashes[job['id']]=job['attempts'][-1]['receipt_sha256'];root=a.campaign/job['attempts'][-1]['directory']/'result'
   if job['kind']=='ip':
    with (root/'raw/ip_windows.csv').open() as f:
     rr=csv.reader(f);raw=next(rr);header=['source_job','context_id','split']+[{'label':'attack_applied','attack_type':'attack_family','attack_types':'attack_families','group_id':'source_group_id'}.get(k,k) for k in raw];name='ip_'+job['split'];w=writer(name,header)
     for row in rr:w.writerow([job['id'],job['context']['name'],job['split']]+row);counts[name]+=1
   elif job['kind']=='rf':
    m=json.loads((root/'manifest.json').read_text());c=m['configuration']
    for split in ('train','validation','test'):
     with (root/(split+'.csv')).open() as f:
      rr=csv.reader(f);raw=next(rr);name='rf_inputs_'+split;w=writer(name,['source_job','source_group_id','split','profile','snr_db']+[{'label':'true_task_class','h_i':'true_h_real','h_q':'true_h_imag'}.get(k,k) for k in raw])
      for row in rr:w.writerow([job['id'],'rf-s'+str(m['inputs'][split]['seed'])+'-'+row[0]+'-'+row[1],split,job['profile'],job['snr_db']]+row);counts[name]+=1
    xx,yy=load_frames(root/'test.csv',c['eval_samples'],c['length']);summary=json.loads((root/'summary.json').read_text())['conditions'];name='rf_attack_test';w=writer(name,['source_job','source_group_id','task','frame_id','method','psr_db','attack_applied','input_changed','power_ratio','true_task_target_json','predicted_task_target_json','mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq'])
    for condition in summary:
     task=condition['task'];method=condition['mode'];budget=condition.get('psr_db');filename=task+'-'+method+('' if budget is None else '-'+str(budget))+'-audit.npz'
     with np.load(root/filename,allow_pickle=False) as z:
      delta=z['delta'];pred=z['prediction'];moments=features(xx[task]+delta);ratios=np.sum(delta**2,axis=1)/np.maximum(np.sum(xx[task]**2,axis=1),1e-30)
      for i in range(len(delta)):
       changed=bool(np.any(delta[i]!=0));w.writerow([job['id'],'rf-s'+str(m['inputs']['test']['seed'])+'-'+task+'-'+str(i),task,i,method,'' if budget is None else budget,int(method in ('fgsm','pgd') and changed),int(changed),ratios[i],json.dumps(yy[task][i].tolist()),json.dumps(pred[i].tolist()),*moments[i]]);counts[name]+=1
   else:
    rows=json.loads((root/'summary.json').read_text())['conditions'];name='training_outcomes';w=writer(name,['source_job','task','method','fraction','metrics_json'])
    for row in rows:w.writerow([job['id'],row['task'],row['mode'],row['fraction_requested'],json.dumps(row['metrics'],separators=(',',':'))]);counts[name]+=1
   for f in handles.values():f.flush()
   state.update(jobs=state['jobs']+1,current_job=job['id'],rows=counts);save()
  for f in handles.values():f.close()
  expected={'ip_train':720000,'ip_validation':360000,'ip_test':720000,'rf_inputs_train':540000,'rf_inputs_validation':180000,'rf_inputs_test':180000,'rf_attack_test':1980000,'training_outcomes':130}
  assert counts==expected,(counts,expected)
  (a.output/'manifest.json').write_text(json.dumps({'rows':counts,'receipt_hashes':receipt_hashes,'scope':'Original 665 main benchmark jobs; pilots excluded from detector rows; all original raw evidence retained'},indent=2)+'\n');state.update(state='complete');save();print('Original benchmark CSV complete',counts)
 except BaseException as e:
  for f in handles.values():f.close()
  state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
