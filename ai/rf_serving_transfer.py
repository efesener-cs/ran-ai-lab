"""Concrete model-artifact/output tampering and poisoned transfer fine-tuning."""
import argparse,csv,json,copy,shutil,hashlib,subprocess
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.rf_training_extended import trigger
from simulation.run_rf import load_frames


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
 p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--training',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert json.loads((a.training/'status.json').read_text())['state']=='complete';a.output.mkdir(parents=True,exist_ok=False)
 plan=json.loads((a.campaign/'campaign.json').read_text());state={'state':'running'};sources={};count=0
 def save():
  t=a.output/'status.tmp';t.write_text(json.dumps(state,indent=2));t.replace(a.output/'status.json')
 save()
 try:
  with (a.output/'serving_requests.csv').open('w',newline='') as sf,(a.output/'transfer_outcomes.csv').open('w',newline='') as tf:
   sw=csv.writer(sf);sw.writerow(['source_job','task','frame_id','condition','model_artifact_changed','trusted_hash_check_passed','true_class','trusted_shadow_prediction','reported_prediction','output_changed','eligible_clean_correct_nontarget','target_hit'])
   tw=csv.writer(tf);tw.writerow(['source_job','target_job','task','condition','selected_epoch','validation_accuracy','test_accuracy','eligible_clean_reference_correct_nontarget','triggered_target_hits','reference_triggered_hits'])
   for job in plan['jobs']:
    if job['kind']!='rf_attack' or job['profile']!='diverse':continue
    root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration'];test,truth=load_frames(root/'test.csv',c['eval_samples'],c['length']);repeat=int(job['id'].rsplit('-r',1)[1])
    assert sha(root/'test.csv')==m['inputs']['test']['sha256'];sources[str(root/'test.csv')]=sha(root/'test.csv')
    tr=a.output/('fresh-target-r'+str(repeat));tr.mkdir();binary=root/'rf-generator';assert sha(binary)==m['binary_sha256'];sources[str(binary)]=sha(binary);tm={'inputs':{}};tc=c
    for role,base in (('train',1810001),('validation',1820001),('test',1830001)):
     new_seed=base+repeat;assert new_seed not in c['seeds'];samples=c['train_samples'] if role=='train' else c['eval_samples'];path=tr/(role+'.csv')
     command=[str(binary),'--samples',str(samples),'--length',str(c['length']),'--seed',str(new_seed),'--snr-db','10','--output',str(path),'--profile','stress']
     with (tr/(role+'.log')).open('w') as log:subprocess.run(command,check=True,stdout=log,stderr=subprocess.STDOUT)
     tm['inputs'][role]={'seed':new_seed,'sha256':sha(path),'command':command}
    (tr/'generation.json').write_text(json.dumps(tm,indent=2)+'\n');target_job={'id':'fresh-stress-r'+str(repeat)};target_data={}
    for split in ('train','validation','test'):
     path=tr/(split+'.csv');assert sha(path)==tm['inputs'][split]['sha256'];sources[str(path)]=sha(path);target_data[split]=load_frames(path,tc['train_samples'] if split=='train' else tc['eval_samples'],tc['length'])
    for task in ('sensing','amc'):
     x,y=test[task],truth[task];seed=m['inputs']['train']['seed'];prefix=job['id']+'-'+task
     clean_path=a.training/(prefix+'-reference.npz');bad_path=a.training/(prefix+'-dynamic_backdoor-0.2-model.npz');sources[str(clean_path)]=sha(clean_path);sources[str(bad_path)]=sha(bad_path);reference=RFModel.load(clean_path);shadow=reference.forward(x)[0].argmax(1);eligible=(shadow==y)&(y!=1)
     for condition in ('clean_artifact','replacement_model_artifact','output_label_remap','random_output_control'):
      folder=a.output/(prefix+'-'+condition);folder.mkdir();artifact=folder/'served-model.npz';shutil.copyfile(bad_path if condition=='replacement_model_artifact' else clean_path,artifact);reported=RFModel.load(artifact).forward(x)[0].argmax(1);changed_hash=sha(artifact)!=sha(clean_path)
      if condition=='output_label_remap':reported[:]=1
      if condition=='random_output_control':
       rng=np.random.default_rng(seed+77000);selected=rng.permutation(len(x))[:int(np.sum(shadow!=1))];reported[selected]=rng.integers(0,2 if task=='sensing' else 3,len(selected))
      for i in range(len(x)):sw.writerow([job['id'],task,i,condition,int(changed_hash),int(not changed_hash),int(y[i]),int(shadow[i]),int(reported[i]),int(shadow[i]!=reported[i]),int(eligible[i]),int(reported[i]==1)])
     # Distinct target-domain seed family; all parameters adapted, original scaler retained.
     tx,ty=target_data['train'][0][task],target_data['train'][1][task];vx,vy=target_data['validation'][0][task],target_data['validation'][1][task];ex,ey=target_data['test'][0][task],target_data['test'][1][task];initial=RFModel.load(root/(task+'-model.npz'));sources[str(root/(task+'-model.npz'))]=sha(root/(task+'-model.npz'));references=None
     for condition in ('clean_finetune','poisoned_finetune'):
      model=copy.deepcopy(initial);px=tx.copy();py=ty.copy();rng=np.random.default_rng(seed+78000);indices=rng.permutation(np.flatnonzero(ty!=1))[:int(.2*len(tx))]
      if len(indices)!=int(.2*len(tx)):raise ValueError('Infeasible target-domain poison fraction')
      if condition=='poisoned_finetune':px[indices]=trigger(px[indices],seed+79000);py[indices]=1
      best=None;best_acc=-1;selected_epoch=0
      for epoch in range(20):
       order=np.random.default_rng(seed+80000+epoch).permutation(len(px))
       for start in range(0,len(px),128):
        take=order[start:start+128];grads=model.loss_gradient(px[take],py[take],False)[2];norm=np.sqrt(sum(float(np.sum(g*g)) for g in grads));factor=min(1,10/max(norm,1e-30));model.parameters=[w-.003*factor*g for w,g in zip(model.parameters,grads)]
       acc=float(np.mean(model.forward(vx)[0].argmax(1)==vy))
       if acc>best_acc:best_acc=acc;best=copy.deepcopy(model);selected_epoch=epoch+1
      best.save(a.output/(prefix+'-'+condition+'.npz'));prediction=best.forward(ex)[0].argmax(1);probe_prediction=best.forward(trigger(ex,seed+81000))[0].argmax(1)
      if condition=='clean_finetune':references=(prediction,probe_prediction)
      ref,rp=references;ee=(ref==ey)&(ey!=1);tw.writerow([job['id'],target_job['id'],task,condition,selected_epoch,best_acc,float(np.mean(prediction==ey)),int(ee.sum()),int(np.sum(ee&(probe_prediction==1))),int(np.sum(ee&(rp==1)))])
      count+=1;state.update(conditions=count,current_job=job['id'],task=task,condition=condition);sf.flush();tf.flush();save()
   (a.output/'sources.json').write_text(json.dumps(sources,indent=2)+'\n');state.update(state='complete',conditions=count);save()
 except BaseException as e:state.update(state='failed',error=str(e));save();raise

if __name__=='__main__':main()
