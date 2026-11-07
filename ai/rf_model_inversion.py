"""White-box class-representative inversion with private data used only for audit."""
import argparse,csv,json
from pathlib import Path
import numpy as np
from ai.rf import RFModel,features,feature_backward,normalize,project
from simulation.run_rf import load_frames


def invert(model,length,target,seed):
 rng=np.random.default_rng(seed);n=32;power=max(float(model.mean[2]+model.mean[3]),1e-3);radius=np.sqrt(power*length);x=rng.normal(size=(n,2*length));x=normalize(x)*radius;initial=x.copy();best=x.copy();best_value=np.full(n,np.inf);targets=np.full(n,target,dtype=int)
 for step in range(101):
  loss,gradient,_=model.loss_gradient(x,targets,False);f=features(x);prior=np.mean(((f-model.mean)/model.scale)**2,axis=1);value=loss+.01*prior;improved=value<best_value;best[improved]=x[improved];best_value[improved]=value[improved]
  gf=2*(f-model.mean)/(7*model.scale**2);gradient+=.01*feature_backward(x,gf);x=project(x-.03*radius*normalize(gradient),radius)
 return best,initial


def nearest_error(query,private):
 result=[]
 for row in query:
  errors=np.mean((private-row)**2,axis=1)/np.maximum(np.mean(private**2,axis=1),1e-30);result.append(float(errors.min()))
 return np.array(result)


def main():
 p=argparse.ArgumentParser();p.add_argument('campaign',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);plan=json.loads((a.campaign/'campaign.json').read_text());results=[]
 with (a.output/'inverted_prototypes.csv').open('w',newline='') as f:
  w=csv.writer(f);header=None
  for job in plan['jobs']:
   if job['kind']!='rf_attack' or job['profile']!='diverse':continue
   root=a.campaign/job['attempts'][-1]['path']/'result';manifest=json.loads((root/'manifest.json').read_text());c=manifest['configuration'];private,labels=load_frames(root/'train.csv',c['train_samples'],c['length'])
   if header is None:header=['source_job','task','target_class','prototype_id','predicted_class','target_posterior','nearest_member_normalized_mse_audit','random_nearest_member_normalized_mse_audit']+[v+str(i) for i in range(c['length']) for v in ('i','q')];w.writerow(header)
   for task in ('sensing','amc'):
    model=RFModel.load(root/(task+'-model.npz'))
    for target in range(2 if task=='sensing' else 3):
     prototype,random=invert(model,c['length'],target,manifest['inputs']['train']['seed']+82000+target);out=model.forward(prototype)[0];out-=out.max(1,keepdims=True);prob=np.exp(out);prob/=prob.sum(1,keepdims=True);members=private[task][labels[task]==target];distance=nearest_error(prototype,members);baseline=nearest_error(random,members)
     for i,row in enumerate(prototype):w.writerow([job['id'],task,target,i,int(prob[i].argmax()),prob[i,target],distance[i],baseline[i],*row])
     results.append({'source_job':job['id'],'task':task,'target':target,'prototypes':len(prototype),'target_prediction_rate':float(np.mean(prob.argmax(1)==target)),'mean_nearest_member_normalized_mse':float(distance.mean()),'random_mean_nearest_member_normalized_mse':float(baseline.mean()),'approximate_record_recoveries_at_nmse_1e_minus3':int(np.sum(distance<1e-3))});f.flush()
 (a.output/'metrics.json').write_text(json.dumps(results,indent=2)+'\n');(a.output/'status.json').write_text(json.dumps({'state':'complete','class_conditions':len(results),'scope':'white-box class-representative reconstruction; optimization uses model weights/normalizer only, training records are evaluation-only; not evidence of private waveform recovery'},indent=2)+'\n');print('Inversion class conditions',len(results),'recoveries',sum(v['approximate_record_recoveries_at_nmse_1e_minus3'] for v in results))

if __name__=='__main__':main()
