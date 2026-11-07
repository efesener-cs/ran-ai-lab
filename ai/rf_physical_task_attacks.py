"""Attacks against four-subband sensing, six-class AMC and OFDM DL estimation.

Generated research arrays are existing measured simulation inputs. Fit clean
victims with validation-only epoch selection; attack disjoint test/OOD groups.
Independent-subband sensing is not a joint wideband CNN or OTA implementation.
"""
import argparse,csv,json
from pathlib import Path
import numpy as np
from ai.rf import RFModel,attack,features
from ai.ofdm_channel_model import ChannelModel,fit
from simulation.run_research_campaign import verify_receipt


def load(campaign,job):
    verify_receipt(campaign,job)
    root=campaign/job['attempts'][-1]['path']/'result'
    with np.load(root/'observations.npz') as o,np.load(root/'labels.npz') as l,np.load(root/'identities.npz') as ids:
        x=o['received'];y=l['H'] if job['task']=='channel' else l['class']
        groups=ids['group'];frames=ids['frame'];pilots=o['pilots'] if job['task']=='channel' else None
    return x,y,groups,frames,pilots


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);plan=json.loads((a.campaign/'campaign.json').read_text());state=dict(state='running',conditions=0,models=0)
    def save():
        tmp=a.output/'status.tmp';tmp.write_text(json.dumps(state,indent=2)+'\n');tmp.replace(a.output/'status.json')
    save()
    fields=['source_job','source_group_id','task','frame_id','band','split','victim_rep','attack_family','attack_applied','input_changed','psr_db','power_ratio','true_class_audit','target_class','predicted_class','clean_predicted_class','eligible_clean_correct_nontarget','target_hit','predicted_nmse','clean_nmse']
    fields += ['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']
    fields += [v+str(i) for i in range(128) for v in ('i','q')]
    fields += ['true_h_'+v+str(i) for i in range(128) for v in ('i','q')]
    fields += ['known_pilot_'+v+str(i) for i in range(128) for v in ('i','q')]
    try:
        with (a.output/'observations.csv').open('w',newline='') as f:
            writer=csv.DictWriter(f,fields);writer.writeheader()
            for rep in range(5):
                for task in ['sensing','amc','channel']:
                    jobs={role:sorted([j for j in plan['jobs'] if j['kind']=='rf' and j['task']==task and j['role']==role],key=lambda j:j['seed'])[rep] for role in ['train','validation','test','ood']}
                    assert len({j['seed'] for j in jobs.values()})==4
                    data={role:load(a.campaign,j) for role,j in jobs.items()}
                    def flatten(role,count=None):
                        x,y,g,fr,pi=data[role];x=x[:count];y=y[:count]
                        return x.reshape(-1,256),y.reshape(-1,256) if task=='channel' else y.reshape(-1)
                    x,y=flatten('train');vx,vy=flatten('validation');reg=task=='channel';seed=810001+rep
                    model=ChannelModel(x,data['train'][4],seed) if reg else RFModel(x,2 if task=='sensing' else 6,seed)
                    fitmeta=fit(model,x,y,vx,vy,reg,seed,60);modelpath=a.output/f'{task}-r{rep}-model.npz';model.save(modelpath)
                    (a.output/f'{task}-r{rep}-fit.json').write_text(json.dumps(dict(**fitmeta,sources={k:v['id'] for k,v in jobs.items()},scope='train-only normalizer; clean validation epoch selection; synthetic victim reference'),indent=2)+'\n')
                    state['models']+=1;save()
                    for role in ['test','ood']:
                        ex,ey=flatten(role,256);raw,truth,groups,frames,pilots=data[role]
                        clean=model.forward(ex)[0];targets=ey if reg else (1-ey if task=='sensing' else (ey+1)%6)
                        conditions=[('none',0)]+[(method,db) for db in [-20,-10,-6] for method in ['random','fgsm','pgd']]
                        for method,db in conditions:
                            delta=attack(model,ex,targets,method,0 if method=='none' else 10**(db/10),reg,seed+17,30)
                            adv=ex+delta;prediction=model.forward(adv)[0];moments=features(adv)
                            ratio=np.sum(delta*delta,1)/np.maximum(np.sum(ex*ex,1),1e-30)
                            assert np.isfinite(adv).all() and np.max(ratio)<=(0 if method=='none' else 10**(db/10))+1e-10
                            ident=f'{task}-r{rep}-{role}-{method}-{db}'
                            np.savez_compressed(a.output/(ident+'.npz'),delta=delta,prediction=prediction,source_job=jobs[role]['id'])
                            for i in range(len(adv)):
                                frame_index=i//4 if task=='sensing' else i;band=i%4 if task=='sensing' else ''
                                row=dict(source_job=jobs[role]['id'],source_group_id=f"{task}:seed{jobs[role]['seed']}:group{groups[frame_index]}",task=task,frame_id=int(frames[frame_index]),band=band,split=role,victim_rep=rep,
                                    attack_family={'none':'none','random':'random_control','fgsm':'fgsm','pgd':'pgd'}[method],attack_applied=int(method in ['fgsm','pgd'] and np.any(delta[i])),input_changed=int(np.any(delta[i])),psr_db=db if method!='none' else '',power_ratio=ratio[i])
                                row.update(zip(['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq'],moments[i]));row.update(zip([v+str(j) for j in range(128) for v in ('i','q')],adv[i]))
                                if reg:
                                    den=max(float(np.sum(ey[i]**2)),1e-30)
                                    row.update(predicted_nmse=float(np.sum((prediction[i]-ey[i])**2))/den,clean_nmse=float(np.sum((clean[i]-ey[i])**2))/den)
                                    row.update(zip(['true_h_'+v+str(j) for j in range(128) for v in ('i','q')],ey[i]))
                                    row.update(zip(['known_pilot_'+v+str(j) for j in range(128) for v in ('i','q')],pilots.ravel()))
                                else:
                                    row.update(true_class_audit=int(ey[i]),target_class=int(targets[i]),predicted_class=int(prediction[i].argmax()),clean_predicted_class=int(clean[i].argmax()),eligible_clean_correct_nontarget=int(clean[i].argmax()==ey[i]),target_hit=int(prediction[i].argmax()==targets[i]))
                                writer.writerow(row)
                            f.flush();state['conditions']+=1;state['current']=ident;save();print('RF CONDITION',ident,flush=True)
            state['state']='complete';save()
    except BaseException as exc:
        state.update(state='failed',error=str(exc));save();raise


if __name__=='__main__':main()
