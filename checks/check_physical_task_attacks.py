"""Independent full-row RF task IQ, target, model-output and budget verification."""
import argparse,csv,json
from pathlib import Path
import numpy as np
from ai.rf import RFModel,features
from ai.ofdm_channel_model import ChannelModel


def main():
    p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert json.loads((a.output/'status.json').read_text())['state']=='complete'
    plan=json.loads((a.campaign/'campaign.json').read_text());jobs={j['id']:j for j in plan['jobs']};checked=0;conditions=0
    with (a.output/'observations.csv').open() as f:
        reader=csv.DictReader(f)
        for rep in range(5):
            for task in ['sensing','amc','channel']:
                model=(ChannelModel if task=='channel' else RFModel).load(a.output/f'{task}-r{rep}-model.npz')
                fit=json.loads((a.output/f'{task}-r{rep}-fit.json').read_text()); assert len({jobs[j]['seed'] for j in fit['sources'].values()})==4
                for role in ['test','ood']:
                    job=jobs[fit['sources'][role]];root=a.campaign/job['attempts'][-1]['path']/'result'
                    with np.load(root/'observations.npz') as o,np.load(root/'labels.npz') as labels:
                        x=o['received'][:256].reshape(-1,256)
                        y=labels['H'][:256].reshape(-1,256) if task=='channel' else labels['class'][:256].reshape(-1)
                        pilots=o['pilots'] if task=='channel' else None
                    clean=model.forward(x)[0]
                    for method,db in [('none',0)]+[(m,d) for d in [-20,-10,-6] for m in ['random','fgsm','pgd']]:
                        ident=f'{task}-r{rep}-{role}-{method}-{db}'
                        with np.load(a.output/(ident+'.npz')) as saved:delta=saved['delta'];prediction=saved['prediction']
                        adv=x+delta;expected=model.forward(adv)[0]; assert np.allclose(prediction,expected,atol=1e-12,rtol=1e-12)
                        ratio=np.sum(delta*delta,1)/np.maximum(np.sum(x*x,1),1e-30);limit=0 if method=='none' else 10**(db/10);assert np.max(ratio)<=limit+1e-10
                        if method=='pgd':
                            target=y if task=='channel' else (1-y if task=='sensing' else (y+1)%6)
                            before=model.loss_gradient(x,target,task=='channel')[0];after=model.loss_gradient(adv,target,task=='channel')[0]
                            assert np.all(after>=before-1e-10) if task=='channel' else np.all(after<=before+1e-10)
                        moments=features(adv)
                        for i in range(len(x)):
                            r=next(reader);assert r['source_job']==job['id'] and r['split']==role and int(r['victim_rep'])==rep
                            assert r['attack_family']=={'random':'random_control'}.get(method,method)
                            assert int(r['input_changed'])==int(np.any(delta[i]))
                            assert int(r['attack_applied'])==int(method in ['fgsm','pgd'] and np.any(delta[i]))
                            assert np.isclose(float(r['power_ratio']),ratio[i])
                            iq=np.array([float(r[v+str(j)]) for j in range(128) for v in ['i','q']]);assert np.array_equal(iq,adv[i])
                            assert np.allclose([float(r[k]) for k in ['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']],moments[i],atol=1e-12)
                            if task=='channel':
                                h=np.array([float(r['true_h_'+v+str(j)]) for j in range(128) for v in ['i','q']]);assert np.array_equal(h,y[i])
                                pi=np.array([float(r['known_pilot_'+v+str(j)]) for j in range(128) for v in ['i','q']]);assert np.array_equal(pi,pilots.ravel())
                                den=max(float(np.sum(y[i]**2)),1e-30)
                                assert np.isclose(float(r['predicted_nmse']),np.sum((expected[i]-y[i])**2)/den)
                                assert np.isclose(float(r['clean_nmse']),np.sum((clean[i]-y[i])**2)/den)
                            else:
                                target=1-y[i] if task=='sensing' else (y[i]+1)%6
                                assert int(r['true_class_audit'])==y[i] and int(r['target_class'])==target
                                assert int(r['predicted_class'])==expected[i].argmax()
                                assert int(r['clean_predicted_class'])==clean[i].argmax()
                                assert int(r['eligible_clean_correct_nontarget'])==int(clean[i].argmax()==y[i])
                                assert int(r['target_hit'])==int(expected[i].argmax()==target)
                            checked+=1
                        conditions+=1
        assert next(reader,None) is None
    result=dict(verified=True,conditions=conditions,rows=checked,scope='all saved source IQ, H/pilots, victim predictions, NMSE, class targets, eligibility, moments, PSR constraints and PGD objective monotonicity; synthetic receiver inputs, no OTA/operational E2 claim; optimizer not independently retrained')
    (a.output/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
