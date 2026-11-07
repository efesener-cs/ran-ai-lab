"""Verify score-query exported perturbations against immutable RF inputs/models."""
import argparse,csv,hashlib,json
from pathlib import Path
import numpy as np
from ai.rf import RFModel,features
from simulation.run_rf import load_frames


def main():
    p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert json.loads((a.output/'status.json').read_text())['state']=='complete'
    with (a.output/'observations.csv').open() as f:rows=list(csv.DictReader(f))
    plan=json.loads((a.campaign/'campaign.json').read_text()); checked=0; conditions=0
    moments=['mean_i','mean_q','mean_i2','mean_q2','mean_i4','mean_q4','mean_iq']
    for job in plan['jobs']:
        if job['kind']!='rf_attack' or job['profile']!='diverse':continue
        root=a.campaign/job['attempts'][-1]['path']/'result';m=json.loads((root/'manifest.json').read_text());c=m['configuration']
        data=root/'test.csv';assert hashlib.sha256(data.read_bytes()).hexdigest()==m['inputs']['test']['sha256']
        xs,ys=load_frames(data,c['eval_samples'],c['length'])
        for task in ['sensing','amc']:
            x=xs[task][:128]; y=ys[task][:128];model=RFModel.load(root/(task+'-model.npz'));clean=model.forward(x)[0].argmax(1)
            for budget in [64,256,1024]:
                with np.load(a.output/f"{job['id']}-{task}-{budget}.npz") as saved:delta=saved['delta'];savedpost=saved['posterior']
                logits=model.forward(x+delta)[0];exp=np.exp(logits-logits.max(1,keepdims=True));posterior=exp/exp.sum(1,keepdims=True);assert np.allclose(savedpost,posterior,rtol=1e-12,atol=1e-12)
                power=np.sum(delta*delta,axis=1)/np.maximum(np.sum(x*x,axis=1),1e-30);assert np.max(power)<=.1+1e-10
                subset=[r for r in rows if r['source_job']==job['id'] and r['task']==task and int(r['query_budget'])==budget]
                assert len(subset)==128
                for i,r in enumerate(subset):
                    assert int(r['frame_id'])==i and int(r['actual_queries'])==budget-1
                    assert int(r['true_class_audit'])==int(y[i])
                    assert int(r['clean_correct_eligible'])==int(clean[i]==y[i] and y[i]!=1)
                    assert int(r['target_hit'])==int(posterior[i].argmax()==1)
                    assert 0<=float(r['target_posterior'])<=1
                    assert np.isclose(float(r['target_posterior']),posterior[i,1])
                    assert np.isclose(float(r['power_ratio']),power[i])
                    iq=np.array([float(r[v+str(j)]) for j in range(128) for v in ('i','q')]); assert np.array_equal(iq,x[i]+delta[i])
                    assert np.allclose([float(r[k]) for k in moments],features(iq[None])[0],atol=1e-12)
                    checked+=1
                conditions+=1
    assert checked==len(rows)
    result=dict(verified=True,conditions=conditions,rows=checked,scope='all saved IQ/delta, power, posteriors, eligibility, query-account arithmetic and features; optimizer trajectory not replayed; synthetic receiver score oracle, no OTA')
    (a.output/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
