#!/usr/bin/env python3
"""Train a clean-data SINR forecaster and evaluate shadow traffic-steering recommendations."""
import argparse
from collections import Counter
import json
from pathlib import Path
import numpy as np
from ai.data import load_observations,supervised,arrays,write_csv
from ai.model import Forecaster
from ai.policy import recommendations
from check_live import check


def latest_verified(lab):
    paths=sorted((lab/'results').glob('live-*'),reverse=True)
    for root in paths:
        if check(root)['passed']:return root
    raise ValueError('No successfully verified live run found')


def metrics(samples,prediction):
    _,target,current=arrays(samples)
    groups={}
    for s,pred in zip(samples,prediction):
        groups.setdefault((s['run_id'],s['ue'],s['tick']),[]).append((s,float(pred)))
    correct=0;baseline_correct=0;regret=[];n=0
    for entries in groups.values():
        if len(entries)<2:continue
        actual=int(np.argmax([s['target'] for s,p in entries]))
        chosen=int(np.argmax([p for s,p in entries]))
        baseline=int(np.argmax([s['current'] for s,p in entries]))
        correct+=chosen==actual;baseline_correct+=baseline==actual;n+=1
        regret.append(max(s['target'] for s,p in entries)-entries[chosen][0]['target'])
    return dict(samples=len(samples),forecast_mae_db=float(np.mean(abs(prediction-target))),
        forecast_rmse_db=float(np.sqrt(np.mean((prediction-target)**2))),
        persistence_mae_db=float(np.mean(abs(current-target))),
        persistence_rmse_db=float(np.sqrt(np.mean((current-target)**2))),
        rank_decisions=n,best_cell_top1_accuracy=correct/n if n else None,
        persistence_best_cell_top1_accuracy=baseline_correct/n if n else None,
        mean_best_cell_regret_db=float(np.mean(regret)) if regret else None)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',type=Path,action='append')
    parser.add_argument('--test-run-dir',type=Path,action='append')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--seed',type=int,default=17)
    parser.add_argument('--alpha',type=float,default=10.0)
    args=parser.parse_args()
    lab=Path(__file__).resolve().parent
    roots=args.run_dir or [latest_verified(lab)]
    out=args.output or lab/'ai/artifacts/pilot'
    observations=[];sources=[]
    for root in roots:
        obs,meta=load_observations(root);observations.extend(obs);sources.append(meta)
    samples=supervised(observations)
    if args.test_run_dir:
        test_observations=[]
        for root in args.test_run_dir:
            obs,meta=load_observations(root)
            if meta['run_id'] in {s['run_id'] for s in sources}:raise ValueError('Training and test runs overlap')
            test_observations.extend(obs);sources.append(meta)
        training=samples;testing=supervised(test_observations)
        shadow_observations=test_observations
        split='held_out_runs';train_ues=sorted({s['ue'] for s in training});test_ues=sorted({s['ue'] for s in testing})
    else:
        entities=sorted({(s['run_id'],s['ue']) for s in samples})
        if len(entities)<4:raise ValueError('Need at least four UE groups for pilot split')
        rng=np.random.default_rng(args.seed)
        perm=rng.permutation(len(entities));count=max(1,int(np.ceil(len(entities)/3)))
        held={entities[int(i)] for i in perm[:count]}
        training=[s for s in samples if (s['run_id'],s['ue']) not in held]
        testing=[s for s in samples if (s['run_id'],s['ue']) in held]
        shadow_observations=observations
        split='same_run_held_out_UE_pilot'
        train_ues=sorted({s['ue'] for s in training});test_ues=sorted({s['ue'] for s in testing})
    if not training or not testing:raise ValueError('Empty train or test split')
    x,y,current=arrays(training)
    model=Forecaster.fit(x,y,current,alpha=args.alpha)
    tx,ty,tc=arrays(testing)
    prediction=model.predict(tx,tc)
    report=metrics(testing,prediction)
    report.update(split=split,training_samples=len(training),train_ue_ids=train_ues,test_ue_ids=test_ues,
        sources=sources,seed=args.seed,numpy_version=np.__version__,network_actions_applied=0,
        independent_run_validation=split=='held_out_runs',
        model_beats_persistence_on_this_split=bool(report['forecast_mae_db']<report['persistence_mae_db']),
        scope='Recorded telemetry replay/shadow; no live xApp inference and no RAN control.',
        caveats=['Three-second pilot does not establish generalization.',
                 'UE groups share the same simulated cells; this is correlated pilot evaluation.',
                 'Future SINR is a link-quality proxy, not demonstrated throughput/QoS reward.',
                 'Path-cell events are not a complete serving-cell state feed.',
                 'No attack labels, UE/cell identifiers, future values or coordinates are model features.'])
    model.parameters['training_provenance']=dict(sources=sources,split=split,seed=args.seed)
    out.mkdir(parents=True,exist_ok=True);model.save(out/'model.json')
    loaded=Forecaster.load(out/'model.json')
    np.testing.assert_allclose(loaded.predict(tx,tc),prediction,rtol=1e-12,atol=1e-12)
    test_rows=[dict(run_id=s['run_id'],ue_imsi=s['ue'],nr_cell_id=s['cell'],
        decision_time_s=s['decision_time_s'],observed_sinr_db=s['current'],
        predicted_next_sinr_db=float(p),actual_next_sinr_db=s['target']) for s,p in zip(testing,prediction)]
    write_csv(out/'test_predictions.csv',test_rows)
    proposals,scores=recommendations(loaded,shadow_observations)
    write_csv(out/'shadow_decisions.csv',proposals);write_csv(out/'shadow_scores.csv',scores)
    report['shadow_decisions']=len(proposals)
    report['shadow_action_counts']=dict(Counter(r['action'] for r in proposals))
    (out/'evaluation.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({k:report[k] for k in ['split','training_samples','samples','forecast_mae_db',
        'persistence_mae_db','best_cell_top1_accuracy','persistence_best_cell_top1_accuracy',
        'shadow_action_counts','model_beats_persistence_on_this_split']},indent=2))
    print('Artifacts:',out)

if __name__=='__main__':main()
