#!/usr/bin/env python3
"""Train a clean-data SINR forecaster and evaluate shadow traffic-steering recommendations."""
from labcore.paths import ROOT
import argparse
from collections import Counter
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import numpy as np
from ai.data import load_observations,supervised,arrays,write_csv
from ai.model import Forecaster
from ai.policy import recommendations
from checks.check_live import check


def _source_seed(source):
    config=source.get('configuration') or {}
    seed=source.get('seed',config.get('seed') if isinstance(config,dict) else None)
    if seed is None and isinstance(config,dict):
        for key in ('simulation','scenario','ns3'):
            sub=config.get(key)
            if isinstance(sub,dict) and sub.get('seed') is not None:
                seed=sub['seed'];break
    if seed is None:return None
    if isinstance(seed,bool):raise ValueError('Simulation seeds must be finite integers')
    try:value=Decimal(str(seed))
    except (InvalidOperation,TypeError,ValueError) as exc:
        raise ValueError('Simulation seeds must be finite integers') from exc
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError('Simulation seeds must be finite integers')
    return str(int(value))


def validate_sources(sources, label='source', require_seed=False):
    """Validate one side's source inventory; repeated runs never weight a split twice."""
    if not sources:
        raise ValueError(f'No {label} sources provided')
    paths=set();runs=set();hashes=set();seeds=set()
    for source in sources:
        run=source.get('run_id')
        root=source.get('root')
        digest=source.get('sha256')
        if not run or not root or not digest:
            raise ValueError(f'{label.capitalize()} source requires run_id, root, and content hash')
        path=str(Path(root).resolve())
        if path in paths or run in runs or digest in hashes:
            raise ValueError(f'Duplicate {label} source: {run or path}')
        paths.add(path);runs.add(run);hashes.add(digest)
        seed=_source_seed(source)
        if seed is None:
            if require_seed:
                raise ValueError('Independent run validation requires a recorded seed for every run')
        else:
            seeds.add(seed)
    return dict(paths=paths,runs=runs,hashes=hashes,seeds=seeds)


def validate_run_split(training_sources, test_sources):
    """Reject repeated inputs and train/test sharing run, content, or seed identities."""
    train=validate_sources(training_sources,'training',require_seed=True)
    test=validate_sources(test_sources,'test',require_seed=True)
    if train['paths'] & test['paths'] or train['runs'] & test['runs']:
        raise ValueError('Training and test sources contain the same run or source root')
    if train['hashes'] & test['hashes']:
        raise ValueError('Training and test sources contain identical CSV content')
    if train['seeds'] & test['seeds']:
        raise ValueError('Training and test runs share simulation seed identities')
    return dict(training_source_count=len(training_sources),test_source_count=len(test_sources),
                training_seeds=sorted(train['seeds']),test_seeds=sorted(test['seeds']))


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


def select_alpha(training_samples, validation_samples, alpha_grid):
    """Choose ridge alpha using validation MAE; test samples are never an input."""
    if not training_samples or not validation_samples:
        raise ValueError('Alpha selection requires nonempty training and validation samples')
    try:alphas=[float(value) for value in alpha_grid]
    except (TypeError,ValueError) as exc:raise ValueError('alpha-grid values must be finite and positive') from exc
    if not alphas or any(not np.isfinite(value) or value<=0 for value in alphas):
        raise ValueError('alpha-grid values must be finite and positive')
    if len(set(alphas))!=len(alphas):raise ValueError('alpha-grid values must be unique')
    x,y,current=arrays(training_samples)
    vx,vy,vc=arrays(validation_samples)
    scores=[]
    for alpha in sorted(alphas):
        candidate=Forecaster.fit(x,y,current,alpha=alpha)
        prediction=candidate.predict(vx,vc)
        mae=float(np.mean(np.abs(prediction-vy)))
        scores.append(dict(alpha=alpha,validation_mae_db=mae))
    selected=min(scores,key=lambda row:(row['validation_mae_db'],row['alpha']))['alpha']
    return selected,dict(method='validation_mae',selected_alpha=selected,
                         validation_sample_count=len(validation_samples),candidates=scores)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',type=Path,action='append')
    parser.add_argument('--test-run-dir',type=Path,action='append')
    parser.add_argument('--validation-run-dir',type=Path,action='append')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--seed',type=int,default=17)
    parser.add_argument('--alpha',type=float,default=10.0)
    parser.add_argument('--alpha-grid',type=float,nargs='+',default=[0.1,1,10,100,1000])
    parser.add_argument('--allow-native',action='store_true',help='Allow verified native control runs as data sources')
    args=parser.parse_args(argv)
    if args.validation_run_dir and not args.test_run_dir:
        parser.error('--validation-run-dir requires explicit --test-run-dir')
    lab=ROOT
    roots=args.run_dir or [latest_verified(lab)]
    out=args.output or lab/'ai/artifacts/pilot'
    observations=[];train_sources=[]
    for root in roots:
        obs,meta=load_observations(root,allow_native=args.allow_native);observations.extend(obs);meta['root']=str(root.resolve());train_sources.append(meta)
    validate_sources(train_sources,'training')
    samples=supervised(observations)
    validation_samples=None;validation_sources=[];alpha_selection=None
    if args.validation_run_dir:
        validation_observations=[]
        for root in args.validation_run_dir:
            obs,meta=load_observations(root,allow_native=args.allow_native)
            meta['root']=str(root.resolve());validation_observations.extend(obs);validation_sources.append(meta)
        validation_split_provenance=validate_run_split(train_sources,validation_sources)
        validation_samples=supervised(validation_observations)
        if not validation_samples:raise ValueError('Empty validation split')
    if args.test_run_dir:
        test_observations=[]
        test_sources=[]
        for root in args.test_run_dir:
            obs,meta=load_observations(root,allow_native=args.allow_native)
            meta['root']=str(root.resolve());test_observations.extend(obs);test_sources.append(meta)
        test_split_provenance=validate_run_split(train_sources+validation_sources,test_sources)
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
        test_sources=[]
        train_ues=sorted({s['ue'] for s in training});test_ues=sorted({s['ue'] for s in testing})
    if not training or not testing:raise ValueError('Empty train or test split')
    x,y,current=arrays(training)
    selected_alpha=args.alpha
    if validation_samples is not None:
        selected_alpha,alpha_selection=select_alpha(training,validation_samples,args.alpha_grid)
    model=Forecaster.fit(x,y,current,alpha=selected_alpha)
    tx,ty,tc=arrays(testing)
    prediction=model.predict(tx,tc)
    report=metrics(testing,prediction)
    report.update(split=split,training_samples=len(training),train_ue_ids=train_ues,test_ue_ids=test_ues,
        training_sources=train_sources,validation_sources=validation_sources,test_sources=test_sources,
        sources=train_sources+validation_sources+test_sources,
        alpha=selected_alpha,alpha_selection=alpha_selection,
        validation_metrics=({'samples':len(validation_samples),
            'forecast_mae_db':next(r['validation_mae_db'] for r in alpha_selection['candidates']
                                   if r['alpha']==selected_alpha)} if validation_samples is not None else None),
        seed=args.seed,numpy_version=np.__version__,network_actions_applied=0,
        split_provenance=({'training_validation':validation_split_provenance,
                           'fit_validation_test':test_split_provenance}
                          if validation_samples is not None else
                          test_split_provenance if args.test_run_dir else
                          {'independent_run_validation':False}),
        independent_run_validation=bool(args.test_run_dir),
        model_beats_persistence_on_this_split=bool(report['forecast_mae_db']<report['persistence_mae_db']),
        scope='Recorded telemetry replay/shadow; no live xApp inference and no RAN control.',
        caveats=['Three-second pilot does not establish generalization.',
                 'UE groups share the same simulated cells; this is correlated pilot evaluation.',
                 'Future SINR is a link-quality proxy, not demonstrated throughput/QoS reward.',
                 'Path-cell events are not a complete serving-cell state feed.',
                 'No attack labels, UE/cell identifiers, future values or coordinates are model features.'])
    model.parameters['training_provenance']=dict(sources=train_sources,
        validation_sources=validation_sources,split=split,seed=args.seed,alpha=selected_alpha,
        alpha_selection=alpha_selection)
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
