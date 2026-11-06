"""Reproducible Random Forest baseline on the measured IP seed splits.

Training uses train only. A decision threshold is selected on validation only;
test is evaluated once after model and threshold selection. No simulator runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import time

FEATURES = ['tx_packets','tx_ip_bytes','server_rx_packets','server_rx_ip_bytes',
            'bottleneck_queue_drops','bottleneck_qdisc_drops','udp_tx_packets',
            'tcp_tx_packets','icmp_tx_packets','tcp_syn_packets','tcp_rst_packets',
            'tcp_fin_packets','unique_src_ips','unique_dst_ips','unique_dst_ports',
            'dst_port_entropy','server_app_rx_bytes','mean_ip_delay_ms',
            'std_ip_delay_ms','max_ip_delay_ms','delay_samples']


def dump(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')
    temporary.replace(path)


def sha(path):
    result=hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda:handle.read(1024*1024),b''):
            result.update(block)
    return result.hexdigest()


def check_splits(split):
    if split['feature_columns']!=FEATURES or split['target_column']!='attack_applied':
        raise ValueError('Feature whitelist/target mismatch')
    seen=set()
    for role in ('train','validation','test'):
        groups=set(split['counts'][role]['groups'])
        if not groups or seen & groups:
            raise ValueError('Seed group leakage')
        seen.update(groups)


def scores(y,probability,threshold):
    from sklearn.metrics import (accuracy_score,average_precision_score,confusion_matrix,
                                 f1_score,precision_score,recall_score,roc_auc_score)
    predicted=(probability>=threshold).astype('int8')
    confusion=confusion_matrix(y,predicted,labels=[0,1])
    tn,fp,fn,tp=map(int,confusion.ravel())
    return dict(rows=len(y),positives=int(y.sum()),accuracy=accuracy_score(y,predicted),
                precision=precision_score(y,predicted,zero_division=0),
                recall=recall_score(y,predicted,zero_division=0),
                f1=f1_score(y,predicted,zero_division=0),
                average_precision=average_precision_score(y,probability) if int(y.sum()) else None,
                roc_auc=roc_auc_score(y,probability) if len(set(y.tolist()))==2 else None,
                false_positive_rate=fp/(tn+fp) if tn+fp else None,
                confusion_matrix=confusion.tolist(),threshold=float(threshold))


def train(package,output,trees=200):
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score
    package=Path(package).resolve(strict=True);output=Path(output).resolve()
    split=json.loads((package/'splits/ip.json').read_text());check_splits(split)
    output.mkdir(parents=True,exist_ok=False)
    dump(output/'status.json',dict(state='loading_train'))
    source_hashes={role:sha(package/split['table_paths'][role]) for role in ('train','validation','test')}
    def load(role):
        columns=FEATURES+['attack_applied','source_group_id','attack_family','run_id']
        frame=pd.read_csv(package/split['table_paths'][role],usecols=columns,
                          dtype={**{key:'float32' for key in FEATURES},'attack_applied':'int8'})
        if len(frame)!=split['counts'][role]['rows'] or set(frame.source_group_id)!=set(split['counts'][role]['groups']):
            raise ValueError('Input count/group mismatch')
        if not np.isfinite(frame[FEATURES].to_numpy()).all() or not set(frame.attack_applied).issubset({0,1}):
            raise ValueError('Invalid features/targets')
        return frame
    config=dict(n_estimators=trees,max_depth=20,min_samples_leaf=5,
                max_features='sqrt',max_samples=.7,bootstrap=True,
                class_weight='balanced_subsample',n_jobs=2,random_state=20261106)
    try:
        training=load('train');validation=load('validation')
        dump(output/'status.json',dict(state='fitting',configuration=config))
        started=time.monotonic();model=RandomForestClassifier(**config)
        model.fit(training[FEATURES],training.attack_applied)
        fit_seconds=time.monotonic()-started
        p_validation=model.predict_proba(validation[FEATURES])[:,1]
        candidates=[]
        for threshold in np.linspace(.05,.95,19):
            candidates.append(dict(threshold=float(threshold),
                              f1=f1_score(validation.attack_applied,p_validation>=threshold,zero_division=0)))
        # Deterministic tie-break: highest threshold among equal validation F1.
        chosen=max(candidates,key=lambda row:(row['f1'],row['threshold']))['threshold']
        validation_metrics=scores(validation.attack_applied,p_validation,chosen)
        del training,validation,p_validation
        dump(output/'status.json',dict(state='evaluating_test',threshold=chosen))
        test=load('test');probability=model.predict_proba(test[FEATURES])[:,1]
        test_metrics=scores(test.attack_applied,probability,chosen)
        dummy=scores(test.attack_applied,np.zeros(len(test)),.5)
        predictions=(probability>=chosen).astype('int8')
        per_family={}
        for family in sorted(test.attack_family.unique()):
            mask=(test.attack_family==family).to_numpy();labels=test.attack_applied.to_numpy()[mask]
            pred=predictions[mask];positive=labels==1;negative=labels==0
            per_family[family]=dict(rows=int(mask.sum()),positives=int(positive.sum()),
                true_positives=int((pred[positive]==1).sum()),
                recall=float((pred[positive]==1).mean()) if positive.any() else None,
                false_positive_rate=float((pred[negative]==1).mean()) if negative.any() else None)
        per_run={}
        for run in sorted(test.run_id.unique()):
            mask=(test.run_id==run).to_numpy()
            per_run[run]=scores(test.attack_applied.to_numpy()[mask],probability[mask],chosen)
        test['attack_probability']=probability;test['predicted_attack']=predictions
        test[['run_id','source_group_id','attack_family','attack_applied','attack_probability','predicted_attack']].to_csv(output/'test_predictions.csv.gz',index=False)
        artifact=dict(model=model,feature_columns=FEATURES,target='attack_applied',threshold=chosen,
                      configuration=config,sklearn_version=sklearn.__version__)
        joblib.dump(artifact,output/'random_forest.joblib',compress=3)
        importance=dict(zip(FEATURES,map(float,model.feature_importances_)))
        metrics=dict(model='RandomForestClassifier',task='observed wired-IP attack activity detection',
                     configuration=config,feature_columns=FEATURES,fit_seconds=fit_seconds,
                     threshold_selection='Maximum validation F1 over 19 predeclared thresholds .05..95; highest threshold breaks ties.',
                     validation_candidates=candidates,validation=validation_metrics,test=test_metrics,
                     test_most_frequent_dummy=dummy,test_per_family=per_family,test_per_run=per_run,
                     impurity_feature_importance=importance,source_sha256=source_hashes,
                     versions=dict(python=platform.python_version(),numpy=np.__version__,pandas=pd.__version__,sklearn=sklearn.__version__,joblib=joblib.__version__),
                     caveats=['Synthetic wired IP only; not live RAN or RF attack detection.',
                              'Adjacent windows and runs sharing a seed are correlated; no independent-row confidence intervals claimed.',
                              'One fixed model configuration, validation-only threshold, untouched test.',
                              'Metrics use observed prevalence; no balancing, resplitting or test-based tuning.',
                              'Predictor inputs are float32 convenience measurements; canonical raw RF IQ is unchanged.'])
        # Verify serialization produces identical held-out probabilities.
        reloaded=joblib.load(output/'random_forest.joblib')
        check=reloaded['model'].predict_proba(test[FEATURES].iloc[:1000])[:,1]
        if not np.allclose(check,probability[:1000],rtol=1e-12,atol=1e-14) or not np.array_equal(check>=chosen,probability[:1000]>=chosen):
            raise ValueError('Saved model predictions differ')
        dump(output/'metrics.json',metrics)
        dump(output/'model-manifest.json',dict(model_sha256=sha(output/'random_forest.joblib'),
                  predictions_sha256=sha(output/'test_predictions.csv.gz'),serialization_roundtrip_verified=True,roundtrip_tolerance=dict(rtol=1e-12,atol=1e-14),
                  source_split_sha256=sha(package/'splits/ip.json'),training_script_sha256=sha(Path(__file__))))
        dump(output/'status.json',dict(state='complete'))
        (output/'README.md').write_text('# Random Forest IP baseline\n\nTrain/validation/test are disjoint by seed group. Only the 21 whitelisted observed\nfeatures are used. Configuration is fixed; threshold is selected on validation.\nSee metrics.json for test results, family/run breakdowns and limitations.\nThe joblib model requires the versions recorded in metrics.json; load only this\nverified artifact. test_predictions.csv.gz rows preserve original test order;\njoin by run_id and per-run row order (window_index in the original test table).\nNo claim about RF, over-the-air or unseen-family detection follows from this model.\n')
        print(json.dumps(dict(validation=validation_metrics,test=test_metrics,fit_seconds=fit_seconds),indent=2),flush=True)
        return metrics
    except BaseException as error:
        dump(output/'status.json',dict(state='failed',error=str(error)))
        raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--trees',type=int,default=200)
    args=parser.parse_args(argv)
    if not 10<=args.trees<=1000:
        parser.error('trees must be in [10,1000]')
    train(args.package,args.output,args.trees)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
