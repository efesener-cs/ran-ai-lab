"""Exploratory identity-free baselines on disjoint DEVELOPMENT seed groups.

No claim of a blind confirmatory test or external validation. Direct addresses,
ports, actor IDs, timestamps, audit counters and scenario parameters are never X.
"""
import argparse
import json
from pathlib import Path
import platform
import time


def validate_partition(train,validation,evaluation,ood):
    seen=set()
    for group in (train,validation,evaluation,ood):
        if not group or len(set(group))!=len(group) or seen.intersection(group):
            raise ValueError('Nonempty disjoint unique seed groups required')
        seen.update(group)


def train(campaign,output,training,validation,evaluation,ood):
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score
    from ai.ip_random_forest import scores
    from checks.check_ip_research import check,PRIMARY_FEATURES,RICHER_OPTIONAL_FEATURES
    from simulation.run_research_campaign import verify_receipt,sha,save
    validate_partition(training,validation,evaluation,ood)
    campaign=Path(campaign).resolve(strict=True);output=Path(output).resolve()
    if not output.is_relative_to(Path('/mnt/onetb/ran-ai-lab').resolve()):raise ValueError('Outputs must stay on authorized data volume')
    plan=json.loads((campaign/'campaign.json').read_text())
    if plan['stage']!='development' or plan['state']!='complete':raise ValueError('Completed development campaign required')
    rows=[];source={};seed_set=set(training+validation+evaluation+ood)
    for job in plan['jobs']:
        if job['kind']!='ip' or job['seed'] not in seed_set:continue
        if job['state']!='complete':raise ValueError('Incomplete source job')
        verify_receipt(campaign,job)
        result=campaign/job['attempts'][-1]['path']/'result';evidence=check(result)
        if evidence['unattributed_packets'] or evidence['unattributed_app_rx_bytes']:raise ValueError('Unknown provenance cannot be trained as benign')
        path=result/'ip_windows.csv';frame=pd.read_csv(path)
        if frame.source_group_id.nunique()!=1 or frame.source_group_id.iloc[0]!=f"ip3-s{job['seed']}-r1":raise ValueError('Unexpected seed identity')
        frame['seed_group']=job['seed'];frame['condition_id']=job['id'];frame['environment_audit']=job['environment']
        rows.append(frame);source[job['id']]=sha(path)
    data=pd.concat(rows,ignore_index=True)
    if set(data.seed_group.unique())!=seed_set:raise ValueError('Missing requested seed groups')
    output.mkdir(parents=True,exist_ok=False)
    save(output/'status.json',dict(state='fitting'))
    parts={name:data[data.seed_group.isin(values)] for name,values in
           (('train',training),('validation',validation),('evaluation',evaluation),('ood',ood))}
    report=dict(exploratory=True,confirmatory=False,source_campaign=campaign.name,
                source_sha256=source,training_script_sha256=sha(Path(__file__)),seed_partition=dict(train=training,validation=validation,evaluation=evaluation,ood=ood),
                versions=dict(python=platform.python_version(),sklearn=sklearn.__version__,numpy=np.__version__,pandas=pd.__version__,joblib=joblib.__version__),
                results={},counts={},caveats=['Development seed screen only; not a publication-quality blind test.',
                    'One evaluation seed per role is inadequate for between-scenario confidence intervals.',
                    'Observations are topology-wide instrumented synthetic transport telemetry, not a passive Internet capture.',
                    'No fixed target accuracy is an acceptance condition; inspect semantic ambiguity and shortcut support.'])
    for name,frame in parts.items():
        report['counts'][name]=dict(rows=len(frame),positives=int(frame.attack_applied.sum()),seed_groups=int(frame.seed_group.nunique()))
    views={'primary':list(PRIMARY_FEATURES),'behavioral':list(PRIMARY_FEATURES)+list(RICHER_OPTIONAL_FEATURES)}
    forbidden={'source_ipv4','destination_ipv4','ipv4','mac','source_port','destination_port','seed','seed_group','run',
        'source_group_id','condition_id','environment_audit','window_start_s','window_end_s','window_index','attack_applied',
        'attack_scheduled','attack_family','attack_families','attack_tx_packets','attack_rx_packets','attack_drop_packets',
        'benign_rx_ip_bytes','benign_app_rx_bytes','unattributed_packets','unattributed_app_rx_bytes'}
    for view,features in views.items():
        if set(features)&forbidden:raise ValueError('Identity/target/audit feature leakage')
        models={'tree3':DecisionTreeClassifier(max_depth=3,min_samples_leaf=10,random_state=940001),
                'tree5':DecisionTreeClassifier(max_depth=5,min_samples_leaf=10,random_state=940001),
                'random_forest':RandomForestClassifier(n_estimators=200,max_depth=20,min_samples_leaf=5,
                    max_features='sqrt',class_weight='balanced_subsample',n_jobs=2,random_state=940001)}
        for name,model in models.items():
            key=view+'/'+name;start=time.monotonic()
            model.fit(parts['train'][features],parts['train'].attack_applied)
            if list(model.feature_names_in_)!=features:raise ValueError('Fitted feature identity changed')
            val=model.predict_proba(parts['validation'][features])[:,1]
            candidates=[]
            for threshold in np.linspace(.05,.95,19):
                candidates.append(dict(threshold=float(threshold),f1=f1_score(parts['validation'].attack_applied,val>=threshold,zero_division=0)))
            selected=max(candidates,key=lambda row:(row['f1'],row['threshold']))['threshold']
            metrics=dict(features=features,threshold_selection='Maximum validation F1; fixed19threshold grid .05..95; highest threshold on ties',
                         validation_candidates=candidates,fit_and_validation_seconds=time.monotonic()-start,
                         validation=scores(parts['validation'].attack_applied,val,selected),evaluation={},ood={})
            for role in ('evaluation','ood'):
                frame=parts[role];p=model.predict_proba(frame[features])[:,1];metrics[role]=scores(frame.attack_applied,p,selected)
                metrics[role]['per_family']={}
                for family in sorted(frame.attack_family.unique()):
                    mask=(frame.attack_family==family).to_numpy();metrics[role]['per_family'][family]=scores(frame.attack_applied.to_numpy()[mask],p[mask],selected)
            report['results'][key]=metrics
            joblib.dump(dict(model=model,feature_columns=features,target='attack_applied',threshold=selected,sklearn_version=sklearn.__version__),output/(view+'-'+name+'.joblib'),compress=3)
            save(output/'metrics.json',report)
            print(key,'evaluationF1',metrics['evaluation']['f1'],'oodF1',metrics['ood']['f1'],flush=True)
    report['dummy']={role:scores(parts[role].attack_applied,np.zeros(len(parts[role])),.5) for role in ('evaluation','ood')}
    save(output/'metrics.json',report)
    save(output/'status.json',dict(state='complete',exploratory=True))
    save(output/'checksums.json',{p.name:sha(p) for p in output.iterdir() if p.is_file()})
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('campaign',type=Path);p.add_argument('--output',required=True,type=Path)
    for role in ('train','validation','evaluation','ood'):p.add_argument('--'+role+'-seeds',nargs='+',type=int,required=True)
    a=p.parse_args(argv)
    existed_before=a.output.exists()
    try:
        train(a.campaign,a.output,a.train_seeds,a.validation_seeds,a.evaluation_seeds,a.ood_seeds)
    except BaseException as error:
        if not existed_before and a.output.is_dir():
            from simulation.run_research_campaign import save
            save(a.output/'status.json',dict(state='failed',error=str(error)))
        raise
    return 0


if __name__=='__main__':raise SystemExit(main())
