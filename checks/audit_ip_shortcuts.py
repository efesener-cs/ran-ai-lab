"""Exploratory shortcut diagnostics after a synthetic IP test has been inspected.

This fits only shallow diagnostic trees. Results are not new confirmatory tests.
"""
import argparse
import json
from pathlib import Path


def audit(package):
    import numpy as np,pandas as pd
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import f1_score,precision_score,recall_score,confusion_matrix
    FEATURES=json.loads((Path(package)/'splits/ip.json').read_text())['feature_columns']
    r=Path(package).resolve(strict=True)
    frames={}
    for role in ('train','validation','test'):
     frames[role]=pd.read_csv(r/'ip'/(role+'.csv.gz'),usecols=FEATURES+['attack_applied','attack_family','run_id','source_group_id','context_id'],dtype={k:'float64' for k in FEATURES})
    train=frames['train'];test=frames['test'];report={'exploratory':True,'test_already_seen':True}
    hashes={role:pd.util.hash_pandas_object(frame[FEATURES],index=False).to_numpy() for role,frame in frames.items()}
    match=np.isin(hashes['test'],np.unique(hashes['train']))
    report['duplicate_feature_vectors']={'test_rows':len(test),'overlapping_train_test_rows':int(match.sum()),'overlap_fraction':float(match.mean()),'overlapping_attack_rows':int((match & (test.attack_applied.to_numpy()==1)).sum()),'note':'64-bit pandas hashes as a screening diagnostic; no source IDs or labels included.'}
    report['simple_feature_presence_rules']={}
    for key in ('icmp_tx_packets','bottleneck_qdisc_drops','tcp_syn_packets','unique_dst_ports'):
     stats={}
     for label in (0,1):
      a=test.loc[test.attack_applied==label,key]
      stats[str(label)]={'rows':len(a),'positive_count':int((a>0).sum()),'minimum':float(a.min()),'median':float(a.median()),'p95':float(a.quantile(.95)),'max':float(a.max())}
     report['simple_feature_presence_rules'][key]=stats
    report['shallow_models']={}
    for depth in (1,3,5):
     m=DecisionTreeClassifier(max_depth=depth,min_samples_leaf=10,random_state=20261106)
     m.fit(train[FEATURES],train.attack_applied)
     p=m.predict(test[FEATURES]);report['shallow_models'][str(depth)]={'f1':f1_score(test.attack_applied,p),'precision':precision_score(test.attack_applied,p),'recall':recall_score(test.attack_applied,p),'confusion_matrix':confusion_matrix(test.attack_applied,p).tolist(),'root_feature':FEATURES[m.tree_.feature[0]]}
    report['same_contexts']={role:sorted(f.context_id.unique()) for role,f in frames.items()}
    report['icmp_clean_overlap']={'clean_windows_with_icmp':int(((test.attack_applied==0)&(test.icmp_tx_packets>0)).sum()),'icmp_flood_rows':int((test.attack_family=='icmp_flood').sum())}
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    report=audit(args.package)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
