"""Independently recompute training-poisoning transforms and model metrics."""
import argparse
import csv
import json
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from ai.training_attacks import MODES, evaluate, read_table, verify_transform
from checks.check_rf import equivalent
from simulation.run_rf import digest


def verify(root):
    root=Path(root).resolve()
    status=json.loads((root/'run_status.json').read_text())
    if status.get('state')!='completed': raise ValueError('Training study not completed')
    evidence=json.loads((root/'evidence.json').read_text())
    for name,sha in evidence.items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or digest(path)!=sha:
            raise ValueError('Training evidence hash mismatch: '+name)
    manifest=json.loads((root/'manifest.json').read_text())
    config=manifest['configuration']
    if digest(root/'scenario.cc')!=manifest['source']['sha256']: raise ValueError('Training C++ source mismatch')
    rows=json.loads((root/'summary.json').read_text())['conditions']
    expected=set()
    for task in config['tasks']:
        expected.add((task,'none',0.))
        for mode in MODES:
            for fraction in config['fractions']: expected.add((task,mode,fraction))
    seen=set()
    required={'manifest.json','summary.json','scenario.cc'}
    for task in config['tasks']:
        folder=root/task
        for split in ('train','validation','test'): required.add(task+'/'+split+'.csv')
        for mode in MODES:
            source=folder/('zero-'+mode+'.csv')
            if verify_transform(folder/'train.csv',source,task)['selected']!=0:
                raise ValueError('Zero-poison control changed')
        for name in ('triggered-test','random-test'):
            verify_transform(folder/'test.csv',folder/(name+'.csv'),task)
    for row in rows:
        task,mode,fraction=row['task'],row['mode'],row['fraction_requested']
        key=(task,mode,fraction)
        if key not in expected or key in seen: raise ValueError('Invalid/duplicate training condition')
        seen.add(key)
        folder=root/task
        model_path=(root/row['model']).resolve()
        if not model_path.is_relative_to(root): raise ValueError('Invalid model path')
        model=RFModel.load(model_path)
        reference=RFModel.load(folder/'reference-model.npz')
        x,y,ids=read_table(folder/'test.csv',task)
        trigger=read_table(folder/'triggered-test.csv',task)[0]
        random=read_table(folder/'random-test.csv',task)[0]
        metrics,predictions=evaluate(model,reference,x,trigger,random,y,config['target'])
        if not equivalent(row['metrics'],metrics): raise ValueError('Training metrics differ from recomputation')
        required.add(row['model'])
        if mode!='none':
            training=(root/row['training']).resolve()
            if not training.is_relative_to(root): raise ValueError('Invalid training path')
            audit=verify_transform(folder/'train.csv',training,task)
            metadata=json.loads(Path(str(training)+'.meta.json').read_text())
            if metadata['mode']!=mode or metadata['fraction_requested']!=fraction or metadata['target_class']!=config['target']:
                raise ValueError('Training condition configuration mismatch')
            if audit['selected']!=row['selected'] or not equivalent(audit['fraction'],row['fraction_actual']):
                raise ValueError('Training condition budget mismatch')
            with (training.parent/'predictions.csv').open() as handle:
                saved=list(csv.DictReader(handle))
            if len(saved)!=len(x): raise ValueError('Training prediction coverage mismatch')
            for index,entry in enumerate(saved):
                if int(entry['id'])!=ids[index] or int(entry['true'])!=y[index]: raise ValueError('Training prediction identity mismatch')
                for name,values in predictions.items():
                    if int(entry[name])!=values[index]: raise ValueError('Training prediction differs from saved model')
            required.add(row['training'])
    if seen!=expected or not required.issubset(evidence): raise ValueError('Incomplete training evidence/conditions')
    return dict(verified=True,conditions=len(rows),tasks=config['tasks'],
                scope='training-data integrity of local RF classifiers; no DRL/xApp/OTA effects established')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    a=p.parse_args(argv)
    try: print(json.dumps(verify(a.run),indent=2))
    except (OSError,ValueError,KeyError) as error: p.exit(1,'Training verification failed: '+str(error)+'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
