"""Train/evaluate local poisoning and backdoor models on independently split RF data."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import numpy as np
from ai.rf import train
from ai.training_attacks import MODES, evaluate, extract_task, read_table, verify_transform
from checks.check_rf import verify as verify_rf
from scenario.source import snapshot_source
from simulation.run_rf import digest, publish


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rf-run',type=Path,required=True)
    p.add_argument('--scenario',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--tasks',nargs='+',choices=['sensing','amc'],default=['sensing','amc'])
    p.add_argument('--fractions',type=float,nargs='+',default=[.01,.05,.1,.2])
    p.add_argument('--epochs',type=int,default=80)
    p.add_argument('--attack-seed',type=int,default=101)
    p.add_argument('--target',type=int,default=1)
    p.add_argument('--trigger-length',type=int,default=16)
    p.add_argument('--trigger-amplitude',type=float,default=1)
    p.add_argument('--noise-psr-db',type=float,default=-6)
    a=p.parse_args(argv)
    if len(set(a.tasks))!=len(a.tasks) or len(set(a.fractions))!=len(a.fractions) or not np.isfinite(a.fractions).all() or min(a.fractions)<=0 or max(a.fractions)>.2:
        p.error('distinct tasks and poison fractions in (0,.2] required')
    if a.epochs<1 or not 0<=a.attack_seed<=2147483647 or a.target not in (0,1) or a.trigger_length<1 or not np.isfinite(a.trigger_amplitude) or not 0<a.trigger_amplitude<=10 or not np.isfinite(a.noise_psr_db) or not -120<=a.noise_psr_db<=20:
        p.error('invalid training/trigger/seed settings')
    a.rf_run=a.rf_run.resolve();a.output=a.output.resolve()
    verify_rf(a.rf_run)
    parent=json.loads((a.rf_run/'manifest.json').read_text())
    if a.trigger_length>parent['configuration']['length']: p.error('trigger exceeds frame length')
    compiler=shutil.which('g++')
    if not compiler: p.error('g++ required')
    a.output.mkdir(parents=True,exist_ok=False)
    source=snapshot_source(a.scenario,a.output)
    state=dict(state='running',scope='local RF classifier training poisoning; no DRL/RIC/network effects')
    publish(a.output/'run_status.json',state)
    try:
        binary=a.output/'training-transform'
        build=[compiler,'-std=c++17','-O2','-Wall','-Wextra',str(source.path),'-o',str(binary)]
        with (a.output/'build.log').open('w') as handle: subprocess.run(build,check=True,stdout=handle,stderr=subprocess.STDOUT)
        config=vars(a).copy()
        for key in ('rf_run','scenario','output'): config[key]=str(config[key])
        manifest=dict(configuration=config,source=source.metadata(),parent_manifest_sha256=digest(a.rf_run/'manifest.json'),
                      original_inputs=parent['inputs'],binary_sha256=digest(binary),commands=[build],numpy=np.__version__,
                      reference='fresh paired clean model on this runtime; not reused weights from another Python/NumPy',
                      threat='attacker can replace a bounded subset of training rows; no validation/test-label access for tuning')
        rows=[]
        def transform(input_path,output_path,task,mode,fraction):
            command=[str(binary),'--input',str(input_path),'--output',str(output_path),'--task',task,'--mode',mode,
                     '--fraction',str(fraction),'--seed',str(a.attack_seed),'--target',str(a.target),
                     '--trigger-length',str(a.trigger_length),'--trigger-amplitude',str(a.trigger_amplitude),
                     '--noise-psr-db',str(a.noise_psr_db)]
            manifest['commands'].append(command)
            with Path(str(output_path)+'.log').open('w') as handle: subprocess.run(command,check=True,stdout=handle,stderr=subprocess.STDOUT)
            return verify_transform(input_path,output_path,task)
        for task in a.tasks:
            root=a.output/task;root.mkdir()
            data={}
            for split in ('train','validation','test'):
                data[split]=extract_task(a.rf_run/(split+'.csv'),root/(split+'.csv'),task)
            x,y,_=data['train'];vx,vy,_=data['validation'];tx,ty,ids=data['test']
            seed=parent['inputs']['train']['seed']
            reference,fit=train(x,y,vx,vy,False,seed,a.epochs)
            reference.save(root/'reference-model.npz')
            for mode in MODES:
                transform(root/'train.csv',root/('zero-'+mode+'.csv'),task,mode,0)
            transform(root/'test.csv',root/'triggered-test.csv',task,'trigger_only',1)
            transform(root/'test.csv',root/'random-test.csv',task,'random_patch',1)
            triggered=read_table(root/'triggered-test.csv',task)[0]
            random=read_table(root/'random-test.csv',task)[0]
            metrics,predictions=evaluate(reference,reference,tx,triggered,random,ty,a.target)
            baseline=dict(task=task,mode='none',fraction_requested=0.,selected=0,fit=fit,metrics=metrics,model=task+'/reference-model.npz')
            rows.append(baseline)
            for mode in MODES:
                previous=set()
                for index,fraction in enumerate(sorted(a.fractions)):
                    name=mode+'-'+str(index);condition=root/name;condition.mkdir()
                    audit=transform(root/'train.csv',condition/'train.csv',task,mode,fraction)
                    selected=set(audit['selected_ids'])
                    if not previous.issubset(selected): raise ValueError('Poison sweep is not nested')
                    previous=selected
                    px,py,_=read_table(condition/'train.csv',task)
                    model,fit=train(px,py,vx,vy,False,seed,a.epochs)
                    model.save(condition/'model.npz')
                    metrics,predictions=evaluate(model,reference,tx,triggered,random,ty,a.target)
                    row=dict(task=task,mode=mode,fraction_requested=fraction,selected=audit['selected'],
                             fraction_actual=audit['fraction'],fit=fit,metrics=metrics,
                             model=task+'/'+name+'/model.npz',training=task+'/'+name+'/train.csv')
                    rows.append(row)
                    with (condition/'predictions.csv').open('w',newline='') as handle:
                        writer=csv.writer(handle)
                        writer.writerow(['id','true','reference_clean','model_clean','model_triggered','model_random_patch'])
                        for k in range(len(tx)):
                            writer.writerow([ids[k],ty[k],predictions['reference_clean'][k],predictions['model_clean'][k],
                                             predictions['model_triggered'][k],predictions['model_random_patch'][k]])
                    print(task,mode,fraction,json.dumps(metrics),flush=True)
            for split in ('train','validation','test'):
                if digest(a.rf_run/(split+'.csv'))!=parent['inputs'][split]['sha256']:
                    raise ValueError('Original RF split changed during training study')
        publish(a.output/'manifest.json',manifest)
        publish(a.output/'summary.json',dict(conditions=rows))
        evidence={}
        for path in sorted(a.output.rglob('*')):
            if path.is_file() and path.name not in ('run_status.json','evidence.json'):
                evidence[str(path.relative_to(a.output))]=digest(path)
        publish(a.output/'evidence.json',evidence)
        state.update(state='completed',conditions=len(rows),training_only_poisoning=True)
        publish(a.output/'run_status.json',state)
    except BaseException as error:
        state.update(state='failed',error=str(error));publish(a.output/'run_status.json',state);raise
    print('Training attack results:',a.output,flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
