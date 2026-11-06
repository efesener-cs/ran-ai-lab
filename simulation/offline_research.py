"""Offline supervisor: resume collection, then fit categorical family models."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from simulation.run_research_campaign import environment,resources_ok,save,verify,sha



def completed_model(path):
    manifest=path/'artifact_manifest.json'
    checksum=path/'checksums.json'
    if manifest.exists():files=json.loads(manifest.read_text())['files']
    elif checksum.exists():files=json.loads(checksum.read_text())
    else:return False
    for name,value in files.items():
        target=(path/name).resolve()
        if not target.is_relative_to(path.resolve()) or sha(target)!=value:raise ValueError('Saved model artifact changed')
    return (path/'metrics.json').is_file() and any(path.glob('*.joblib'))

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('campaign',type=Path);p.add_argument('--model-python',type=Path,required=True);a=p.parse_args(argv)
    root=a.campaign.resolve(strict=True);plan=json.loads((root/'campaign.json').read_text());verify(root,plan)
    if plan.get('stage')!='research_collection':p.error('Preregistered collection required')
    env=environment(root);status=root/'offline-status.json'
    while True:
        plan=json.loads((root/'campaign.json').read_text())
        reason=resources_ok(plan)
        if reason:
            save(status,dict(state='waiting_for_resources',reason=reason,updated_epoch=time.time()));time.sleep(60);continue
        if plan['state']=='complete':break
        save(status,dict(state='collecting',updated_epoch=time.time()))
        code=subprocess.call([sys.executable,str(root/'runtime/lab.py'),'run_research_campaign','--resume',str(root)],env=env,cwd=root)
        plan=json.loads((root/'campaign.json').read_text())
        if code==0 and plan['state']=='complete':break
        if plan['state']=='resource_limited':time.sleep(60);continue
        save(status,dict(state='collection_failed',campaign_state=plan['state'],returncode=code,updated_epoch=time.time()));return code or 2
    partition=plan['seed_partition'];base=root/'models/ip-attack-family';base.mkdir(parents=True,exist_ok=True)
    complete=[p for p in sorted(base.glob('attempt-*')) if p.is_dir() and completed_model(p)]
    out=complete[0] if complete else None
    if out is None:
        attempts=list(base.glob('attempt-*'));out=base/('attempt-'+str(len(attempts)+1))
        cmd=[str(a.model_python),str(root/'runtime/ai/research_ip_multilabel.py'),'--campaign',str(root),'--output',str(out)]
        for flag,role in (('train','train'),('validation','validation'),('evaluation','test'),('ood','ood')):
            cmd+=['--'+flag+'-seeds',*map(str,partition[role])]
        save(status,dict(state='fitting_ip_attack_families',output=out.relative_to(root).as_posix(),updated_epoch=time.time()))
        with (root/'categorical-training.log').open('a') as log:code=subprocess.call(cmd,env=env,cwd=root,stdout=log,stderr=subprocess.STDOUT)
        if code:
            save(status,dict(state='ip_model_failed',returncode=code,updated_epoch=time.time()));return code
    rfbase=root/'models/rf-attack-method';rfbase.mkdir(parents=True,exist_ok=True)
    done=[p for p in rfbase.glob('attempt-*') if p.is_dir() and completed_model(p)]
    code=0
    if not done:
        rfout=rfbase/('attempt-'+str(len(list(rfbase.glob('attempt-*')))+1))
        cmd=[str(a.model_python),str(root/'runtime/ai/rf_attack_family.py'),str(root),'--output',str(rfout)]
        save(status,dict(state='fitting_rf_attack_methods',output=rfout.relative_to(root).as_posix(),updated_epoch=time.time()))
        with (root/'rf-categorical-training.log').open('a') as log:code=subprocess.call(cmd,env=env,cwd=root,stdout=log,stderr=subprocess.STDOUT)
    save(status,dict(state='complete' if code==0 else 'rf_model_failed',returncode=code,ip_model_output=out.relative_to(root).as_posix(),updated_epoch=time.time()))
    return code


if __name__=='__main__':raise SystemExit(main())
