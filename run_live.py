#!/usr/bin/env python3
"""Host entry point; uses the existing flexric container, copies results back even on failure."""
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import json

p=argparse.ArgumentParser()
p.add_argument('--container',default='flexric')
p.add_argument('--ai-model',type=Path)
p.add_argument('--evasion-config',type=Path)
p.add_argument('--apply-ai-control',action='store_true')
args,extra=p.parse_known_args()
lab=Path(__file__).resolve().parent
if args.evasion_config and (not args.evasion_config.is_file() or args.ai_model is None):p.error('--evasion-config requires an existing JSON file and --ai-model')
if args.apply_ai_control and args.ai_model is None:p.error('--apply-ai-control requires --ai-model')
if args.apply_ai_control:extra+=['--apply-ai-control']
if args.ai_model is not None and not args.ai_model.is_file():
    p.error('AI model file not found: '+str(args.ai_model))
run_id='live-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f')
remote='/tmp/ran-ai-'+run_id
out=lab/'results'/run_id
# Check before making a run folder; no sudo or permissions changes.
try:
    state=subprocess.check_output(['docker','inspect','-f','{{.State.Running}}',args.container],text=True).strip()
except subprocess.CalledProcessError:
    sys.exit('Docker access failed. Run this command in your normal host terminal.')
if state!='true':subprocess.run(['docker','start',args.container],check=True)
subprocess.run(['docker','exec',args.container,'mkdir','-p',remote],check=True)
for name in ['container_run.py','check_control.py','check_live.py','ric_address.py','kpm_fixes.py','discover_sources.py','portable_build.py','experiment_plan.py','export_dataset.py','build_csv.py','ran-ai-scenario.cc']:
    subprocess.run(['docker','cp',str(lab/name),args.container+':'+remote+'/'+name],check=True)
if args.ai_model is not None:
    subprocess.run(['docker','exec',args.container,'mkdir','-p',remote+'/ai'],check=True)
    for name in ['__init__.py','runtime.py','policy.py','stream.py','evasion.py']:
        subprocess.run(['docker','cp',str(lab/'ai'/name),args.container+':'+remote+'/ai/'+name],check=True)
    subprocess.run(['docker','cp',str(lab/'shadow_stream.py'),args.container+':'+remote+'/shadow_stream.py'],check=True)
    subprocess.run(['docker','cp',str(args.ai_model),args.container+':'+remote+'/model.json'],check=True)
    extra+=['--shadow-model',remote+'/model.json']
if args.evasion_config:
    subprocess.run(['docker','cp',str(args.evasion_config),args.container+':'+remote+'/evasion.json'],check=True)
    extra+=['--evasion-config',remote+'/evasion.json']
# Search bind-mount destinations as well as standard container workspace roots.
mounts=json.loads(subprocess.check_output(['docker','inspect','-f','{{json .Mounts}}',args.container],text=True))
for mount in mounts or []:
    if mount.get('Type')=='bind' and mount.get('Destination') not in ['/var/run/docker.sock']:
        extra += ['--search-root',mount['Destination']]
print('Container workdir:',remote,flush=True)
code=1
try:
    code=subprocess.call(['docker','exec',args.container,'python3',remote+'/container_run.py',*extra])
except KeyboardInterrupt:
    code=130
    subprocess.call(['docker','exec',args.container,'python3','-c',
        'import os,signal,sys; from pathlib import Path; os.kill(int(Path(sys.argv[1]).read_text()),signal.SIGTERM)',
        remote+'/controller.pid'])
finally:
    out.mkdir(parents=True,exist_ok=True)
    copied=subprocess.call(['docker','cp',args.container+':'+remote+'/result/.',str(out)])
    print('Results and diagnostic logs:',out,flush=True)
    if copied:print('Result copy failed; files remain in the container at '+remote,file=sys.stderr)
sys.exit(code)
