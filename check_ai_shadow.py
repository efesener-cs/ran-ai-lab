#!/usr/bin/env python3
"""Verify full shadow recommendation coverage; this does not prove policy quality or control."""
import argparse
import csv
import json
from pathlib import Path
import sys
from check_live import check

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('run_dir',type=Path,nargs='?')
p.add_argument('--latest',action='store_true')
a=p.parse_args()
root=a.run_dir
if a.latest:
    roots=sorted((Path(__file__).resolve().parent/'results').glob('live-*'))
    if not roots:p.error('No live run found')
    root=roots[-1]
if root is None:p.error('Provide a run directory or --latest')
status=json.loads((root/'run_status.json').read_text())
file=root/'csv/ai_shadow_status.json'
shadow=json.loads(file.read_text()) if file.exists() else {}
def rows(name):
    path=root/'csv'/name
    if not path.exists():return []
    with path.open() as stream:return list(csv.DictReader(stream))
app=rows('ue_application_100ms.csv');decisions=rows('ai_shadow_decisions.csv')
expected={(r['ue_imsi'],round(float(r['window_end_s']),8)) for r in app if r['is_warmup']=='0'}
actual={(r['ue_imsi'],round(float(r['decision_time_s']),8)) for r in decisions}
checks={'live_e2_passed':check(root)['passed'],
        'shadow_enabled':status.get('ai_shadow_enabled') is True,
        'shadow_completed':shadow.get('status')=='complete',
        'concurrent_execution':shadow.get('mode')=='concurrent shadow process',
        'all_nonwarmup_windows_have_one_decision':bool(expected) and expected==actual and len(actual)==len(decisions),
        'no_network_actions_applied':bool(decisions) and all(r['network_action_applied']=='0' for r in decisions)}
result=dict(passed=all(checks.values()),checks=checks,decision_count=len(decisions),
            note='Shadow plumbing only; forecast quality is reported separately in evaluation.json.')
(root/'ai_verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));sys.exit(0 if result['passed'] else 1)
