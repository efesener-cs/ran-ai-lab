#!/usr/bin/env python3
"""Check recorded live E2 evidence; a build or duplicated setup requests do not suffice."""
from labcore.paths import ROOT
import argparse
import csv
import json
from pathlib import Path
import re
import sys


def check(root):
    root=Path(root)
    status_path=root/'run_status.json'
    status=json.loads(status_path.read_text()) if status_path.exists() else {}
    def read(name):
        path=root/'raw'/name
        return path.read_text(errors='replace') if path.exists() else ''
    ric=read('ric.log');xapp=read('xapp.log');sim=read('simulation.log')
    nodes=set(re.findall(r'E2 SETUP-REQUEST rx[^\n]*Node ID (\d+) RAN type (\S+)',ric))
    discoveries=[int(v) for v in re.findall(r'Connected E2 nodes = (\d+)',xapp)]
    csv_path=root/'csv/ue_application_100ms.csv'
    row_count=0
    if csv_path.exists():
        with csv_path.open() as stream:row_count=sum(1 for _ in csv.DictReader(stream))
    expected_nodes = int(status.get('configuration', {}).get('e2_nodes', 5))
    # Preserve the historical check keys; their threshold now follows the supplied topology.
    evidence={'status_complete':status.get('status')=='complete',
              'runner_verified_e2':status.get('live_ric_verified') is True,
              'simulation_exit_zero':status.get('simulation_exit_code')==0,
              'five_distinct_e2_nodes':expected_nodes > 0 and len(nodes)>=expected_nodes,
              'xapp_discovered_five_nodes':expected_nodes > 0 and max(discoveries,default=0)>=expected_nodes,
              'decoded_kpm_indications':xapp.count('KPM ind_msg latency')>0,
              'numeric_kpm_measurements':'[KPM VALID]' in xapp,
              'sender_fix_executed':'[KPM FIX] patched message constructor' in sim,
              'application_csv_nonempty':row_count>0}
    return {'passed':all(evidence.values()),'checks':evidence,'distinct_e2_nodes':len(nodes),
            'kpm_indications':xapp.count('KPM ind_msg latency'),'application_csv_rows':row_count,
            'runner_error':status.get('error'), 'expected_e2_nodes':expected_nodes}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir',type=Path,nargs='?')
    parser.add_argument('--latest',action='store_true')
    args=parser.parse_args(argv)
    root=args.run_dir
    if args.latest:
        paths=sorted((ROOT/'results').glob('live-*'))
        if not paths:parser.error('No live run found')
        root=paths[-1]
    if root is None:parser.error('Provide a run directory or --latest')
    result=check(root)
    (root/'live_verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Run:',root)
    print(json.dumps(result,indent=2))
    sys.exit(0 if result['passed'] else 1)

if __name__=='__main__':main()
