#!/usr/bin/env python3
"""Check recorded live E2 evidence; a build or duplicated setup requests do not suffice."""
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
    evidence={'status_complete':status.get('status')=='complete',
              'runner_verified_e2':status.get('live_ric_verified') is True,
              'simulation_exit_zero':status.get('simulation_exit_code')==0,
              'five_distinct_e2_nodes':len(nodes)>=5,
              'xapp_discovered_five_nodes':max(discoveries,default=0)>=5,
              'decoded_kpm_indications':xapp.count('KPM ind_msg latency')>0,
              'numeric_kpm_measurements':'[KPM VALID]' in xapp,
              'sender_fix_executed':'[KPM FIX] patched message constructor' in sim,
              'application_csv_nonempty':row_count>0}
    return {'passed':all(evidence.values()),'checks':evidence,'distinct_e2_nodes':len(nodes),
            'kpm_indications':xapp.count('KPM ind_msg latency'),'application_csv_rows':row_count,
            'runner_error':status.get('error')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir',type=Path,nargs='?')
    parser.add_argument('--latest',action='store_true')
    args=parser.parse_args()
    root=args.run_dir
    if args.latest:
        paths=sorted((Path(__file__).resolve().parent/'results').glob('live-*'))
        if not paths:parser.error('No live run found')
        root=paths[-1]
    if root is None:parser.error('Provide a run directory or --latest')
    result=check(root)
    (root/'live_verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Run:',root)
    print(json.dumps(result,indent=2))
    sys.exit(0 if result['passed'] else 1)

if __name__=='__main__':main()
