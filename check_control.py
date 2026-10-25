#!/usr/bin/env python3
"""Join model recommendations, RRC submissions and later connected-cell observations."""
import argparse
import csv
import json
from pathlib import Path
import sys
from check_live import check as check_live


def read_rows(path):
    if not path.exists():return []
    with path.open() as stream:return list(csv.DictReader(stream))


def verify(root,require_live=True):
    root=Path(root);status=json.loads((root/'run_status.json').read_text())
    requests=read_rows(root/'raw/control_dispatch.csv')
    events=read_rows(root/'raw/control_events.csv')
    decisions=read_rows(root/'csv/ai_shadow_decisions.csv')
    def key(row):return (round(float(row['decision_time_s']),8),int(row['ue_imsi']),int(row['recommended_cell_id']))
    recommended={key(row) for row in decisions if row['action']=='recommend_handover'}
    submitted=[r for r in requests if r['status']=='submitted']
    events_by_id={}
    for event in events:events_by_id.setdefault(event['request_id'],[]).append(event)
    matches=[];confirmed_keys=set()
    for request in submitted:
        ident=request['request_id'];result=events_by_id.get(ident,[])
        source_key=(round(float(request['sim_time_s']),8),int(request['ue_imsi']),int(request['target_cell']))
        evidence=(len(result)==1 and result[0]['event']=='confirmed_target_connected'
            and result[0]['ue_imsi']==request['ue_imsi']
            and result[0]['from_cell']==request['from_cell']
            and result[0]['target_cell']==request['target_cell']==result[0]['observed_cell']
            and request['from_cell']!=request['target_cell']
            and float(result[0]['sim_time_s'])>float(request['sim_time_s'])
            and source_key in recommended)
        if evidence:confirmed_keys.add(source_key)
        matches.append(dict(request_id=ident,ue_imsi=request['ue_imsi'],
            request_time_s=request['sim_time_s'],from_cell=request['from_cell'],
            target_cell=request['target_cell'],confirmed=bool(evidence),
            confirmation_time_s=result[0]['sim_time_s'] if evidence else None))
    checks={'simulation_completed':status.get('status')=='complete' and status.get('simulation_exit_code')==0,
            'control_enabled':status.get('ai_control_enabled') is True,
            'recommendations_present':bool(decisions),
            'at_least_one_rrc_submission':bool(submitted),
            'unique_request_ids':len({r['request_id'] for r in requests})==len(requests),
            'all_submissions_have_later_target_connected_evidence':bool(matches) and all(r['confirmed'] for r in matches)}
    if require_live:checks['live_e2_passed']=check_live(root)['passed']
    result=dict(passed=all(checks.values()),checks=checks,transport='atomic CSV -> ns-3 RRC API; not E2 RC',
        submitted=len(submitted),confirmed=sum(r['confirmed'] for r in matches),
        rejected=sum(r['status']!='submitted' for r in requests),requests=matches,
        note='Target cell and CONNECTED_NORMALLY state observed after submission; not a throughput benefit claim.')
    out=root/'csv';out.mkdir(exist_ok=True)
    if decisions:
        annotated=[{**row,'network_action_applied':int(key(row) in confirmed_keys)} for row in decisions]
        with (out/'ai_control_decisions.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(annotated[0]));writer.writeheader();writer.writerows(annotated)
    (root/'control_verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run_dir',type=Path,nargs='?');p.add_argument('--latest',action='store_true')
    p.add_argument('--native',action='store_true',help='Explicitly omit live E2 check for host-only integration tests')
    a=p.parse_args();root=a.run_dir
    if a.latest:
        roots=sorted((Path(__file__).resolve().parent/'results').glob('control-native-*' if a.native else 'live-*'))
        if not roots:p.error('No matching run found')
        root=roots[-1]
    if root is None:p.error('Provide a run directory or --latest')
    result=verify(root,not a.native)
    print(json.dumps({k:v for k,v in result.items() if k!='requests'},indent=2))
    sys.exit(0 if result['passed'] else 1)

if __name__=='__main__':main()
