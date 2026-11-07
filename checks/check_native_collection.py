"""Recompute native LTE collection invariants from raw simulator evidence."""
import argparse
import csv
import json
from pathlib import Path
import math


def read(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))


def verify(root):
    plan=json.loads((root/'collection.json').read_text())
    assert plan['state']=='complete' and not plan['failed']
    counts=dict(runs=0, windows=0, payload_bytes=0, submitted=0, confirmed=0, resource_configurations=0)
    for name in plan['completed']:
        run=root/'runs'/name; raw=run/'raw'
        receipt=json.loads((run/'run_status.json').read_text())
        assert receipt['status']=='complete'
        assert receipt['scenario']['sha256']==plan['source_sha256']
        windows=read(raw/'ran_windows.csv'); events=read(raw/'control_events.csv')
        commands=read(raw/'control_dispatch.csv'); resources=read(raw/'resource_events.csv')
        keys=set(); total=0
        for row in windows:
            key=(row['window_end_s'],row['ue_imsi']); assert key not in keys; keys.add(key)
            dt=float(row['window_end_s'])-float(row['window_start_s']); assert dt>0
            payload=int(row['rx_payload_bytes']); total+=payload
            assert math.isclose(float(row['app_goodput_mbps']),payload*8/dt/1e6,abs_tol=1e-8)
            assert int(row['cell_id']) in (1,2)
            for k in ['app_goodput_mbps','serving_sinr_db','serving_rsrp_dbm']:
                assert math.isfinite(float(row[k]))
        assert len(windows)==1600 and total>0
        assert len({r['ue_imsi'] for r in events if r['event']=='connected'})==10
        submitted={r['request_id']:r for r in commands if r['status']=='submitted'}
        assert len(submitted)<=2
        confirmations=[r for r in events if r['event']=='confirmed_target_connected']
        for row in confirmations:
            request=submitted[row['request_id']]
            assert row['observed_cell']==row['target_cell']==request['target_cell']
            assert float(row['sim_time_s'])>float(request['sim_time_s'])
        assert len({r['request_id'] for r in confirmations})==len(confirmations)
        budgets={};integer_budgets={};allocation_counts={}
        for row in resources:
            key=(row['sim_time_s'],row['cell_id'])
            budgets[key]=budgets.get(key,0)+float(row['configured_mbr_bps'])
            integer_budgets[key]=integer_budgets.get(key,0)+int(float(row['configured_mbr_bps']))
            allocation_counts[key]=allocation_counts.get(key,0)+1
            expected=float(row['true_group_demand_mbps'])*(8 if row['attack_applied']=='1' and row['service_group']=='0' else 1)
            assert math.isclose(float(row['reported_group_demand_mbps']),expected)
        assert all(abs(v-20e6)<=10 for v in budgets.values())
        assert all(0<=20e6-v<allocation_counts[k] for k,v in integer_budgets.items())
        records=[json.loads(line) for line in (raw/'decision_states.jsonl').read_text().splitlines()]
        assert all(r['state']['time']>=2 for r in records)
        assert all(r['state']['handover_budget_remaining'] in (0,1,2) for r in records)
        assert all(r['action']=='hold' for r in records if r['state']['time']<4)
        assert records[-1]['state']['terminal']
        counts['runs']+=1; counts['windows']+=len(windows);counts['payload_bytes']+=total
        counts['submitted']+=len(submitted);counts['confirmed']+=len(confirmations);counts['resource_configurations']+=len(resources)
    # Same seed/workload prefix must be identical across all paired interventions.
    for rep in range(5):
        paired=sorted((root/'runs').glob(f'eval-r{rep}-*'))
        reference=None
        for run in paired:
            prefix=[r for r in read(run/'raw/ran_windows.csv') if float(r['window_end_s'])<=4]
            if reference is None:reference=prefix
            else:assert prefix==reference,run.name
    result=dict(verified=True,**counts, mbr_rounding='raw configured_mbr_bps records nominal allocation; actual SAP integer bps=floor(nominal), verified total unused budget below allocation count bps',
        scope='all window byte/goodput arithmetic, row keys, RRC requests/confirmations, actual scheduler MBR budget/configuration, intervention-free paired prefixes; no claim of O-RAN/E2/OTA or attack success')
    (root/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();print(json.dumps(verify(a.root),indent=2))
