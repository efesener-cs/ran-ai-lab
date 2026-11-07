"""Validate learned resource actions, actual LTE token weights and traffic TX/RX."""
import argparse,csv,json,math
from pathlib import Path
from checks.check_native_collection import verify as verify_base,read


def verify(root):
    base=verify_base(root)
    plan=json.loads((root/'collection.json').read_text());profiles=0;transmitted=0
    for name in plan['completed']:
        run=root/'runs'/name;raw=run/'raw';config=json.loads((run/'run_status.json').read_text())['configuration']
        windows=read(raw/'ran_windows.csv');allocations=read(raw/'resource_events.csv');commands=read(raw/'control_dispatch.csv')
        tx={};rx={};budgets={}
        for row in windows:
            ue=row['ue_imsi'];count=int(row['tx_packets']);bytes_=int(row['tx_payload_bytes'])
            assert bytes_==1000*count and count>=0
            tx[ue]=tx.get(ue,0)+bytes_;rx[ue]=rx.get(ue,0)+int(row['rx_payload_bytes']);transmitted+=bytes_
        assert all(rx[ue]<=n for ue,n in tx.items())
        for row in allocations:
            key=(float(row['sim_time_s']),row['cell_id']); group=int(row['service_group']);budget=int(row['configured_mbr_bps'])
            assert budget==float(row['configured_mbr_bps'])
            budgets.setdefault(key,[0,0])[group]+=budget
        assert all(abs(sum(v)-20e6)<=10 for v in budgets.values())
        for command in commands:
            assert command['status']=='resource_profile_applied'
            profile=int(command['target_cell']);assert profile in (0,1,2)
            when=float(command['sim_time_s'])+1e-6
            actual=[value for (time_,cell),value in budgets.items() if math.isclose(time_,when,abs_tol=1e-9)]
            assert len(actual)==2
            for value in actual:assert math.isclose(value[0]/sum(value),[.2,.5,.8][profile],abs_tol=1e-6)
            profiles+=1
        records=[json.loads(line) for line in (raw/'decision_states.jsonl').read_text().splitlines()]
        for record in records:
            s=record['state'];o=record['observed']
            if s['time']>=4 and config['attack']=='fake_request':assert o['group0_demand_mbps']==8*s['group0_demand_mbps']
        if config['traffic_overload']:
            flow=[row for row in windows if row['ue_imsi']=='2' and float(row['window_start_s'])>=4]
            seconds=sum(float(row['window_end_s'])-float(row['window_start_s']) for row in flow)
            offered=sum(int(row['tx_payload_bytes']) for row in flow)*8/seconds/1e6
            assert 70<offered<81,offered
    result=dict(base,verified=True,resource_profile_actions=profiles,application_tx_payload_bytes=transmitted,
        scope='all base LTE invariants plus actual TX payload/packet consistency and RX<=TX, per-command deferred scheduler profile20/50/80% execution, group/cell token budgets, fake request input magnitude, actual70–81Mbps flood source; no enforceable5G isolation/E2/OTA')
    (root/'verification.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();print(json.dumps(verify(a.root),indent=2))
