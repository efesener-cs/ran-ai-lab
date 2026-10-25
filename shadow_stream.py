#!/usr/bin/env python3
"""Evaluate a fitted AI model during ns-3 execution, without issuing network controls."""
import argparse
import csv
import json
import hashlib
from pathlib import Path
import time
import os
from ai.runtime import RuntimeForecaster
from ai.stream import Telemetry
from ai.policy import recommendations
from ai.evasion import Evasion


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model',type=Path,required=True)
    p.add_argument('--raw-dir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--run-id',required=True)
    p.add_argument('--ues',type=int,required=True)
    p.add_argument('--stop-file',type=Path)
    p.add_argument('--replay',action='store_true')
    p.add_argument('--apply-control',action='store_true')
    p.add_argument('--evasion-config',type=Path)
    a=p.parse_args()
    if a.replay and a.apply_control:p.error('Control cannot be applied to completed-trace replay')
    if not a.replay and not a.stop_file:p.error('--stop-file is required during live operation')
    model=RuntimeForecaster.load(a.model);reader=Telemetry(a.raw_dir,a.run_id,a.ues)
    attack_config=json.loads(a.evasion_config.read_text()) if a.evasion_config else {'mode':'none','epsilon_db':0,'events':[]}
    engine=Evasion(model,attack_config)
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'evasion_config.json').write_text(json.dumps(attack_config,indent=2)+'\n')
    # Maintain recommendation cooldown across closed-window batches.
    reference_state={};policy_state={};emitted=set();count=0;writers={};streams=[]
    try:
        while True:
            # Snapshot completion before polling so the final flush is always drained.
            finished=a.replay or a.stop_file.exists()
            batch=reader.poll()
            reference,_=recommendations(model,batch,state=reference_state)
            observed,audit=engine.transform(batch)
            decisions,scores=recommendations(model,observed,state=policy_state)
            new=[r for r in decisions if (r['ue_imsi'],r['decision_time_s']) not in emitted]
            if a.apply_control:
                for row in new:row['network_action_applied']=''
            for name,rows in [('attack_audit',audit),('reference_decisions',reference),('decisions',new),('scores',[r for r in scores if (r['ue_imsi'],r['decision_time_s']) not in emitted])]:
                if rows:
                    if name not in writers:
                        stream=(a.output/('ai_shadow_'+name+'.csv')).open('w',newline='');streams.append(stream)
                        writers[name]=csv.DictWriter(stream,fieldnames=list(rows[0]));writers[name].writeheader()
                    writers[name].writerows(rows)
            if a.apply_control:
                steps={}
                for record in new:
                    tick=round(record['decision_time_s']*10)
                    state=reader.control.get((tick-1,record['ue_imsi']))
                    if state and state['control_required']=='1':steps.setdefault(tick,[]).append(record)
                directory=a.raw_dir/'control';directory.mkdir(exist_ok=True)
                for tick,records in steps.items():
                    if len(records)!=a.ues:raise RuntimeError('Incomplete control window; refusing partial commands')
                    temp=directory/f'.step-{tick}.tmp';dest=directory/f'step-{tick}.csv'
                    with temp.open('w',newline='') as stream:
                        writer=csv.writer(stream);writer.writerow(['decision_time_s','ue_imsi','action','target_cell'])
                        for record in sorted(records,key=lambda row:row['ue_imsi']):
                            writer.writerow([record['decision_time_s'],record['ue_imsi'],record['action'],record['recommended_cell_id']])
                    os.replace(temp,dest)
            emitted.update((r['ue_imsi'],r['decision_time_s']) for r in new);count+=len(new)
            for stream in streams:stream.flush()
            if finished:break
            time.sleep(0.05)
        if count==0:raise RuntimeError('AI shadow process produced no complete-window recommendations')
        applied=0
        if a.apply_control:
            path=a.raw_dir/'control_events.csv'
            if path.exists():
                with path.open() as stream:applied=sum(r['event']=='confirmed_target_connected' for r in csv.DictReader(stream))
        summary=dict(status='complete',decision_count=count,network_actions_applied=applied,
                     model_sha256=hashlib.sha256(a.model.read_bytes()).hexdigest(),
                     mode='completed-trace replay' if a.replay else 'concurrent control bridge' if a.apply_control else 'concurrent shadow process',
                     control_transport='atomic CSV to ns-3 RRC API' if a.apply_control else 'none',
                     evasion_mode=attack_config['mode'],epsilon_db=attack_config.get('epsilon_db',0),
                     input='closed ns-3 trace windows; no E2 KPM input adapter yet')
        (a.output/'ai_shadow_status.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary),flush=True)
    finally:
        for stream in streams:stream.close()

if __name__=='__main__':main()
