#!/usr/bin/env python3
"""Validate bounded telemetry evasion and export clean/observed feature pairs."""
import argparse
import csv
import json
import math
from pathlib import Path


def read(path):
    with path.open() as stream:return list(csv.DictReader(stream))


def verify(root):
    directory=root/'csv';config=json.loads((directory/'evasion_config.json').read_text())
    rows=read(directory/'ai_shadow_attack_audit.csv')
    reference=read(directory/'ai_shadow_reference_decisions.csv');decisions=read(directory/'ai_shadow_decisions.csv')
    key=lambda r:(round(float(r['decision_time_s'])*10),int(r['ue_imsi']))
    refs={key(r):r for r in reference};actual={key(r):r for r in decisions}
    checks=dict(audit_nonempty=bool(rows),unique_audit_keys=True,budget=True,event_mask=True,
                consistent_features=True,temporal_history=True,complete_decisions=bool(refs) and set(refs)==set(actual))
    seen=set();history={};active=set();affected=set()
    close=lambda x,y:math.isclose(float(x),float(y),abs_tol=1e-7,rel_tol=1e-8)
    for r in sorted(rows,key=lambda r:(float(r['decision_time_s']),int(r['ue_imsi']),int(r['nr_cell_id']))):
        tick,ue=key(r);cell=int(r['nr_cell_id']);identity=(tick,ue,cell)
        checks['unique_audit_keys'] &= identity not in seen;seen.add(identity)
        delta=float(r['delta_sinr_db']);previous=float(r['previous_delta_db'])
        expected_active=config['mode']!='none' and any(int(e['ue_imsi'])==ue and float(e['start_s'])<=tick/10<float(e['end_s']) for e in config.get('events',[]))
        checks['event_mask'] &= bool(int(r['event_active']))==expected_active and (expected_active or close(delta,0))
        limit=float(config.get('epsilon_db',0)) if config['mode']!='none' else 0
        checks['budget'] &= math.isfinite(delta) and abs(delta)<=limit+1e-9
        prior=history.get((ue,cell));expected=prior[1] if prior and prior[0]==tick-1 else 0
        checks['temporal_history'] &= close(previous,expected)
        history[(ue,cell)]=(tick,delta)
        changes={'sinr_mean_db':delta,'sinr_last_db':delta,'mean_change_db':delta-previous}
        for name in [k[6:] for k in r if k.startswith('clean_') and 'model_'+k[6:] in r]:
            a,b=r['clean_'+name],r['model_'+name]
            checks['consistent_features'] &= (a==b if not a or not b else close(float(b)-float(a),changes.get(name,0)))
        checks['consistent_features'] &= close(float(r['model_sinr_mean_db'])-float(r['raw_sinr_mean_db']),delta)
        if expected_active:active.add((tick,ue))
        if int(r['input_perturbed']):affected.add((tick,ue))
    changed=sum((refs[k]['action'],refs[k]['recommended_cell_id'])!=(actual[k]['action'],actual[k]['recommended_cell_id']) for k in affected if k in refs and k in actual)
    action_changes=sum(refs[k]['action']!=actual[k]['action'] for k in affected if k in refs and k in actual)
    command=lambda r:(r['action'],r['recommended_cell_id'] if r['action']=='recommend_handover' else '')
    command_changes=sum(command(refs[k])!=command(actual[k]) for k in affected if k in refs and k in actual)
    target_hits=0;target_total=0
    groups={}
    for r in rows:
        if int(r['event_active']):groups.setdefault(key(r),[]).append(r)
    for k,group in groups.items():
        winner=max(group,key=lambda r:float(r['observed_prediction_db']))
        target_total+=1;target_hits+=winner['nr_cell_id']==winner['attack_target_cell']
    # A separate dataset keeps measured ground truth and model-observed features side by side.
    source=directory/'ran_features_100ms.csv'
    if source.exists():
        index={(round(float(r['decision_time_s'])*10),r['ue_imsi'],r['nr_cell_id']):r for r in rows}
        radio=read(source);output=[]
        for row in radio:
            attack=index.get((round(float(row['window_end_s'])*10),row['ue_imsi'],row['nr_cell_id']))
            row.update({'aml_'+k:v for k,v in (attack or {}).items() if k not in ['run_id','decision_time_s','ue_imsi','nr_cell_id']})
            row['aml_audit_available']=int(attack is not None);output.append(row)
        fields=list(dict.fromkeys(k for row in output for k in row))
        with (directory/'adversarial_dataset.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(output)
    result=dict(passed=all(checks.values()),checks=checks,mode=config['mode'],audit_rows=len(rows),
                active_ue_windows=len(active),affected_ue_windows=len(affected),same_state_policy_changes=changed,action_changes=action_changes,executable_command_changes=command_changes,
                targeted_rank_hits=target_hits,targeted_rank_trials=target_total,
                note='Reference policy sees clean telemetry on the attacked trajectory; separate clean run required for QoS comparison. Pipeline pass does not mean attack success.')
    (root/'evasion_verification.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path,nargs='?');p.add_argument('--latest',action='store_true');a=p.parse_args()
    root=a.root
    if a.latest:root=max((p.parent.parent for p in (Path(__file__).resolve().parent/'results').glob('*/csv/ai_shadow_attack_audit.csv')),key=lambda p:p.stat().st_mtime)
    if root is None:p.error('Provide run directory or --latest')
    result=verify(root);print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
