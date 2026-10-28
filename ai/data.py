"""Turn recorded radio windows into causal observations and separate future targets."""
import csv
import hashlib
import json
import math
from pathlib import Path
import numpy as np


def number(row,key):
    try:
        value=float(row[key])
        return value if math.isfinite(value) else float('nan')
    except (KeyError,ValueError,TypeError):return float('nan')


def load_observations(root,require_clean=True,allow_native=False):
    root=Path(root).resolve()
    status=json.loads((root/'run_status.json').read_text())
    if status.get('status')!='complete' or status.get('simulation_exit_code')!=0:
        raise ValueError('AI pilot requires a completed run with simulation exit code zero: '+str(root))
    if status.get('live_ric_verified') is True:
        backend='live'
    elif allow_native and status.get('control_transport','').startswith('atomic CSV to ns-3 RRC API') and status.get('ai_control_enabled') is True:
        backend='native'
    else:
        raise ValueError('Run must be live-E2-verified; native runs require --allow-native and verified native control transport: '+str(root))
    evasion=root/'csv/evasion_config.json'
    if require_clean and evasion.exists() and json.loads(evasion.read_text()).get('mode','none')!='none':
        raise ValueError('Training baseline must not contain telemetry evasion')
    path=root/'csv/ran_features_100ms.csv'
    with path.open() as stream:rows=list(csv.DictReader(stream))
    if require_clean and any(r.get('attack_present')!='0' for r in rows):
        raise ValueError('Training/evaluation baseline must be clean')
    grouped={};seen=set()
    for r in rows:
        if r['run_id']!=root.name:raise ValueError('Noncanonical run_id; regenerate CSV with export_dataset.py')
        start,end=number(r,'window_start_s'),number(r,'window_end_s')
        if not math.isfinite(start) or not math.isfinite(end) or start<0 or abs(start*10-round(start*10))>1e-7 or abs(end-start-0.1)>1e-7:
            raise ValueError('Only contiguous 100ms windows are supported')
        key=(int(r['ue_imsi']),int(r['nr_cell_id']))
        tick=round(start*10)
        identity=(*key,tick)
        if identity in seen:raise ValueError('Duplicate UE/cell/window')
        seen.add(identity);grouped.setdefault(key,[]).append((tick,r))
    observations=[]
    for (ue,cell),entries in sorted(grouped.items()):
        previous=None
        for tick,r in sorted(entries):
            current=number(r,'sinr_mean_db');last=number(r,'sinr_last_db');std=number(r,'sinr_std_db')
            if not all(math.isfinite(v) for v in [current,last,std]):
                previous=None;continue
            if previous is not None and previous[0]+1==tick:
                corrupt=number(r,'cell_dl_corrupt_fraction')
                features=[current,last,std,current-previous[1],last-current,
                          number(r,'cell_dl_tb_count'),corrupt,float(not math.isfinite(corrupt))]
                observations.append(dict(run_id=root.name,ue=ue,cell=cell,tick=tick,
                    decision_time_s=number(r,'window_end_s'),features=features,current=current,
                    warmup=r.get('ue_is_warmup')=='1',
                    current_path_cell=int(r.get('ue_nr_rrc_cell_id') or r['last_recorded_path_cell_id']) if (r.get('ue_nr_rrc_cell_id') or r['last_recorded_path_cell_id']) else None))
            previous=(tick,current)
    metadata=dict(run_id=root.name,source_csv='csv/ran_features_100ms.csv',
                  scenario_sha256=(status.get('scenario') or {}).get('sha256'),
                  sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  configuration=status.get('configuration',{}),
                  seed=(status.get('configuration') or {}).get('seed'),
                  backend=backend,
                  feature_source=('ns-3 radio trace CSV from verified E2 run; not live xApp inference'
                                  if backend == 'live' else
                                  'ns-3 native control run radio trace CSV; not E2 or live xApp inference'))
    return observations,metadata


def supervised(observations):
    indexed={(o['run_id'],o['ue'],o['cell'],o['tick']):o for o in observations}
    result=[]
    for o in observations:
        following=indexed.get((o['run_id'],o['ue'],o['cell'],o['tick']+1))
        if not o['warmup'] and following is not None:
            result.append({**o,'target':following['current']})
    return result


def arrays(samples):
    return (np.array([s['features'] for s in samples]),
            np.array([s['target'] for s in samples]),np.array([s['current'] for s in samples]))


def write_csv(path,rows):
    if not rows:raise ValueError('No output rows')
    with Path(path).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
