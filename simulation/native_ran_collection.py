"""Resumable native LTE graph-Q/reference attack collection, with raw evidence.

Exploration, fitting, and evaluation use disjoint simulator seeds. Five paired
evaluation contexts are the statistical units; 100ms rows are not replicates.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import numpy as np

from ai.native_graph_q import GraphQ, encode


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def transitions(folders):
    rows = []
    for folder in folders:
        records = [json.loads(line) for line in (folder/'raw/decision_states.jsonl').read_text().splitlines()]
        decisions = [r for r in records if r['state']['step'] % 10 == 0 and r['state']['time'] >= 4]
        for previous, following in zip(decisions, decisions[1:]):
            s, ns = previous['state'], following['state']
            between = [r['state'] for r in records if s['time'] < r['state']['time'] <= ns['time']]
            reward = np.mean([r['target_goodput_mbps'] + .1*(r['cell0_goodput_mbps']+r['cell1_goodput_mbps']) for r in between])/8
            action = previous['target'] if previous['action'] == 'handover' else 0
            reward -= .05*(action != 0)
            rows.append((encode(s), action, reward, encode(ns), ns['terminal'], folder.name, s['step']))
    return rows


def fit(rows, output, seed, intervention):
    rng = np.random.default_rng(seed)
    x = np.stack([r[0] for r in rows]); action = np.array([r[1] for r in rows])
    reward = np.array([r[2] for r in rows]); nx = np.stack([r[3] for r in rows])
    done = np.array([r[4] for r in rows])
    selected = rng.choice(len(rows), max(1, len(rows)//10), replace=False)
    if intervention == 'reward_poison':
        reward[selected] = -reward[selected] + 1.5*(action[selected] == 2)
    if intervention == 'backdoor':
        x[selected, 8] = -.4  # same -8dB observed trigger used at evaluation
        action[selected] = 2
        reward[selected] = 2
    model = GraphQ(seed)
    target = GraphQ(seed)
    losses = []
    for iteration in range(1500):
        ids = rng.integers(0, len(rows), min(64, len(rows)))
        y = reward[ids] + .9*(~done[ids])*target.forward(nx[ids]).max(1)
        losses.append(model.train(x[ids], action[ids], np.clip(y, -10, 10)))
        if iteration % 50 == 0:
            target.w = {k:v.copy() for k,v in model.w.items()}
    model.save(output)
    atomic(output.with_suffix('.json'), dict(seed=seed, intervention=intervention,
        transitions=len(rows), modified_transition_indices=selected.tolist() if intervention!='none' else [],
        steps=1500, discount=.9, target_sync_steps=50, final_loss=losses[-1],
        scope='offline neural fitted Q replay; one learned two-cell message-passing layer; no external validation selection'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--scenario', type=Path, required=True)
    p.add_argument('--ns3', type=Path, required=True)
    p.add_argument('--workers', type=int, choices=[1,2], default=2)
    a = p.parse_args(); root = a.output.resolve(); root.mkdir(parents=True, exist_ok=True)
    lock = (root/'.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
    source = root/'scenario.cc'
    if not source.exists(): shutil.copyfile(a.scenario, source)
    elif source.read_bytes() != a.scenario.read_bytes(): raise ValueError('Scenario changed; choose new collection')
    status = dict(state='running', source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  completed=[], failed=[], planned=0, scope='native LTE simulated RRC and TBFQ MBR logical service groups; two handover submissions per episode; no E2/OTA/5G slice isolation')
    def execute(job):
        name, seed, load, speed, policy, attack, model, fake, flood = job
        dest = root/'runs'/name
        if (dest/'run_status.json').exists():
            if json.loads((dest/'run_status.json').read_text())['status'] == 'complete': return name
            raise RuntimeError('Previous failed attempt must remain; create a revised collection: '+name)
        cmd = [sys.executable, '-m', 'simulation.run_native_control', '--scenario', str(source),
               '--ns3', str(a.ns3), '--output', str(dest), '--seed', str(seed), '--duration', '16',
               '--load', str(load), '--speed', str(speed), '--policy', policy, '--attack', attack, '--resource-control']
        if model: cmd += ['--model', str(model)]
        if fake: cmd += ['--fake-requests']
        if flood: cmd += ['--traffic-overload']
        logdir = root/'logs'; logdir.mkdir(exist_ok=True)
        with (logdir/(name+'.log')).open('w') as log:
            subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
        return name
    def stage(jobs):
        status['planned'] += len(jobs); atomic(root/'collection.json', status)
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futures = [(j[0], pool.submit(execute,j)) for j in jobs]
            for name, future in futures:
                try: status['completed'].append(future.result())
                except Exception as exc:
                    status['failed'].append(dict(job=name,error=str(exc))); status['state']='failed'
                    atomic(root/'collection.json', status); raise
                status['updated_unix_s']=time.time(); atomic(root/'collection.json', status)
                print('COMPLETE',name,flush=True)
    exploration = [('explore-%02d'%i,720101+i, [.6,1,1.5][i%3], [0,8,16][(i//3)%3], 'explore','none',None,False,False) for i in range(15)]
    stage(exploration)
    train = transitions([root/'runs'/j[0] for j in exploration[:10]])
    validation = transitions([root/'runs'/j[0] for j in exploration[10:]])
    models = root/'models'; models.mkdir(exist_ok=True)
    for rep in range(5):
        for intervention in ['none','reward_poison','backdoor']:
            output = models/f'graphq-r{rep}-{intervention}.npz'
            if not output.exists(): fit(train, output, 740001+rep, intervention)
    atomic(root/'split.json',dict(train_runs=[j[0] for j in exploration[:10]],
        validation_runs=[j[0] for j in exploration[10:]], train_transitions=len(train), validation_transitions=len(validation),
        model_selection='fixed settings; no test tuning', evaluation_seeds=[730101+i for i in range(5)]))
    jobs=[]
    for rep in range(5):
        seed=730101+rep; load=[.6,1,1.5,.8,1.2][rep]; speed=[0,8,16,4,12][rep]
        for attack in ['none','load_spoof','sinr_spoof','stale','random_control','action_override']:
            jobs.append((f'eval-r{rep}-{attack}',seed,load,speed,'graph_q',attack,models/f'graphq-r{rep}-none.npz',False,False))
        for intervention,attack in [('reward_poison','none'),('backdoor','none'),('backdoor','backdoor_trigger')]:
            jobs.append((f'eval-r{rep}-{intervention}-{attack}',seed,load,speed,'graph_q',attack,models/f'graphq-r{rep}-{intervention}.npz',False,False))
        for policy,attack,fake,name in [('hold','none',False,'resource-clean'),('hold','none',True,'fake-resource-request'),('graph_q','load_spoof',True,'joint-resource-telemetry')]:
            jobs.append((f'eval-r{rep}-{name}',seed,load,speed,policy,attack,models/f'graphq-r{rep}-none.npz' if policy=='graph_q' else None,fake,False))
        for attack in ['none','load_spoof']:
            jobs.append((f'eval-r{rep}-traffic-overload-{attack}',seed,load,speed,'graph_q',attack,models/f'graphq-r{rep}-none.npz',False,True))
    stage(jobs)
    status['state']='complete';atomic(root/'collection.json',status)


if __name__ == '__main__': main()
