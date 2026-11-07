"""Explicit native LTE file-barrier controller; no E2 or real-time claim.

The action at time t changes future traffic only. Raw simulator observations,
controller inputs, requests and RRC confirmations remain separate evidence.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import numpy as np
from ai.native_graph_q import GraphQ, encode

from scenario.source import build_native, snapshot_source
from simulation.native_runner import write_status


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scenario', type=Path, required=True)
    p.add_argument('--ns3', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seed', type=int, required=True)
    p.add_argument('--duration', type=float, default=12)
    p.add_argument('--load', type=float, default=1)
    p.add_argument('--speed', type=float, default=8)
    p.add_argument('--policy', choices=['hold', 'forced', 'load_balance', 'explore', 'graph_q'], default='hold')
    p.add_argument('--attack', choices=['none', 'load_spoof', 'sinr_spoof', 'stale', 'random_control', 'action_override', 'backdoor_trigger', 'cross_domain'], default='none')
    p.add_argument('--model', type=Path)
    p.add_argument('--resource-control', action='store_true')
    p.add_argument('--fake-requests', action='store_true')
    p.add_argument('--traffic-overload', action='store_true')
    p.add_argument('--decision-period', type=int, default=10)
    a = p.parse_args(argv)
    if a.policy == 'graph_q' and a.model is None:
        p.error('--model is required for graph_q')
    model = GraphQ.load(a.model) if a.model else None
    rng = np.random.default_rng(a.seed + 730000)
    root = a.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    raw = root / 'raw'
    raw.mkdir()
    selected = snapshot_source(a.scenario, root)
    status = {'status': 'building', 'scenario': selected.metadata(),
              'configuration': vars(a) | {'scenario': str(a.scenario), 'ns3': str(a.ns3), 'output': str(root), 'model': str(a.model) if a.model else None},
              'scope': 'native LTE RRC; offline atomic file controller; no E2/OTA'}
    write_status(root, status)
    proc = None
    try:
        binary = build_native(selected.path, ns3=a.ns3)
        status.update(status='running', simulation_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        write_status(root, status)
        command = [str(binary), '--controlled=true', f'--simTime={a.duration}',
                   f'--trafficOverload={str(a.traffic_overload).lower()}', f'--resourceControl={str(a.resource_control).lower()}', f'--fakeRequests={str(a.fake_requests).lower()}',
                   f'--RngSeed={a.seed}', f'--loadScale={a.load}', f'--targetSpeed={a.speed}']
        (root / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
        with (raw / 'simulation.log').open('w') as log, (raw / 'controller.csv').open('w', newline='') as out:
            writer = csv.DictWriter(out, fieldnames=['decision_time_s', 'request_id', 'policy', 'attack_type',
                'attack_applied', 'true_cell0_load', 'true_cell1_load', 'observed_cell0_load',
                'observed_cell1_load', 'true_target_sinr_db', 'observed_target_sinr_db', 'action', 'target_cell'])
            writer.writeheader()
            proc = subprocess.Popen(command, cwd=raw, stdout=log, stderr=subprocess.STDOUT)
            state_log = (raw / 'decision_states.jsonl').open('w')
            last = -1
            history = []
            deadline = time.monotonic() + 1800
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError('Native run exceeded wall-clock guard')
                try:
                    state = json.loads((raw / 'request.json').read_text())
                except FileNotFoundError:
                    time.sleep(.003)
                    continue
                step = state['step']
                if step == last:
                    time.sleep(.003)
                    continue
                last = step
                if state['terminal']:
                    state_log.write(json.dumps(dict(state=state, observed=state, action='hold', target=state['target_cell'], recommended_action='hold', recommended_target=state['target_cell'], attack_applied=False))+'\n')
                    state_log.flush()
                    continue
                observed = dict(state)
                applied = a.attack != 'none' and state['time'] >= 4
                if applied:
                    if a.attack in ('load_spoof', 'cross_domain'):
                        observed['cell0_load'], observed['cell1_load'] = 0, 10
                    elif a.attack == 'sinr_spoof':
                        observed['target_sinr_db'] -= 12
                    elif a.attack == 'backdoor_trigger':
                        observed['target_sinr_db'] = -8
                    elif a.attack == 'stale' and history:
                        observed.update({k: history[max(0, len(history)-10)][k] for k in
                                         ['cell0_load', 'cell1_load', 'target_sinr_db']})
                    elif a.attack == 'random_control':
                        # Deterministic equal-amplitude sign-changing negative control.
                        observed['target_sinr_db'] += 12 * (1 if step % 2 else -1)
                action, target = 'hold', state['target_cell']
                if not state['pending'] and state['handover_budget_remaining'] > 0:
                    if a.policy == 'forced' and 3 <= state['time'] < 3.15:
                        action, target = 'handover', 2
                    elif a.policy == 'load_balance' and state['time'] >= 4:
                        target = 1 if observed['cell0_load'] < observed['cell1_load'] else 2
                        if target != state['target_cell'] and step % 20 == 0:
                            action = 'handover'
                if state['time'] >= 4 and a.policy in ('explore', 'graph_q') and not state['pending'] and state['handover_budget_remaining'] > 0 and step % a.decision_period == 0:
                    choice = int(rng.integers(0,3)) if a.policy == 'explore' else int(model.forward(encode(observed))[0].argmax())
                    if choice and choice != state['target_cell']:
                        action, target = 'handover', choice
                recommended_action, recommended_target = action, target
                if applied and a.attack == 'action_override' and not state['pending'] and state['handover_budget_remaining'] > 0 and step % a.decision_period == 0:
                    action, target = 'handover', 3-state['target_cell']
                state_log.write(json.dumps(dict(state=state, observed=observed, action=action, target=target,
                    recommended_action=recommended_action, recommended_target=recommended_target, attack_applied=applied))+'\n')
                state_log.flush()
                writer.writerow(dict(decision_time_s=state['time'], request_id=step, policy=a.policy,
                    attack_type=a.attack, attack_applied=int(applied),
                    true_cell0_load=state['cell0_load'], true_cell1_load=state['cell1_load'],
                    observed_cell0_load=observed['cell0_load'], observed_cell1_load=observed['cell1_load'],
                    true_target_sinr_db=state['target_sinr_db'], observed_target_sinr_db=observed['target_sinr_db'],
                    action=action, target_cell=target))
                out.flush()
                temporary = raw / 'control.csv.tmp'
                temporary.write_text(f'step,action,target_cell\n{step},{action},{target}\n')
                os.replace(temporary, raw / 'control.csv')
                history.append(state)
            state_log.close()
            if proc.returncode:
                raise subprocess.CalledProcessError(proc.returncode, command)
        status.update(status='complete', simulation_exit_code=0)
    except BaseException as exc:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=20)
        status.update(status='failed', error=str(exc))
        raise
    finally:
        write_status(root, status)
    print(root)


if __name__ == '__main__':
    main()
