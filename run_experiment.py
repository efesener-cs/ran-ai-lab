#!/usr/bin/env python3
"""Host-only stochastic RAN experiment; UDP attack packets stay inside ns-3."""
import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import subprocess
import sys
from labcore.experiment_plan import make_plan

from labcore.native_runner import export_run, run_simulation, simulation_command, write_status


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--duration', type=float, default=3)
    p.add_argument('--ues', type=int, default=24)
    p.add_argument('--warmup', type=float, default=0.5)
    p.add_argument('--attacks', type=int, default=3)
    p.add_argument('--seed', type=int, default=17)
    p.add_argument('--run', type=int, default=1)
    args = p.parse_args(argv)
    if not 3 <= args.ues <= 120:
        p.error('UE count must be 3..120')
    return args


def main(argv=None):
    args = parse_args(argv)
    lab = Path(__file__).resolve().parent
    binary = lab / 'ran-ai-offline'
    source = lab / 'ran-ai-scenario.cc'
    if not binary.exists() or source.stat().st_mtime > binary.stat().st_mtime:
        subprocess.run([sys.executable, str(lab / 'build_offline.py')], check=True)
    root = lab / 'results' / ('stochastic-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    raw = root / 'raw'
    raw.mkdir(parents=True)
    attack_seed = args.seed * 100003 + args.run
    plan = make_plan(raw / 'attack_plan.csv', args.duration, args.ues, args.warmup, attack_seed, args.attacks)
    status = {
        'configuration': vars(args), 'attack_seed': attack_seed,
        'live_ric_verified': False, 'mode': 'host ns-3, offline E2 logging',
        'ai_controller_installed': False,
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'status': 'running',
    }
    write_status(root, status)
    print('Results:', root, flush=True)
    print(f'{args.ues} UEs; {len(plan)} stochastic UDP events, seed {attack_seed}', flush=True)
    command = simulation_command(lab, args, '--attackPlan=' + str(raw / 'attack_plan.csv'))
    try:
        run_simulation(command, raw)
        export_run(lab, root, args.duration)
        status['status'] = 'complete'
    except BaseException as exc:
        status.update(status='failed', error=str(exc))
        raise
    finally:
        write_status(root, status)


if __name__ == '__main__':
    main()
