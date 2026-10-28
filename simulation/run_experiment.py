"""Run traffic-load events in an external scenario implementing the lab trace contract."""
import argparse
from datetime import datetime
import hashlib
from pathlib import Path

from labcore.paths import ROOT
from scenario.source import build_native, read_source, snapshot_source
from simulation.experiment_plan import make_plan
from simulation.native_runner import export_run, run_simulation, simulation_command, write_status


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--ns3', type=Path)
    parser.add_argument('--duration', type=float, default=3)
    parser.add_argument('--ues', type=int, default=24)
    parser.add_argument('--warmup', type=float, default=.5)
    parser.add_argument('--attacks', type=int, default=3)
    parser.add_argument('--seed', type=int, default=17)
    parser.add_argument('--run', type=int, default=1)
    args = parser.parse_args(argv)
    if not 3 <= args.ues <= 120:
        parser.error('UE count must be 3..120')
    return args


def main(argv=None):
    args = parse_args(argv)
    read_source(args.scenario)
    root = ROOT / 'results' / ('stochastic-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    raw = root / 'raw'
    raw.mkdir(parents=True)
    selected = snapshot_source(args.scenario, root)
    attack_seed = args.seed * 100003 + args.run
    plan = make_plan(raw / 'attack_plan.csv', args.duration, args.ues, args.warmup, attack_seed, args.attacks)
    status = dict(status='building', live_ric_verified=False, ai_controller_installed=False,
        scenario=selected.metadata(), source_sha256=selected.sha256, attack_seed=attack_seed,
        mode='host ns-3, offline E2 logging',
        configuration=dict(duration=args.duration, ues=args.ues, warmup=args.warmup,
                           attacks=args.attacks, seed=args.seed, run=args.run))
    write_status(root, status)
    print('Results:', root, flush=True)
    print(f'{args.ues} UEs; {len(plan)} simulated UDP events, seed {attack_seed}', flush=True)
    try:
        binary = build_native(selected.path, ns3=args.ns3)
        status.update(status='running', simulation_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        write_status(root, status)
        run_simulation(simulation_command(binary, args, '--attackPlan=' + str(raw / 'attack_plan.csv')), raw)
        export_run(ROOT, root, args.duration)
        status.update(status='complete', simulation_exit_code=0)
    except BaseException as exc:
        status.update(status='failed', error=str(exc))
        raise
    finally:
        write_status(root, status)


if __name__ == '__main__':
    main()
