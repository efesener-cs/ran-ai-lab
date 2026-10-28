#!/usr/bin/env python3
"""Plan and run sequential matched suites while preserving every attempt."""
import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import subprocess

from ai.evasion import ACCESS, MODES, validate
from labcore.commands import command as cli_command
from labcore.paths import ROOT
from labcore.provenance import source_hashes
from scenario.source import read_source, snapshot_source

LAB = ROOT
LEGACY_MODES = ['none', 'random', 'fgsm', 'pgd']


def save_plan(root, plan):
    temporary = root / '.campaign.json.tmp'
    temporary.write_text(json.dumps(plan, indent=2) + '\n')
    temporary.replace(root / 'campaign.json')


def execution_hashes():
    return source_hashes(LAB)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, help='Required for a new campaign; captured in its snapshot')
    parser.add_argument('--ns3', type=Path)
    parser.add_argument('--e2-nodes', type=int, default=5)
    parser.add_argument('--backend', choices=['live', 'native'], default='live')
    parser.add_argument('--duration', type=float, default=10)
    parser.add_argument('--ues', type=int, default=24)
    parser.add_argument('--seeds', type=int, nargs='+', default=[41, 53, 67])
    parser.add_argument('--epsilons', type=float, nargs='+', default=[0, .5, 1, 2])
    parser.add_argument('--model', type=Path, default=LAB / 'ai/artifacts/pilot/model.json')
    parser.add_argument('--modes', nargs='+', choices=sorted(MODES),
                        default=['none', 'random', 'bias', 'fgsm', 'pgd', 'exact'])
    parser.add_argument('--predictors', nargs='+', choices=['ridge', 'persistence'], default=['ridge'])
    parser.add_argument('--robust-budgets-db', nargs='+', default=['off'],
                        help='off or a dB budget; each is a separate matched suite')
    parser.add_argument('--access', choices=sorted(ACCESS), default='two_cell')
    parser.add_argument('--max-step-db', type=float)
    parser.add_argument('--steps', type=int, default=10)
    parser.add_argument('--restarts', type=int, default=5)
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--resume', type=Path)
    parser.add_argument('--allow-code-change', action='store_true',
                        help='Record an explicit source revision boundary before resuming')
    args = parser.parse_args(argv)
    if args.resume:
        return args
    if args.scenario is None:
        parser.error('A new campaign requires --scenario PATH')
    read_source(args.scenario)
    if args.e2_nodes < 1:
        parser.error('--e2-nodes must be positive')
    if (not math.isfinite(args.duration) or args.duration < 3 or not 3 <= args.ues <= 120
            or any(not math.isfinite(v) or not 0 <= v <= 5 for v in args.epsilons)):
        parser.error('Invalid duration/UE/epsilon')
    if len(set(args.modes)) != len(args.modes) or 'none' not in args.modes:
        parser.error('Modes must be distinct and include none')
    return args


def create_plan(args):
    budgets = []
    for value in args.robust_budgets_db:
        budget = None if value == 'off' else float(value)
        if budget is not None and (not math.isfinite(budget) or not 0 <= budget <= 5):
            raise ValueError('Invalid robust budget')
        if budget not in budgets:
            budgets.append(budget)
    config = dict(mode='pgd', steps=args.steps, restarts=args.restarts)
    if args.max_step_db is not None:
        config['max_step_db'] = args.max_step_db
    validate(config)
    read_source(args.scenario)
    model_bytes = args.model.read_bytes()
    root = LAB / 'results' / ('campaign-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True)
    selected = snapshot_source(args.scenario, root)
    model = root / 'model.json'
    model.write_bytes(model_bytes)
    plan = dict(backend=args.backend, duration=args.duration, ues=args.ues, model=str(model),
                model_sha256=hashlib.sha256(model_bytes).hexdigest(), modes=args.modes,
                scenario=str(selected.path), scenario_sha256=selected.sha256,
                ns3=str(args.ns3) if args.ns3 else None, e2_nodes=args.e2_nodes,
                access=args.access, steps=args.steps, restarts=args.restarts,
                max_step_db=args.max_step_db, jobs=[])
    for seed in dict.fromkeys(args.seeds):
        for epsilon in dict.fromkeys(args.epsilons):
            for predictor in dict.fromkeys(args.predictors):
                for budget in budgets:
                    plan['jobs'].append(dict(seed=seed, epsilon=epsilon, run=1,
                        attack_seed=311 + seed, predictor=predictor, robust_budget_db=budget,
                        status='pending', attempts=[]))
    return root, plan


def job_command(plan, job, destination):
    command = [*cli_command('run_adversarial_suite', LAB), '--backend', plan['backend'],
               '--duration', str(plan['duration']), '--ues', str(plan['ues']),
               '--seed', str(job['seed']), '--run', str(job['run']),
               '--epsilon', str(job['epsilon']), '--attack-seed', str(job['attack_seed']),
               '--model', plan['model'], '--output', str(destination),
               '--scenario', plan['scenario'],
               '--modes', *plan.get('modes', LEGACY_MODES),
               '--predictor', job.get('predictor', 'ridge'), '--access', plan.get('access', 'two_cell'),
               '--steps', str(plan.get('steps', 10)), '--restarts', str(plan.get('restarts', 5))]
    if plan.get('ns3'):
        command += ['--ns3', plan['ns3']]
    if plan['backend'] == 'live':
        command += ['--e2-nodes', str(plan.get('e2_nodes', 5))]
    if job.get('robust_budget_db') is not None:
        command += ['--robust-budget-db', str(job['robust_budget_db'])]
    if plan.get('max_step_db') is not None:
        command += ['--max-step-db', str(plan['max_step_db'])]
    return command


def run_job(root, plan, index, job):
    destination = root / f'suite-{index:02d}-attempt-{len(job["attempts"]) + 1}'
    job['attempts'].append(str(destination))
    job['status'] = 'running'
    save_plan(root, plan)
    print('Job', index + 1, '/', len(plan['jobs']), flush=True)
    try:
        log_path = root / f'job-{index:02d}-attempt-{len(job["attempts"])}.log'
        with log_path.open('w') as log:
            subprocess.run(job_command(plan, job, destination), cwd=LAB,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        job.update(status='complete', suite=str(destination))
    except BaseException:
        job['status'] = 'failed'
        raise
    finally:
        save_plan(root, plan)


def main(argv=None):
    args = parse_args(argv)
    if args.resume:
        root = args.resume.resolve()
        plan = json.loads((root / 'campaign.json').read_text())
    else:
        root, plan = create_plan(args)
    if not plan.get('scenario') or not plan.get('scenario_sha256'):
        raise ValueError('Legacy campaign has no external scenario snapshot; start a new campaign with --scenario')
    _, scenario_bytes = read_source(plan['scenario'])
    if hashlib.sha256(scenario_bytes).hexdigest() != plan['scenario_sha256']:
        raise ValueError('Campaign scenario snapshot changed')
    if args.scenario is not None and hashlib.sha256(read_source(args.scenario)[1]).hexdigest() != plan['scenario_sha256']:
        raise ValueError('Cannot replace the scenario of an existing campaign')
    current_sources = execution_hashes()
    previous_sources = plan.get('execution_source_sha256')
    if previous_sources and previous_sources != current_sources:
        if not args.allow_code_change:
            raise ValueError('Sources changed since campaign start; review changes and use --allow-code-change to record a revision boundary')
        plan.setdefault('source_revision_history', []).append(previous_sources)
    plan['execution_source_sha256'] = current_sources
    save_plan(root, plan)
    print('Campaign:', root, ' suites:', len(plan['jobs']),
          ' runs:', len(plan.get('modes', LEGACY_MODES)) * len(plan['jobs']), flush=True)
    if args.plan_only:
        print('Execute/resume: python3 lab.py collect_campaign --resume ' + str(root))
        return
    if hashlib.sha256(Path(plan['model']).read_bytes()).hexdigest() != plan['model_sha256']:
        raise ValueError('Campaign model changed')
    for index, job in enumerate(plan['jobs']):
        if hashlib.sha256(Path(plan['scenario']).read_bytes()).hexdigest() != plan['scenario_sha256']:
            raise RuntimeError('Campaign scenario snapshot changed')
        if execution_hashes() != current_sources:
            raise RuntimeError('Source files changed during campaign; stop editing before resuming')
        if job['status'] != 'complete':
            run_job(root, plan, index, job)
    plan['status'] = 'complete'
    save_plan(root, plan)
    print('Campaign complete. Per-suite CSV files:', root, flush=True)



if __name__ == '__main__':
    main()
