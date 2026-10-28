#!/usr/bin/env python3
"""Matched control experiments with explicit access, baseline, and optimizer checks."""
from labcore.provenance import source_hashes
from labcore.paths import ROOT
from labcore.commands import command as cli_command
import argparse
import csv
from datetime import datetime
import hashlib
import importlib.metadata
import math
import os
from decimal import Decimal
import json
from pathlib import Path
import platform
import random
import subprocess
import sys
from ai.baselines import persistence_parameters
from ai.evasion import MODES, ACCESS, validate
from ai.runtime import RuntimeForecaster
from checks.check_evasion import verify
from scenario.source import read_source, snapshot_source, build_native


def save_manifest(root, manifest):
    temporary = root / '.manifest.tmp'
    temporary.write_text(json.dumps(manifest, indent=2, allow_nan=False) + '\n')
    temporary.replace(root / 'manifest.json')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path)
    p.add_argument('--scenario', type=Path, required=True)
    p.add_argument('--ns3', type=Path)
    p.add_argument('--e2-nodes', type=int, default=5)
    p.add_argument('--attack-seed', type=int, default=311)
    p.add_argument('--backend', choices=['native', 'live'], default='native')
    p.add_argument('--duration', type=float, default=3)
    p.add_argument('--ues', type=int, default=6)
    p.add_argument('--seed', type=int, default=7)
    p.add_argument('--run', type=int, default=1)
    p.add_argument('--epsilon', type=float, default=2)
    p.add_argument('--model', type=Path, default=Path('ai/artifacts/pilot/model.json'))
    p.add_argument('--modes', nargs='+', choices=sorted(MODES), default=['none', 'random', 'bias', 'fgsm', 'pgd', 'exact'])
    p.add_argument('--access', choices=sorted(ACCESS), default='two_cell')
    p.add_argument('--steps', type=int, default=10)
    p.add_argument('--restarts', type=int, default=5)
    p.add_argument('--step-size-db', type=float)
    p.add_argument('--max-step-db', type=float)
    p.add_argument('--predictor', choices=['ridge', 'persistence'], default='ridge')
    p.add_argument('--robust-budget-db', type=float)
    p.add_argument('--allow-training-seeds',action='store_true',help='Explicit exploratory reuse; not independent validation')
    a = p.parse_args(argv)
    if not math.isfinite(a.duration) or a.duration < 3 or not 3 <= a.ues <= 120:
        p.error('Use duration >=3 and 3 <= ues <=120')
    if len(a.modes) != len(set(a.modes)) or 'none' not in a.modes:
        p.error('Modes must be distinct and include none')
    a.modes = ['none'] + [mode for mode in a.modes if mode != 'none']
    config = dict(mode='fgsm', epsilon_db=a.epsilon, access=a.access, steps=a.steps, restarts=a.restarts)
    for name in ['step_size_db', 'max_step_db', 'robust_budget_db']:
        value = getattr(a, name)
        if value is not None:
            config[name] = value
    validate(config)
    read_source(a.scenario)
    if a.e2_nodes < 1:
        p.error('--e2-nodes must be positive')
    lab = ROOT
    source_model = a.model.resolve()
    parameters = json.loads(source_model.read_text())
    RuntimeForecaster(parameters)  # Validate before creating any artifacts.
    provenance=parameters.get('training_provenance',{})
    sources=provenance.get('sources',[])+provenance.get('validation_sources',[])
    known_seeds=[]
    for source in sources:
        seed=source.get('seed',source.get('configuration',{}).get('seed'))
        if seed is not None:known_seeds.append(Decimal(str(seed)))
    overlap=Decimal(a.seed) in known_seeds
    if overlap and not a.allow_training_seeds:
        p.error('Experiment seed was used for model fitting/selection; choose a held-out seed or explicitly --allow-training-seeds for a pilot')
    independent=bool(sources) and len(known_seeds)==len(sources) and not overlap
    if a.predictor == 'persistence':
        parameters = persistence_parameters(parameters)
    root = a.output.resolve() if a.output else lab / 'results' / ('adversarial-suite-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True, exist_ok=False)
    selected = snapshot_source(a.scenario, root)
    model = root / 'model.json'
    model.write_text(json.dumps(parameters, indent=2, allow_nan=False) + '\n')
    rng = random.Random(a.attack_seed)
    events = []
    for ue in rng.sample(range(1, a.ues + 1), max(1, a.ues // 3)):
        start = round(rng.uniform(1.1, a.duration - 1.2), 2)
        end = round(min(a.duration - .3, start + rng.uniform(.5, 1.0)), 2)
        events.append(dict(id='sinr-' + str(ue), ue_imsi=ue, start_s=start, end_s=end))
    configuration = vars(a) | {'model': 'model.json', 'output': '.', 'scenario': 'scenario.cc',
                                'ns3': str(a.ns3) if a.ns3 else None}
    manifest = dict(schema_version=2, configuration=configuration, events=events,
        model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        scenario_sha256=selected.sha256, scenario_origin=selected.origin,
        input_model_sha256=hashlib.sha256(source_model.read_bytes()).hexdigest(),
        runs={}, attempts={}, independent_from_model_selection_seeds=independent,
        training_seed_overlap=overlap, environment=dict(python=sys.version, platform=platform.platform()),
        invocation=sys.argv)
    # Hash the full local source surface used to generate, validate and analyze runs.
    manifest['source_sha256'] = source_hashes(lab)
    if a.backend == 'native':
        binary = build_native(selected.path, ns3=a.ns3)
        manifest['simulation_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    elif os.environ.get('RAN_AI_IN_CONTAINER') == '1':
        image_id = os.environ.get('RAN_AI_IMAGE_ID')
        if not image_id:
            p.error('Use docker/lab.sh to record the live container image identity')
        manifest['environment']['container_image_id'] = image_id
    else:
        manifest['environment']['container_image_id'] = subprocess.check_output(
            ['docker', 'inspect', '--format', '{{.Image}}', 'flexric'], text=True).strip()
    manifest['environment']['packages']={}
    if os.environ.get('RAN_AI_IMAGE_ID'):
        manifest['environment']['container_image_id'] = os.environ['RAN_AI_IMAGE_ID']
    for package in ['numpy','matplotlib']:
        try:manifest['environment']['packages'][package]=importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:manifest['environment']['packages'][package]=None
    save_manifest(root, manifest)
    summaries = []
    for mode in a.modes:
        attack = root / (mode + '.json')
        attack.write_text(json.dumps(config | dict(mode=mode, seed=a.attack_seed, events=events), indent=2) + '\n')
        run = root / (root.name + '-' + mode)
        cmd = [*cli_command('run_controlled' if a.backend == 'native' else 'run_live', lab),
            '--duration', str(a.duration), '--ues', str(a.ues), '--seed', str(a.seed), '--run', str(a.run),
            '--model' if a.backend == 'native' else '--ai-model', str(model),
            '--evasion-config', str(attack), '--output', str(run), '--scenario', str(selected.path)]
        if a.ns3:
            cmd += ['--ns3', str(a.ns3)]
        if a.backend == 'live':
            cmd += ['--apply-ai-control', '--e2-nodes', str(a.e2_nodes)]
        manifest['attempts'][mode] = dict(status='running', command=cmd, path=run.name)
        save_manifest(root, manifest)
        print('Running', mode, flush=True)
        try:
            subprocess.run(cmd, cwd=lab, check=True)
            run_status = json.loads((run / 'run_status.json').read_text())
            if run_status.get('scenario', {}).get('sha256') != selected.sha256:
                raise RuntimeError('Run used a different scenario source')
            if a.backend == 'native' and run_status.get('simulation_binary_sha256') != manifest['simulation_binary_sha256']:
                raise RuntimeError('Native binary changed between paired conditions')
            summary = verify(run)
            if not summary['passed']:
                raise RuntimeError('Evasion audit failed')
            with (run / 'csv/ue_application_100ms.csv').open() as stream:
                apps = list(csv.DictReader(stream))
            control = json.loads((run / 'control_verification.json').read_text())
            summary.update(control_submitted=control['submitted'], control_confirmed=control['confirmed'],
                control_unconfirmed=control.get('unconfirmed', 0),
                application_rx_bytes=sum(int(r['rx_bytes']) for r in apps if r['is_warmup'] == '0'))
            summaries.append(summary)
            manifest['runs'][mode] = run.name
            manifest['attempts'][mode]['status'] = 'complete'
        except BaseException as exc:
            manifest['attempts'][mode].update(status='failed', error=str(exc))
            raise
        finally:
            save_manifest(root, manifest)
    clean = summaries[0]['application_rx_bytes']
    for row in summaries:
        row['rx_bytes_change_vs_clean'] = row['application_rx_bytes'] - clean
    (root / 'comparison.json').write_text(json.dumps(summaries, indent=2) + '\n')
    combine(root, manifest)
    print('Suite:', root, flush=True)


def resolve_run(root, path):
    value = Path(path)
    return value if value.is_absolute() else root / value


def combine(root, manifest):
    rows = []
    for mode, path in manifest['runs'].items():
        with (resolve_run(root, path) / 'csv/adversarial_dataset.csv').open() as stream:
            rows.extend(dict(row, experiment_condition=mode) for row in csv.DictReader(stream))
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with (root / 'dataset.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
