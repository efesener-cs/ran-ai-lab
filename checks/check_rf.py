"""Recompute RF predictions, metrics and power budgets from retained evidence."""
import argparse
import csv
import json
from pathlib import Path
import numpy as np
from ai.rf import RFModel
from simulation.run_rf import TASKS, check_split_overlap, digest, load_frames, measure


def verify_interference(path, frames, truth, metadata):
    count = metadata['frames_per_task']
    length = metadata['complex_samples_per_frame']
    allowed = {'sensing': {'tone_jamming', 'barrage_jamming', 'burst_jamming'},
               'amc': {'tone_jamming', 'barrage_jamming', 'burst_jamming'},
               'channel': {'pilot_contamination'}}
    iq_columns = []
    for k in range(length):
        iq_columns.extend(['i'+str(k), 'q'+str(k)])
    expected_header = ['group_id', 'task', 'id', 'label', 'attack_type', 'signal_label',
                       'h_i', 'h_q', 'actual_power_ratio'] + iq_columns
    seen = set()
    positives = dict.fromkeys(TASKS, 0)
    ratio = 10**(metadata['interference_psr_db']/10)
    with path.open(newline='') as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected_header:
            raise ValueError('Physical interference header mismatch')
        for row in reader:
            task, index = row['task'], int(row['id'])
            if task not in TASKS or not 0 <= index < count or (task, index) in seen:
                raise ValueError('Invalid/duplicate physical interference frame')
            seen.add((task, index))
            if row['group_id'] != 'rf-s'+str(metadata['seed'])+'-'+task+'-'+str(index):
                raise ValueError('Physical interference group identity mismatch')
            x = frames[task][index]
            observed = np.array([float(row[key]) for key in iq_columns])
            if x.shape != observed.shape or not np.isfinite(observed).all():
                raise ValueError('Invalid physical interference IQ')
            label = int(row['label'])
            changed = bool(np.any(x != observed))
            if label not in (0, 1) or bool(label) != changed:
                raise ValueError('Physical interference label differs from actual IQ change')
            if row['attack_type'] not in (allowed[task] if changed else {'none'}):
                raise ValueError('Physical interference type mismatch')
            original = truth[task][index]
            if task != 'channel':
                if int(row['signal_label']) != original:
                    raise ValueError('Physical interference RF class changed')
            elif not np.array_equal(np.array([float(row['h_i']), float(row['h_q'])]), original):
                raise ValueError('Physical interference true H changed')
            power = float(np.sum((observed-x)**2) / max(float(np.sum(x*x)), 1e-30))
            if power > ratio+1e-12 or not equivalent(float(row['actual_power_ratio']), power):
                raise ValueError('Physical interference power mismatch')
            positives[task] += label
    if len(seen) != 3*count:
        raise ValueError('Missing physical interference frames')
    for task in TASKS:
        if positives[task] != metadata['interference_frames_per_task']:
            raise ValueError('Physical interference class mixture mismatch')
    return positives


def equivalent(actual, expected):
    if isinstance(expected, dict):
        return (isinstance(actual, dict) and actual.keys() == expected.keys()
                and all(equivalent(actual[k], expected[k]) for k in expected))
    if isinstance(expected, (float, int)):
        return actual is not None and np.isclose(actual, expected, rtol=1e-10, atol=1e-12)
    return actual == expected


def verify(root):
    status = json.loads((root / 'run_status.json').read_text())
    if status.get('state') != 'completed' or status.get('experiment') != 'synthetic_receiver_iq':
        raise ValueError('Not a completed RF experiment')
    evidence = json.loads((root / 'evidence.json').read_text())
    for name, expected in evidence.items():
        if Path(name).name != name or digest(root / name) != expected:
            raise ValueError('Artifact hash mismatch: ' + name)
    manifest = json.loads((root / 'manifest.json').read_text())
    if digest(root / 'scenario.cc') != manifest['source']['sha256']:
        raise ValueError('Generator source mismatch')
    config = manifest['configuration']
    if len(set(config['seeds'])) != 3:
        raise ValueError('Split seeds overlap')
    splits = {}
    for index, split in enumerate(('train', 'validation', 'test')):
        path = root / (split + '.csv')
        recorded = manifest['inputs'][split]
        if digest(path) != recorded['sha256'] or recorded['seed'] != config['seeds'][index]:
            raise ValueError('Split provenance mismatch')
        count = config['train_samples'] if split == 'train' else config['eval_samples']
        if count != recorded['frames_per_task']:
            raise ValueError('Split size mismatch')
        splits[split] = load_frames(path, count, config['length'])
    check_split_overlap(splits)
    sidecar_checks = {}
    for split, metadata in manifest.get('generator_metadata', {}).items():
        if metadata.get('generator') != 'analytical_rf_v2':
            continue
        if split not in splits or metadata['seed'] != manifest['inputs'][split]['seed']:
            raise ValueError('Physical generator split seed mismatch')
        if metadata['frames_per_task'] != len(splits[split][0]['sensing']):
            raise ValueError('Physical generator frame count mismatch')
        path = root/(split+'.csv')
        saved_metadata = json.loads(Path(str(path)+'.meta.json').read_text())
        if saved_metadata != metadata:
            raise ValueError('Physical generator metadata differs from manifest')
        for suffix in ('.frames.csv', '.interference.csv', '.meta.json'):
            if split+'.csv'+suffix not in evidence:
                raise ValueError('Physical generator evidence index incomplete')
        sidecar_checks[split] = verify_interference(Path(str(path)+'.interference.csv'),
                                                   splits[split][0], splits[split][1], metadata)
    rows = json.loads((root / 'summary.json').read_text())['conditions']
    expected_conditions = set()
    for task in TASKS:
        expected_conditions.add((task, 'none', None))
        expected_conditions.add((task, 'pgd-zero', None))
        for psr in config['psr_db']:
            for mode in ('random', 'fgsm', 'pgd'):
                expected_conditions.add((task, mode, psr))
    seen = set()
    models = {}
    for task in TASKS:
        models[task] = RFModel.load(root / (task + '-model.npz'))
    for row in rows:
        task, mode, psr = row['task'], row['mode'], row['psr_db']
        condition = (task, mode, psr)
        if condition not in expected_conditions or condition in seen:
            raise ValueError('Invalid/duplicate RF condition')
        seen.add(condition)
        name = task + '-' + mode
        if psr is not None:
            name += '-' + str(psr)
        x, y = splits['test'][0][task], splits['test'][1][task]
        regression = task == 'channel'
        target = y
        if not regression:
            target = 1-y if task == 'sensing' else (y+1) % 3
        with np.load(root / (name + '-audit.npz'), allow_pickle=False) as archive:
            delta = archive['delta']
            prediction = archive['prediction']
            if not np.array_equal(archive['target'], target):
                raise ValueError('Attack target mismatch')
        if delta.shape != x.shape or not np.isfinite(delta).all():
            raise ValueError('Invalid delta')
        ratio = 0 if psr is None else 10**(psr/10)
        power = np.sum(delta*delta, axis=1) / np.maximum(np.sum(x*x, axis=1), 1e-30)
        if np.any(power > ratio + 1e-12):
            raise ValueError('RF power budget violation')
        if ratio == 0 and np.any(delta != 0):
            raise ValueError('Zero-budget delta is nonzero')
        model = models[task]
        clean = model.forward(x)[0]
        if not regression:
            clean = clean.argmax(1)
        metrics, recomputed = measure(model, x+delta, y, target, clean, regression)
        if not np.allclose(prediction, recomputed, rtol=1e-10, atol=1e-12):
            raise ValueError('Saved predictions differ from model inference')
        if not equivalent(row['metrics'], metrics):
            raise ValueError('Saved metrics differ from recomputed metrics')
        if not equivalent(row['max_actual_power_ratio'], float(power.max())):
            raise ValueError('Saved power ratio differs from recomputed power')
    if seen != expected_conditions:
        raise ValueError('Missing RF conditions')
    required = {'manifest.json', 'summary.json', 'predictions.csv', 'scenario.cc'}
    for task in TASKS:
        required.add(task + '-model.npz')
    for task, mode, psr in seen:
        name = task + '-' + mode
        if psr is not None:
            name += '-' + str(psr)
        required.add(name + '-audit.npz')
    for split in ('train', 'validation', 'test'):
        required.add(split + '.csv')
    if not required.issubset(evidence):
        raise ValueError('Evidence index omits required artifacts')
    return dict(verified=True, conditions=len(seen), frames_per_task=config['eval_samples'],
                physical_interference_verified=sidecar_checks,
                scope='synthetic receiver-IQ only; no container/ns-3/OTA validation')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify(args.run.resolve()), indent=2))
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, 'RF verification failed: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
