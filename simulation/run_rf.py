"""Run paired synthetic receiver-IQ attacks; no ns-3, RIC or OTA claim."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import numpy as np
from ai.rf import attack, train
from scenario.source import snapshot_source

TASKS = ('sensing', 'amc', 'channel')


def publish(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_frames(path, count, length):
    frames, labels = {}, {}
    for task in TASKS:
        frames[task], labels[task] = [], []
    with path.open(newline='') as handle:
        reader = csv.reader(handle)
        expected = ['task', 'id', 'label', 'h_i', 'h_q']
        for index in range(length):
            expected.extend(['i' + str(index), 'q' + str(index)])
        if next(reader) != expected:
            raise ValueError('RF CSV header mismatch')
        for row in reader:
            task = row[0]
            if task not in TASKS or len(row) != len(expected):
                raise ValueError('Invalid RF row')
            if int(row[1]) != len(frames[task]):
                raise ValueError('RF frame IDs must be unique and consecutive within each task')
            values = np.asarray(row[2:], dtype=float)
            if not np.isfinite(values).all():
                raise ValueError('Nonfinite RF data')
            label = values[0]
            if task != 'channel':
                classes = 2 if task == 'sensing' else 3
                if label != int(label) or not 0 <= label < classes:
                    raise ValueError('Invalid RF class label')
                labels[task].append(int(label))
            else:
                labels[task].append(values[1:3])
            frames[task].append(values[3:])
    for task in TASKS:
        if len(frames[task]) != count:
            raise ValueError('RF sample count mismatch: ' + task)
        frames[task] = np.asarray(frames[task])
        labels[task] = np.asarray(labels[task])
    return frames, labels


def check_split_overlap(splits):
    for task in TASKS:
        seen = set()
        for split in ('train', 'validation', 'test'):
            current = set()
            for frame in splits[split][0][task]:
                identity = hashlib.sha256(frame.tobytes()).digest()
                if identity in seen:
                    raise ValueError('Identical RF frame across splits: ' + task)
                current.add(identity)
            seen.update(current)


def measure(model, x, y, target, clean, regression):
    output = model.forward(x)[0]
    if regression:
        denominator = float(np.sum(y*y))
        if denominator <= 0:
            raise ValueError('Zero true-channel energy')
        return dict(mse=float(np.mean((output-y)**2)),
                    nmse=float(np.sum((output-y)**2) / denominator)), output
    prediction = output.argmax(1)
    eligible = clean == y
    total = int(eligible.sum())
    successes = int(np.sum(eligible & (prediction == target)))
    metrics = dict(accuracy=float(np.mean(prediction == y)),
                   eligible_clean_correct=total, targeted_successes=successes,
                   targeted_asr=successes / total if total else None)
    directions = {}
    for label in range(int(y.max()) + 1):
        selected = eligible & (y == label)
        n = int(selected.sum())
        success = int(np.sum(selected & (prediction == target)))
        directions[str(label) + '->' + str(int(target[y == label][0]))] = dict(
            eligible=n, successes=success, targeted_asr=success/n if n else None)
    metrics['directions'] = directions
    return metrics, prediction


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True,
                        help='Explicit external analytical RF generator .cc')
    parser.add_argument('--output', type=Path, required=True, help='Fresh result directory')
    parser.add_argument('--train-samples', type=int, default=2400)
    parser.add_argument('--eval-samples', type=int, default=600)
    parser.add_argument('--length', type=int, default=64)
    parser.add_argument('--seeds', type=int, nargs=3, default=[11, 23, 37],
                        metavar=('TRAIN', 'VALIDATION', 'TEST'))
    parser.add_argument('--snr-db', type=float, default=10)
    parser.add_argument('--rf-profile', choices=['baseline', 'diverse', 'stress'],
                        help='Optional profile of the supplied v2 RF generator')
    parser.add_argument('--generator-arg', action='append', default=[],
                        help='Repeat --generator-arg=--NAME=VALUE for RF physical settings')
    parser.add_argument('--psr-db', type=float, nargs='+', default=[-20, -10, -6])
    parser.add_argument('--epochs', type=int, default=80)
    parser.add_argument('--steps', type=int, default=30)
    args = parser.parse_args(argv)
    if args.train_samples < 60 or args.eval_samples < 60 or not 8 <= args.length <= 4096:
        parser.error('samples must be >=60; length must be 8..4096')
    if len(set(args.seeds)) != 3 or min(args.seeds) < 0 or max(args.seeds) > 2**32-1:
        parser.error('three distinct uint32 split seeds required')
    if args.epochs < 1 or args.steps < 1:
        parser.error('epochs/steps must be positive')
    physical_options = {'--snr-jitter-db', '--gain-range-db', '--phase-max-deg',
                        '--cfo-max', '--timing-max', '--rolloff', '--rician-k-db',
                        '--fading', '--attack-fraction', '--interference-psr-db',
                        '--samples-per-symbol', '--rrc-span', '--channel-taps'}
    seen_options = set()
    for option in args.generator_arg:
        key, separator, value = option.partition('=')
        if key not in physical_options or not separator or not value or key in seen_options:
            parser.error('Generator arguments must be distinct allowed --NAME=VALUE physical settings')
        seen_options.add(key)
    if not np.isfinite(args.snr_db) or not -30 <= args.snr_db <= 60:
        parser.error('SNR must be finite and in [-30,60] dB')
    if (not np.isfinite(args.psr_db).all() or max(args.psr_db) > 0
            or min(args.psr_db) < -120 or len(set(args.psr_db)) != len(args.psr_db)):
        parser.error('PSR values must be distinct, finite and in [-120,0] dB')
    compiler = shutil.which('g++')
    if compiler is None:
        parser.error('g++ is required')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'controller.pid').write_text(str(os.getpid()))
    status = dict(state='running', experiment='synthetic_receiver_iq',
                  network_simulation=False, ota_validated=False, ric_connected=False)
    publish(out / 'run_status.json', status)
    try:
        source = snapshot_source(args.scenario, out)
        binary = out / 'rf-generator'
        commands = []
        command = [compiler, '-std=c++17', '-O2', '-Wall', '-Wextra', '-pedantic',
                   str(source.path), '-o', str(binary)]
        commands.append(command)
        with (out / 'build.log').open('w') as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        splits = {}
        inputs = {}
        generator_metadata = {}
        for split, seed in zip(('train', 'validation', 'test'), args.seeds):
            count = args.train_samples if split == 'train' else args.eval_samples
            path = out / (split + '.csv')
            command = [str(binary), '--samples', str(count), '--length', str(args.length),
                       '--seed', str(seed), '--snr-db', str(args.snr_db), '--output', str(path)]
            if args.rf_profile:
                command += ['--profile', args.rf_profile]
            command += args.generator_arg
            commands.append(command)
            with (out / (split + '.log')).open('w') as log:
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
            splits[split] = load_frames(path, count, args.length)
            metadata_path = Path(str(path) + '.meta.json')
            if metadata_path.is_file():
                generator_metadata[split] = json.loads(metadata_path.read_text())
            inputs[split] = dict(seed=seed, frames_per_task=count, sha256=digest(path))
        check_split_overlap(splits)
        config = vars(args).copy()
        config['scenario'] = str(args.scenario.resolve())
        config['output'] = str(out)
        module_hashes = {}
        for relative in ('ai/rf.py', 'simulation/run_rf.py'):
            module_hashes[relative] = digest(Path(__file__).resolve().parents[1] / relative)
        manifest = dict(configuration=config, source=source.metadata(), inputs=inputs,
                        generator_metadata=generator_metadata,
                        commands=commands, binary_sha256=digest(binary),
                        implementation_sha256=module_hashes, python=sys.version,
                        numpy=np.__version__, platform=platform.platform(),
                        compiler=subprocess.check_output([compiler, '--version'], text=True),
                        image_id=os.environ.get('RAN_AI_IMAGE_ID'),
                        threat_model='white-box digital additive receiver-IQ; no attacker channel',
                        budget='per-frame L2; PSR relative to clean RECEIVED signal+noise energy',
                        labels=dict(sensing=['vacant', 'occupied'], amc=['BPSK', 'QPSK', '16QAM']),
                        target='sensing:1-y; amc:(y+1)%3; channel:maximize true-H MSE',
                        limitations=['Synthetic receiver IQ; see per-split generator metadata for physical settings.',
                                     'Flat fading and known repeated pilot for channel estimation.',
                                     'Generator interference sidecars are separate from FGSM/PGD and clean inputs.',
                                     'No ns-3 topology, beamforming, QoS or E2 control measurement.',
                                     'Zero ASR is a valid outcome; no test-based budget selection.'])
        publish(out / 'manifest.json', manifest)
        rows = []
        with (out / 'predictions.csv').open('w', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(['task', 'mode', 'psr_db', 'id', 'true', 'target', 'clean_prediction',
                             'attacked_prediction', 'l2_delta', 'l2_budget', 'actual_power_ratio'])
            for task in TASKS:
                regression = task == 'channel'
                x, y = splits['train'][0][task], splits['train'][1][task]
                vx, vy = splits['validation'][0][task], splits['validation'][1][task]
                tx, ty = splits['test'][0][task], splits['test'][1][task]
                model, fit = train(x, y, vx, vy, regression, args.seeds[0], args.epochs)
                model.save(out / (task + '-model.npz'))
                clean = model.forward(tx)[0]
                if not regression:
                    clean = clean.argmax(1)
                    target = 1-ty if task == 'sensing' else (ty+1) % 3
                else:
                    target = ty
                conditions = [('none', None, 0.), ('pgd-zero', None, 0.)]
                for psr in args.psr_db:
                    for mode in ('random', 'fgsm', 'pgd'):
                        conditions.append((mode, psr, 10**(psr/10)))
                for mode, psr, ratio in conditions:
                    delta = attack(model, tx, target, mode.removesuffix('-zero'), ratio,
                                   regression, args.seeds[2], args.steps)
                    norms = np.linalg.norm(delta, axis=1)
                    energy = np.sum(tx*tx, axis=1)
                    budget = np.sqrt(ratio*energy)
                    actual = np.sum(delta*delta, axis=1) / np.maximum(energy, 1e-30)
                    if not np.isfinite(delta).all() or np.any(norms > budget + 1e-10):
                        raise ValueError('RF perturbation budget violated')
                    if ratio == 0 and not np.array_equal(tx+delta, tx):
                        raise ValueError('Zero budget changed input')
                    metrics, prediction = measure(model, tx+delta, ty, target, clean, regression)
                    name = task + '-' + mode
                    if psr is not None:
                        name += '-' + str(psr)
                    np.savez_compressed(out / (name + '-audit.npz'), delta=delta,
                                        target=target, prediction=prediction)
                    record = dict(task=task, mode=mode, psr_db=psr, metrics=metrics,
                                  fit=fit, max_actual_power_ratio=float(actual.max()),
                                  budget_verified=True)
                    rows.append(record)
                    for index in range(len(tx)):
                        writer.writerow([task, mode, psr, index, json.dumps(ty[index].tolist()),
                                         json.dumps(target[index].tolist()),
                                         json.dumps(clean[index].tolist()),
                                         json.dumps(prediction[index].tolist()), norms[index],
                                         budget[index], actual[index]])
                    print(task, mode, psr, json.dumps(metrics), flush=True)
        publish(out / 'summary.json', dict(experiment='synthetic_receiver_iq', conditions=rows))
        artifacts = {}
        for path in sorted(out.iterdir()):
            if path.name not in ('controller.pid', 'run_status.json', 'evidence.json') and path.is_file():
                artifacts[path.name] = digest(path)
        publish(out / 'evidence.json', artifacts)
        status.update(state='completed', budget_verified=True, independent_split_seeds=True)
        publish(out / 'run_status.json', status)
    except BaseException as error:
        status.update(state='failed', error=str(error))
        publish(out / 'run_status.json', status)
        raise
    finally:
        (out / 'controller.pid').unlink(missing_ok=True)
    print('RF results:', out, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
