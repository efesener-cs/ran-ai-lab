"""Export labeled receiver-IQ detection data from a verified RF experiment."""
import argparse
import csv
import json
from pathlib import Path
import sys
import numpy as np
from ai.rf import RFModel, attack, features
from checks.check_rf import verify
from simulation.run_rf import TASKS, digest, load_frames, publish

MOMENTS = ['mean_i', 'mean_q', 'mean_i2', 'mean_q2', 'mean_i4', 'mean_q4', 'mean_iq']


def group_prefix(manifest, split, task):
    generator = manifest.get('generator_metadata', {}).get(split, {})
    if generator.get('generator') == 'analytical_rf_v2':
        return 'rf-s' + str(generator['seed']) + '-' + task + '-'
    return manifest['inputs'][split]['sha256'][:16] + ':' + task + ':'


def assignments(count, fraction, modes, seed):
    if not 0 <= fraction <= 1 or not modes or len(set(modes)) != len(modes):
        raise ValueError('Invalid mixture')
    if any(mode not in ('fgsm', 'pgd') for mode in modes):
        raise ValueError('Only intentional FGSM/PGD attacks are labeled malicious')
    labels = np.full(count, 'none', dtype='<U4')
    n = int(np.floor(count * fraction + .5))
    order = np.random.default_rng(seed).permutation(count)
    for index in range(n):
        labels[order[index]] = modes[index % len(modes)]
    return labels


def export(root, out, fraction=.2, modes=('fgsm', 'pgd'), psr_db=-10., steps=30, seed=101):
    verify(root)
    manifest = json.loads((root / 'manifest.json').read_text())
    config = manifest['configuration']
    out.mkdir(parents=True, exist_ok=False)
    publish(out / 'run_status.json', dict(state='running'))
    iq_columns = []
    for k in range(config['length']):
        iq_columns.extend(['i' + str(k), 'q' + str(k)])
    metadata = ['group_id', 'split', 'task', 'frame_id', 'label', 'attack_type',
                'attack_applied', 'attack_success', 'signal_label', 'psr_db', 'actual_power_ratio']
    columns = metadata + MOMENTS + iq_columns
    report = dict(schema_version=1, source_run=str(root), source_manifest_sha256=digest(root/'manifest.json'),
                  source_evidence_sha256=digest(root/'evidence.json'), attack_fraction_requested=fraction,
                  modes=list(modes), psr_db=psr_db, steps=steps, selection_seed=seed,
                  target_column='label', multiclass_target_column='attack_type',
                  feature_columns=MOMENTS, alternative_raw_iq_columns=iq_columns,
                  exclude_from_features=metadata,
                  split_policy='Preserve original independent RF splits; one version per source frame.',
                  numpy=np.__version__, python=sys.version,
                  caveat='Same victim model and known attack families across splits; not unseen-model robustness.',
                  files={})
    report['implementation_sha256'] = {}
    for relative in ('datasets/export_rf_detection.py', 'ai/rf.py'):
        report['implementation_sha256'][relative] = digest(Path(__file__).resolve().parents[1]/relative)
    try:
        for s, split in enumerate(('train', 'validation', 'test')):
            count = config['train_samples'] if split == 'train' else config['eval_samples']
            data, truth = load_frames(root/(split+'.csv'), count, config['length'])
            path = out / (split + '.csv')
            temporary = path.with_suffix('.csv.tmp')
            counts = {}
            with temporary.open('w', newline='') as handle:
                writer = csv.writer(handle)
                writer.writerow(columns)
                for t, task in enumerate(TASKS):
                    x, y = data[task], truth[task]
                    model = RFModel.load(root / (task+'-model.npz'))
                    regression = task == 'channel'
                    target = y
                    if not regression:
                        target = 1-y if task == 'sensing' else (y+1) % 3
                    selection_seed = seed + s*1009 + t*100003
                    selected = assignments(count, fraction, modes, selection_seed)
                    delta = np.zeros_like(x)
                    for mode in modes:
                        indices = np.flatnonzero(selected == mode)
                        if len(indices):
                            delta[indices] = attack(model, x[indices], target[indices], mode,
                                                    10**(psr_db/10), regression, selection_seed, steps)
                    applied = np.any(delta != 0, axis=1)
                    if not np.array_equal(applied, selected != 'none'):
                        raise ValueError('Selected attack produced zero delta; cannot label clean IQ as attack')
                    energy = np.sum(x*x, axis=1)
                    power = np.sum(delta*delta, axis=1) / np.maximum(energy, 1e-30)
                    if not np.isfinite(delta).all() or np.any(power > 10**(psr_db/10)+1e-12):
                        raise ValueError('Detection export perturbation budget violation')
                    observed = x + delta
                    moments = features(observed)
                    clean_loss = model.loss_gradient(x, target, regression)[0]
                    attacked_loss = model.loss_gradient(observed, target, regression)[0]
                    if regression:
                        success = applied & (attacked_loss > clean_loss + 1e-12)
                    else:
                        clean_pred = model.forward(x)[0].argmax(1)
                        pred = model.forward(observed)[0].argmax(1)
                        success = applied & (clean_pred == y) & (pred == target)
                    n_attack = int(applied.sum())
                    counts[task] = dict(total=count, clean=count-n_attack, attack=n_attack,
                                        actual_attack_fraction=n_attack/count)
                    counts[task]['by_type'] = {}
                    for mode in ('none', *modes):
                        counts[task]['by_type'][mode] = int(np.sum(selected == mode))
                    prefix = group_prefix(manifest, split, task)
                    for index in range(count):
                        psr = psr_db if applied[index] else ''
                        row = [prefix+str(index), split, task, index, int(applied[index]),
                               selected[index], int(applied[index]), int(success[index]),
                               json.dumps(y[index].tolist()), psr, power[index]]
                        row.extend(moments[index].tolist())
                        row.extend(observed[index].tolist())
                        writer.writerow(row)
            temporary.replace(path)
            report['files'][split] = dict(path=path.name, sha256=digest(path), counts=counts)
        publish(out/'dataset.json', report)
        publish(out/'run_status.json', dict(state='completed', label='0=clean,1=applied intentional attack'))
    except BaseException as error:
        publish(out/'run_status.json', dict(state='failed', error=str(error)))
        raise
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--attack-fraction', type=float, default=.2)
    parser.add_argument('--modes', nargs='+', choices=['fgsm', 'pgd'], default=['fgsm', 'pgd'])
    parser.add_argument('--psr-db', type=float, default=-10)
    parser.add_argument('--steps', type=int, default=30)
    parser.add_argument('--seed', type=int, default=101)
    args = parser.parse_args(argv)
    if not np.isfinite(args.attack_fraction) or not 0 <= args.attack_fraction <= 1:
        parser.error('attack fraction must be in [0,1]')
    if not np.isfinite(args.psr_db) or not -120 <= args.psr_db <= 0:
        parser.error('PSR must be finite and in [-120,0] dB')
    if args.steps < 1 or not 0 <= args.seed <= 2**32-1 or len(set(args.modes)) != len(args.modes):
        parser.error('positive steps, uint32 seed and distinct modes required')
    report = export(args.run.resolve(), args.output.resolve(), args.attack_fraction,
                    args.modes, args.psr_db, args.steps, args.seed)
    print(json.dumps(report['files'], indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
