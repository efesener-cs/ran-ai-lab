"""Fail-closed RF research artifact and deterministic physical-model checker."""
import argparse
import json
from pathlib import Path
import zipfile
import numpy as np
from datasets import generate_rf_research as rf


def check(path, other_paths=()):
    path = Path(path)
    m = json.loads((path / 'manifest.json').read_text())
    if m['schema'] != 'rf-research-v1':
        raise ValueError('schema')
    c = rf.Config(**m['config'])
    c.validate()
    namespace = f'rf-research-v1/{c.task}/{c.split}/{c.seed}'
    if m['identity_namespace'] != namespace or m['role_seeds'] != {r: rf.role_seed(c, r) for r in rf.ROLES}:
        raise ValueError('split identity/seeds')
    if m['code']['generator_sha256'] != rf.sha(rf.__file__):
        raise ValueError('generator source mismatch')
    if m['counts'] != {'frames': c.samples, 'groups': (c.samples + c.group_frames - 1) // c.group_frames}:
        raise ValueError('counts')
    names = ('observations', 'labels', 'audit', 'identities')
    expected_files = {name + '.npz' for name in names}
    expected_files.add('generator_source.py')
    snapshot = path / 'generator_source.py'
    if snapshot.is_symlink() or rf.sha(snapshot) != m['code']['generator_sha256'] or rf.sha(snapshot) != m['files']['generator_source.py']:
        raise ValueError('generator snapshot hash')
    if set(m['files']) != expected_files or set(m['arrays']) != set(names):
        raise ValueError('unexpected artifact contract')
    generated = rf.build_arrays(c)
    loaded = []
    for name, expected in zip(names, generated):
        file = path / (name + '.npz')
        if file.is_symlink() or rf.sha(file) != m['files'][file.name]:
            raise ValueError('hash/symlink: ' + name)
        with zipfile.ZipFile(file) as archive:
            if sorted(archive.namelist()) != sorted(k + '.npy' for k in expected):
                raise ValueError('unexpected or duplicate zip members')
        with np.load(file, allow_pickle=False) as archive:
            values = {k: archive[k] for k in archive.files}
        if set(values) != set(expected) or set(m['arrays'][name]) != set(expected):
            raise ValueError('unexpected arrays, possible feature leakage')
        for key, value in values.items():
            wanted = expected[key]
            spec = {'shape': list(wanted.shape), 'dtype': str(wanted.dtype)}
            if value.dtype != wanted.dtype or value.shape != wanted.shape or m['arrays'][name][key] != spec:
                raise ValueError('shape/precision: ' + key)
            if not np.isfinite(value).all() or not np.array_equal(value, wanted):
                raise ValueError('physical-model replay mismatch: ' + key)
        loaded.append(values)
    for other in other_paths:
        om = json.loads((Path(other) / 'manifest.json').read_text())
        if om['identity_namespace'] == namespace:
            raise ValueError('same emission namespace reused across collections')
        if om['config']['task'] == c.task and om['config']['split'] != c.split:
            if om['config']['seed'] == c.seed:
                raise ValueError('distinct split requires fresh root seed')
            with np.load(Path(other) / 'observations.npz', allow_pickle=False) as archive:
                prior = archive['received']
            current = loaded[0]['received']
            # Exact duplicate observed frames, independent of identifier naming.
            hashes = set()
            import hashlib
            for frame in prior:
                hashes.add(hashlib.sha256(frame.tobytes()).digest())
            for frame in current:
                if hashlib.sha256(frame.tobytes()).digest() in hashes:
                    raise ValueError('duplicate observed frame across splits')
    evidence = {'checked_frames': c.samples, 'groups': m['counts']['groups'], 'task': c.task, 'split': c.split}
    if c.task == 'channel':
        h = rf.complex_iq(loaded[1]['H'])
        taps = rf.complex_iq(loaded[2]['taps'])
        if not np.allclose(h, np.fft.fft(taps, n=c.length, axis=1), rtol=1e-13, atol=1e-13):
            raise ValueError('H/taps inconsistency')
        estimate = rf.ls_interpolate(rf.complex_iq(loaded[0]['received']), rf.complex_iq(loaded[0]['pilots']))
        metric = rf.nmse(estimate, h)
        if not np.array_equal(rf.iq(estimate), loaded[2]['ls_interpolated']) or metric != m['baseline']['linear_interpolation_nmse']:
            raise ValueError('LS baseline mismatch')
        evidence['linear_interpolation_nmse'] = metric
    if c.task == 'amc':
        if m['classes'] != list(rf.CLASSES) or m['uniform_guess_accuracy'] != 1 / 6:
            raise ValueError('class contract')
        evidence['per_class'] = {}
        for label, name in enumerate(rf.CLASSES):
            mask = loaded[1]['class'] == label
            nuisance = loaded[2]['nuisance'][mask]
            evidence['per_class'][name] = {'frames': int(mask.sum()),
                'groups': int(len(np.unique(loaded[3]['group'][mask]))),
                'nuisance_min': nuisance.min(axis=0).tolist() if mask.any() else None,
                'nuisance_max': nuisance.max(axis=0).tolist() if mask.any() else None,
                'nuisance_mean': nuisance.mean(axis=0).tolist() if mask.any() else None}
        evidence['support_note'] = 'nuisance rows repeat within bursts; small empirical class differences are not evidence of sampler dependence'
    if c.task == 'sensing':
        calibration = m['energy_detector']
        variance = 10 ** ((c.noise_uncertainty_db - c.snr_min) / 10)
        threshold = rf.energy_threshold(c.length, variance, .05)
        if calibration['pfa'] != .05 or calibration['noise_variance_upper_bound'] != variance or calibration['threshold_conservative'] != threshold:
            raise ValueError('energy calibration')
        energy = np.mean(np.sum(loaded[0]['received'] ** 2, axis=-1), axis=-1)
        calibration = loaded[0]['quiet_calibration']
        estimated_variance = np.mean(np.sum(calibration ** 2, axis=-1), axis=-1)
        calibrated_threshold = estimated_variance[:, None] * rf.energy_threshold(c.length, 1., .05)
        labels = loaded[1]['class']
        for truth, key in ((0, 'vacant_fpr'), (1, 'occupied_detection_rate')):
            mask = labels == truth
            evidence[key] = float(np.mean(energy[mask] > threshold)) if mask.any() else None
            evidence['calibrated_' + key] = float(np.mean((energy > calibrated_threshold)[mask])) if mask.any() else None
        evidence['calibration_note'] = 'calibrated threshold uses independent observable quiet receiver data only; plug-in Gamma calibration has approximate finite-reference PFA; no confidence or external calibration claim'
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--other', type=Path, action='append', default=[])
    args = parser.parse_args(argv)
    print(json.dumps(check(args.path, args.other), indent=2))

if __name__ == '__main__':
    main()
