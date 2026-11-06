"""Independent synthetic RF research development data; NumPy only, no training."""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sys
import numpy as np

SPLITS = ('development', 'train', 'validation', 'test', 'ood')
CLASSES = ('BPSK', 'QPSK', '8PSK', '16PSK', '16QAM', '64QAM')
ROLES = ('labels', 'nuisance', 'symbols', 'noise', 'channel', 'calibration')

@dataclass(frozen=True)
class Config:
    task: str = 'sensing'
    seed: int = 101
    samples: int = 120
    split: str = 'development'
    length: int = 128
    group_frames: int = 4
    bands: int = 4
    occupancy: float = 0.5
    snr_min: float = -8.0
    snr_max: float = 20.0
    noise_uncertainty_db: float = 2.0
    sps: int = 4
    rolloff: float = 0.35
    taps: int = 4
    cp: int = 16
    pilot_spacing: int = 4
    cfo_max: float = 0.002
    timing_max: float = 0.4
    calibration_length: int = 2048

    def validate(self):
        if self.task not in ('sensing', 'amc', 'channel') or self.split not in SPLITS:
            raise ValueError('unknown task/split')
        for key in ('seed', 'samples', 'length', 'group_frames', 'bands', 'sps', 'taps', 'cp', 'pilot_spacing', 'calibration_length'):
            value = getattr(self, key)
            if isinstance(value, bool) or not isinstance(value, int) or value < (0 if key == 'seed' else 1):
                raise ValueError('invalid integer: ' + key)
        for key, value in asdict(self).items():
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError('nonfinite: ' + key)
        if not 128 <= self.calibration_length <= 65536:
            raise ValueError('calibration length outside limits')
        if not (16 <= self.length <= 16384 and self.samples <= 1000000 and self.bands <= 32 and self.sps <= 16):
            raise ValueError('shape outside limits')
        if not (0 <= self.occupancy <= 1 and -60 <= self.snr_min <= self.snr_max <= 100):
            raise ValueError('invalid occupancy/SNR')
        if not (0 <= self.noise_uncertainty_db <= 20 and 0 < self.rolloff <= 1 and 0 <= self.cfo_max <= .1 and 0 <= self.timing_max <= 1):
            raise ValueError('invalid impairment')
        if not (self.taps <= self.cp + 1 <= self.length and self.length % self.pilot_spacing == 0):
            raise ValueError('CP must cover taps; pilot spacing must divide length')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def role_seed(c, role):
    text = f'rf-research-v1/{c.task}/{c.split}/{c.seed}/{role}'
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], 'little')


def iq(z):
    return np.stack((z.real, z.imag), axis=-1).astype(np.float64)


def complex_iq(x):
    return x[..., 0] + 1j * x[..., 1]


def constellation(label):
    if label < 4:
        order = (2, 4, 8, 16)[label]
        return np.exp(2j * np.pi * np.arange(order) / order)
    side = (4, 8)[label - 4]
    axis = np.arange(-side + 1, side, 2, dtype=np.float64)
    z = (axis[:, None] + 1j * axis[None, :]).ravel()
    return z / np.sqrt(np.mean(abs(z) ** 2))


def rrc(sps, beta, span=8):
    t = np.arange(-span * sps // 2, span * sps // 2 + 1) / sps
    h = np.empty_like(t)
    for i, v in enumerate(t):
        if abs(v) < 1e-12:
            h[i] = 1 + beta * (4 / np.pi - 1)
        elif abs(abs(v) - 1 / (4 * beta)) < 1e-12:
            h[i] = beta / np.sqrt(2) * ((1 + 2 / np.pi) * np.sin(np.pi / (4 * beta)) + (1 - 2 / np.pi) * np.cos(np.pi / (4 * beta)))
        else:
            h[i] = (np.sin(np.pi * v * (1 - beta)) + 4 * beta * v * np.cos(np.pi * v * (1 + beta))) / (np.pi * v * (1 - (4 * beta * v) ** 2))
    return h / np.sqrt(np.sum(h ** 2))


def waveform(rng, label, c):
    points = constellation(label)
    guarded_length = c.length + 2 * c.taps + 8
    count = math.ceil(guarded_length / c.sps) + 32
    symbols = points[rng.integers(len(points), size=count)]
    up = np.zeros(count * c.sps, dtype=np.complex128)
    up[::c.sps] = symbols
    shaped = np.convolve(up, rrc(c.sps, c.rolloff)) * np.sqrt(c.sps)
    start = 16 * c.sps
    return shaped[start:start + guarded_length]


def ofdm_receive(symbols, taps, cp):
    """Unitary IFFT, CP, linear channel, CP removal and unitary FFT."""
    time = np.fft.ifft(symbols, norm='ortho')
    extended = np.concatenate((time[-cp:], time))
    received = np.convolve(extended, taps)
    return np.fft.fft(received[cp:cp + len(symbols)], norm='ortho')


def ls_interpolate(received, pilots):
    mask = abs(pilots) > 0
    positions = np.flatnonzero(mask)
    estimates = received[..., mask] / pilots[mask]
    grid = np.arange(len(pilots))
    result = np.empty_like(received)
    for i in range(len(received)):
        x = np.concatenate((positions - len(pilots), positions, positions + len(pilots)))
        z = np.tile(estimates[i], 3)
        result[i] = np.interp(grid, x, z.real) + 1j * np.interp(grid, x, z.imag)
    return result


def nmse(estimate, target):
    return float(np.sum(abs(estimate - target) ** 2) / np.sum(abs(target) ** 2))


def energy_threshold(length, variance, pfa):
    """Exact integer-gamma survival inversion for mean complex AWGN energy."""
    def tail(x):
        if x == 0:
            return 1.0
        terms = []
        for k in range(length):
            terms.append(k * math.log(x) - math.lgamma(k + 1))
        peak = max(terms)
        return math.exp(-x + peak) * sum(math.exp(v - peak) for v in terms)
    low, high = 0.0, float(length * 4 + 100)
    for _ in range(90):
        middle = (low + high) / 2
        if tail(middle) > pfa:
            low = middle
        else:
            high = middle
    return variance * (low + high) / (2 * length)


def build_arrays(c):
    c.validate()
    rng = {role: np.random.default_rng(role_seed(c, role)) for role in ROLES}
    n = c.samples
    groups = (n + c.group_frames - 1) // c.group_frames
    index = np.arange(n) // c.group_frames
    nu = rng['nuisance']
    # All nuisance draws precede labels and are independent of class assignment.
    nuisance = np.column_stack((nu.uniform(c.snr_min, c.snr_max, groups),
        nu.uniform(-c.noise_uncertainty_db, c.noise_uncertainty_db, groups),
        nu.uniform(-np.pi, np.pi, groups), nu.uniform(-c.cfo_max, c.cfo_max, groups),
        nu.uniform(-c.timing_max, c.timing_max, groups)))
    powers = np.exp(-np.arange(c.taps))
    powers /= powers.sum()
    taps = (rng['channel'].normal(size=(groups, c.taps)) + 1j * rng['channel'].normal(size=(groups, c.taps))) * np.sqrt(powers / 2)
    audits = {'nuisance': nuisance[index].astype(np.float64), 'taps': iq(taps[index])}
    identities = {'group': index.astype(np.int64), 'frame': np.arange(n, dtype=np.int64)}
    if c.task == 'channel':
        pilots = np.zeros(c.length, dtype=np.complex128)
        pilots[::c.pilot_spacing] = (1 + 1j) / np.sqrt(2)
        target = np.fft.fft(taps[index], n=c.length)
        received = np.empty((n, c.length), dtype=np.complex128)
        for i in range(n):
            symbols = constellation(1)[rng['symbols'].integers(4, size=c.length)]
            symbols[::c.pilot_spacing] = pilots[::c.pilot_spacing]
            variance = 10 ** ((nuisance[index[i], 1] - nuisance[index[i], 0]) / 10)
            noise = (rng['noise'].normal(size=c.length) + 1j * rng['noise'].normal(size=c.length)) * np.sqrt(variance / 2)
            received[i] = ofdm_receive(symbols, taps[index[i]], c.cp) + noise
        audits['ls_interpolated'] = iq(ls_interpolate(received, pilots))
        return {'received': iq(received), 'pilots': iq(pilots)}, {'H': iq(target)}, audits, identities
    if c.task == 'sensing':
        labels = (rng['labels'].random((groups, c.bands)) < c.occupancy).astype(np.int64)[index]
        received = np.empty((n, c.bands, c.length), dtype=np.complex128)
    else:
        classes = np.arange(groups) % len(CLASSES)
        rng['labels'].shuffle(classes)
        labels = classes[index].astype(np.int64)
        received = np.empty((n, c.length), dtype=np.complex128)
    for i in range(n):
        snr, noise_db, phase, cfo, timing = nuisance[index[i]]
        variance = 10 ** ((noise_db - snr) / 10)
        for band in range(c.bands if c.task == 'sensing' else 1):
            label = 1 if c.task == 'sensing' else int(labels[i])
            wave = waveform(rng['symbols'], label, c)
            wave = np.convolve(wave, taps[index[i]])
            axis = np.arange(c.length) + c.taps + 2 + timing
            wave = np.interp(axis, np.arange(len(wave)), wave.real) + 1j * np.interp(axis, np.arange(len(wave)), wave.imag)
            wave *= np.exp(1j * (phase + 2 * np.pi * cfo * np.arange(c.length)))
            if c.task == 'sensing':
                wave *= labels[i, band]
            noise = (rng['noise'].normal(size=c.length) + 1j * rng['noise'].normal(size=c.length)) * np.sqrt(variance / 2)
            if c.task == 'sensing':
                received[i, band] = wave + noise
            else:
                received[i] = wave + noise
    observations = {'received': iq(received)}
    if c.task == 'sensing':
        # A separate quiet receiver reference capture, never task IQ or oracle v.
        variance = 10 ** ((nuisance[:, 1] - nuisance[:, 0]) / 10)
        shape = (groups, c.calibration_length)
        reference = (rng['calibration'].normal(size=shape) + 1j * rng['calibration'].normal(size=shape)) * np.sqrt(variance[:, None] / 2)
        observations['quiet_calibration'] = iq(reference[index])
    return observations, {'class': labels}, audits, identities


def generate(c, output):
    c.validate()
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    arrays = build_arrays(c)
    output.mkdir(parents=True, exist_ok=False)
    names = ('observations', 'labels', 'audit', 'identities')
    for name, values in zip(names, arrays):
        for value in values.values():
            if value.dtype.kind not in 'fi' or not np.isfinite(value).all():
                raise ValueError('invalid array')
        np.savez_compressed(output / (name + '.npz'), **values)
    (output / 'generator_source.py').write_bytes(Path(__file__).read_bytes())
    manifest = {'schema': 'rf-research-v1', 'scientific_status': 'development-unvalidated-synthetic',
        'config': asdict(c), 'counts': {'frames': c.samples, 'groups': int(arrays[3]['group'][-1]) + 1},
        'role_seeds': {role: role_seed(c, role) for role in ROLES},
        'identity_namespace': f'rf-research-v1/{c.task}/{c.split}/{c.seed}',
        'environment': {'python': platform.python_version(), 'numpy': np.__version__, 'platform': platform.platform(),
            'threads': {k: os.environ.get(k) for k in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS')}},
        'code': {'generator_sha256': sha(__file__)},
        'arrays': {name: {k: {'shape': list(v.shape), 'dtype': str(v.dtype)} for k, v in values.items()} for name, values in zip(names, arrays)},
        'files': {name + '.npz': sha(output / (name + '.npz')) for name in names}}
    manifest['files']['generator_source.py'] = sha(output / 'generator_source.py')
    if c.task == 'channel':
        manifest['baseline'] = {'linear_interpolation_nmse': nmse(complex_iq(arrays[2]['ls_interpolated']), complex_iq(arrays[1]['H']))}
    if c.task == 'amc':
        manifest['classes'] = list(CLASSES)
        manifest['uniform_guess_accuracy'] = 1 / len(CLASSES)
    if c.task == 'sensing':
        # Noise variance relative to unit transmit power includes nominal SNR.
        worst = 10 ** ((c.noise_uncertainty_db - c.snr_min) / 10)
        nominal = 10 ** (-c.snr_min / 10)
        manifest['energy_detector'] = {'pfa': 0.05, 'noise_variance_nominal_at_snr_min': nominal,
            'noise_variance_upper_bound': worst, 'threshold_conservative': energy_threshold(c.length, worst, .05),
            'calibrated_definition': 'estimate variance from separate quiet_calibration receiver samples only; multiply by unit-variance Gamma threshold; approximate PFA with finite calibration',
            'calibration_length': c.calibration_length,
            'definition': 'mean |IQ|^2 per band; conditional AWGN Gamma(length, variance/length); conservative over configured noise range'}
    temporary = output / 'manifest.json.tmp'
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    temporary.replace(output / 'manifest.json')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    for key, value in asdict(Config()).items():
        parser.add_argument('--' + key.replace('_', '-'), type=type(value), default=value)
    args = vars(parser.parse_args(argv))
    output = args.pop('output')
    generate(Config(**args), output)
    print(output / 'manifest.json')

if __name__ == '__main__':
    main()
