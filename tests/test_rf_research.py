import dataclasses
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from datasets import generate_rf_research as rf
from checks.check_rf_research import check


class RFResearchTests(unittest.TestCase):
    def config(self, **kwargs):
        return dataclasses.replace(rf.Config(samples=12, length=32, cp=8, taps=3, group_frames=2), **kwargs)

    def test_constellations_and_rrc(self):
        for label, count in enumerate((2, 4, 8, 16, 16, 64)):
            points = rf.constellation(label)
            self.assertEqual(len(np.unique(points)), count)
            self.assertAlmostEqual(float(np.mean(abs(points) ** 2)), 1)
        h = rf.rrc(4, .5)
        np.testing.assert_allclose(h, h[::-1])
        self.assertAlmostEqual(float(np.sum(h ** 2)), 1)

    def test_known_multipath_noiseless_ofdm_ls(self):
        taps = np.array([1 + .3j, .2 - .4j, -.1 + .2j])
        symbols = np.full(32, (1 + 1j) / np.sqrt(2))
        y = rf.ofdm_receive(symbols, taps, 8)
        expected = np.fft.fft(taps, n=32)
        np.testing.assert_allclose(y / symbols, expected, atol=1e-14)
        estimate = rf.ls_interpolate(y[None], symbols)
        self.assertLess(rf.nmse(estimate, expected[None]), 1e-28)
        sparse = np.zeros(32, dtype=complex)
        sparse[::4] = symbols[::4]
        estimate = rf.ls_interpolate(y[None], sparse)
        np.testing.assert_allclose(estimate[0, ::4], expected[::4], atol=1e-14)
        self.assertGreater(rf.nmse(estimate, expected[None]), 0)

    def test_nuisances_are_counterfactually_class_independent(self):
        empty = rf.build_arrays(self.config(occupancy=0))
        full = rf.build_arrays(self.config(occupancy=1))
        for key in empty[2]:
            np.testing.assert_array_equal(empty[2][key], full[2][key])
        self.assertFalse(empty[1]['class'].any())
        self.assertTrue(full[1]['class'].all())
        np.testing.assert_array_equal(empty[0]['quiet_calibration'], full[0]['quiet_calibration'])
        np.testing.assert_array_equal(empty[0]['quiet_calibration'][0], empty[0]['quiet_calibration'][1])
        longer = rf.build_arrays(self.config(occupancy=0, calibration_length=4096))
        np.testing.assert_array_equal(empty[0]['received'], longer[0]['received'])
        self.assertFalse(np.array_equal(empty[0]['quiet_calibration'][0], empty[0]['quiet_calibration'][2]))
        # AMC labels share no RNG state with nuisance/channel generation.
        c = self.config(task='amc')
        actual = rf.build_arrays(c)
        nu = np.random.default_rng(rf.role_seed(c, 'nuisance'))
        expected_snr = nu.uniform(c.snr_min, c.snr_max, 6)
        np.testing.assert_array_equal(actual[2]['nuisance'][::2, 0], expected_snr)
        self.assertEqual(set(actual[1]['class']), set(range(6)))
        original = rf.role_seed
        def alternate(config, role):
            return original(config, role) + (100 if role == 'labels' else 0)
        with patch.object(rf, 'role_seed', alternate):
            counterfactual = rf.build_arrays(c)
        self.assertFalse(np.array_equal(actual[1]['class'], counterfactual[1]['class']))
        for key in ('nuisance', 'taps'):
            np.testing.assert_array_equal(actual[2][key], counterfactual[2][key])

    def test_all_tasks_precision_replay_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            for task in ('sensing', 'amc', 'channel'):
                c = self.config(task=task)
                path = Path(temporary) / task
                rf.generate(c, path)
                result = check(path)
                self.assertEqual(result['checked_frames'], 12)
                with np.load(path / 'observations.npz', allow_pickle=False) as data:
                    for key in data.files:
                        self.assertEqual(data[key].dtype, np.dtype('float64'))
                with self.assertRaises(FileExistsError):
                    rf.generate(c, path)
                a = rf.build_arrays(c)[0]['received']
                b = rf.build_arrays(c)[0]['received']
                np.testing.assert_array_equal(a, b)
                changed = rf.build_arrays(dataclasses.replace(c, seed=c.seed + 1))[0]['received']
                self.assertFalse(np.array_equal(a, changed))

    def test_invalid_configuration(self):
        for changes in ({'samples': 0}, {'seed': -1}, {'snr_min': float('nan')}, {'occupancy': 1.1}, {'taps': 12}, {'length': 33}):
            with self.assertRaises(ValueError):
                self.config(**changes).validate()

    def test_tamper_leakage_and_split_reuse_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / 'a', Path(temporary) / 'b'
            rf.generate(self.config(), a)
            rf.generate(self.config(split='validation'), b)
            with self.assertRaisesRegex(ValueError, 'fresh root seed'):
                check(a, [b])
            file = a / 'observations.npz'
            np.savez_compressed(file, received=np.zeros((12, 4, 32, 2)), true_label=np.ones(12))
            manifest = json.loads((a / 'manifest.json').read_text())
            manifest['files']['observations.npz'] = rf.sha(file)
            (a / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                check(a)

    def test_observable_quiet_calibration_null(self):
        c = self.config(samples=800, group_frames=1, bands=2, occupancy=0,
                        snr_min=-4., snr_max=12., noise_uncertainty_db=6.)
        observations, _, _, _ = rf.build_arrays(c)
        reference = observations['quiet_calibration']
        estimate = np.mean(np.sum(reference ** 2, axis=-1), axis=-1)
        energy = np.mean(np.sum(observations['received'] ** 2, axis=-1), axis=-1)
        threshold = estimate[:, None] * rf.energy_threshold(c.length, 1., .05)
        rate = float(np.mean(energy > threshold))
        self.assertLess(abs(rate - .05), .02)
        # All bands/frames use only their separate observed reference, no label,
        # true nuisance, or signal-containing test energy to choose threshold.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'null'
            rf.generate(c, path)
            evidence = check(path)
            self.assertEqual(evidence['calibrated_vacant_fpr'], rate)
            self.assertIsNone(evidence['calibrated_occupied_detection_rate'])

    def test_exact_awgn_energy_calibration(self):
        threshold = rf.energy_threshold(1, 2., .05)
        self.assertAlmostEqual(threshold, -2 * np.log(.05), places=12)
        rng = np.random.default_rng(11)
        noise = (rng.normal(size=(20000, 32)) + 1j * rng.normal(size=(20000, 32))) / np.sqrt(2)
        rate = np.mean(np.mean(abs(noise) ** 2, axis=1) > rf.energy_threshold(32, 1., .05))
        self.assertLess(abs(rate - .05), .006)

if __name__ == '__main__':
    unittest.main()
