"""Numerical and evidence checks for receiver-IQ attacks (no Docker required)."""
import csv
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
from ai.rf import RFModel, attack, features, feature_backward
from simulation.run_rf import check_split_overlap, load_frames, main, measure
from checks.check_rf import verify, verify_interference


class RFTests(unittest.TestCase):
    def test_generator_options_cannot_override_split_identity_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for options in (['--generator-arg=--seed=99'], ['--generator-arg=--output=elsewhere'],
                            ['--generator-arg=--cfo-max=0.01', '--generator-arg=--cfo-max=0.02'],
                            ['--rf-profile', 'unknown']):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    main(['--scenario', str(root/'supplied.cc'), '--output', str(root/'result'), *options])
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse((root/'result').exists())

    def setUp(self):
        self.rng = np.random.default_rng(7)
        self.x = self.rng.normal(size=(12, 16))

    def test_iq_feature_chain_rule_matches_finite_differences(self):
        weights = self.rng.normal(size=(12, 7))
        analytical = feature_backward(self.x, weights)
        for row, column in ((0, 0), (2, 7), (5, 10)):
            plus, minus = self.x.copy(), self.x.copy()
            plus[row, column] += 1e-6
            minus[row, column] -= 1e-6
            numerical = np.sum((features(plus)-features(minus))*weights) / 2e-6
            self.assertAlmostEqual(analytical[row, column], numerical, places=6)

    def test_classification_and_regression_raw_iq_and_weight_gradients(self):
        for regression in (False, True):
            model = RFModel(self.x, 3 if not regression else 2, 19)
            y = np.arange(12) % 3
            if regression:
                y = self.rng.normal(size=(12, 2))
            losses, gradient, weights = model.loss_gradient(self.x, y, regression)
            self.assertTrue(np.isfinite(losses).all())
            for row, column in ((0, 0), (1, 1), (2, 8)):
                plus, minus = self.x.copy(), self.x.copy()
                plus[row, column] += 1e-6
                minus[row, column] -= 1e-6
                a = model.loss_gradient(plus, y, regression)[0][row]
                b = model.loss_gradient(minus, y, regression)[0][row]
                self.assertAlmostEqual(gradient[row, column], (a-b)/2e-6, places=6)
            for k in range(6):
                index = (0, 0) if k % 2 == 0 else (0,)
                initial = model.parameters[k][index]
                model.parameters[k][index] = initial + 1e-6
                a = model.loss_gradient(self.x, y, regression)[0].mean()
                model.parameters[k][index] = initial - 1e-6
                b = model.loss_gradient(self.x, y, regression)[0].mean()
                model.parameters[k][index] = initial
                self.assertAlmostEqual(weights[k][index], (a-b)/2e-6, places=6)

    def test_all_attacks_preserve_l2_budget_and_zero_controls(self):
        model = RFModel(self.x, 3, 19)
        y = np.arange(12) % 3
        for mode in ('none', 'random', 'fgsm', 'pgd'):
            for ratio in (0., .01, .1):
                delta = attack(model, self.x, y, mode, ratio, False, 37, steps=8)
                self.assertTrue(np.all(np.linalg.norm(delta, axis=1) <=
                                       np.sqrt(ratio)*np.linalg.norm(self.x, axis=1)+1e-12))
                if ratio == 0 or mode == 'none':
                    np.testing.assert_array_equal(delta, np.zeros_like(delta))
        zeros = np.zeros_like(self.x)
        delta = attack(model, zeros, y, 'pgd', .1, False, 37, steps=8)
        np.testing.assert_array_equal(delta, zeros)

    def test_pgd_optimizes_correct_direction_for_both_objectives(self):
        for regression in (False, True):
            model = RFModel(self.x, 2, 19)
            y = np.arange(12) % 2
            if regression:
                y = self.rng.normal(size=(12, 2))
            clean = model.loss_gradient(self.x, y, regression)[0]
            delta = attack(model, self.x, y, 'pgd', .01, regression, 37, steps=8)
            attacked = model.loss_gradient(self.x+delta, y, regression)[0]
            difference = attacked - clean
            if not regression:
                difference = -difference
            self.assertTrue(np.all(difference >= -1e-12))
            self.assertGreater(float(difference.mean()), 1e-6)

    def test_success_denominator_excludes_already_wrong_clean_predictions(self):
        class FakeModel:
            def forward(self, x):
                return np.array([[0., 1.], [1., 0.], [0., 1.]]), None
        y = np.array([0, 1, 0])
        target = 1-y
        clean = np.array([0, 0, 0])
        metrics, _ = measure(FakeModel(), np.zeros((3, 2)), y, target, clean, False)
        self.assertEqual(metrics['eligible_clean_correct'], 2)
        self.assertEqual(metrics['targeted_successes'], 2)
        self.assertEqual(metrics['targeted_asr'], 1.)
        self.assertIsNone(metrics['directions']['1->0']['targeted_asr'])

    def test_loader_rejects_duplicate_ids_and_nonfinite_iq(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'frames.csv'
            for bad in ('duplicate', 'nonfinite'):
                with path.open('w', newline='') as handle:
                    writer = csv.writer(handle)
                    writer.writerow(['task', 'id', 'label', 'h_i', 'h_q', 'i0', 'q0'])
                    for task in ('sensing', 'amc', 'channel'):
                        for index in range(2):
                            identifier = 0 if bad == 'duplicate' else index
                            value = 'nan' if bad == 'nonfinite' else 1
                            writer.writerow([task, identifier, 0, 1, 0, value, 0])
                with self.assertRaises(ValueError):
                    load_frames(path, 2, 1)

    def test_model_round_trip_preserves_inference(self):
        model = RFModel(self.x, 3, 19)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'model.npz'
            model.save(path)
            loaded = RFModel.load(path)
            np.testing.assert_array_equal(model.forward(self.x)[0], loaded.forward(self.x)[0])

    def test_duplicate_frame_across_splits_is_rejected(self):
        splits = {}
        for split in ('train', 'validation', 'test'):
            frames = {}
            for task in ('sensing', 'amc', 'channel'):
                frames[task] = self.x.copy()
            splits[split] = (frames, {})
        with self.assertRaisesRegex(ValueError, 'Identical RF frame across splits'):
            check_split_overlap(splits)

    def test_checker_rejects_changed_artifact_before_using_its_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'run_status.json').write_text(json.dumps(dict(
                state='completed', experiment='synthetic_receiver_iq')))
            data = b'original audit data'
            (root / 'evidence.json').write_text(json.dumps({
                'audit.npz': hashlib.sha256(data).hexdigest()}))
            (root / 'audit.npz').write_bytes(b'changed audit data')
            with self.assertRaisesRegex(ValueError, 'Artifact hash mismatch'):
                verify(root)

    def test_physical_labels_require_iq_change_and_preserve_true_signal_labels(self):
        frames, truth = {}, {}
        metadata = dict(frames_per_task=1, complex_samples_per_frame=8, seed=11,
                        interference_psr_db=-10, interference_frames_per_task=0)
        columns = ['group_id', 'task', 'id', 'label', 'attack_type', 'signal_label',
                   'h_i', 'h_q', 'actual_power_ratio']
        for k in range(8):
            columns.extend(['i'+str(k), 'q'+str(k)])
        rows = []
        for task in ('sensing', 'amc', 'channel'):
            frames[task] = self.x[:1].copy()
            truth[task] = np.array([[.3, -.4]]) if task == 'channel' else np.array([1])
            row = ['rf-s11-'+task+'-0', task, 0, 0, 'none', 1, .3, -.4, 0.]
            row.extend(frames[task][0].tolist())
            rows.append(row)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'physical.csv'
            def write():
                with path.open('w', newline='') as handle:
                    writer = csv.writer(handle)
                    writer.writerow(columns)
                    writer.writerows(rows)
            write()
            self.assertEqual(verify_interference(path, frames, truth, metadata)['sensing'], 0)
            rows[0][3:5] = [1, 'tone_jamming']
            write()
            with self.assertRaisesRegex(ValueError, 'label differs from actual IQ change'):
                verify_interference(path, frames, truth, metadata)
            rows[0][3:5] = [0, 'none']
            rows[0][5] = 0
            write()
            with self.assertRaisesRegex(ValueError, 'RF class changed'):
                verify_interference(path, frames, truth, metadata)


if __name__ == '__main__':
    unittest.main()
