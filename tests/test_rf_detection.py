"""Training exports keep attack labels out of features and preserve RF splits."""
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from ai.rf import RFModel, features
from datasets.export_rf_detection import assignments, export, group_prefix
from simulation.run_rf import TASKS, digest


class DetectionExportTests(unittest.TestCase):
    def test_v2_groups_match_physical_interference_and_v1_groups_remain_supported(self):
        manifest = dict(inputs=dict(train=dict(sha256='abcdef0123456789' * 4)))
        self.assertEqual(group_prefix(manifest, 'train', 'sensing'), 'abcdef0123456789:sensing:')
        manifest['generator_metadata'] = dict(train=dict(generator='analytical_rf_v2', seed=11))
        self.assertEqual(group_prefix(manifest, 'train', 'sensing'), 'rf-s11-sensing-')

    def test_exact_mixture_reproducible_and_only_intentional_attacks(self):
        selected = assignments(600, .2, ('fgsm', 'pgd'), 101)
        self.assertEqual(int(np.sum(selected == 'none')), 480)
        self.assertEqual(int(np.sum(selected == 'fgsm')), 60)
        self.assertEqual(int(np.sum(selected == 'pgd')), 60)
        np.testing.assert_array_equal(selected, assignments(600, .2, ('fgsm', 'pgd'), 101))
        for modes in (('random',), ('fgsm', 'fgsm')):
            with self.assertRaises(ValueError):
                assignments(60, .2, modes, 101)

    def fixture(self, root):
        rng = np.random.default_rng(7)
        config = dict(length=8, train_samples=60, eval_samples=60)
        inputs = {}
        original = {}
        for split in ('train', 'validation', 'test'):
            header = ['task', 'id', 'label', 'h_i', 'h_q']
            for k in range(8):
                header.extend(['i'+str(k), 'q'+str(k)])
            path = root / (split+'.csv')
            with path.open('w', newline='') as handle:
                writer = csv.writer(handle)
                writer.writerow(header)
                for task in TASKS:
                    x = rng.normal(size=(60, 16))
                    original[(split, task)] = x
                    outputs = 3 if task == 'amc' else 2
                    if split == 'train':
                        RFModel(x, outputs, 19).save(root / (task+'-model.npz'))
                    for index in range(60):
                        row = [task, index, index % outputs, .5, -.2]
                        row.extend(x[index].tolist())
                        writer.writerow(row)
            inputs[split] = dict(sha256=digest(path))
        (root/'manifest.json').write_text(json.dumps(dict(configuration=config, inputs=inputs)))
        (root/'evidence.json').write_text('{}')
        return original

    def test_export_contains_observed_iq_true_labels_and_exact_split_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'input'
            root.mkdir()
            original = self.fixture(root)
            out = Path(folder)/'output'
            # Input experiment validation has independent tests; this fixture exercises export semantics.
            with patch('datasets.export_rf_detection.verify') as check:
                report = export(root, out, steps=2)
            check.assert_called_once_with(root)
            self.assertNotIn('label', report['feature_columns'])
            self.assertNotIn('attack_type', report['feature_columns'])
            groups = set()
            for split in ('train', 'validation', 'test'):
                with (out/(split+'.csv')).open() as handle:
                    rows = list(csv.DictReader(handle))
                self.assertEqual(len(rows), 180)
                for task in TASKS:
                    self.assertEqual(report['files'][split]['counts'][task]['attack'], 12)
                for row in rows:
                    self.assertNotIn(row['group_id'], groups)
                    groups.add(row['group_id'])
                    x = original[(split, row['task'])][int(row['frame_id'])]
                    observed = np.array([float(row[name]) for name in report['alternative_raw_iq_columns']])
                    changed = bool(np.any(x != observed))
                    self.assertEqual(changed, row['label'] == '1')
                    self.assertEqual(row['attack_applied'], row['label'])
                    np.testing.assert_allclose(features(observed[None, :])[0],
                                               [float(row[name]) for name in report['feature_columns']])
                    if not changed:
                        self.assertEqual(row['attack_type'], 'none')
                    self.assertLessEqual(float(row['actual_power_ratio']), .1+1e-12)

    def test_zero_delta_attack_is_not_mislabeled_positive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'input'
            root.mkdir()
            self.fixture(root)
            out = Path(folder)/'output'
            with patch('datasets.export_rf_detection.verify'), \
                    patch('datasets.export_rf_detection.attack', side_effect=lambda model, x, *args: np.zeros_like(x)):
                with self.assertRaisesRegex(ValueError, 'zero delta'):
                    export(root, out, steps=2)
            self.assertEqual(json.loads((out/'run_status.json').read_text())['state'], 'failed')


if __name__ == '__main__':
    unittest.main()
