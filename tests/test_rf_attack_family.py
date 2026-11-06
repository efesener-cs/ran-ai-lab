import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from ai import rf_attack_family as rf


class RFAttackFamilyTests(unittest.TestCase):
    def fixture(self, root):
        directory = root / 'jobs/reference/attempt-1/attack-family-data'
        directory.mkdir(parents=True)
        metadata = dict(feature_columns=list(rf.FEATURES), multiclass_target_column='attack_type',
                        modes=['fgsm', 'pgd'], files={})
        for split in rf.SPLITS:
            path = directory / (split + '.csv')
            with path.open('w', newline='') as handle:
                writer = csv.writer(handle)
                writer.writerow(list(rf.FEATURES) + ['attack_type', 'task', 'group_id', 'label', 'signal_label', 'psr_db', 'i0'])
                for task in rf.TASKS:
                    for i in range(30):
                        label = rf.CLASSES[i % 3]
                        writer.writerow([float(i % 3) + j / 10 for j in range(7)] +
                                        [label, task, split + '-' + task + '-' + str(i),
                                         'DO_NOT_PARSE', 'nan', 'SECRET', 'RAW_IDENTIFIER'])
            metadata['files'][split] = dict(path=path.name, sha256=rf.sha(path), counts={
                task: dict(total=30, by_type={label: 10 for label in rf.CLASSES}) for task in rf.TASKS})
        (directory / 'dataset.json').write_text(json.dumps(metadata))
        (directory / 'run_status.json').write_text(json.dumps(dict(state='completed')))
        attempt = directory.parent
        (attempt / 'verification.json').write_text('{}')
        files = {p.relative_to(attempt).as_posix(): rf.sha(p) for p in attempt.rglob('*') if p.is_file()}
        (attempt / 'receipt.json').write_text(json.dumps(dict(files=files)))
        plan = dict(state='complete', jobs=[dict(id='reference', kind='rf_attack', state='complete',
                    attempts=[dict(path='jobs/reference/attempt-1', state='complete',
                                   receipt_sha256=rf.sha(attempt / 'receipt.json'))])])
        (root / 'campaign.json').write_text(json.dumps(plan))
        return directory

    def test_explicit_features_and_categorical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.fixture(Path(temporary))
            parts = rf.load_dataset(directory)
            for frame in parts.values():
                self.assertEqual(set(frame.columns), set(rf.FEATURES) | {'attack_type', 'task', 'group_id'})
                self.assertEqual(set(frame.attack_type), set(rf.CLASSES))
                self.assertTrue(np.isfinite(frame[list(rf.FEATURES)]).all().all())

    def test_groups_reject_cross_split_but_allow_within_split_duplicates(self):
        import pandas as pd
        parts = {split: pd.DataFrame({'group_id': [split, split]}) for split in rf.SPLITS}
        rf.validate_groups(parts)
        parts['test']['group_id'] = ['train', 'new']
        with self.assertRaises(ValueError):
            rf.validate_groups(parts)

    def test_metadata_feature_leakage_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.fixture(Path(temporary))
            path = directory / 'dataset.json'
            metadata = json.loads(path.read_text())
            metadata['feature_columns'].append('label')
            path.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, 'feature/target'):
                rf.load_dataset(directory)

    def test_hash_and_unknown_target_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.fixture(Path(temporary))
            path = directory / 'train.csv'
            text = path.read_text().replace('fgsm', 'unknown')
            path.write_text(text)
            with self.assertRaisesRegex(ValueError, 'hash'):
                rf.load_dataset(directory)
            metadata_path = directory / 'dataset.json'
            metadata = json.loads(metadata_path.read_text())
            metadata['files']['train']['sha256'] = rf.sha(path)
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, 'Unknown attack_type'):
                rf.load_dataset(directory)

    def test_bounded_train_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            output = root / 'models'
            with patch.object(rf, 'OUTPUT_ROOT', root):
                report = rf.train(root, output)
                self.assertEqual(set(report['results']), set(rf.TASKS))
                self.assertEqual(json.loads((output / 'status.json').read_text())['state'], 'complete')
                self.assertEqual(report['target'], 'attack_type')
                self.assertEqual(report['feature_columns'], list(rf.FEATURES))
                before = (output / 'status.json').read_bytes()
                with self.assertRaises(FileExistsError):
                    rf.train(root, output)
                self.assertEqual((output / 'status.json').read_bytes(), before)
                plan_path = root / 'campaign.json'
                plan = json.loads(plan_path.read_text())
                plan['state'] = 'running'
                plan_path.write_text(json.dumps(plan))
                with self.assertRaisesRegex(ValueError, 'Completed campaign'):
                    rf.train(root, root / 'not-created')
                self.assertFalse((root / 'not-created').exists())

if __name__ == '__main__':
    unittest.main()
