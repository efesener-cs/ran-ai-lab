"""Packaging fixtures only: no model fitting, RF generation, ns-3 or Docker."""
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from checks.check_kaggle_structure import SPEC, relative_file, verify


class KaggleStructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = json.loads(SPEC.read_text())
        for name in self.spec['release_gate']['required_artifacts']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Fixture, not a scientific release.\n')
        self.write_json('dataset-metadata.json', {
            'title': 'Fixture dataset', 'id': 'fixture/structural-check',
            'licenses': [{'name': 'fixture-license-not-for-release'}]})
        self.rows = {name: [] for name in self.spec['tables']}
        for i in range(3):
            sample = self.row('rf_samples', sample_id=f's{i}', source_group_id=f'g{i}',
                              source_frame_id=str(i), task='sensing', context_id='id')
            observation = self.row('rf_observations', observation_id=f'o{i}', sample_id=f's{i}',
                                   source_group_id=f'g{i}', task='sensing', sample_role='clean',
                                   attack_applied='0', input_changed='0', attack_method='none',
                                   victim_model_id='', context_id='id')
            self.rows['rf_samples'].append(sample)
            self.rows['rf_observations'].append(observation)
        self.split = {
            'benchmark_track': 'fixture_id', 'table': 'rf_observations',
            'train_group_ids': ['g0'], 'validation_group_ids': ['g1'], 'test_group_ids': ['g2'],
            'train_context_allowlist': ['id'], 'validation_context_allowlist': ['id'],
            'test_context_allowlist': ['id'], 'sampling_policy': 'unsampled_fixture',
            'feature_columns': self.spec['tables']['rf_observations']['feature_columns'],
            'target_columns': ['attack_applied']}
        self.publish()

    def row(self, table, **values):
        rule = self.spec['tables'][table]
        columns = list(dict.fromkeys(rule['required_columns'] + rule['feature_columns']))
        row = {col: '0' for col in columns}
        row.update(values)
        return row

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def hashes(self):
        files = sorted(p for p in self.root.rglob('*') if p.is_file() and p.name != 'checksums.sha256')
        (self.root / 'checksums.sha256').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(self.root).as_posix() + '\n'
            for p in files))

    def publish(self):
        index = {'schema_version': self.spec['schema_version'], 'tables': {},
                 'split_manifests': ['splits/id.json']}
        for name, rows in self.rows.items():
            rule = self.spec['tables'][name]
            columns = list(dict.fromkeys(rule['required_columns'] + rule['feature_columns'] +
                                        [key for row in rows for key in row]))
            with (self.root / (name + '.csv')).open('w', newline='') as handle:
                writer = csv.DictWriter(handle, fieldnames=columns)
                writer.writeheader()
                writer.writerows(rows)
            index['tables'][name] = {'paths': [name + '.csv'], 'rows': len(rows)}
        self.write_json('splits/id.json', self.split)
        self.write_json('package-index.json', index)
        self.hashes()

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            verify(self.root)

    def test_valid_structure_does_not_claim_scientific_verification(self):
        result = verify(self.root)
        self.assertTrue(result['structural_verified'])
        self.assertFalse(result['scientific_verified'])
        self.assertEqual(result['tables']['rf_observations'], 3)

    def test_modified_file_rejected(self):
        (self.root / 'README.md').write_text('tampered')
        self.reject('Checksum mismatch')

    def test_unlisted_extra_file_rejected(self):
        (self.root / 'unlisted.txt').write_text('extra')
        self.reject('inventory')

    def test_duplicate_primary_key_across_shards_rejected(self):
        index = json.loads((self.root / 'package-index.json').read_text())
        (self.root / 'extra.csv').write_bytes((self.root / 'rf_samples.csv').read_bytes())
        index['tables']['rf_samples']['paths'].append('extra.csv')
        index['tables']['rf_samples']['rows'] *= 2
        self.write_json('package-index.json', index)
        self.hashes()
        self.reject('Duplicate primary key')

    def test_unknown_sample_reference_rejected(self):
        self.rows['rf_observations'][0]['sample_id'] = 'absent'
        self.publish()
        self.reject('Unresolved foreign key')

    def test_relabeling_source_group_cannot_hide_variant_leakage(self):
        self.rows['rf_observations'][0]['source_group_id'] = 'g1'
        self.publish()
        self.reject('changed source group')

    def test_empty_split_rejected(self):
        self.split['test_group_ids'] = []
        self.publish()
        self.reject('Invalid/duplicate split groups')

    def test_split_group_leakage_rejected(self):
        self.split['test_group_ids'] = ['g0']
        self.publish()
        self.reject('group leakage')

    def test_unknown_split_group_rejected(self):
        self.split['test_group_ids'] = ['absent']
        self.publish()
        self.reject('Unknown group')

    def test_context_mismatch_rejected(self):
        self.split['test_context_allowlist'] = ['ood']
        self.publish()
        self.reject('context outside')

    def test_ood_overlap_rejected(self):
        self.split['heldout_ood'] = True
        self.publish()
        self.reject('OOD context overlaps')

    def test_audit_feature_leakage_rejected(self):
        self.split['feature_columns'] = ['attack_success']
        self.publish()
        self.reject('whitelist mismatch')

    def test_nonfinite_feature_rejected(self):
        self.rows['rf_observations'][0]['mean_i'] = 'nan'
        self.publish()
        self.reject('Nonfinite feature')

    def test_false_count_rejected(self):
        index = json.loads((self.root / 'package-index.json').read_text())
        index['tables']['rf_samples']['rows'] = 99
        self.write_json('package-index.json', index)
        self.hashes()
        self.reject('Row count mismatch')

    def test_paths_and_symlinks_rejected(self):
        for name in ('../outside', '/etc/passwd', 'a/../b', './README.md', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                relative_file(self.root, name)
        (self.root / 'link').symlink_to(self.root / 'README.md')
        self.reject('Symlink')


if __name__ == '__main__':
    unittest.main()
