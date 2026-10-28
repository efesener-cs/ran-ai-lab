"""Synthetic checks for independent run split validation."""
import unittest

import numpy as np

from ai.train import select_alpha, validate_run_split, validate_sources


def source(name, digest, seed):
    return {'run_id': name, 'root': '/synthetic/' + name, 'sha256': digest,
            'configuration': {'seed': seed, 'scenario': {'cells': 3}}}


class RunSplitValidationTests(unittest.TestCase):
    def test_disjoint_sources_and_seeds_are_accepted(self):
        result = validate_run_split([source('train-a', 'hash-a', 1)],
                                    [source('test-b', 'hash-b', 2)])
        self.assertEqual(result['training_seeds'], ['1'])
        self.assertEqual(result['test_seeds'], ['2'])

    def test_same_seed_within_training_sources_is_allowed(self):
        inventory = validate_sources([source('train-a', 'hash-a', 1),
                                      source('train-b', 'hash-b', 1)],
                                     'training', require_seed=True)
        self.assertEqual(inventory['seeds'], {'1'})

    def test_duplicate_training_source_is_rejected(self):
        item = source('train-a', 'hash-a', 1)
        with self.assertRaisesRegex(ValueError, 'Duplicate training'):
            validate_run_split([item, dict(item)], [source('test-b', 'hash-b', 2)])

    def test_duplicate_test_source_is_rejected(self):
        item = source('test-a', 'hash-a', 2)
        with self.assertRaisesRegex(ValueError, 'Duplicate test'):
            validate_run_split([source('train-a', 'hash-train', 1)], [item, dict(item)])

    def test_default_split_inventory_rejects_duplicate_sources(self):
        item = source('train-a', 'hash-a', 1)
        with self.assertRaisesRegex(ValueError, 'Duplicate training'):
            validate_sources([item, dict(item)], 'training')

    def test_content_hash_overlap_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'identical CSV content'):
            validate_run_split([source('train-a', 'same', 1)],
                               [source('renamed-test', 'same', 2)])

    def test_same_seed_with_different_names_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'share simulation seed'):
            validate_run_split([source('train-a', 'hash-a', 9)],
                               [source('renamed-test', 'hash-b', 9)])

    def test_numeric_seed_aliases_are_canonicalized(self):
        with self.assertRaisesRegex(ValueError, 'share simulation seed'):
            validate_run_split([source('train-a', 'hash-a', '07')],
                               [source('test-b', 'hash-b', 7)])

    def test_same_run_or_root_with_different_hash_is_rejected_cross_split(self):
        train = source('shared-run', 'hash-a', 1)
        test = source('shared-run', 'hash-b', 2)
        test['root'] = '/synthetic/renamed-root'
        with self.assertRaisesRegex(ValueError, 'same run or source root'):
            validate_run_split([train], [test])

    def test_shared_root_with_different_run_and_hash_is_rejected(self):
        train = source('train-run', 'hash-a', 1)
        test = source('test-run', 'hash-b', 2)
        test['root'] = train['root']
        with self.assertRaisesRegex(ValueError, 'same run or source root'):
            validate_run_split([train], [test])

    def test_missing_seed_is_rejected_for_independent_validation(self):
        unseeded = {'run_id': 'test', 'root': '/synthetic/test', 'sha256': 'b',
                    'configuration': {}}
        with self.assertRaisesRegex(ValueError, 'requires a recorded seed'):
            validate_run_split([source('train', 'a', 1)], [unseeded])

    def test_missing_content_hash_is_rejected_for_independent_validation(self):
        unhashed = source('test', '', 2)
        with self.assertRaisesRegex(ValueError, 'requires run_id, root, and content hash'):
            validate_run_split([source('train', 'a', 1)], [unhashed])

    def test_validation_source_overlap_with_test_is_rejected(self):
        train = source('train', 'train-hash', 1)
        validation = source('validation-test', 'validation-hash', 2)
        test = dict(validation, sha256='different-hash')
        with self.assertRaisesRegex(ValueError, 'same run or source root'):
            validate_run_split([train, validation], [test])


def synthetic_samples(seed=5, count=80):
    rng = np.random.default_rng(seed)
    samples=[]
    for index in range(count):
        features=rng.normal(size=8).tolist()
        current=float(rng.normal())
        target=current+0.7*features[0]-0.25*features[2]+float(rng.normal(scale=0.2))
        samples.append(dict(features=features,current=current,target=target))
    return samples


class AlphaSelectionTests(unittest.TestCase):
    def test_selects_candidate_with_lowest_validation_mae(self):
        selected, details=select_alpha(synthetic_samples(),synthetic_samples(19, 30),[100,0.1,1])
        best=min(details['candidates'],key=lambda item:(item['validation_mae_db'],item['alpha']))
        self.assertEqual(selected,best['alpha'])
        self.assertEqual(details['selected_alpha'],selected)
        self.assertEqual(details['validation_sample_count'],30)

    def test_mae_ties_choose_smallest_alpha(self):
        samples=[dict(features=[0.0]*8,current=2.0,target=2.0) for _ in range(24)]
        selected,details=select_alpha(samples,samples[:4],[10,0.1,1])
        self.assertEqual(selected,0.1)
        self.assertEqual(len({row['validation_mae_db'] for row in details['candidates']}),1)

    def test_alpha_selection_requires_nonempty_validation_and_valid_grid(self):
        samples=synthetic_samples()
        with self.assertRaisesRegex(ValueError,'nonempty training and validation'):
            select_alpha(samples,[],[1])
        with self.assertRaisesRegex(ValueError,'finite and positive'):
            select_alpha(samples,samples[:4],[0,-1])


if __name__ == '__main__':
    unittest.main()
