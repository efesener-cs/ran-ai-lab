"""Leakage and metric boundary checks for the IP baseline."""
import importlib.util
import unittest

from ai.ip_random_forest import FEATURES,check_splits,scores


class IPBaselineTests(unittest.TestCase):
    def fixture(self):
        return dict(feature_columns=list(FEATURES),target_column='attack_applied',
                    counts={role:{'groups':[group]} for role,group in
                            (('train','seed1'),('validation','seed2'),('test','seed3'))})

    def test_attack_audit_columns_cannot_become_features(self):
        split=self.fixture();split['feature_columns'].append('attack_tx_packets')
        with self.assertRaisesRegex(ValueError,'whitelist'):
            check_splits(split)

    def test_shared_seed_between_train_and_test_rejected(self):
        split=self.fixture();split['counts']['test']['groups']=['seed1']
        with self.assertRaisesRegex(ValueError,'leakage'):
            check_splits(split)

    @unittest.skipUnless(importlib.util.find_spec('sklearn'),'scikit-learn not installed in this interpreter')
    def test_false_positive_denominator_uses_negative_examples(self):
        import numpy as np
        metric=scores(np.array([0,0,0,1]),np.array([.1,.2,.8,.9]),.5)
        self.assertEqual(metric['confusion_matrix'],[[2,1],[0,1]])
        self.assertAlmostEqual(metric['false_positive_rate'],1/3)
        self.assertEqual(metric['recall'],1)
        clean=scores(np.array([0,0]),np.array([.1,.2]),.5)
        self.assertIsNone(clean['average_precision'])
        self.assertIsNone(clean['roc_auc'])


if __name__=='__main__':
    unittest.main()
