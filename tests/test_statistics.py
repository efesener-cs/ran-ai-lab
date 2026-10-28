import csv
from pathlib import Path
import tempfile
import unittest

from analysis.summarize_campaign import load_rows, summarize, write_outputs


FIELDS = ['suite_id', 'backend', 'experiment_seed', 'experiment_condition',
          'ues', 'duration_s', 'epsilon_db', 'rx_bytes', 'model_sha256',
          'control_submitted', 'control_confirmed', 'robust_budget_db', 'attack_access',
          'defense', 'experiment_run', 'experiment_pipeline_sha256']


def row(suite, backend, seed, condition, rx, epsilon=1, model='same-model',
        access='two_cell', budget='off', defense='none', run='1', pipeline='pipe-a'):
    return dict(suite_id=suite, backend=backend, experiment_seed=str(seed),
                experiment_condition=condition, ues='12', duration_s='10',
                epsilon_db=str(epsilon), rx_bytes=str(rx), model_sha256=model,
                control_submitted='4', control_confirmed='3', attack_access=access,
                robust_budget_db=budget, defense=defense, experiment_run=str(run),
                experiment_pipeline_sha256=pipeline)


class CampaignStatisticsTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row('s1-e1', 'native', 7, 'none', 100),
            row('s1-e1', 'native', 7, 'fgsm', 90),
            row('s1-e2', 'native', 7, 'none', 200),
            row('s1-e2', 'native', 7, 'fgsm', 220),
            row('s2-e1', 'native', 19, 'none', 100),
            row('s2-e1', 'native', 19, 'fgsm', 110),
            row('live-s1', 'live', 7, 'none', 100),
            row('live-s1', 'live', 7, 'fgsm', 105),
        ]

    def test_pairing_seed_aggregation_and_backend_separation(self):
        paired, result = summarize(self.rows, bootstrap_seed=4, resamples=200)
        self.assertEqual(len(paired), 4)
        native_e1 = next(x for x in result['comparisons']
                         if x['backend'] == 'native' and x['epsilon_db'] == 1.0)
        self.assertEqual(native_e1['independent_seed_clusters'], 2)
        # Seed 7 contributes mean(-10%, +10%) = 0%; seed 19 contributes +10%.
        self.assertAlmostEqual(native_e1['mean_paired_rx_delta_percent'], 5.0)
        self.assertEqual(native_e1['paired_suite_count'], 3)
        live = next(x for x in result['comparisons'] if x['backend'] == 'live')
        self.assertEqual(live['independent_seed_clusters'], 1)
        self.assertIsNone(live['bootstrap_ci_95_percent'])

    def test_zero_effect_has_zero_interval(self):
        rows = [row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'fgsm', 100),
                row('b', 'native', 2, 'none', 300), row('b', 'native', 2, 'fgsm', 300)]
        _, result = summarize(rows, resamples=200)
        comp = result['comparisons'][0]
        self.assertEqual(comp['mean_paired_rx_delta_percent'], 0)
        self.assertEqual(comp['bootstrap_ci_95_percent'], [0.0, 0.0])

    def test_insufficient_independent_seeds_explicit(self):
        rows = [row('a', 'native', 3, 'none', 100), row('a', 'native', 3, 'fgsm', 80),
                row('b', 'native', 3, 'none', 100), row('b', 'native', 3, 'fgsm', 90)]
        _, result = summarize(rows, resamples=100)
        comp = result['comparisons'][0]
        self.assertEqual(comp['independent_seed_clusters'], 1)
        self.assertIsNone(comp['bootstrap_ci_95_percent'])
        self.assertEqual(comp['status'], 'insufficient_independent_seeds')
        self.assertTrue(comp['warnings'])

    def test_missing_clean_duplicate_and_zero_denominator_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing matching clean'):
            summarize([row('a', 'native', 1, 'fgsm', 80)])
        with self.assertRaisesRegex(ValueError, 'Duplicate suite/condition'):
            summarize([row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'none', 100)])
        with self.assertRaisesRegex(ValueError, 'Zero clean RX'):
            summarize([row('a', 'native', 1, 'none', 0), row('a', 'native', 1, 'fgsm', 10)])

    def test_incompatible_models_and_failed_unconfirmed_counts(self):
        rows = [row('a', 'native', 1, 'none', 100, model='m1'),
                row('a', 'native', 1, 'fgsm', 90, model='m2')]
        with self.assertRaisesRegex(ValueError, 'Incompatible model hashes'):
            summarize(rows)
        rows = [row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'fgsm', 90)]
        _, result = summarize(rows)
        self.assertEqual(result['comparisons'][0]['unconfirmed_controls'], 1)

    def test_access_budget_defense_and_legacy_defaults_are_separate(self):
        rows = [row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'fgsm', 90),
                row('b', 'native', 2, 'none', 100, access='target_only', budget='0'),
                row('b', 'native', 2, 'fgsm', 90, access='target_only', budget='0'),
                row('c', 'native', 3, 'none', 100, access='target_only', budget='off', defense='robust'),
                row('c', 'native', 3, 'fgsm', 90, access='target_only', budget='off', defense='robust')]
        _, result = summarize(rows, resamples=50)
        self.assertEqual(len(result['comparisons']), 3)
        self.assertEqual({x['attack_access'] for x in result['comparisons']}, {'two_cell', 'target_only'})
        self.assertEqual({x['robust_budget_db'] for x in result['comparisons']}, {'off', '0'})
        self.assertEqual({x['defense'] for x in result['comparisons']}, {'none', 'robust'})

    def test_pair_seed_and_run_mismatches_and_direct_invalid_values_rejected(self):
        rows = [row('a', 'native', 1, 'none', 100), row('a', 'native', 2, 'fgsm', 90)]
        with self.assertRaisesRegex(ValueError, 'seed mismatch'):
            summarize(rows)
        rows = [row('a', 'native', 1, 'none', 100, run='1'),
                row('a', 'native', 1, 'fgsm', 90, run='2')]
        with self.assertRaisesRegex(ValueError, 'run mismatch'):
            summarize(rows)
        for bad_rx in ('1.5', '-1', 'nan'):
            bad = [row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'fgsm', bad_rx)]
            with self.subTest(rx=bad_rx), self.assertRaisesRegex(ValueError, 'rx_bytes'):
                summarize(bad)

    def test_count_validation_and_unknown_aggregate_remains_null(self):
        rows = [row('a', 'native', 1, 'none', 100), row('a', 'native', 1, 'fgsm', 90),
                row('b', 'native', 2, 'none', 100), row('b', 'native', 2, 'fgsm', 90)]
        rows[1]['control_confirmed'] = ''
        _, result = summarize(rows, resamples=50)
        self.assertIsNone(result['comparisons'][0]['unconfirmed_controls'])
        rows[1]['control_submitted'] = '1.5'
        with self.assertRaisesRegex(ValueError, 'control_submitted'):
            summarize(rows)
        rows[1]['control_submitted'] = '2'
        rows[1]['control_confirmed'] = '3'
        with self.assertRaisesRegex(ValueError, 'cannot exceed'):
            summarize(rows)

    def test_pipeline_fingerprints_are_separate_and_legacy_defaults_unrecorded(self):
        rows = [row('a', 'native', 1, 'none', 100, pipeline='pipeline-a'),
                row('a', 'native', 1, 'fgsm', 90, pipeline='pipeline-a'),
                row('b', 'native', 2, 'none', 100, pipeline='pipeline-b'),
                row('b', 'native', 2, 'fgsm', 80, pipeline='pipeline-b')]
        paired, result = summarize(rows, resamples=50)
        self.assertEqual({r['experiment_pipeline_sha256'] for r in paired},
                         {'pipeline-a', 'pipeline-b'})
        self.assertEqual(len(result['comparisons']), 2)
        self.assertEqual({r['independent_seed_clusters'] for r in result['comparisons']}, {1})
        legacy = [dict(r) for r in rows]
        for r in legacy:
            r.pop('experiment_pipeline_sha256')
        paired, result = summarize(legacy, resamples=50)
        self.assertEqual({r['experiment_pipeline_sha256'] for r in paired}, {'unrecorded'})
        self.assertEqual(len(result['comparisons']), 1)

    def test_cli_writes_all_outputs_with_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'run_summary.csv'
            with source.open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows([row('a', 'native', 1, 'none', 100),
                                  row('a', 'native', 1, 'fgsm', 90),
                                  row('b', 'native', 2, 'none', 100),
                                  row('b', 'native', 2, 'fgsm', 90)])
            output = Path(temp) / 'summary'
            result = write_outputs(source, output)
            self.assertEqual(result['resamples'], 2000)
            self.assertTrue((output / 'paired_effects.csv').is_file())
            self.assertTrue((output / 'statistics.json').is_file())
            self.assertTrue((output / 'summary.md').is_file())
            with (output / 'paired_effects.csv').open() as stream:
                output_rows = list(csv.DictReader(stream))
                self.assertEqual(len(output_rows), 2)
                self.assertEqual({r['experiment_pipeline_sha256'] for r in output_rows}, {'pipe-a'})
            markdown = (output / 'summary.md').read_text()
            self.assertIn('Pipeline SHA256', markdown)


if __name__ == '__main__':
    unittest.main()
