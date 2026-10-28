import csv
import json
from pathlib import Path
import tempfile
import unittest

from ai.data import load_observations, supervised
from ai.runtime import RuntimeForecaster
from ai.evaluate_replay import replay_metrics, split_check, write_results


FIXTURE = Path(__file__).resolve().parents[1] / 'tests/fixtures/model.json'


def write_run(root, backend='native', seed=29):
    root.mkdir(parents=True)
    status = dict(status='complete', simulation_exit_code=0, live_ric_verified=False,
                  ai_control_enabled=True,
                  control_transport='atomic CSV to ns-3 RRC API; no E2 RC',
                  configuration=dict(seed=seed, run=1))
    (root / 'run_status.json').write_text(json.dumps(status))
    (root / 'csv').mkdir()
    fields = ['run_id', 'window_start_s', 'window_end_s', 'ue_imsi', 'nr_cell_id',
              'sinr_mean_db', 'sinr_last_db', 'sinr_std_db', 'cell_dl_corrupt_fraction',
              'cell_dl_tb_count', 'ue_is_warmup', 'ue_nr_rrc_cell_id',
              'last_recorded_path_cell_id', 'attack_present']
    values = {1: [10, 10, 8, 9], 2: [8, 12, 13, 12]}
    with (root / 'csv/ran_features_100ms.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for cell, series in values.items():
            for tick, current in enumerate(series):
                writer.writerow(dict(run_id=root.name, window_start_s=tick / 10,
                    window_end_s=(tick + 1) / 10, ue_imsi=1, nr_cell_id=cell,
                    sinr_mean_db=current, sinr_last_db=current + .1, sinr_std_db=.5,
                    cell_dl_corrupt_fraction=.01, cell_dl_tb_count=10,
                    ue_is_warmup='0', ue_nr_rrc_cell_id=1,
                    last_recorded_path_cell_id=1, attack_present='0'))


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.model = RuntimeForecaster.load(FIXTURE)

    def test_clean_targets_stay_fixed_and_persistence_uses_attacked_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'native-run'
            write_run(root)
            observations, _ = load_observations(root, allow_native=True)
            samples = supervised(observations)
            original = json.dumps(samples, sort_keys=True)
            clean = replay_metrics(samples, observations, self.model, 'none', 2, 'two_cell')
            attacked = replay_metrics(samples, observations, self.model, 'exact', 2, 'two_cell')
            self.assertEqual(json.dumps(samples, sort_keys=True), original)
            self.assertTrue(all(s['target'] == supervised(observations)[i]['target']
                                for i, s in enumerate(samples)))
            self.assertNotEqual(clean['forecast_mae_db'], attacked['forecast_mae_db'])
            self.assertEqual(clean['clean_target_sha256'], attacked['clean_target_sha256'])
            self.assertEqual(clean['network_actions_applied'], 0)
            self.assertIn('robust_recommendation_count', attacked)
            self.assertIsNotNone(clean['clean_mode_robust_utility_cost_recommendations'])
            persistence = RuntimeForecaster.load(FIXTURE)
            from ai.baselines import persistence_parameters
            persistence = RuntimeForecaster(persistence_parameters(persistence.parameters))
            persist_clean = replay_metrics(samples, observations, persistence, 'none', 2, 'two_cell')
            persist_attack = replay_metrics(samples, observations, persistence, 'exact', 2, 'two_cell')
            self.assertNotEqual(persist_clean['forecast_mae_db'], persist_attack['forecast_mae_db'])
            robust = replay_metrics(samples, observations, self.model, 'none', 2, 'two_cell',
                                    robust_budget_db=.5)
            self.assertEqual(robust['robust_budget_db'], .5)
            self.assertGreaterEqual(robust['robust_blocked_recommendation_count'], 0)

    def test_native_is_explicit_opt_in_and_backend_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'native-run'
            write_run(root)
            with self.assertRaisesRegex(ValueError, 'live-E2-verified'):
                load_observations(root)
            _, metadata = load_observations(root, allow_native=True)
            self.assertEqual(metadata['backend'], 'native')
            status = json.loads((root / 'run_status.json').read_text())
            status['control_transport'] = 'none'
            (root / 'run_status.json').write_text(json.dumps(status))
            with self.assertRaisesRegex(ValueError, 'native runs require'):
                load_observations(root, allow_native=True)
            status['control_transport'] = 'atomic CSV to ns-3 RRC API; no E2 RC'
            status['simulation_exit_code'] = 2
            (root / 'run_status.json').write_text(json.dumps(status))
            with self.assertRaisesRegex(ValueError, 'simulation exit code zero'):
                load_observations(root, allow_native=True)

    def test_training_seed_leakage_rejected_and_missing_provenance_explicit(self):
        source = dict(run_id='eval-run', root='/tmp/eval-run', sha256='eval-hash',
                      seed=7, configuration={'seed': 7})
        self.assertFalse(split_check(self.model, [source], allow_unverified=True)['verified'])
        with self.assertRaisesRegex(ValueError, 'Duplicate replay evaluation source'):
            split_check(self.model, [source, source], allow_unverified=True)
        with self.assertRaisesRegex(ValueError, 'no training provenance'):
            split_check(self.model, [source])
        parameters = dict(self.model.parameters)
        parameters['training_provenance'] = {'sources': [dict(run_id='train-run',
            root='/tmp/train-run', sha256='train-hash', seed=7, configuration={'seed': 7})]}
        trained = RuntimeForecaster(parameters)
        with self.assertRaisesRegex(ValueError, 'share simulation seed'):
            split_check(trained, [source])
        parameters['training_provenance'] = {
            'sources': [dict(run_id='train-run', root='/tmp/train-run', sha256='train-hash',
                             seed=1, configuration={'seed': 1})],
            'validation_sources': [dict(run_id='validation-run', root='/tmp/validation-run',
                sha256='validation-hash', seed=7, configuration={'seed': 7})],
        }
        selected_trained = RuntimeForecaster(parameters)
        with self.assertRaisesRegex(ValueError, 'share simulation seed'):
            split_check(selected_trained, [source])

    def test_output_states_no_qos_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'out'
            result = [dict(run_id='r', experiment_seed=1, predictor='ridge', mode='none',
                           network_actions_applied=0,
                           recommendation_actions={'hold': 2, 'recommend_handover': 1},
                           recommendation_reasons={'hysteresis_or_same_cell': 2})]
            write_results(result, {'verified': False}, output, 'hash',
                          ['No QoS or throughput effect is measured.'])
            payload = json.loads((output / 'replay_metrics.json').read_text())
            self.assertIn('No QoS', payload['limitations'][0])
            with (output / 'replay_metrics.csv').open() as stream:
                row = next(csv.DictReader(stream))
                self.assertEqual(row['network_actions_applied'], '0')
                self.assertEqual(json.loads(row['recommendation_actions']),
                                 {'hold': 2, 'recommend_handover': 1})


if __name__ == '__main__':
    unittest.main()
