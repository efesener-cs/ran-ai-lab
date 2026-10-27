import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_control import verify
from analyze_experiments import analyze


class ControlOutcomeTests(unittest.TestCase):
    def fixture(self, root, dispatch='', events=''):
        (root / 'raw').mkdir(); (root / 'csv').mkdir()
        (root / 'run_status.json').write_text(json.dumps(dict(
            status='complete', simulation_exit_code=0, ai_control_enabled=True)))
        (root / 'raw/control_dispatch.csv').write_text(
            'sim_time_s,request_id,ue_imsi,from_cell,target_cell,status\n' + dispatch)
        (root / 'raw/control_events.csv').write_text(
            'sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell\n' + events)
        (root / 'csv/ai_shadow_decisions.csv').write_text(
            'decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,recommend_handover\n')

    def test_healthy_zero_submission_is_valid_and_counted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            result = verify(root, require_live=False)
            self.assertTrue(result['infrastructure_valid'])
            self.assertEqual(result['control_outcomes']['outcome'], 'no_submissions')
            self.assertEqual(result['submitted'], 0)
            self.assertIsNone(result['control_outcomes']['confirmation_rate'])

    def test_healthy_all_hold_decisions_are_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            (root / 'csv/ai_shadow_decisions.csv').write_text(
                'decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,hold\n')
            result = verify(root, require_live=False)
            self.assertTrue(result['infrastructure_valid'])
            self.assertEqual(result['control_outcomes']['outcome'], 'no_submissions')

    def test_decision_keys_are_unique_by_time_and_ue_and_cover_postwarmup_window_end(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            (root / 'csv/ue_application_100ms.csv').write_text(
                'window_start_s,window_end_s,ue_imsi,is_warmup\n1.0,1.1,3,0\n1.1,1.2,3,0\n')
            decisions = root / 'csv/ai_shadow_decisions.csv'
            decisions.write_text('decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,hold\n1.2,3,4,hold\n')
            self.assertTrue(verify(root, require_live=False)['infrastructure_valid'])
            decisions.write_text('decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,hold\n')
            self.assertFalse(verify(root, require_live=False)['infrastructure_valid'])
            decisions.write_text('decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,hold\n1.1,3,5,hold\n1.2,3,4,hold\n')
            self.assertFalse(verify(root, require_live=False)['infrastructure_valid'])
            decisions.write_text('decision_time_s,ue_imsi,recommended_cell_id,action\n1.1,3,4,hold\n1.2,3,4,hold\n1.3,3,4,hold\n')
            self.assertFalse(verify(root, require_live=False)['infrastructure_valid'])

    def test_timeout_submission_is_valid_but_unconfirmed_outcome(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, '1.1,1,3,2,4,submitted\n')
            result = verify(root, require_live=False)
            self.assertTrue(result['infrastructure_valid'])
            self.assertFalse(result['passed'])
            self.assertEqual(result['submitted'], 1)
            self.assertEqual(result['confirmed'], 0)
            self.assertEqual(result['control_outcomes']['outcome'], 'some_unconfirmed')
            self.assertEqual(result['requests'][0]['outcome'], 'no_confirmation_event')

    def test_later_confirmation_is_retained_as_timestamped_outcome(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, '1.1,1,3,2,4,submitted\n',
                '1.25,1,3,confirmed_target_connected,2,4,4\n')
            result = verify(root, require_live=False)
            self.assertEqual(result['confirmed'], 1)
            self.assertEqual(result['requests'][0]['confirmation_time_s'], '1.25')
            # Confirmation is an event time and is not relabeled as whole-window application.
            with (root / 'csv/ai_control_decisions.csv').open() as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row['decision_target_connected_confirmed'], '1')
            self.assertEqual(row['decision_confirmation_time_s'], '1.25')

    def test_timeout_event_is_an_unconfirmed_outcome(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, '1.1,1,3,2,4,submitted\n',
                '2.1,1,3,timeout,2,4,0\n')
            result = verify(root, require_live=False)
            self.assertTrue(result['infrastructure_valid'])
            self.assertEqual(result['requests'][0]['outcome'], 'unconfirmed')
            self.assertEqual(result['confirmed'], 0)

    def test_missing_control_evidence_files_are_invalid(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            (root / 'raw/control_dispatch.csv').unlink()
            result = verify(root, require_live=False)
            self.assertFalse(result['infrastructure_valid'])

    def test_malformed_dispatch_status_is_invalid(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, '1.1,1,3,2,4,sent\n')
            result = verify(root, require_live=False)
            self.assertFalse(result['infrastructure_valid'])

    def test_actual_rejection_statuses_are_valid_control_outcomes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = ''.join(f'1.{i},r{i},3,2,4,{status}\n' for i, status in enumerate(
                ['rejected_target', 'rejected_pending', 'rejected_rrc_state', 'already_on_target'], 1))
            self.fixture(root, rows)
            result = verify(root, require_live=False)
            self.assertTrue(result['infrastructure_valid'])
            self.assertEqual(result['rejected'], 4)
            self.assertEqual(result['rejected_by_status'], {
                'already_on_target':1,'rejected_pending':1,'rejected_rrc_state':1,'rejected_target':1})

    def test_event_attached_to_rejected_request_is_malformed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root, '1.1,1,3,2,4,rejected_target\n',
                '1.2,1,3,confirmed_target_connected,2,4,4\n')
            result = verify(root, require_live=False)
            self.assertFalse(result['infrastructure_valid'])
            self.assertTrue(any('non-submitted request' in error for error in result['validation_errors']))

    def test_analysis_keeps_failed_outcome_and_aligns_to_window_start_with_relative_runs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); suite = root / 'suite'; suite.mkdir()
            modes = ['none', 'bias', 'exact']; run_paths = {}
            model_hash = 'model-hash'
            (suite / 'manifest.json').write_text(json.dumps({
                'configuration': {'backend':'native','modes':modes,'seed':7,'run':1,'epsilon':0,
                                  'ues':1,'duration':1},
                'model_sha256':model_hash,
                'runs': {mode:f'runs/{mode}' for mode in modes}, 'events': []}))
            for mode in modes:
                run = suite / 'runs' / mode; run_paths[mode] = run
                (run / 'raw').mkdir(parents=True); (run / 'csv').mkdir()
                (run / 'run_status.json').write_text(json.dumps(dict(
                    status='complete',simulation_exit_code=0,ai_control_enabled=True)))
                dispatch = 'sim_time_s,request_id,ue_imsi,from_cell,target_cell,status\n'
                events = 'sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell\n'
                if mode == 'bias':
                    dispatch += '0.2,req,1,1,2,submitted\n'
                    events += '0.8,req,1,timeout,1,2,0\n'
                (run / 'raw/control_dispatch.csv').write_text(dispatch)
                (run / 'raw/control_events.csv').write_text(events)
                (run / 'csv/ai_shadow_decisions.csv').write_text(
                    'decision_time_s,ue_imsi,recommended_cell_id,action\n' +
                    ''.join(f'{i/10:.1f},1,2,recommend_handover\n' for i in range(2,11)))
                (run / 'csv/ai_shadow_status.json').write_text(json.dumps({'model_sha256':model_hash}))
                audit = ['decision_time_s,ue_imsi,nr_cell_id,event_active,input_perturbed,clean_best_cell,attack_target_cell,clean_prediction_db,observed_prediction_db,raw_sinr_mean_db,model_sinr_mean_db\n']
                audit += [f'0.2,1,{cell},1,0,1,2,10,9,5,5\n' for cell in (1,2)]
                (run / 'csv/ai_shadow_attack_audit.csv').write_text(''.join(audit))
                with (run / 'csv/ue_application_100ms.csv').open('w') as stream:
                    stream.write('window_start_s,window_end_s,ue_imsi,is_warmup,rx_bytes,app_goodput_mbps\n')
                    for i in range(1,11):
                        stream.write(f'{(i-1)/10:.1f},{i/10:.1f},1,{int(i==1)},10,0.01\n')
                with (run / 'csv/adversarial_dataset.csv').open('w') as stream:
                    stream.write('window_end_s,ue_imsi,nr_cell_id\n')
                    for i in range(1,11):
                        for cell in range(1,5): stream.write(f'{i/10:.1f},1,{cell}\n')
            with patch('analyze_experiments.verify', return_value=dict(
                passed=True,targeted_rank_hits=0,targeted_rank_trials=0,action_changes=0,
                executable_command_changes=0,affected_ue_windows=0)), \
                 patch('analyze_experiments.subprocess.run'):
                output = root / 'analysis'
                analyze([suite], output)
            with (output / 'application_dataset.csv').open() as stream:
                rows = list(csv.DictReader(stream))
            by_condition_end = {(r['experiment_condition'],r['window_end_s']):r for r in rows}
            failed_outcome_row = by_condition_end[('bias','0.3')]
            self.assertEqual(failed_outcome_row['prior_decision_time_s'], '0.2')
            self.assertEqual(failed_outcome_row['prior_decision_control_submitted'], '1')
            self.assertEqual(failed_outcome_row['prior_decision_target_connected_confirmed'], '0')
            self.assertEqual(by_condition_end[('bias','0.2')]['aml_input_event_active_same_window'], '1')
            self.assertEqual(failed_outcome_row['aml_input_event_active_same_window'], '0')
            with (output / 'run_summary.csv').open() as stream:
                summaries = list(csv.DictReader(stream))
            bias = next(r for r in summaries if r['experiment_condition']=='bias')
            self.assertEqual(bias['control_submitted'], '1')
            self.assertEqual(bias['control_confirmed'], '0')
            self.assertEqual(bias['control_unconfirmed'], '1')
            self.assertEqual(bias['control_rejected'], '0')
            self.assertEqual(bias['control_outcome'], 'some_unconfirmed')
            self.assertEqual(bias['control_status'], 'not_verified')


if __name__ == '__main__':
    unittest.main()
