import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from checks.check_control import verify


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



if __name__ == '__main__':
    unittest.main()
