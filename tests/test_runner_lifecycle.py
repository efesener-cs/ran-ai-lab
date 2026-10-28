"""Runner contracts without Docker, ns-3, or saved experiment artifacts."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from labcore.native_runner import write_status
import run_controlled
import run_live


class RunnerLifecycleTests(unittest.TestCase):
    def test_imports_do_not_parse_arguments_or_start_processes(self):
        with patch.object(sys, 'argv', ['runner', '--invalid-import-argument']), \
                patch('argparse.ArgumentParser.parse_args', side_effect=AssertionError('parsed')), \
                patch('argparse.ArgumentParser.parse_known_args', side_effect=AssertionError('parsed')), \
                patch('subprocess.run', side_effect=AssertionError('started')), \
                patch('subprocess.Popen', side_effect=AssertionError('started')), \
                patch('subprocess.check_output', side_effect=AssertionError('started')), \
                patch('subprocess.call', side_effect=AssertionError('started')), \
                patch.object(Path, 'mkdir', side_effect=AssertionError('created directory')), \
                patch.object(Path, 'write_text', side_effect=AssertionError('wrote file')):
            for name in ['run_live', 'run_controlled', 'run_experiment']:
                importlib.reload(importlib.import_module(name))

    def test_failed_status_publication_preserves_previous_document(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write_status(root, {'status': 'running'})
            with patch.object(Path, 'replace', side_effect=OSError('publish failed')):
                with self.assertRaisesRegex(OSError, 'publish failed'):
                    write_status(root, {'status': 'complete'})
            self.assertEqual(json.loads((root / 'run_status.json').read_text()),
                             {'status': 'running'})
            self.assertEqual([p.name for p in root.iterdir()], ['run_status.json'])

    def test_native_failure_records_status_and_stops_controller(self):
        controller = Mock()
        controller.poll.return_value = None
        failure = subprocess.CalledProcessError(1, ['fake-simulation'])
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'run'
            with patch.object(run_controlled.subprocess, 'Popen', return_value=controller), \
                    patch.object(run_controlled, 'run_simulation', side_effect=failure), \
                    patch.object(run_controlled, 'export_run') as export, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError):
                    run_controlled.main(['--output', str(output)])
            status = json.loads((output / 'run_status.json').read_text())
            self.assertEqual(status['status'], 'failed')
            self.assertIn('error', status)
            self.assertNotIn('ai_control_verified_native', status)
            controller.terminate.assert_called_once()
            controller.wait.assert_called_once_with(timeout=5)
            export.assert_not_called()

    def test_healthy_native_run_without_submission_is_not_verified(self):
        controller = Mock()
        controller.wait.return_value = 0
        controller.poll.return_value = 0
        evidence = dict(infrastructure_valid=True, control_outcomes={}, submitted=0, confirmed=0)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'run'
            with patch.object(run_controlled.subprocess, 'Popen', return_value=controller), \
                    patch.object(run_controlled, 'run_simulation'), \
                    patch.object(run_controlled, 'export_run'), \
                    patch('check_control.verify', return_value=evidence), \
                    contextlib.redirect_stdout(io.StringIO()):
                run_controlled.main(['--output', str(output)])
            status = json.loads((output / 'run_status.json').read_text())
            self.assertEqual(status['status'], 'complete')
            self.assertTrue(status['ai_control_infrastructure_valid'])
            self.assertFalse(status['ai_control_verified_native'])
            self.assertTrue((output / 'raw' / 'ai_shadow.stop').exists())

    def test_live_failure_still_copies_diagnostics_and_preserves_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'live-test'
            with patch.object(run_live, 'prepare_container'), \
                    patch.object(run_live.subprocess, 'call', side_effect=[7, 0]) as call, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    run_live.main(['--output', str(output), '--duration', '3'])
            self.assertEqual(raised.exception.code, 7)
            self.assertEqual(call.call_args_list[-1].args[0], [
                'docker', 'cp', 'flexric:/tmp/ran-ai-live-test/result/.', str(output)])
            self.assertIn('--duration', call.call_args_list[0].args[0])

    def test_live_validation_rejects_control_without_model_before_docker(self):
        with patch.object(run_live, 'prepare_container') as prepare, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                run_live.main(['--apply-ai-control'])
            self.assertEqual(raised.exception.code, 2)
            prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
