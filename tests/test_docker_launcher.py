"""Optional Docker launcher contracts; no daemon or simulator required."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from labcore.paths import ROOT
from labcore.runtime_bundle import copy_runtime
import simulation.run_docker as runner

class DockerLauncherTests(unittest.TestCase):
    def test_runtime_bundle_help_works_without_original_checkout(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            copy_runtime(ROOT, root)
            result = subprocess.run([sys.executable, str(root / 'lab.py'), 'run_live', '--help'],
                                    cwd=folder, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--scenario', result.stdout)
            self.assertFalse((root / 'ai/artifacts').exists())

    def test_failed_container_run_still_retrieves_results(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'input.cc'
            source.write_text('int main() { return 0; }\n')
            output = root / 'docker-run'
            with patch.object(runner, 'prepare_container') as prepare, \
                    patch.object(runner.subprocess, 'call', side_effect=[7, 0]) as call, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    runner.main(['--scenario', str(source), '--output', str(output)])
            self.assertEqual(raised.exception.code, 7)
            prepare.assert_called_once()
            command = call.call_args_list[0].args[0]
            self.assertEqual(command[:3], ['docker', 'exec', 'flexric'])
            self.assertIn('run_live', command)
            self.assertIn('/tmp/ran-ai-docker-run/result', command)
            self.assertEqual(call.call_args_list[1].args[0][:2], ['docker', 'cp'])
            self.assertTrue(output.is_dir())

    def test_preparation_copies_exact_external_source_and_forwards_remote_path(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.cc'
            source.write_bytes(b'// supplied source\nint main() { return 0; }\n')
            args, extra = runner.parse_args(['--scenario', str(source)])
            with patch.object(runner.subprocess, 'check_output', side_effect=['true', '[]']), \
                    patch.object(runner.subprocess, 'run'), \
                    patch.object(runner, 'copy_to_container') as copy:
                runner.prepare_container(ROOT, args, '/tmp/test-lab', extra)
            self.assertIn(unittest.mock.call('flexric', source, '/tmp/test-lab/scenario.cc'), copy.call_args_list)
            self.assertEqual(extra, ['--scenario', '/tmp/test-lab/scenario.cc'])

if __name__ == '__main__':
    unittest.main()
