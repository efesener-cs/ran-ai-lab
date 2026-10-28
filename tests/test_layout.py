"""Exercise relocated CLIs, runtime dependencies, and source fingerprint coverage."""
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from labcore.commands import COMMANDS, command
from labcore.paths import ROOT
from labcore.provenance import source_hashes
from labcore.runtime_bundle import copy_runtime
from tests.fixtures.telemetry import write_telemetry


class LayoutTests(unittest.TestCase):
    def test_every_command_provides_help_from_an_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', MPLCONFIGDIR=folder)
            for name in COMMANDS:
                with self.subTest(command=name):
                    result = subprocess.run([*command(name), '--help'], cwd=folder,
                                            env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('usage:', result.stdout)

    def test_copied_runtime_runs_its_own_entrypoints_without_models_or_host_imports(self):
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder) / 'runtime'
            copy_runtime(ROOT, bundle)
            self.assertTrue((bundle / 'scenario/source.py').is_file())
            self.assertFalse(list((bundle / 'scenario').glob('*.cc')))
            self.assertFalse((bundle / 'ai/artifacts').exists())
            self.assertFalse(any(bundle.rglob('__pycache__')))
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            environment.pop('PYTHONPATH', None)
            for name in ['container_run', 'shadow_stream', 'export_dataset', 'check_control']:
                with self.subTest(command=name):
                    result = subprocess.run([*command(name, bundle), '--help'], cwd=folder,
                                            env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_training_cli_preserves_independent_split_and_output_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, seed in [('train', 11), ('validation', 23), ('test', 37)]:
                run = write_telemetry(root / name, ues=4, windows=14)
                status_file = run / 'run_status.json'
                status = json.loads(status_file.read_text())
                status['configuration']['seed'] = seed
                status_file.write_text(json.dumps(status))
            output = root / 'model'
            result = subprocess.run([
                *command('train_ai'), '--run-dir', str(root / 'train'),
                '--validation-run-dir', str(root / 'validation'),
                '--test-run-dir', str(root / 'test'), '--alpha-grid', '0.1', '1',
                '--output', str(output),
            ], cwd=folder, capture_output=True, text=True,
               env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((output / 'evaluation.json').read_text())
            self.assertTrue(report['independent_run_validation'])
            self.assertEqual(report['training_sources'][0]['seed'], 11)
            self.assertEqual(report['validation_sources'][0]['seed'], 23)
            self.assertEqual(report['test_sources'][0]['seed'], 37)
            self.assertTrue((output / 'model.json').is_file())
            self.assertTrue((output / 'test_predictions.csv').is_file())

    def test_fingerprints_cover_relocated_runtime_and_synthetic_test_sources(self):
        hashes = source_hashes(ROOT)
        for name in ['simulation/build_live.py', 'simulation/collect_campaign.py',
                     'ai/shadow_stream.py', 'scenario/source.py',
                     'datasets/export_dataset.py', 'checks/check_control.py',
                     'analysis/analyze_experiments.py', 'tests/fixtures/telemetry.py']:
            self.assertIn(name, hashes)
        self.assertFalse(any('/artifacts/' in name or name.startswith('results/') for name in hashes))


if __name__ == '__main__':
    unittest.main()
