"""Check external input, exact snapshots, real small C++ builds, and campaign pinning."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from labcore.commands import command
from labcore.paths import ROOT
from scenario.source import build_native, read_source, snapshot_source
from simulation import collect_campaign


FIXTURE = ROOT / 'tests/fixtures/external_scenario.cc'


class ExternalScenarioTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'student scenario.cc'
        shutil.copyfile(FIXTURE, self.source)

    def native_dependencies(self):
        ns3 = self.root / 'synthetic-ns3'
        (ns3 / 'build/lib').mkdir(parents=True)
        (ns3 / 'build/include').mkdir()
        compiler = shutil.which('g++')
        self.assertIsNotNone(compiler, 'The compiler checks require g++')
        result = subprocess.run([compiler, '-shared', '-fPIC',
            str(ROOT / 'tests/fixtures/native_library.cc'), '-o',
            str(ns3 / 'build/lib/libfixture.so')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return ns3

    def test_snapshot_preserves_bytes_and_does_not_rewrite_input(self):
        data = self.source.read_bytes().replace(b'\n', b'\r\n')
        self.source.write_bytes(data)
        selected = snapshot_source(self.source, self.root / 'run')
        self.assertEqual(selected.path.read_bytes(), data)
        self.assertEqual(self.source.read_bytes(), data)
        self.assertEqual(selected.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(selected.origin, str(self.source.resolve()))

    def test_snapshot_rejects_replacing_a_different_source(self):
        selected = snapshot_source(self.source, self.root / 'run')
        before = selected.path.read_bytes()
        self.source.write_bytes(before + b'\n// changed\n')
        with self.assertRaisesRegex(ValueError, 'overwrite a different scenario'):
            snapshot_source(self.source, self.root / 'run')
        self.assertEqual(selected.path.read_bytes(), before)

    def test_missing_empty_and_non_cpp_inputs_are_rejected(self):
        empty = self.root / 'empty.cc'
        empty.touch()
        wrong = self.root / 'scenario.py'
        wrong.write_text('print("not C++")')
        for path in [None, self.root / 'missing.cc', empty, wrong]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                read_source(path)

    def test_cache_uses_selected_source_and_rebuilds_a_tampered_binary(self):
        ns3 = self.native_dependencies()
        builds = self.root / 'builds'
        binary = build_native(self.source, ns3=ns3, build_root=builds)
        good_bytes = binary.read_bytes()
        self.assertEqual(build_native(self.source, ns3=ns3, build_root=builds), binary)
        binary.write_bytes(b'corrupted executable')
        self.assertEqual(build_native(self.source, ns3=ns3, build_root=builds), binary)
        self.assertEqual(binary.read_bytes(), good_bytes)
        self.source.write_bytes(self.source.read_bytes() + b'\n// another scenario revision\n')
        other = build_native(self.source, ns3=ns3, build_root=builds)
        self.assertNotEqual(other, binary)
        metadata = json.loads((other.parent / 'build.json').read_text())
        self.assertEqual(metadata['inputs']['source_sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_generic_cli_builds_and_forwards_only_supplied_arguments(self):
        ns3 = self.native_dependencies()
        output = self.root / 'run'
        before = self.source.read_bytes()
        result = subprocess.run([*command('run_scenario'), '--scenario', str(self.source),
            '--ns3', str(ns3), '--output', str(output), '--', '--label=student', 'value with spaces'],
            cwd=self.root, capture_output=True, text=True,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', RAN_AI_BUILD_ROOT=str(self.root / 'builds')))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / 'raw/simulation.log').read_text(), '--label=student\nvalue with spaces\n')
        status = json.loads((output / 'run_status.json').read_text())
        self.assertEqual(status['status'], 'complete')
        self.assertFalse(status['live_ric_verified'])
        self.assertEqual(status['scenario']['sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual((output / 'scenario.cc').read_bytes(), before)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse((output / 'csv').exists())

    def test_campaign_pins_the_scenario_and_passes_its_snapshot_to_suites(self):
        args = collect_campaign.parse_args(['--scenario', str(self.source),
            '--model', str(ROOT / 'tests/fixtures/model.json'), '--backend', 'native',
            '--seeds', '41', '--epsilons', '0', '--modes', 'none'])
        with patch.object(collect_campaign, 'LAB', self.root):
            directory, plan = collect_campaign.create_plan(args)
        selected = Path(plan['scenario'])
        self.assertEqual(selected.read_bytes(), self.source.read_bytes())
        self.source.write_text('int main() { return 12; }\n')
        self.assertNotEqual(selected.read_bytes(), self.source.read_bytes())
        args = collect_campaign.job_command(plan, plan['jobs'][0], directory / 'suite')
        self.assertEqual(args[args.index('--scenario') + 1], str(selected))
        self.assertEqual(plan['scenario_sha256'], hashlib.sha256(selected.read_bytes()).hexdigest())

    def test_resume_rejects_a_changed_snapshot_even_with_code_change_override(self):
        args = collect_campaign.parse_args(['--scenario', str(self.source),
            '--model', str(ROOT / 'tests/fixtures/model.json'), '--seeds', '41', '--epsilons', '0'])
        with patch.object(collect_campaign, 'LAB', self.root):
            directory, plan = collect_campaign.create_plan(args)
        collect_campaign.save_plan(directory, plan)
        Path(plan['scenario']).write_text('int main() { return 99; }')
        with self.assertRaisesRegex(ValueError, 'scenario snapshot changed'), \
                patch.object(collect_campaign.subprocess, 'run') as launch:
            collect_campaign.main(['--resume', str(directory), '--allow-code-change'])
        launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
