"""Container adapter contracts without Docker or simulation processes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from labcore.container_local import run


class ContainerLocalTests(unittest.TestCase):
    def test_failure_preserves_diagnostics_and_canonical_run_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'suite-none'
            lab = root / 'lab'
            lab.mkdir()
            def copy_file(source, dest):
                Path(dest).write_text('test')
            def copy_tree(source, dest, **kwargs):
                Path(dest).mkdir(parents=True, exist_ok=True)
            def supervise(command):
                work = Path(command[1]).parent
                self.assertEqual(work.name, 'ran-ai-suite-none')
                self.assertIn('--apply-ai-control', command)
                self.assertIn(str(work / 'flexric-source'), command)
                raw = work / 'result/raw'
                raw.mkdir(parents=True)
                (raw / 'simulation.log').write_text('diagnostic')
                return 7
            # Preserve real result copying while replacing image source copies.
            import shutil
            real_copytree = shutil.copytree
            def tree(source, dest, *args, **kwargs):
                if str(source) == '/opt/flexric' or Path(source).parent == lab:
                    return copy_tree(source, dest, **kwargs)
                return real_copytree(source, dest, *args, **kwargs)
            with patch('labcore.container_local.shutil.copy2', side_effect=copy_file), \
                 patch('labcore.container_local.shutil.copytree', side_effect=tree), \
                 patch('labcore.container_local.subprocess.call', side_effect=supervise):
                self.assertEqual(run(lab, output, ['--apply-ai-control']), 7)
            self.assertEqual((output / 'raw/simulation.log').read_text(), 'diagnostic')

    def test_existing_output_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch('labcore.container_local.subprocess.call') as launch:
                with self.assertRaises(FileExistsError):
                    run(Path(temporary), Path(temporary), [])
                launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
