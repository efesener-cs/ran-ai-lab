"""Run the existing live supervisor locally when already inside the lab image."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(lab, output, extra, model=None, evasion=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    # Keep per-run builds separate from immutable image sources and results.
    with tempfile.TemporaryDirectory(prefix='ran-ai-' + output.name + '-') as temporary:
        work = Path(temporary) / ('ran-ai-' + output.name)
        work.mkdir()
        for name in ['container_run.py', 'check_control.py', 'check_live.py',
                     'export_dataset.py', 'build_csv.py', 'ran-ai-scenario.cc',
                     'shadow_stream.py']:
            shutil.copy2(lab / name, work / name)
        for name in ['labcore', 'ai']:
            shutil.copytree(lab / name, work / name,
                            ignore=shutil.ignore_patterns('artifacts', '__pycache__'))
        # FlexRIC's CMake writes compile_commands.json into its source tree.
        # Give each run a source copy rather than requiring writable image trees.
        flexric = work / 'flexric-source'
        shutil.copytree('/opt/flexric', flexric,
                        ignore=shutil.ignore_patterns('.git', 'build', 'build-config',
                                                     'compile_commands.json'))
        (flexric / 'build').mkdir()
        shutil.copy2('/opt/flexric/build/CMakeCache.txt', flexric / 'build/CMakeCache.txt')
        command = [sys.executable, str(work / 'container_run.py'),
                   '--flexric', str(flexric), '--ns3', '/opt/mmwave-LENA-oran', *extra]
        if model:
            command += ['--shadow-model', str(model.resolve())]
        if evasion:
            command += ['--evasion-config', str(evasion.resolve())]
        # The caller has already forwarded --apply-ai-control in extra.
        try:
            return subprocess.call(command)
        finally:
            result = work / 'result'
            if result.is_dir():
                shutil.copytree(result, output, dirs_exist_ok=True)
            print('Results and diagnostic logs:', output, flush=True)
