"""Run the existing live supervisor locally when already inside the lab image."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from labcore.runtime_bundle import copy_runtime
from scenario.source import snapshot_source
from labcore.commands import command as cli_command


def run(lab, output, extra, model=None, evasion=None, scenario=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    # Keep per-run builds separate from immutable image sources and results.
    with tempfile.TemporaryDirectory(prefix='ran-ai-' + output.name + '-') as temporary:
        work = Path(temporary) / ('ran-ai-' + output.name)
        work.mkdir()
        copy_runtime(lab, work)
        selected = snapshot_source(scenario, work)
        # FlexRIC's CMake writes compile_commands.json into its source tree.
        # Give each run a source copy rather than requiring writable image trees.
        flexric = work / 'flexric-source'
        shutil.copytree('/opt/flexric', flexric,
                        ignore=shutil.ignore_patterns('.git', 'build', 'build-config',
                                                     'compile_commands.json'))
        (flexric / 'build').mkdir()
        shutil.copy2('/opt/flexric/build/CMakeCache.txt', flexric / 'build/CMakeCache.txt')
        command = [*cli_command('container_run', work),
                   '--flexric', str(flexric), '--ns3', '/opt/mmwave-LENA-oran',
                   '--scenario', str(selected.path), *extra]
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
