"""Build the same self-contained source bundle for both live launch paths."""
from pathlib import Path
import shutil

RUNTIME_PATHS = ('lab.py', 'ai', 'simulation', 'scenario', 'datasets', 'checks', 'labcore')


def copy_runtime(source, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name in RUNTIME_PATHS:
        origin = source / name
        target = destination / name
        if origin.is_dir():
            shutil.copytree(origin, target,
                            ignore=shutil.ignore_patterns('artifacts', '__pycache__', '*.pyc'))
        else:
            shutil.copy2(origin, target)
