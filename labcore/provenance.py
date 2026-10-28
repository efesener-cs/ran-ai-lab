"""Fingerprint the maintained source surface without traversing local artifacts."""
import hashlib
from labcore.paths import ROOT

SOURCE_PACKAGES = ('ai', 'simulation', 'scenario', 'datasets', 'checks', 'labcore', 'tests')


def source_hashes(root=ROOT):
    files = set(root.glob('*.py'))
    for package in SOURCE_PACKAGES:
        files.update(path for path in (root / package).rglob('*.py')
                     if not {'artifacts', '__pycache__'} & set(path.relative_to(root).parts))
    files.update((root / 'tests/fixtures').glob('*.cc'))
    files.update(path for path in [root / 'requirements-ai.txt'] if path.is_file())
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}
