"""Bounded host source discovery; never select an incompatible tree silently."""
from pathlib import Path
import os


def cache_values(path):
    result = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith(('#', '//')) and '=' in line and ':' in line.split('=')[0]:
            key, value = line.split('=', 1)
            result[key.split(':')[0]] = value
    return result


def identify(path, kind):
    path = Path(path)
    if kind == 'flexric':
        cache = path / 'build/CMakeCache.txt'
        if not cache.is_file() or not (path/'examples/xApp/c/monitor/xapp_kpm_moni.c').is_file():
            return False
        values = cache_values(cache)
        return values.get('E2AP_VERSION') == 'E2AP_V1' and values.get('KPM_VERSION') == 'KPM_V3_00'
    marker = path/'contrib/oran-interface/model/oran-interface.cc'
    return (marker.is_file() and (path/'build/include/ns3').is_dir()
            and (path/'build/lib').is_dir()
            and 'ActionDefinition-Format4' in marker.read_text(errors='replace'))


def discover(kind, explicit=None, roots=()):
    if explicit is not None:
        if not identify(explicit, kind):
            raise RuntimeError(f'Explicit {kind} source/build is missing or incompatible: {explicit}')
        return Path(explicit).resolve()
    roots = list(roots) + ['/work', '/workspace', '/opt', '/root', '/home', '/app', '/mnt', '/src', '/projects']
    found = set()
    seen = set()
    skip = {'.git', '.cache', '.venv', 'node_modules', 'build', 'cmake-cache', '_deps',
            'results', 'result', '__pycache__', '.local', '.npm', '.cargo', '.rustup'}
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for current, dirs, _ in os.walk(root, followlinks=False):
            path = Path(current)
            resolved = path.resolve()
            if resolved in seen:
                dirs[:] = []
                continue
            seen.add(resolved)
            if len(seen) > 25000:
                raise RuntimeError('Source discovery limit exceeded; provide --flexric and --ns3 explicitly')
            if identify(path, kind):
                found.add(resolved)
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith('.')]
            if len(path.relative_to(root).parts) >= 7:
                dirs[:] = []
    if len(found) != 1:
        candidates = ', '.join(str(p) for p in sorted(found)) or 'none'
        raise RuntimeError(f'Expected one compatible {kind} tree; candidates: {candidates}. '
                           f'Use --{kind} /host/source/path. Source trees must already be installed.')
    return next(iter(found))
