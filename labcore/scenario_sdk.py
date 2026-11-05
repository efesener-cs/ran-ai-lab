"""Stage a minimal already-built ns-3 SDK without editing/rebuilding the original."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from labcore.discover_sources import cache_values

MODULES = ('core', 'network', 'internet', 'point-to-point', 'applications',
           'flow-monitor', 'traffic-control')


def dependency_closure(source):
    libdir = Path(source) / 'build/lib'
    available = {}
    for path in sorted(libdir.glob('*.so')):
        available[path.name] = path
    selected = {}
    queue = []
    for module in MODULES:
        matches = []
        for name, path in available.items():
            suffixes = ('-'+module+'.so',)
            for variant in ('default','debug','optimized','release','debugoptimized'):
                suffixes += ('-'+module+'-'+variant+'.so',)
            if name.endswith(suffixes):
                matches.append(path)
        matches.sort(key=lambda p: ('default' not in p.name, p.name))
        if not matches:
            raise ValueError('Missing prebuilt ns-3 module: '+module)
        queue.append(matches[0])
    while queue:
        path = queue.pop()
        if path.name in selected:
            continue
        selected[path.name] = path
        output = subprocess.check_output(['readelf', '-d', str(path)], text=True)
        for name in re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', output):
            if name.startswith('libns'):
                if name not in available:
                    raise ValueError('Missing ns-3 dependency: '+name)
                queue.append(available[name])
    return sorted(selected.values())


def stage_sdk(source, destination, remote_destination):
    source, destination = Path(source).resolve(), Path(destination)
    libraries = dependency_closure(source)
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(source/'src', destination/'src')
    shutil.copytree(source/'build/include', destination/'build/include')
    (destination/'build/lib').mkdir(parents=True)
    record = dict(source=str(source), relocated_to=remote_destination, libraries={})
    for path in libraries:
        shutil.copy2(path, destination/'build/lib'/path.name)
        record['libraries'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    old_root = cache_values(source/'cmake-cache/CMakeCache.txt').get('CMAKE_HOME_DIRECTORY', str(source))
    for path in (destination/'build/include').rglob('*'):
        if path.is_file():
            data = path.read_text()
            data = data.replace(old_root+'/', remote_destination+'/')
            data = data.replace(str(source)+'/', remote_destination+'/')
            path.write_text(data)
    return record
