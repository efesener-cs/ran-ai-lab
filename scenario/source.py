"""Use a caller-supplied C++ source unchanged and build it against native ns-3."""
from dataclasses import dataclass
import hashlib
import fcntl
import os
import json
from pathlib import Path
import shutil
import subprocess

from labcore.paths import ROOT
from labcore.portable_build import shared_library_args


@dataclass(frozen=True)
class ScenarioSource:
    path: Path
    sha256: str
    origin: str

    def metadata(self):
        return dict(path=str(self.path), sha256=self.sha256, origin=self.origin)


def read_source(path):
    if path is None:
        raise ValueError('Provide --scenario PATH to a self-contained ns-3 C++ source')
    source = Path(path).expanduser().resolve()
    if source.suffix.lower() not in {'.cc', '.cpp', '.cxx'} or not source.is_file():
        raise ValueError('Scenario must be an existing .cc, .cpp, or .cxx file: ' + str(source))
    data = source.read_bytes()
    if not data.strip():
        raise ValueError('Scenario source is empty: ' + str(source))
    return source, data


def snapshot_source(path, directory):
    origin, data = read_source(path)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / 'scenario.cc'
    if target.exists() and target.read_bytes() != data:
        raise ValueError('Refusing to overwrite a different scenario snapshot: ' + str(target))
    target.write_bytes(data)
    return ScenarioSource(target.resolve(), hashlib.sha256(data).hexdigest(), str(origin))


def build_native(source, ns3=None, build_root=None, compiler='g++'):
    """Cache by source and build inputs; never reuse the historical default binary."""
    origin, data = read_source(source)
    ns3 = Path(ns3 or ROOT.parent / 'ns-o-ran-ns3-mmwave').resolve()
    libraries = sorted((ns3 / 'build/lib').glob('*.so'))
    if not libraries:
        raise ValueError('No built ns-3 shared libraries found in ' + str(ns3 / 'build/lib'))
    cxx = shutil.which(compiler)
    if cxx is None:
        raise ValueError('C++ compiler not found: ' + compiler)
    inputs = dict(source_sha256=hashlib.sha256(data).hexdigest(), ns3=str(ns3),
                  compiler=str(Path(cxx).resolve()), standard='c++17',
                  libraries=[dict(path=str(p.resolve()), size=p.stat().st_size,
                                  mtime_ns=p.stat().st_mtime_ns) for p in libraries])
    identity = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    directory = Path(build_root or os.environ.get('RAN_AI_BUILD_ROOT', ROOT / 'host-build/scenarios')) / identity
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _compile_cached(directory, inputs, data, origin, libraries, cxx, ns3)


def _compile_cached(directory, inputs, data, origin, libraries, cxx, ns3):
    binary = directory / 'program'
    record = directory / 'build.json'
    if binary.is_file() and record.is_file():
        metadata = json.loads(record.read_text())
        if (metadata.get('inputs') == inputs
                and metadata.get('binary_sha256') == hashlib.sha256(binary.read_bytes()).hexdigest()):
            return binary
    copied = directory / 'scenario.cc'
    copied.write_bytes(data)
    temporary = directory / 'program.building'
    command = [cxx, '-std=c++17', '-O1', '-I' + str(ns3 / 'build/include'),
               '-I/usr/local/include/e2sim', str(copied), '-o', str(temporary),
               '-Wl,-rpath,' + str(ns3 / 'build/lib'), *shared_library_args(libraries)]
    try:
        subprocess.run(command, check=True)
        temporary.replace(binary)
    finally:
        temporary.unlink(missing_ok=True)
    metadata = dict(inputs=inputs, source_origin=str(origin), command=command,
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    staged = directory / '.build.json.tmp'
    staged.write_text(json.dumps(metadata, indent=2) + '\n')
    staged.replace(record)
    return binary
