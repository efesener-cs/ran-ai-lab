#!/usr/bin/env python3
from pathlib import Path
import subprocess
def main():
    base = Path(__file__).resolve().parent
    lib = base.parent/'ns-o-ran-ns3-mmwave/build/lib'
    libraries = sorted(lib.glob('*.so'))
    if not libraries:
        raise SystemExit(f'No built ns-3 shared libraries in {lib}')
    cmd = ['g++','-std=c++17','-O1','-I'+str(lib.parent/'include'),
           '-I/usr/local/include/e2sim',str(base/'ran-ai-scenario.cc'),
           '-o',str(base/'ran-ai-offline'),'-Wl,-rpath,'+str(lib)]
    cmd += [str(p) for p in libraries]
    subprocess.run(cmd, check=True)


if __name__ == '__main__':
    main()
