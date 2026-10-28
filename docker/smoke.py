#!/usr/bin/env python3
"""Small end-to-end acceptance run inside an already built lab image."""
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--e2-nodes', type=int, default=5)
    parser.add_argument('--backend', choices=['native', 'live'], required=True)
    args = parser.parse_args()
    if not args.scenario.is_file():
        parser.error('Provide an existing compatible external C++ scenario')
    lab = Path(__file__).resolve().parents[1]
    root = lab / 'results' / ('container-smoke-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True, exist_ok=False)

    def execute(script, *arguments):
        subprocess.run([sys.executable, str(lab / 'lab.py'), Path(script).stem, *map(str, arguments)],
                       cwd=lab, check=True)

    for name, seed in [('train', 11), ('validation', 23), ('test', 37)]:
        common = ['--scenario', args.scenario.resolve(), '--duration', 3, '--ues', 6, '--seed', seed, '--output', root / name]
        if args.backend == 'native':
            execute('run_controlled.py', '--model', lab / 'tests/fixtures/model.json', *common)
        else:
            execute('run_live.py', *common, '--e2-nodes', args.e2_nodes)
            execute('check_live.py', root / name)
    native = ['--allow-native'] if args.backend == 'native' else []
    execute('train_ai.py', *native, '--run-dir', root / 'train',
            '--validation-run-dir', root / 'validation', '--test-run-dir', root / 'test',
            '--alpha-grid', 1, 10, '--output', root / 'model')
    execute('run_adversarial_suite.py', '--backend', args.backend,
            '--model', root / 'model/model.json', '--duration', 3, '--ues', 6,
            '--seed', 41, '--epsilon', 2, '--output', root / 'suite',
            '--scenario', args.scenario.resolve(), '--e2-nodes', args.e2_nodes)
    print('Container acceptance passed:', root, flush=True)


if __name__ == '__main__':
    main()
