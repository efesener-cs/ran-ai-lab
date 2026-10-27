#!/usr/bin/env python3
"""Small end-to-end acceptance run inside an already built lab image."""
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['native', 'live'], required=True)
    args = parser.parse_args()
    lab = Path(__file__).resolve().parents[1]
    root = lab / 'results' / ('container-smoke-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True, exist_ok=False)

    def execute(script, *arguments):
        subprocess.run([sys.executable, str(lab / script), *map(str, arguments)],
                       cwd=lab, check=True)

    for name, seed in [('train', 11), ('validation', 23), ('test', 37)]:
        common = ['--duration', 3, '--ues', 6, '--seed', seed, '--output', root / name]
        if args.backend == 'native':
            execute('run_controlled.py', '--model', lab / 'tests/fixtures/model.json', *common)
        else:
            execute('run_live.py', *common)
            execute('check_live.py', root / name)
    native = ['--allow-native'] if args.backend == 'native' else []
    execute('train_ai.py', *native, '--run-dir', root / 'train',
            '--validation-run-dir', root / 'validation', '--test-run-dir', root / 'test',
            '--alpha-grid', 1, 10, '--output', root / 'model')
    execute('run_adversarial_suite.py', '--backend', args.backend,
            '--model', root / 'model/model.json', '--duration', 3, '--ues', 6,
            '--seed', 41, '--epsilon', 2, '--output', root / 'suite')
    execute('analyze_experiments.py', root / 'suite', '--output', root / 'analysis')
    print('Container acceptance passed:', root, flush=True)


if __name__ == '__main__':
    main()
