"""Compile a supplied C++ scenario; no source generation or default scenario."""
import argparse
from pathlib import Path
from scenario.source import build_native


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--ns3', type=Path, help='Built native ns-3 source tree')
    args = parser.parse_args(argv)
    print(build_native(args.scenario, ns3=args.ns3))


if __name__ == '__main__':
    main()
