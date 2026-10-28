#!/usr/bin/env python3
"""Run a lab command. Use: python3 lab.py COMMAND --help."""
import argparse
from importlib import import_module
from labcore.commands import COMMANDS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=sorted(COMMANDS))
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    module = import_module(COMMANDS[args.command])
    return module.main(args.arguments)


if __name__ == '__main__':
    raise SystemExit(main())
