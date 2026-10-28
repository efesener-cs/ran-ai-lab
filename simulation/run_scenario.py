"""Compile and run an external scenario without assuming AI telemetry or control."""
import argparse
from datetime import datetime
import hashlib
from pathlib import Path

from labcore.paths import ROOT
from scenario.source import build_native, read_source, snapshot_source
from simulation.native_runner import run_simulation, write_status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--ns3', type=Path, help='Built native ns-3 source tree')
    parser.add_argument('--output', type=Path, help='New result directory')
    parser.add_argument('scenario_args', nargs=argparse.REMAINDER,
                        help='Scenario-specific arguments after --, forwarded unchanged')
    args = parser.parse_args(argv)
    read_source(args.scenario)
    root = args.output.resolve() if args.output else ROOT / 'results' / ('scenario-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True, exist_ok=False)
    raw = root / 'raw'
    raw.mkdir()
    selected = snapshot_source(args.scenario, root)
    forwarded = args.scenario_args[1:] if args.scenario_args[:1] == ['--'] else args.scenario_args
    status = dict(status='building', live_ric_verified=False, scenario=selected.metadata(),
                  configuration=dict(scenario_args=forwarded),
                  scope='External scenario execution only; no AI, telemetry export, or RIC verification')
    write_status(root, status)
    try:
        binary = build_native(selected.path, ns3=args.ns3)
        status.update(status='running', simulation_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        write_status(root, status)
        run_simulation([str(binary), *forwarded], raw)
        status.update(status='complete', simulation_exit_code=0)
    except BaseException as exc:
        status.update(status='failed', error=str(exc))
        raise
    finally:
        write_status(root, status)
    print('Results:', root)


if __name__ == '__main__':
    main()
