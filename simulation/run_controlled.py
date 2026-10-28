"""Run a compatible external scenario with AI decisions over the CSV-to-RRC bridge."""
import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import subprocess

from ai.runtime import RuntimeForecaster
from labcore.commands import command as cli_command
from labcore.paths import ROOT
from scenario.source import build_native, read_source, snapshot_source
from simulation.native_runner import export_run, run_simulation, simulation_command, write_status


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--ns3', type=Path, help='Built native ns-3 source tree')
    parser.add_argument('--duration', type=float, default=3)
    parser.add_argument('--ues', type=int, default=6)
    parser.add_argument('--model', type=Path, default=ROOT / 'ai/artifacts/pilot/model.json')
    parser.add_argument('--warmup', type=float, default=1.0)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--run', type=int, default=1)
    parser.add_argument('--evasion-config', type=Path)
    parser.add_argument('--output', type=Path, help='New result directory')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    read_source(args.scenario)
    RuntimeForecaster.load(args.model)
    root = args.output.resolve() if args.output else ROOT / 'results' / ('control-native-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    root.mkdir(parents=True, exist_ok=False)
    raw = root / 'raw'
    raw.mkdir()
    selected = snapshot_source(args.scenario, root)
    stop = raw / 'ai_shadow.stop'
    status = dict(status='building', live_ric_verified=False, ai_control_enabled=True,
        control_transport='atomic CSV to ns-3 RRC API; no E2 RC', scenario=selected.metadata(),
        configuration=dict(duration=args.duration, ues=args.ues, seed=args.seed, run=args.run, warmup=args.warmup))
    write_status(root, status)
    print('Results:', root, flush=True)
    controller = None
    shadow_log = None
    try:
        binary = build_native(selected.path, ns3=args.ns3)
        status.update(status='running', simulation_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        write_status(root, status)
        shadow_log = (raw / 'ai-shadow.log').open('w')
        controller_command = [*cli_command('shadow_stream'), '--model', str(args.model),
            '--raw-dir', str(raw), '--output', str(root / 'csv'), '--run-id', root.name,
            '--ues', str(args.ues), '--stop-file', str(stop), '--apply-control']
        if args.evasion_config:
            controller_command += ['--evasion-config', str(args.evasion_config.resolve())]
        controller = subprocess.Popen(controller_command, stdout=shadow_log, stderr=subprocess.STDOUT)
        run_simulation(simulation_command(binary, args, '--applyAiControl=true'), raw)
        stop.touch()
        if controller.wait(timeout=15) != 0:
            raise RuntimeError('AI controller failed')
        export_run(ROOT, root, args.duration)
        status.update(status='complete', simulation_exit_code=0)
        write_status(root, status)
        from checks.check_control import verify
        result = verify(root, require_live=False)
        if not result['infrastructure_valid']:
            raise RuntimeError('Control evidence is malformed or infrastructure-invalid')
        status['ai_control_infrastructure_valid'] = True
        status['control_outcomes'] = result['control_outcomes']
        status['ai_control_verified_native'] = bool(result['submitted']) and result['confirmed'] == result['submitted']
    except BaseException as exc:
        status.update(status='failed', error=str(exc))
        raise
    finally:
        if controller is not None and controller.poll() is None:
            controller.terminate()
            controller.wait(timeout=5)
        if shadow_log is not None:
            shadow_log.close()
        write_status(root, status)


if __name__ == '__main__':
    main()
