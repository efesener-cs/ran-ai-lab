#!/usr/bin/env python3
"""Host integration test: model -> atomic commands -> ns-3 RRC; no E2 RC claim."""
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import sys

from labcore.native_runner import export_run, run_simulation, simulation_command, write_status


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--duration', type=float, default=3)
    p.add_argument('--ues', type=int, default=6)
    p.add_argument('--model', type=Path)
    p.add_argument('--warmup', type=float, default=1.0)
    p.add_argument('--seed', type=int, default=7)
    p.add_argument('--run', type=int, default=1)
    p.add_argument('--evasion-config', type=Path)
    p.add_argument('--output', type=Path, help='Run output directory (must not already exist)')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    lab = Path(__file__).resolve().parent
    model = args.model or lab / 'ai/artifacts/pilot/model.json'
    root = args.output.resolve() if args.output else lab / 'results' / ('control-native-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    if args.output:
        root.mkdir(parents=True, exist_ok=False)
    raw = root / 'raw'
    raw.mkdir(parents=True, exist_ok=False)
    stop = raw / 'ai_shadow.stop'
    status = dict(
        status='running', live_ric_verified=False, ai_control_enabled=True,
        control_transport='atomic CSV to ns-3 RRC API; no E2 RC',
        configuration=dict(duration=args.duration, ues=args.ues, seed=args.seed,
                           run=args.run, warmup=args.warmup),
    )
    write_status(root, status)
    print('Results:', root, flush=True)
    shadow_log = (raw / 'ai-shadow.log').open('w')
    controller_command = [
        sys.executable, str(lab / 'shadow_stream.py'), '--model', str(model),
        '--raw-dir', str(raw), '--output', str(root / 'csv'), '--run-id', root.name,
        '--ues', str(args.ues), '--stop-file', str(stop), '--apply-control',
    ]
    if args.evasion_config:
        controller_command += ['--evasion-config', str(args.evasion_config.resolve())]
    controller = subprocess.Popen(controller_command, stdout=shadow_log,
                                  stderr=subprocess.STDOUT)
    try:
        run_simulation(simulation_command(lab, args, '--applyAiControl=true'), raw)
        stop.touch()
        if controller.wait(timeout=15) != 0:
            raise RuntimeError('AI controller failed')
        export_run(lab, root, args.duration)
        status.update(status='complete', simulation_exit_code=0)
        write_status(root, status)
        from check_control import verify
        result = verify(root, require_live=False)
        if not result['infrastructure_valid']:
            raise RuntimeError('Control evidence is malformed or infrastructure-invalid')
        status['ai_control_infrastructure_valid'] = True
        status['control_outcomes'] = result['control_outcomes']
        # Healthy infrastructure does not imply a submitted, confirmed handover.
        status['ai_control_verified_native'] = bool(result['submitted']) and result['confirmed'] == result['submitted']
    except BaseException as exc:
        status.update(status='failed', error=str(exc))
        raise
    finally:
        if controller.poll() is None:
            controller.terminate()
            controller.wait(timeout=5)
        shadow_log.close()
        write_status(root, status)


if __name__ == '__main__':
    main()
