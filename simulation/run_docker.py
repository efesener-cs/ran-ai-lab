#!/usr/bin/env python3
"""Copy the lab into a prepared Docker container, run host-style live supervision, and retrieve logs."""
from labcore.paths import ROOT
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import json
import tempfile
from labcore.runtime_bundle import RUNTIME_PATHS, copy_runtime
from scenario.source import read_source


def build_parser():
    p = argparse.ArgumentParser(
        description=__doc__,
        epilog="Scenario options such as --duration, --ues, --seed, --flexric, and --ns3 "
               "are forwarded to the container runner. See docs/RUNNING.md.",
    )
    p.add_argument('--scenario', type=Path, required=True, help='External self-contained C++ scenario')
    p.add_argument('--container', default='flexric', help='Prepared Docker container name')
    p.add_argument('--output', type=Path, help='New host result directory')
    p.add_argument('--ai-model', type=Path, help='Trained model JSON; omit for measurement-only runs')
    p.add_argument('--evasion-config', type=Path, help='Bounded model-input attack configuration JSON')
    p.add_argument('--apply-ai-control', action='store_true',
                   help='Apply model decisions through the CSV-to-RRC bridge')
    return p


def parse_args(argv=None):
    return build_parser().parse_known_args(argv)


def argument_error(message):
    build_parser().error(message)


def copy_to_container(container, source, destination):
    subprocess.run(['docker', 'cp', str(source), container + ':' + destination], check=True)


def prepare_container(lab, args, remote, extra):
    try:
        state = subprocess.check_output(['docker', 'inspect', '-f', '{{.State.Running}}', args.container], text=True).strip()
    except subprocess.CalledProcessError:
        sys.exit('Docker access failed. Run this command in your normal host terminal.')
    if state != 'true':
        subprocess.run(['docker', 'start', args.container], check=True)
    subprocess.run(['docker', 'exec', args.container, 'mkdir', '-p', remote], check=True)
    with tempfile.TemporaryDirectory(prefix='ran-ai-runtime-') as directory:
        bundle = Path(directory)
        copy_runtime(lab, bundle)
        for name in RUNTIME_PATHS:
            copy_to_container(args.container, bundle / name, remote + '/' + name)
    copy_to_container(args.container, args.scenario, remote + '/scenario.cc')
    extra += ['--scenario', remote + '/scenario.cc']
    if args.ai_model is not None:
        copy_to_container(args.container, args.ai_model, remote + '/model.json')
        extra += ['--shadow-model', remote + '/model.json']
    if args.evasion_config:
        copy_to_container(args.container, args.evasion_config, remote + '/evasion.json')
        extra += ['--evasion-config', remote + '/evasion.json']
    mounts = json.loads(subprocess.check_output(['docker', 'inspect', '-f', '{{json .Mounts}}', args.container], text=True))
    for mount in mounts or []:
        if mount.get('Type') == 'bind' and mount.get('Destination') not in ['/var/run/docker.sock']:
            extra += ['--search-root', mount['Destination']]


def main(argv=None):
    args, extra = parse_args(argv)
    lab = ROOT
    read_source(args.scenario)
    if args.evasion_config and (not args.evasion_config.is_file() or args.ai_model is None):
        argument_error('--evasion-config requires an existing JSON file and --ai-model')
    if args.apply_ai_control and args.ai_model is None:
        argument_error('--apply-ai-control requires --ai-model')
    if args.apply_ai_control:
        extra += ['--apply-ai-control']
    if args.ai_model is not None and not args.ai_model.is_file():
        argument_error('AI model file not found: ' + str(args.ai_model))
    run_id = args.output.resolve().name if args.output else 'live-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    if not run_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in run_id):
        argument_error('Output directory name must contain only letters, numbers, hyphens and underscores')
    remote = '/tmp/ran-ai-' + run_id
    out = args.output.resolve() if args.output else lab / 'results' / run_id
    if out.exists():
        argument_error('Output directory already exists: ' + str(out))
    prepare_container(lab, args, remote, extra)
    print('Container workdir:', remote, flush=True)
    code = 1
    try:
        code = subprocess.call(['docker', 'exec', args.container, 'python3', remote + '/lab.py', 'run_live', '--output', remote + '/result', *extra])
    except KeyboardInterrupt:
        code = 130
        subprocess.call(['docker', 'exec', args.container, 'python3', '-c', 'import os,signal,sys; from pathlib import Path; os.kill(int(Path(sys.argv[1]).read_text()),signal.SIGTERM)', remote + '/result/work/controller.pid'])
    finally:
        out.mkdir(parents=True, exist_ok=True)
        copied = subprocess.call(['docker', 'cp', args.container + ':' + remote + '/result/.', str(out)])
        print('Results and diagnostic logs:', out, flush=True)
        if copied:
            print('Result copy failed; files remain in the container at ' + remote, file=sys.stderr)
    sys.exit(code)


if __name__ == '__main__':
    main()
