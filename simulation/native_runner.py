"""Shared native runner commands and atomic run-status publication."""
from labcore.commands import command as cli_command
import json
from pathlib import Path
import subprocess
import tempfile


def write_status(root, status):
    """Publish a complete JSON document; concurrent readers never see a partial write."""
    target = Path(root) / 'run_status.json'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=target.parent,
                                         prefix='.run_status-', suffix='.tmp',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(status, indent=2) + '\n')
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def simulation_command(binary, args, *options):
    return [
        str(binary),
        '--liveRic=false',
        *options,
        '--simTime=' + str(args.duration),
        '--ueCount=' + str(args.ues),
        '--warmup=' + str(args.warmup),
        '--RngSeed=' + str(args.seed),
        '--RngRun=' + str(args.run),
    ]


def run_simulation(command, raw):
    with (raw / 'simulation.log').open('w') as log:
        subprocess.run(command, cwd=raw, check=True,
                       stdout=log, stderr=subprocess.STDOUT)


def export_run(lab, root, duration):
    subprocess.run([
        *cli_command('export_dataset', lab), str(root),
        '--duration', str(duration),
    ], check=True)
