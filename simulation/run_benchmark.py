"""Resume an isolated RF/IP/training benchmark with a bounded two-core queue."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from labcore.paths import ROOT
from labcore.provenance import source_hashes
from labcore.runtime_bundle import copy_runtime
from labcore.scenario_sdk import stage_sdk
from simulation.collect_campaign import save_plan


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def physical_cpus():
    selected, seen = [], set()
    for cpu in sorted(os.sched_getaffinity(0)):
        topology = Path('/sys/devices/system/cpu') / ('cpu' + str(cpu)) / 'topology'
        identity = ((topology / 'physical_package_id').read_text().strip(),
                    (topology / 'core_id').read_text().strip())
        if identity not in seen:
            selected.append(cpu)
            seen.add(identity)
    if len(selected) < 2:
        raise ValueError('Two distinct available physical CPU cores required')
    return selected[:2]


def recipes(proposal):
    jobs = []
    # Four matched workloads at 1 and 2 workers. Four workers exceed approval.
    for workers in (1, 2):
        for mode in ('none', 'udp_flood', 'udp_ddos', 'tcp_connection_churn'):
            jobs.append(dict(id=f'pilot-w{workers}-{mode}', kind='ip',
                phase='pilot-' + str(workers), seed=900001, attack=mode,
                sim_time_s=120, warmup_s=2, episodes=6, scheduled_fraction=.2,
                context=dict(clients=12, attackers=12, servers=3, core_mbps=20,
                             attack_mbps=60, queue_packets=200), depends=[]))
    rf = sorted(proposal['rf_blocks'], key=lambda j: (not (j['profile'] == 'diverse' and j['snr_db'] == 10), j['repeat'], j['id']))
    for row in rf:
        jobs.append(dict(row, kind='rf', phase='main', depends=[]))
        if row['profile'] == 'diverse' and row['snr_db'] == 10:
            jobs.append(dict(id='training-r' + str(row['repeat']), kind='training',
                             phase='main', depends=[row['id']], parent=row['id']))
    for row in proposal['ip_jobs']:
        jobs.append(dict(row, kind='ip', phase='main', depends=[]))
    if len({j['id'] for j in jobs}) != len(jobs):
        raise ValueError('Duplicate benchmark job identifiers')
    for job in jobs:
        job.update(status='pending', attempts=[])
    return jobs


def make_plan(output_root, proposal_path, ns3):
    proposal = json.loads(proposal_path.read_text())
    output_root.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='run-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '-', dir=output_root))
    copy_runtime(ROOT, root / 'runtime')
    (root / 'inputs').mkdir()
    for name, expected in proposal['scenario_sha256'].items():
        origin = ROOT / 'examples/scenarios' / name
        if sha(origin) != expected:
            raise ValueError('Scenario differs from reviewed proposal: ' + name)
        shutil.copy2(origin, root / 'inputs' / name)
    shutil.copy2(proposal_path, root / 'proposal.json')
    # Relocate only a private SDK copy; never modify shared forwarding headers.
    sdk = root / 'sdk'
    sdk_record = stage_sdk(ns3, sdk, str(sdk))
    plan = dict(format='rf-ip-training-benchmark-v1', status='prepared',
                execution_approved=True, publication_approved=False,
                approval='User authorized two CPU cores and approximately 18 hours.',
                backend='host', cpus=physical_cpus(), workers=2, wall_budget_seconds=18*3600,
                elapsed_seconds=0., ns3=str(sdk), sdk=sdk_record,
                runtime_sha256=source_hashes(root / 'runtime'),
                input_sha256={p.name:sha(p) for p in (root / 'inputs').iterdir()},
                proposal_sha256=sha(root / 'proposal.json'), jobs=recipes(proposal),
                limits=dict(min_disk_gib=20, min_mem_available_gib=3,
                            max_growth_gib=25, max_job_rss_gib=5),
                sessions=[], scientific_scope='Synthetic receiver-IQ, local RF training integrity and wired IP. No live RAN/OTA acceptance.')
    save_plan(root, plan)
    print('Campaign:', root, flush=True)
    return root, plan


def execute_job(root, plan, job, destination):
    """Child process runs collection followed by independent evidence checks."""
    runtime = root / 'runtime'
    def cli(name, *args):
        return [sys.executable, str(runtime / 'lab.py'), name, *map(str, args)]
    def run(command):
        print('$', repr(command), flush=True)
        subprocess.run(command, cwd=destination, check=True)
    result = destination / 'result'
    if job['kind'] == 'ip':
        context = job['context']
        flags = ['--attack=' + job['attack'], '--RngSeed=' + str(job['seed']), '--RngRun=1',
                 '--simTime=' + str(job['sim_time_s']), '--warmup=' + str(job['warmup_s']),
                 '--episodes=' + str(job['episodes']), '--attackFraction=' + str(job['scheduled_fraction'])]
        for option, key in [('clients','clients'), ('attackers','attackers'), ('servers','servers'),
                            ('bottleneckMbps','core_mbps'), ('attackMbps','attack_mbps'), ('queuePackets','queue_packets')]:
            flags.append('--' + option + '=' + str(context[key]))
        run(cli('run_scenario', '--scenario', root/'inputs/ip-network-attacks.cc',
                '--ns3', plan['ns3'], '--output', result, '--', *flags))
        from simulation.scenario_batch import validate_ip
        check = validate_ip(result, job['attack'], job['seed'])
        expected = dict(sim_time_s=job['sim_time_s'], warmup_s=job['warmup_s'],
                        clients=context['clients'], attackers=context['attackers'], servers=context['servers'],
                        bottleneck_mbps=context['core_mbps'], aggregate_flood_mbps=context['attack_mbps'],
                        queue_disc_packets=context['queue_packets'], attack_fraction_requested=job['scheduled_fraction'])
        if any(check['metadata'].get(key) != value for key, value in expected.items()):
            raise ValueError('IP measured context differs from planned configuration')
        if check['rows'] != round((job['sim_time_s']-job['warmup_s'])/.1):
            raise ValueError('IP closed-window coverage differs from plan')
        evidence = dict(rows=check['rows'], positives=check['positives'])
    elif job['kind'] == 'rf':
        run(cli('run_rf', '--scenario', root/'inputs/rf-ai-frames.cc', '--output', result,
                '--rf-profile', job['profile'], '--snr-db', job['snr_db'],
                '--train-samples', job['train_per_task'], '--eval-samples', job['test_per_task'],
                '--length', job['complex_length'], '--epochs', 80, '--steps', 30,
                '--seeds', *job['seeds'], '--psr-db', -20, -10, -6))
        run(cli('check_rf', result))
        evidence = dict(conditions=33)
    elif job['kind'] == 'training':
        parent = next(j for j in plan['jobs'] if j['id'] == job['parent'])
        parent_path = root / parent['attempts'][-1]['directory'] / 'result'
        run(cli('run_training_attacks', '--rf-run', parent_path,
                '--scenario', root/'inputs/training-data-attacks.cc', '--output', result,
                '--epochs', 80, '--attack-seed', 101 + int(job['id'].split('r')[-1])))
        run(cli('check_training_attacks', result))
        evidence = dict(conditions=26)
    else:
        raise ValueError('Unknown benchmark job kind')
    files = {str(p.relative_to(destination)):sha(p) for p in sorted(result.rglob('*')) if p.is_file()}
    if not files:
        raise ValueError('No result artifacts')
    (destination / 'receipt.json').write_text(json.dumps(dict(files=files, evidence=evidence), indent=2) + '\n')


def verify_completed(root, job):
    attempt = job['attempts'][-1]
    directory = root / attempt['directory']
    if sha(directory / 'receipt.json') != attempt['receipt_sha256']:
        raise ValueError('Completed receipt changed: ' + job['id'])
    for name, expected in json.loads((directory / 'receipt.json').read_text())['files'].items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or sha(path) != expected:
            raise ValueError('Completed evidence changed: ' + job['id'])


def verify_freeze(root, plan):
    if source_hashes(root / 'runtime') != plan['runtime_sha256']:
        raise ValueError('Frozen runtime changed; refusing mixed-revision resume')
    if sha(root / 'proposal.json') != plan['proposal_sha256']:
        raise ValueError('Frozen scientific proposal changed')
    for name, expected in plan['input_sha256'].items():
        if sha(root / 'inputs' / name) != expected:
            raise ValueError('Frozen scenario changed: ' + name)


def pilot_agrees(root, plan):
    for mode in ('none', 'udp_flood', 'udp_ddos', 'tcp_connection_churn'):
        hashes = []
        for workers in (1, 2):
            job = next(j for j in plan['jobs'] if j['id'] == f'pilot-w{workers}-{mode}')
            if job['status'] != 'complete':
                return False
            hashes.append(sha(root / job['attempts'][-1]['directory'] / 'result/raw/ip_windows.csv'))
        if hashes[0] != hashes[1]:
            raise ValueError('Pilot output differs across concurrency levels: ' + mode)
    return True


def available_memory():
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return int(values['MemAvailable'].split()[0]) * 1024


def tree_bytes(root):
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file())


def process_rss(groups):
    total = 0
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) in groups:  # pgrp (field 5)
                total += int((proc / 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            pass
    return total


def resource_reason(root, plan, active):
    limits, gib = plan['limits'], 1024**3
    if shutil.disk_usage(root).free < limits['min_disk_gib'] * gib:
        return 'free disk below limit'
    if available_memory() < limits['min_mem_available_gib'] * gib:
        return 'available memory below limit'
    if process_rss({item['process'].pid for item in active.values()}) > limits['max_job_rss_gib'] * gib:
        return 'job RSS above limit'
    if tree_bytes(root) > limits['max_growth_gib'] * gib:
        return 'campaign size above limit'
    return None


def terminate(active):
    for item in active.values():
        try:
            os.killpg(item['process'].pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and any(i['process'].poll() is None for i in active.values()):
        time.sleep(.1)
    for item in active.values():
        try:
            os.killpg(item['process'].pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        item['process'].wait()
        item['handle'].close()


def recover_orphan(root, job):
    """Stop only a verifiably owned worker from a crashed controller."""
    pid = job['attempts'][-1].get('pid')
    if not pid:
        return
    try:
        command = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
        if (str(root).encode() not in command or job['id'].encode() not in command or
                b'--job' not in command or os.getpgid(pid) != pid):
            return
        os.killpg(pid, signal.SIGTERM)
        until = time.monotonic() + 3
        while Path('/proc', str(pid)).exists() and time.monotonic() < until:
            time.sleep(.1)
        if Path('/proc', str(pid)).exists():
            os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, FileNotFoundError):
        pass


def run_queue(root, plan):
    with (root / '.campaign.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('Campaign already has a live controller') from error
        verify_freeze(root, plan)
        for name, expected in plan.get('sdk', {}).get('libraries', {}).items():
            if sha(Path(plan['ns3'])/'build/lib'/name) != expected:
                raise ValueError('Private SDK library changed: ' + name)
        for job in plan['jobs']:
            if job['status'] == 'complete':
                verify_completed(root, job)
            elif job['status'] == 'running':
                recover_orphan(root, job)
                job['attempts'][-1]['state'] = 'interrupted'
                job['status'] = 'pending'
        os.sched_setaffinity(0, set(plan['cpus']))
        started = time.monotonic()
        elapsed_before = plan['elapsed_seconds']
        plan.setdefault('deadline_epoch', time.time() + plan['wall_budget_seconds'] - elapsed_before)
        remaining = min(plan['wall_budget_seconds'] - elapsed_before, plan['deadline_epoch'] - time.time())
        if remaining <= 0:
            raise ValueError('Approved cumulative wall-time budget exhausted')
        session = dict(started_utc=datetime.now(timezone.utc).isoformat(), pid=os.getpid(), state='running')
        plan['sessions'].append(session)
        plan['status'] = 'running'
        active, attempted = {}, set()
        stop = None
        env = dict(os.environ, PYTHONUNBUFFERED='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1',
                   MKL_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1', VECLIB_MAXIMUM_THREADS='1',
                   PYTHONPATH=str(root / 'runtime'), PYTHONDONTWRITEBYTECODE='1',
                   RAN_AI_BUILD_ROOT=str(root / 'build-cache'))
        env['LD_LIBRARY_PATH'] = str(Path(plan['ns3'])/'build/lib') + os.pathsep + env.get('LD_LIBRARY_PATH', '')
        # Forward SIGTERM into the same bounded cancellation path as Ctrl-C.
        old_handler = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        last_resource = 0.
        try:
            while True:
                for cpu, item in list(active.items()):
                    code = item['process'].poll()
                    if code is None:
                        continue
                    item['handle'].close()
                    job, attempt = item['job'], item['job']['attempts'][-1]
                    attempt.update(exit_code=code, elapsed_seconds=time.monotonic()-item['started'])
                    if code == 0 and (root / attempt['directory'] / 'receipt.json').is_file():
                        attempt['receipt_sha256'] = sha(root / attempt['directory'] / 'receipt.json')
                        job['status'] = attempt['state'] = 'complete'
                    else:
                        job['status'] = attempt['state'] = 'failed'
                    print(job['status'].upper(), job['id'], flush=True)
                    del active[cpu]
                    save_plan(root, plan)
                if time.monotonic()-started >= remaining:
                    stop = 'timeout'
                    break
                if time.monotonic()-last_resource >= 10:
                    reason = resource_reason(root, plan, active)
                    last_resource = time.monotonic()
                    plan['elapsed_seconds'] = elapsed_before + time.monotonic()-started
                    session['elapsed_seconds'] = time.monotonic()-started
                    save_plan(root, plan)
                    if reason:
                        plan['stop_reason'] = reason
                        stop = 'resource_limited'
                        break
                unfinished_pilot = [j for j in plan['jobs'] if j['phase'].startswith('pilot') and j['status'] != 'complete']
                if unfinished_pilot:
                    phase = min(j['phase'] for j in unfinished_pilot)
                    capacity = 1 if phase == 'pilot-1' else 2
                else:
                    if not plan.get('pilot_verified'):
                        plan['pilot_verified'] = pilot_agrees(root, plan)
                        save_plan(root, plan)
                    phase, capacity = 'main', 2
                complete_ids = {j['id'] for j in plan['jobs'] if j['status'] == 'complete'}
                candidates = [j for j in plan['jobs'] if j['phase'] == phase and j['status'] != 'complete'
                              and j['id'] not in attempted and set(j['depends']).issubset(complete_ids)]
                for cpu in plan['cpus']:
                    if len(active) >= capacity or not candidates:
                        break
                    if cpu in active:
                        continue
                    verify_freeze(root, plan)
                    job = candidates.pop(0)
                    attempted.add(job['id'])
                    destination = root / 'jobs' / job['id'] / ('attempt-' + str(len(job['attempts'])+1))
                    destination.mkdir(parents=True, exist_ok=False)
                    attempt = dict(directory=str(destination.relative_to(root)), state='running', cpu=cpu,
                                   started_utc=datetime.now(timezone.utc).isoformat())
                    job['attempts'].append(attempt)
                    job['status'] = 'running'
                    save_plan(root, plan)
                    command = ['taskset', '-c', str(cpu), sys.executable, str(root/'runtime/lab.py'),
                               'run_benchmark', '--job', job['id'], '--resume', str(root),
                               '--attempt', str(destination)]
                    handle = (destination/'job.log').open('w')
                    process = subprocess.Popen(command, env=env, cwd=destination, stdout=handle,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                    attempt['pid'] = process.pid
                    active[cpu] = dict(process=process, handle=handle, job=job, started=time.monotonic())
                    save_plan(root, plan)
                    print('RUN', job['id'], 'CPU', cpu, flush=True)
                if not active:
                    stop = 'complete' if all(j['status'] == 'complete' for j in plan['jobs']) else 'incomplete'
                    break
                time.sleep(.5)
        except KeyboardInterrupt:
            stop = 'interrupted'
        except BaseException:
            stop = 'failed'
            raise
        finally:
            terminate(active)
            for item in active.values():
                job = item['job']
                job['status'] = job['attempts'][-1]['state'] = stop or 'interrupted'
            session['elapsed_seconds'] = time.monotonic()-started
            plan['elapsed_seconds'] = elapsed_before + session['elapsed_seconds']
            session['state'] = plan['status'] = stop or 'failed'
            signal.signal(signal.SIGTERM, old_handler)
            save_plan(root, plan)
        return 0 if stop == 'complete' else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume', type=Path)
    parser.add_argument('--proposal', type=Path, default=ROOT/'reports/benchmark-planning/plan.json')
    parser.add_argument('--output-root', type=Path, default=ROOT/'results/benchmark')
    parser.add_argument('--ns3', type=Path, default=ROOT.parent/'ns-o-ran-ns3-mmwave')
    parser.add_argument('--job', help=argparse.SUPPRESS)
    parser.add_argument('--attempt', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--prepare-only', action='store_true', help='Snapshot inputs/SDK without executing experiments')
    args = parser.parse_args(argv)
    if args.resume:
        root = args.resume.resolve()
        plan = json.loads((root/'campaign.json').read_text())
        if plan.get('format') != 'rf-ip-training-benchmark-v1':
            parser.error('Use collect_campaign --resume for legacy telemetry campaigns')
        if Path(__file__).resolve() != root/'runtime/simulation/run_benchmark.py':
            verify_freeze(root, plan)
            command = [sys.executable, str(root/'runtime/lab.py'), 'run_benchmark', '--resume', str(root)]
            if args.job:
                command += ['--job', args.job, '--attempt', str(args.attempt)]
            if args.prepare_only:
                command += ['--prepare-only']
            os.execv(sys.executable, command)
    else:
        os.sched_setaffinity(0, set(physical_cpus()))
        root, plan = make_plan(args.output_root.resolve(), args.proposal.resolve(), args.ns3.resolve())
    if args.job:
        verify_freeze(root, plan)
        job = next(j for j in plan['jobs'] if j['id'] == args.job)
        execute_job(root, plan, job, args.attempt.resolve())
        return 0
    print('Resume: python3 lab.py run_benchmark --resume', root, flush=True)
    if args.prepare_only:
        return 0
    return run_queue(root, plan)


if __name__ == '__main__':
    raise SystemExit(main())
