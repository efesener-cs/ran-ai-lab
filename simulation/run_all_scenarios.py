"""Run every provided RF/IP scenario in fresh directories; default: prepared Docker container."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from labcore.paths import ROOT
from labcore.runtime_bundle import copy_runtime
from labcore.provenance import source_hashes
from labcore.scenario_sdk import stage_sdk


def atomic_json(path, value):
    temp = path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(value, indent=2, allow_nan=False)+'\n')
    temp.replace(path)


def call(command, log, cwd=None):
    with log.open('a') as handle:
        handle.write('\n$ '+repr(command)+'\n')
        handle.flush()
        return subprocess.call(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend', choices=['docker', 'host'], default='docker')
    p.add_argument('--container', default='ran-lab')
    p.add_argument('--scenario-dir', type=Path, default=ROOT/'examples/scenarios')
    p.add_argument('--output-root', type=Path, default=ROOT/'results/all-scenarios')
    p.add_argument('--only', choices=['all', 'rf', 'ip', 'training'], default='all')
    p.add_argument('--ns3', type=Path, help='Explicit SDK path in the selected environment')
    p.add_argument('--prepared-sdk', type=Path, help='Host prebuilt SDK to stage into Docker')
    p.add_argument('--seeds', type=int, nargs=3, default=[11, 23, 37])
    p.add_argument('--quick', action='store_true', help='All modes, smaller smoke-test data/durations')
    p.add_argument('--rf-train-samples', type=int, default=2400)
    p.add_argument('--rf-eval-samples', type=int, default=600)
    p.add_argument('--rf-epochs', type=int, default=80)
    p.add_argument('--rf-steps', type=int, default=30)
    p.add_argument('--ip-duration', type=int, default=120)
    return p


def main(argv=None):
    p = parser()
    a = p.parse_args(argv)
    if len(set(a.seeds)) != 3 or min(a.seeds) < 1 or max(a.seeds) > 2147483647:
        p.error('three distinct positive int31 seeds required (train/validation/test)')
    if min(a.rf_train_samples, a.rf_eval_samples) < 60 or min(a.rf_epochs, a.rf_steps) < 1 or not 8 <= a.ip_duration <= 7200:
        p.error('invalid sample count, epochs/steps or duration')
    inputs = {}
    if a.only in ('all', 'rf', 'training'):
        inputs['rf'] = a.scenario_dir.resolve()/'rf-ai-frames.cc'
    if a.only in ('all', 'training'):
        inputs['training'] = a.scenario_dir.resolve()/'training-data-attacks.cc'
    if a.only in ('all', 'ip'):
        inputs['ip'] = a.scenario_dir.resolve()/'ip-network-attacks.cc'
    for path in inputs.values():
        if not path.is_file():
            p.error('Scenario missing: '+str(path))
    a.output_root = a.output_root.resolve()
    a.output_root.mkdir(parents=True, exist_ok=True)
    prefix = 'run-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'-'
    out = Path(tempfile.mkdtemp(prefix=prefix, dir=a.output_root))
    result = out/'result'
    log = out/'launcher.log'
    remote = '/tmp/ran-ai-all-'+out.name
    manifest = dict(state='preparing', backend=a.backend, container=a.container,
                    output=str(out), remote=remote if a.backend == 'docker' else None, inputs={})
    atomic_json(out/'launcher.json', manifest)
    latest = a.output_root/('latest-'+out.name)
    latest.symlink_to(out.name, target_is_directory=True)
    latest.replace(a.output_root/'latest')
    print('Sonuc dizini:', out, flush=True)
    print('Canli log:', out/'batch.log', flush=True)
    code = 1
    extraction_ready = False
    try:
        with tempfile.TemporaryDirectory(prefix='ran-ai-all-bundle-') as folder:
            bundle = Path(folder)
            copy_runtime(ROOT, bundle/'runtime')
            manifest['runtime_sha256'] = source_hashes(bundle/'runtime')
            (bundle/'inputs').mkdir()
            for name, path in inputs.items():
                target = bundle/'inputs'/path.name
                shutil.copy2(path, target)
                manifest['inputs'][name] = dict(origin=str(path), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            config = dict(only=a.only, seeds=a.seeds, quick=a.quick, result='', rf_scenario='', ip_scenario='',
                          rf_train=180 if a.quick else a.rf_train_samples,
                          rf_eval=60 if a.quick else a.rf_eval_samples,
                          rf_epochs=3 if a.quick else a.rf_epochs, rf_steps=3 if a.quick else a.rf_steps,
                          rf_length=64 if a.quick else 128, ip_duration=12 if a.quick else a.ip_duration,
                          ns3_candidates=[])
            envroot = str(out) if a.backend == 'host' else remote
            config['result'] = envroot+'/result'
            for name, path in inputs.items():
                config[name+'_scenario'] = envroot+'/inputs/'+path.name
            if a.ns3:
                config['ns3_candidates'] = [str(a.ns3)]
            elif a.backend == 'host':
                config['ns3_candidates'] = [str(ROOT.parent/'ns-o-ran-ns3-mmwave')]
            elif a.only in ('all', 'ip'):
                prepared = a.prepared_sdk or Path.home()/'ran-ai-lab-shared/work/ns-o-ran-ns3-mmwave'
                ready = prepared.parent/'READY.json'
                if prepared.is_dir() and (ready.is_file() or a.prepared_sdk):
                    try:
                        print('Hazir native SDK paketleniyor (derleme yok)...', flush=True)
                        manifest['staged_sdk'] = stage_sdk(prepared, bundle/'sdk', remote+'/sdk')
                        config['ns3_candidates'].append(remote+'/sdk')
                    except (OSError, ValueError, subprocess.CalledProcessError) as error:
                        manifest['sdk_staging_error'] = str(error)
                        print('SDK paketleme basarisiz; mevcut container yollari denenecek:', error, flush=True)
                config['ns3_candidates'] += ['/work/ns-o-ran-ns3-mmwave', '/opt/ns-o-ran-ns3-mmwave']
            atomic_json(bundle/'batch-config.json', config)
            atomic_json(out/'launcher.json', manifest)
            for name in ('inputs', 'runtime'):
                shutil.copytree(bundle/name, out/name)
            shutil.copy2(bundle/'batch-config.json', out/'batch-config.json')
            if a.backend == 'docker':
                if shutil.which('docker') is None:
                    raise RuntimeError('docker komutu bulunamadi')
                state = subprocess.check_output(['docker', 'inspect', '-f', '{{.State.Running}}', a.container], text=True).strip()
                if state != 'true':
                    subprocess.run(['docker', 'start', a.container], check=True)
                archive = bundle/'bundle.tar.gz'
                with tarfile.open(archive, 'w:gz', compresslevel=1, dereference=True) as tar:
                    for name in ('runtime', 'inputs', 'batch-config.json', 'sdk'):
                        if (bundle/name).exists():
                            tar.add(bundle/name, arcname=name)
                for command in (['docker','exec',a.container,'mkdir','-p',remote],
                                ['docker','cp',str(archive),a.container+':'+remote+'/bundle.tar.gz'],
                                ['docker','exec',a.container,'tar','-xzf',remote+'/bundle.tar.gz','-C',remote]):
                    if call(command, log):
                        raise RuntimeError('Container hazirligi basarisiz; launcher.log dosyasina bakin')
                extraction_ready = True
                command = ['docker','exec',a.container,'python3',remote+'/runtime/lab.py',
                           'run_batch_worker','--config',remote+'/batch-config.json']
            else:
                command = [sys.executable,str(out/'runtime/lab.py'),'run_batch_worker','--config',str(out/'batch-config.json')]
            manifest['state'] = 'running'
            atomic_json(out/'launcher.json', manifest)
            with (out/'batch.log').open('w') as handle:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    for line in process.stdout:
                        print(line, end='', flush=True)
                        handle.write(line); handle.flush()
                    code = process.wait()
                except KeyboardInterrupt:
                    if a.backend == 'docker':
                        call(['docker','exec',a.container,'python3','-c',
                              'import os,signal,sys; from pathlib import Path; p=Path(sys.argv[1]); '
                              'os.killpg(int(p.read_text()),signal.SIGTERM) if p.is_file() else None',
                              remote+'/result/worker.pid'], log)
                    else:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            process.terminate()
                    process.wait()
                    code = 130
    except KeyboardInterrupt:
        code = 130
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        manifest['error'] = str(error)
        print('Hata:', error, flush=True)
        with log.open('a') as handle: handle.write(str(error)+'\n')
    finally:
        if a.backend == 'docker' and extraction_ready:
            result.mkdir(exist_ok=True)
            copied = call(['docker','cp',a.container+':'+remote+'/result/.',str(result)], log)
            if copied:
                manifest['copy_failed'] = True
                code = code or 1
                print('Sonuc kopyalanamadi; container dizini:', remote, flush=True)
        summary = result/'summary.json'
        if code == 0:
            if not summary.is_file() or json.loads(summary.read_text()).get('state') != 'completed':
                code = 1
                manifest['error'] = 'Worker complete kaniti yok; basarili sayilmadi'
        manifest['exit_code'] = code
        manifest['state'] = 'completed' if code == 0 else ('interrupted' if code == 130 else 'failed')
        atomic_json(out/'launcher.json', manifest)
        result.mkdir(exist_ok=True)
        if not (result/'SUMMARY.md').is_file():
            (result/'SUMMARY.md').write_text('# Batch startup failure\n\n'+
                manifest.get('error', 'See launcher.log and batch.log.')+'\n')
        print('\nSonuc dizini:', out, flush=True)
        print('Ozet:', result/'SUMMARY.md', flush=True)
        print('Durum:', manifest['state'], flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
