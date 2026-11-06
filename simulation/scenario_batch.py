"""Execute a snapshotted RF/IP batch in the current environment (internal runner)."""
import argparse
import csv
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
from labcore.paths import ROOT
from simulation.run_all_scenarios import atomic_json

IP_MODES = ('none','udp_flood','udp_ddos','pulsed_udp','udp_port_scan',
            'tcp_connection_churn','icmp_flood','mixed')
RF_PROFILES = ('baseline','diverse','stress')


def validate_ip(folder, mode, seed):
    status = json.loads((folder/'run_status.json').read_text())
    if status.get('status') != 'complete':
        raise ValueError('IP simulation completion evidence missing')
    meta = json.loads((folder/'raw/ip_dataset.json').read_text())
    with (folder/'raw/ip_windows.csv').open(newline='') as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != meta['windows'] or meta['seed'] != seed or meta['attack'] != mode:
        raise ValueError('IP size/seed/mode mismatch')
    positives = 0
    for row in rows:
        support = sum(int(row[key]) for key in ('attack_tx_packets','attack_rx_packets','attack_drop_packets'))
        if int(row['label']) != int(support > 0) or row['group_id'] != 'ip-s'+str(seed)+'-r1':
            raise ValueError('IP ground-truth label/group mismatch')
        positives += int(row['label'])
        for key in meta['feature_columns']:
            if not math.isfinite(float(row[key])) or float(row[key]) < 0:
                raise ValueError('Invalid IP feature: '+key)
    if abs(meta['observed_attack_fraction']-positives/len(rows)) > 1e-12:
        raise ValueError('IP prevalence mismatch')
    if (mode == 'none' and positives) or (mode != 'none' and not positives):
        raise ValueError('IP attack/control support missing or unexpected')
    return dict(rows=len(rows), positives=positives, metadata=meta)


def sample_training(rows, feature_columns, seed):
    # Matched variants can share identical benign windows; retain a single copy.
    clean, attack, seen = [], [], set()
    for row in rows:
        if row['label'] == '1':
            attack.append(row)
        else:
            key = (row['group_id'], row['window_start_s'], *(row[k] for k in feature_columns))
            if key not in seen:
                seen.add(key); clean.append(row)
    n = min(len(attack), len(clean)//4)
    if n < 1:
        raise ValueError('Cannot form 80/20 training mixture without inventing rows')
    rng = random.Random(seed)
    rng.shuffle(clean); rng.shuffle(attack)
    first_by_type, remaining = {}, []
    for row in attack:
        if row['attack_type'] not in first_by_type:
            first_by_type[row['attack_type']] = row
        else:
            remaining.append(row)
    if n < len(first_by_type):
        raise ValueError('Too few clean rows for 80/20 while preserving all observed attack types')
    selected = clean[:4*n]+list(first_by_type.values())+remaining[:n-len(first_by_type)]
    rng.shuffle(selected)
    return selected


def merge_ip(result, seeds):
    destination = result/'datasets/ip'
    destination.mkdir(parents=True, exist_ok=False)
    record = dict(target='label', mixture='80/20 training only; validation/test retain observed prevalence',
                  grouping='same seed/run across all modes stays in one split', files={})
    feature_columns = None
    seen_groups = set()
    for split, seed in zip(('train','validation','test'), seeds):
        combined, header = [], None
        for mode in IP_MODES:
            folder = result/'ip'/('seed-'+str(seed))/mode
            meta = json.loads((folder/'raw/ip_dataset.json').read_text())
            if feature_columns is None:
                feature_columns = meta['feature_columns']
            elif feature_columns != meta['feature_columns']:
                raise ValueError('Cannot merge incompatible IP feature schemas')
            with (folder/'raw/ip_windows.csv').open(newline='') as handle:
                reader = csv.DictReader(handle)
                if header is None:
                    header = reader.fieldnames
                elif header != reader.fieldnames:
                    raise ValueError('IP CSV header mismatch')
                for row in reader:
                    row['condition'] = mode
                    combined.append(row)
        original_count = len(combined)
        if split == 'train':
            combined = sample_training(combined, feature_columns, seed+900001)
        groups = set(row['group_id'] for row in combined)
        if seen_groups & groups:
            raise ValueError('IP group leakage across splits')
        seen_groups.update(groups)
        path = destination/(split+'.csv')
        temporary = path.with_suffix('.csv.tmp')
        with temporary.open('w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=header+['condition'])
            writer.writeheader(); writer.writerows(combined)
        temporary.replace(path)
        positives = sum(int(row['label']) for row in combined)
        by_type = {}
        for row in combined:
            by_type[row['attack_type']] = by_type.get(row['attack_type'],0)+1
        record['files'][split] = dict(file=path.name, seed=seed, raw_rows=original_count,
                                    rows=len(combined), clean=len(combined)-positives,
                                    attack=positives, attack_fraction=positives/len(combined), by_type=by_type)
    record['feature_columns'] = feature_columns
    record['exclude_from_features'] = [key for key in header+['condition'] if key not in feature_columns]
    atomic_json(destination/'dataset.json', record)
    return record


class Batch:
    def __init__(self, config):
        self.config = config
        self.root = Path(config['result'])
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root/'logs').mkdir()
        self.env = dict(os.environ, PYTHONUNBUFFERED='1')
        self.env['PYTHONPATH'] = str(ROOT)+os.pathsep+self.env.get('PYTHONPATH','')
        self.summary = dict(state='running', configuration=config, tasks=[], scientific_scope=
                            'Synthetic receiver-IQ and wired IP; no live RAN/E2/OTA acceptance')
        self.save()

    def save(self):
        atomic_json(self.root/'summary.json', self.summary)
        lines = ['# Scenario batch', '', 'State: '+self.summary['state'], '',
                 '| Task | Status | Log |', '|---|---|---|']
        for task in self.summary['tasks']:
            lines.append('| '+task['name']+' | '+task['state']+' | [log]('+task['log']+') |')
        lines += ['', 'RF: `rf/`; IP: `ip/`; labeled data: `datasets/`.',
                  'RF detectors: 80/20 per split. IP detector: 80/20 train; observed validation/test.',
                  'Seeds are split by train/validation/test; matched modes share a group.']
        (self.root/'SUMMARY.md').write_text('\n'.join(lines)+'\n')

    def skip(self, name, reason):
        self.summary['tasks'].append(dict(name=name, state='skipped', reason=reason, log=''))
        self.save()
        print('[SKIP]', name, reason, flush=True)

    def run(self, name, command, validate=None):
        logfile = 'logs/'+name.replace('/','-')+'.log'
        task = dict(name=name, state='running', command=command, log=logfile)
        self.summary['tasks'].append(task); self.save()
        print('[RUN]', name, flush=True)
        code = 1
        try:
            with (self.root/logfile).open('w') as handle:
                code = subprocess.call(command, env=self.env, stdout=handle, stderr=subprocess.STDOUT)
            if code:
                raise RuntimeError('Command exit code '+str(code))
            if validate:
                task['evidence'] = validate()
            task['state'] = 'completed'
            print('[OK]', name, flush=True)
            return True
        except KeyboardInterrupt:
            code = 130
            task.update(state='interrupted', error='Batch interrupted')
            raise
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            task.update(state='failed', error=str(error))
            print('[FAIL]', name, str(error), flush=True)
            with (self.root/logfile).open('a') as handle: handle.write('\nVALIDATION: '+str(error)+'\n')
            return False
        finally:
            task['exit_code'] = code
            self.save()

    def cli(self, name, *args):
        return [sys.executable, str(ROOT/'lab.py'), name, *map(str,args)]

    def ensure_numpy(self):
        needs_numpy = self.config['only'] in ('all','rf','training')
        if needs_numpy and importlib.util.find_spec('numpy') is None:
            target = self.root/'python-deps'
            if not self.run('numpy-install', [sys.executable,'-m','pip','install','--target',str(target),'numpy>=1.24,<3']):
                raise RuntimeError('NumPy unavailable; see numpy-install.log')
            self.env['PYTHONPATH'] = str(target)+os.pathsep+self.env.get('PYTHONPATH','')
        probe = 'import shutil; assert shutil.which("g++"), "g++ missing"'
        if needs_numpy:
            probe += '; import numpy; print(numpy.__version__)'
        if not self.run('python-preflight', [sys.executable,'-c',probe]):
            raise RuntimeError('Python/compiler preflight failed')

    def sdk(self):
        source = self.config['ip_scenario']
        for index, candidate in enumerate(self.config['ns3_candidates']):
            libs = str(Path(candidate)/'build/lib')
            self.env['LD_LIBRARY_PATH'] = libs+':/usr/local/lib:'+os.environ.get('LD_LIBRARY_PATH','')
            code = ('import subprocess,sys; from pathlib import Path; from scenario.source import build_native; '
                    'p=build_native(Path(sys.argv[1]),ns3=Path(sys.argv[2])); '
                    'subprocess.run([str(p),"--PrintHelp"],check=True)')
            # A failed candidate is diagnostic, not a failed scenario if another SDK passes.
            name = 'sdk-candidate-'+str(index)
            ok = self.run(name, [sys.executable,'-c',code,source,candidate])
            if not ok:
                self.summary['tasks'][-1]['state'] = 'rejected_sdk'
                self.save()
                continue
            self.summary['selected_ns3'] = candidate
            self.save()
            return candidate
        raise RuntimeError('No compatible prebuilt ns-3 SDK; see sdk-candidate logs (no rebuild attempted)')

    def rf(self, profiles=RF_PROFILES):
        c = self.config
        for profile in profiles:
            folder = self.root/'rf'/profile
            name = 'rf-'+profile
            command = self.cli('run_rf','--scenario',c['rf_scenario'],'--output',folder,
                               '--rf-profile',profile,'--train-samples',c['rf_train'],
                               '--eval-samples',c['rf_eval'],'--length',c['rf_length'],
                               '--epochs',c['rf_epochs'],'--steps',c['rf_steps'],'--seeds',*c['seeds'])
            if not self.run(name, command):
                self.skip(name+'-check', 'RF run failed'); self.skip(name+'-dataset', 'RF run failed')
                continue
            if self.run(name+'-check', self.cli('check_rf',folder)):
                self.run(name+'-dataset',self.cli('export_rf_detection',folder,'--output',
                         self.root/'datasets/rf'/profile,'--attack-fraction','.2','--psr-db','-10'))
            else:
                self.skip(name+'-dataset', 'RF verification failed')

    def training(self):
        ready = any(t['name']=='rf-diverse-check' and t['state']=='completed' for t in self.summary['tasks'])
        if not ready:
            self.skip('training-attacks','Verified diverse RF data is unavailable')
            return
        folder = self.root/'training-attacks'
        command = self.cli('run_training_attacks','--rf-run',self.root/'rf/diverse',
                           '--scenario',self.config['training_scenario'],'--output',folder,
                           '--epochs',self.config['rf_epochs'])
        if self.run('training-attacks',command):
            self.run('training-attacks-check',self.cli('check_training_attacks',folder))
        else:
            self.skip('training-attacks-check','Training study failed')

    def ip(self):
        c = self.config
        try:
            ns3 = self.sdk()
        except RuntimeError as error:
            for seed in c['seeds']:
                for mode in IP_MODES: self.skip('ip-'+str(seed)+'-'+mode,str(error))
            self.summary['ip_error'] = str(error)
            self.save()
            return
        complete = True
        for seed in c['seeds']:
            for mode in IP_MODES:
                folder = self.root/'ip'/('seed-'+str(seed))/mode
                command = self.cli('run_scenario','--scenario',c['ip_scenario'],'--ns3',ns3,
                                   '--output',folder,'--','--attack='+mode,'--simTime='+str(c['ip_duration']),
                                   '--warmup=2','--episodes=6','--clients=12','--attackers=12','--servers=3',
                                   '--attackFraction=0.2','--RngSeed='+str(seed),'--RngRun=1')
                def evidence(folder=folder, mode=mode, seed=seed):
                    data = validate_ip(folder,mode,seed)
                    return dict(rows=data['rows'], positives=data['positives'])
                if not self.run('ip-'+str(seed)+'-'+mode, command, evidence): complete = False
        if complete:
            name = 'ip-dataset'
            task = dict(name=name,state='running',log='logs/ip-dataset.log')
            self.summary['tasks'].append(task); self.save()
            try:
                task['evidence'] = merge_ip(self.root,c['seeds'])
                task['state'] = 'completed'
            except (OSError, ValueError, KeyError) as error:
                task.update(state='failed',error=str(error))
            (self.root/task['log']).write_text(json.dumps(task,indent=2)+'\n')
            self.save()
            print('['+('OK' if task['state']=='completed' else 'FAIL')+']',name,flush=True)
        else:
            self.skip('ip-dataset','At least one required IP condition failed')


def interrupted(signum, frame):
    raise KeyboardInterrupt()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    a = p.parse_args(argv)
    if os.getpgrp() != os.getpid(): os.setsid()
    signal.signal(signal.SIGTERM, interrupted)
    config = json.loads(a.config.read_text())
    batch = Batch(config)
    (batch.root/'worker.pid').write_text(str(os.getpid()))
    code = 1
    try:
        batch.ensure_numpy()
        if config['only'] in ('all','rf'): batch.rf()
        if config['only']=='training': batch.rf(('diverse',))
        if config['only'] in ('all','training'): batch.training()
        if config['only'] in ('all','ip'): batch.ip()
        failures = any(t['state'] in ('failed','skipped') for t in batch.summary['tasks']) or bool(batch.summary.get('ip_error'))
        code = 1 if failures else 0
        batch.summary['state'] = 'failed' if failures else 'completed'
    except KeyboardInterrupt:
        code = 130; batch.summary['state'] = 'interrupted'
    except (OSError, RuntimeError, ValueError) as error:
        batch.summary.update(state='failed',error=str(error)); print('Batch error:',error,flush=True)
    finally:
        (batch.root/'worker.pid').unlink(missing_ok=True)
        batch.save()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
