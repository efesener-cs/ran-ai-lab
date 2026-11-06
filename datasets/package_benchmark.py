"""Package a completed benchmark without generating new data or uploading it.

The measured-evidence format preserves original domain-specific schemas. It is
separate from the proposed seven-table normalized schema.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

FORMAT = 'ran-measured-evidence-v1'
ROLES = ('train', 'validation', 'test')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def scrub(value, root):
    """Keep package-local references; redact unrelated machine-specific paths."""
    if isinstance(value, dict):
        return {k: scrub(v, root) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, root) for v in value]
    if isinstance(value, str):
        # Replace longest prefix first. No absolute source-machine paths survive.
        value = value.replace(str(root) + '/', 'campaign:/')
        value = value.replace(str(root), 'campaign:')
        value = re.sub(r'/(?:home|work|tmp|usr|opt|lib|bin|mnt|media|run|var)(?:/[^\s\"\'\[\],;]*)?', '<local-path>', value)
        return value
    return value


def package_file(source, target, expected, campaign):
    """Hash the exact source while losslessly copying/compressing its payload."""
    if source.is_symlink() or not source.resolve().is_relative_to(campaign):
        raise ValueError('Escaping source file')
    target.parent.mkdir(parents=True, exist_ok=True)
    original = hashlib.sha256()
    if source.suffix == '.json':
        data = source.read_bytes()
        original.update(data)
        write_json(target, scrub(json.loads(data), campaign))
        transformation = 'json-path-redaction'
    else:
        compress = source.suffix in ('.csv', '.xml')
        with source.open('rb') as src, target.open('wb') as raw:
            dst = gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=1, mtime=0) if compress else raw
            try:
                for block in iter(lambda: src.read(1024 * 1024), b''):
                    original.update(block)
                    dst.write(block)
            finally:
                if compress:
                    dst.close()
        transformation = 'gzip-lossless' if compress else 'byte-identical'
    if original.hexdigest() != expected:
        raise ValueError('Receipt hash mismatch: ' + str(source))
    return dict(source_sha256=expected, transformation=transformation,
                bytes=target.stat().st_size, sha256=digest(target))


def ip_split(seed):
    if 4001 <= seed <= 4010:
        return 'train'
    if 5001 <= seed <= 5005:
        return 'validation'
    if 6001 <= seed <= 6010:
        return 'test'
    raise ValueError('Unknown confirmatory IP seed')


def write_ip(campaign, plan, out, spec):
    from contextlib import ExitStack
    features = spec['tables']['ip_windows']['feature_columns']
    audit = ['run_id', 'source_group_id', 'context_id', 'split', 'window_index',
             'window_start_s', 'window_end_s', 'attack_applied', 'attack_scheduled',
             'attack_family', 'attack_families', 'seed', 'run', 'attack_tx_packets',
             'attack_rx_packets', 'attack_drop_packets', 'benign_rx_ip_bytes',
             'benign_app_rx_bytes']
    columns = audit + features
    counts = {role: dict(rows=0, positives=0, runs=0, groups=[]) for role in ROLES}
    (out/'ip').mkdir()
    with ExitStack() as stack:
        writers = {}
        for role in ROLES:
            handle = stack.enter_context(gzip.open(out/'ip'/(role+'.csv.gz'), 'wt', newline=''))
            writers[role] = csv.DictWriter(handle, fieldnames=columns)
            writers[role].writeheader()
        for job in plan['jobs']:
            if job['kind'] != 'ip' or job['phase'] != 'main':
                continue
            seed = job['seed']
            role = ip_split(seed)
            group = 'ip-s'+str(seed)+'-r1'
            if group not in counts[role]['groups']:
                counts[role]['groups'].append(group)
            context = job['id'].split('-')[2]
            source = campaign/job['attempts'][-1]['directory']/'result/raw/ip_windows.csv'
            n = 0
            with source.open(newline='') as handle:
                for index, row in enumerate(csv.DictReader(handle)):
                    if row['group_id'] != group or int(row['seed']) != seed or int(row['run']) != 1:
                        raise ValueError('IP source identity mismatch')
                    active = int(row['attack_tx_packets']) + int(row['attack_rx_packets']) + int(row['attack_drop_packets']) > 0
                    if int(row['label']) != int(active):
                        raise ValueError('IP observed-activity label mismatch')
                    result = {key: row[key] for key in features}
                    result.update(run_id=job['id'], source_group_id=group, context_id=context,
                                  split=role, window_index=index,
                                  window_start_s=row['window_start_s'], window_end_s=row['window_end_s'],
                                  attack_applied=int(active), attack_scheduled=row['attack_scheduled'],
                                  attack_family=row['attack_type'], attack_families=row['attack_types'],
                                  seed=seed, run=1)
                    for key in ('attack_tx_packets','attack_rx_packets','attack_drop_packets','benign_rx_ip_bytes','benign_app_rx_bytes'):
                        result[key] = row[key]
                    writers[role].writerow(result)
                    counts[role]['rows'] += 1
                    counts[role]['positives'] += int(active)
                    n += 1
            if n != 3000:
                raise ValueError('Expected 3000 windows per confirmatory run')
            counts[role]['runs'] += 1
    split = dict(track='wired-ip', table_paths={role:'ip/'+role+'.csv.gz' for role in ROLES},
                 group_column='source_group_id', feature_columns=features, target_column='attack_applied',
                 excluded_from_features=audit, policy='Seed/run groups stay together across all modes and contexts; no balancing.',
                 counts=counts)
    write_json(out/'splits/ip.json', split)
    return split


def write_docs(out, plan, index, schema):
    card = '''# RAN AI synthetic adversarial benchmark

Measured synthetic receiver-IQ, local classifier training-integrity experiments,
and wired ns-3 IP traffic. This dataset does not establish over-the-air attacks,
cellular RAN effects, live RIC control, wideband/MIMO/RIS robustness, or broad
state-of-the-art coverage. The victim is a moment-feature MLP baseline.

## Contents and identity

60 RF blocks (3 profiles x 4 SNRs x 5 repetitions), 1,980 RF task/condition
results, 5 training studies (130 model conditions), 600 confirmatory IP runs
(1,800,000 closed 100 ms windows), and 8 separate pilot runs. Failed/interrupted
attempts remain in provenance/attempts.csv; partial payloads stay in the original
campaign, rather than appearing as successful samples.

The format is `ran-measured-evidence-v1`. Original CSV headers and NPZ arrays are
preserved. This is not the proposed seven-table `0.1-draft` normalized schema.
Every successful result CSV, JSON, model/audit NPZ and flow-monitor XML is included
under evidence/JOB_ID, except logs, compiled binaries and repeated scenario code.
CSV/XML use lossless gzip. JSON machine paths are redacted; original and packaged
hashes plus transformations are recorded in file-provenance.json. Existing
source evidence manifests refer to original bytes; checksums.sha256 verifies the
published bytes. Provenance hashes identify omitted runtime/scenario dependencies;
no third-party SDK, binaries, credentials or local documents are bundled.

## Labels and safe features

IP `attack_applied` means observed attack-origin TX/RX/drop, not attack success.
IP features are ONLY the explicit whitelist in splits/ip.json. Endpoints,
seed/group/context IDs, schedule, attack counters and benign-only breakdowns
are audit information; never auto-select every numeric column as a feature.
Validation and test retain measured prevalence. No artificial 80/20 balancing.

Raw RF `label` is the true occupancy/AMC target, not attack presence. Channel
truth h_i/h_q is a target, never a feature. Raw IQ is float64 as written; NPZ
files load with allow_pickle=False. In each RF block, train/validation/test CSVs
have separate seeds; keep profile/SNR variants of a seed together. A task/frame
identity is (block ID, split, task, frame ID); IDs alone are not globally unique.
NPZ audit delta is added to the corresponding clean TEST task frame. File names
identify method and dB power budget. `none` and `pgd-zero` are controls; random
perturbations are benign corruption controls, not malicious attacks. Physical
interference sidecars are separate receiver-additive data, not OTA validation.

Training labels may be deliberately poisoned. Use the audit's clean_label as
truth and training_label as the supplied label; selected does not by itself mean
a changed row. Triggered/random test probes retain true labels. A poisoned model
does not turn every clean test sample into an attacked input. Models, transforms,
metrics and selected epochs are retained per condition. Rates with no eligible
samples must remain null. Do not pool the three data domains into one table.

## Validation and limitations

Source files were checked against all successful attempt receipts. Exported IP
counts, seed splits, observed-activity labels and finite whitelisted features are
checked. All package files have SHA-256 coverage. Per-job scientific checkers ran
during collection; packaging does not replace them with a new scientific audit.
The loader notebook independently validates hashes, IP rows/groups and NPZ dtypes.
No new experiments or test-based parameter tuning occur during export. OOD,
unseen-model robustness, defenses and literature superiority are not claimed.

## Licensing and publication

See LICENSE.txt and publication-status.json. Metadata is a template until owner,
slug and data-license decisions are supplied. Preparing this local artifact is
not authorization to upload it. Source code has separate licensing (repository
NOTICE.md); no code or dependency license is implicitly applied to the data.
'''
    (out/'DATASET_CARD.md').write_text(card)
    (out/'README.md').write_text('''# RAN AI measured benchmark package

Start with DATASET_CARD.md, DATA_DICTIONARY.csv and notebooks/01_load_and_validate.ipynb.
`ip/train.csv.gz`, `ip/validation.csv.gz`, `ip/test.csv.gz` are ready for pandas.
`evidence/` preserves RF, training, IP and pilot measurements separately.
Use `gzip.open(path, "rt")` for CSVs and `numpy.load(path, allow_pickle=False)` for NPZ.
Run `python validate_package.py .` offline to validate this package.
See package-index.json for counts and provenance/ for experiment configuration.
Publication decisions are recorded in publication-status.json. No upload performed.
''')
    (out/'LICENSE.txt').write_text('Data license not selected. No open data license is granted by this draft.\nOriginal authors retain rights. Choose a data license before publication.\n')
    write_json(out/'dataset-metadata.template.json', dict(title='RAN AI Adversarial Synthetic Benchmark',
               id='YOUR_KAGGLE_USERNAME/ran-ai-adversarial-benchmark', licenses=[],
               description=card))
    write_json(out/'publication-status.json',dict(uploaded=False, metadata_ready=False,
                pending=['data_license','kaggle_owner_and_slug']))
    (out/'CITATION.bib').write_text('@misc{ran_ai_benchmark_2026,\n  title={RAN AI Synthetic RF, Training Integrity and IP Benchmark},\n  year={2026},\n  howpublished={Local measured dataset; public DOI/version not yet assigned},\n  url={https://github.com/efesener-cs/ran-ai-lab}\n}\n')
    with (out/'DATA_DICTIONARY.csv').open('w',newline='') as handle:
        w=csv.writer(handle);w.writerow(['table','column','role','description'])
        for name, rule in schema['tables'].items():
            if name != 'ip_windows':
                continue
            for key in rule['feature_columns']:
                w.writerow(['ip/*.csv.gz',key,'feature','Observed window measurement; see docs/IP_ATTACKS.md in repository'])
        for key in index['ip']['excluded_from_features']:
            w.writerow(['ip/*.csv.gz',key,'target' if key=='attack_applied' else 'audit','Excluded from model features'])
        for column,role,desc in [('task','identity','sensing/amc/channel'),('id','identity','Frame index within task/split/block'),('label','task_target','Occupancy/AMC truth; not an attack flag'),('h_i,h_q','task_target','Complex scalar channel truth'),('i0,q0,...','feature','Float64 receiver IQ samples'),('delta','feature_derivation','NPZ additive delta for test frames; controls distinguished by filename'),('clean_label','audit','Original true class in training-row audit'),('training_label','training_target','May intentionally differ from truth'),('selected','audit','Selected for transformation, not proof of change')]:
            w.writerow(['evidence/RF-or-training',column,role,desc])
    write_json(out/'versions.json',dict(export_python=sys.version,created_utc=datetime.now(timezone.utc).isoformat(),
                campaign_format=plan['format'], runtime_sha256=plan['runtime_sha256'],
                scenario_sha256=plan['input_sha256'], source_receipts_verified=True))


def export(campaign, output, workers=2):
    campaign=Path(campaign).resolve(strict=True);output=Path(output).resolve()
    if output.is_relative_to(campaign) or campaign.is_relative_to(output):
        raise ValueError('Output must be outside source campaign')
    plan=json.loads((campaign/'campaign.json').read_text())
    if plan.get('status')!='complete' or any(j['status']!='complete' for j in plan['jobs']):
        raise ValueError('Only fully completed campaigns can be packaged')
    from simulation.run_benchmark import verify_freeze
    verify_freeze(campaign,plan)
    output.mkdir(parents=True,exist_ok=False)
    try:
        write_json(output/'build-status.json',dict(state='building',format=FORMAT))
        write_json(output/'provenance/campaign.json',scrub(plan,campaign))
        write_json(output/'provenance/proposal.json',scrub(json.loads((campaign/'proposal.json').read_text()),campaign))
        schema=json.loads((Path(__file__).parent/'specs/kaggle_schema.json').read_text())
        tasks=[];omitted=[];ledger=[]
        for job in plan['jobs']:
            for n,attempt in enumerate(job['attempts'],1):
                ledger.append(dict(job_id=job['id'],domain=job['kind'],phase=job['phase'],attempt_index=n,
                    state=attempt['state'],exit_code=attempt.get('exit_code',''),elapsed_seconds=attempt.get('elapsed_seconds',''),
                    successful_payload_included=n==len(job['attempts'])))
            attempt=job['attempts'][-1];directory=campaign/attempt['directory']
            if digest(directory/'receipt.json')!=attempt['receipt_sha256']:
                raise ValueError('Receipt changed: '+job['id'])
            receipt=json.loads((directory/'receipt.json').read_text())
            write_json(output/'provenance/receipts'/(job['id']+'.json'),receipt)
            for relative,sha in receipt['files'].items():
                source=directory/relative
                if source.suffix not in ('.csv','.json','.npz','.xml'):
                    if digest(source)!=sha:
                        raise ValueError('Omitted source hash mismatch')
                    omitted.append(dict(job_id=job['id'],path=relative,sha256=sha,reason='log/binary/code excluded from data release'))
                    continue
                name='evidence/'+job['id']+'/'+Path(relative).relative_to('result').as_posix()
                if source.suffix in ('.csv','.xml'):
                    name+='.gz'
                tasks.append((source,output/name,sha,campaign))
        with (output/'provenance/attempts.csv').open('w',newline='') as handle:
            w=csv.DictWriter(handle,fieldnames=list(ledger[0]));w.writeheader();w.writerows(ledger)
        files={}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for n,(task,record) in enumerate(zip(tasks,pool.map(lambda args: package_file(*args),tasks)),1):
                files[task[1].relative_to(output).as_posix()]=record
                if n%250==0:
                    print('Packaged',n,'/',len(tasks),'files',flush=True)
        write_json(output/'file-provenance.json',dict(files=files,omitted=omitted))
        ip=write_ip(campaign,plan,output,schema)
        rf=[]
        for job in plan['jobs']:
            if job['kind']=='rf':
                rf.append(dict(block_id=job['id'],profile=job['profile'],snr_db=job['snr_db'],repeat=job['repeat'],
                    splits={role:dict(seed=seed,path='evidence/'+job['id']+'/'+('train' if role=='train' else role)+'.csv.gz') for role,seed in zip(ROLES,job['seeds'])}))
        write_json(output/'splits/rf.json',dict(blocks=rf,policy='All profile/SNR variants of each seed remain in its assigned split; no OOD claim.'))
        index=dict(format=FORMAT,state='complete',jobs=len(plan['jobs']),attempts=len(ledger),
                   tracks=dict(rf_blocks=60,rf_conditions=1980,training_studies=5,training_conditions=130,ip_runs=600,pilot_runs=8),
                   ip=ip,raw_payload_files=len(files),normalized_seven_table_schema=False)
        write_docs(output,plan,index,schema)
        # Include a standalone, read-only validator; no simulation dependencies.
        shutil.copyfile(Path(__file__).parents[1]/'checks/check_measured_package.py',output/'validate_package.py')
        notebook={"nbformat":4,"nbformat_minor":5,"metadata":{"kernelspec":{"name":"python3","display_name":"Python 3","language":"python"}},"cells":[]}
        for kind,source in [('markdown','# Load and validate offline\nRun from the package root or notebooks directory. Only NumPy/pandas are optional for loading.'),('code',"from pathlib import Path\nimport subprocess, sys\nroot = Path.cwd()\nif root.name == 'notebooks':\n    root = root.parent\nsubprocess.run([sys.executable, str(root / 'validate_package.py'), str(root)], check=True)"),('code',"import pandas as pd\nimport json\nsplit = json.loads((root / 'splits/ip.json').read_text())\ntrain = pd.read_csv(root / 'ip/train.csv.gz')\nX = train[split['feature_columns']]\ny = train['attack_applied']\nprint(X.shape, y.value_counts())"),('code',"import numpy as np\npath = next((root / 'evidence').glob('rf-*/*-audit.npz'))\nwith np.load(path, allow_pickle=False) as arrays:\n    print({key: (arrays[key].shape, str(arrays[key].dtype)) for key in arrays})")]:
            cell=dict(cell_type=kind,metadata={},source=source.splitlines(keepends=True),id='cell-'+str(len(notebook['cells'])))
            if kind=='code':cell.update(execution_count=None,outputs=[])
            notebook['cells'].append(cell)
        write_json(output/'notebooks/01_load_and_validate.ipynb',notebook)
        write_json(output/'package-index.json',index)
        write_json(output/'build-status.json',dict(state='complete',format=FORMAT))
        enrich(output)
        write_checksums(output)
        return index
    except BaseException as error:
        write_json(output/'build-status.json',dict(state='failed',error=str(error)))
        raise


def write_checksums(root):
    with (root/'checksums.sha256').open('w') as handle:
        for path in sorted(root.rglob('*')):
            if path.is_file() and path.name!='checksums.sha256':
                handle.write(digest(path)+'  '+path.relative_to(root).as_posix()+'\n')



def enrich(root):
    """Add searchable condition summaries without recomputing measurements."""
    root=Path(root)
    def flatten(value,prefix='',result=None):
        if result is None:
            result={}
        for key,item in value.items():
            name=prefix+'.'+key if prefix else key
            if isinstance(item,dict):
                flatten(item,name,result)
            elif isinstance(item,list):
                result[name]=json.dumps(item,separators=(',',':'))
            else:
                result[name]=item
        return result
    versions=json.loads((root/'versions.json').read_text())
    versions['exporter_sha256']=digest(Path(__file__))
    write_json(root/'versions.json',versions)
    (root/'summaries').mkdir(exist_ok=True)
    for domain in ('rf','training'):
        rows=[]
        for source in sorted((root/'evidence').glob(domain+'-*/summary.json')):
            data=json.loads(source.read_text())
            for number,condition in enumerate(data['conditions']):
                row=dict(job_id=source.parent.name,condition_index=number)
                row.update(flatten(condition))
                rows.append(row)
        columns=list(dict.fromkeys(key for row in rows for key in row))
        with (root/'summaries'/(domain+'_conditions.csv')).open('w',newline='') as handle:
            writer=csv.DictWriter(handle,fieldnames=columns)
            writer.writeheader();writer.writerows(rows)
        expected=1980 if domain=='rf' else 130
        if len(rows)!=expected:
            raise ValueError('Condition count mismatch: '+domain)
    # Record every observed CSV header family, including unchanged raw schemas.
    known=set()
    with (root/'DATA_DICTIONARY.csv').open('a',newline='') as handle:
        writer=csv.writer(handle)
        for path in sorted((root/'evidence').rglob('*.csv.gz')):
            with gzip.open(path,'rt',newline='') as source:
                header=tuple(next(csv.reader(source)))
            if header in known:
                continue
            known.add(header)
            exemplar=path.relative_to(root).as_posix()
            for column in header:
                writer.writerow([exemplar,column,'raw_source_column',
                    'Preserved source schema; see DATASET_CARD.md for target/audit exclusions. This path exemplifies the header family.'])
        for path in sorted((root/'summaries').glob('*.csv')):
            with path.open(newline='') as source:
                for column in next(csv.reader(source)):
                    writer.writerow([path.relative_to(root).as_posix(),column,'model_outcome_audit','Flattened recorded condition field; not an input feature.'])

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('campaign',type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--workers',type=int,choices=(1,2),default=2)
    a=p.parse_args(argv)
    index=export(a.campaign,a.output,a.workers)
    print(json.dumps(index['tracks'],indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
