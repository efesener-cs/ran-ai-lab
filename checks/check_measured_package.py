"""Standalone offline validation of ran-measured-evidence-v1 packages."""
import argparse
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re


def digest(path):
    result=hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024),b''):
            result.update(block)
    return result.hexdigest()


def safe_file(root,name):
    if not isinstance(name,str) or '\\' in name or PurePosixPath(name).is_absolute() or any(p in ('','.','..') for p in name.split('/')):
        raise ValueError('Unsafe package path')
    path=root/name
    if any(p.is_symlink() for p in (path,*path.parents) if p!=root.parent) or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError('Missing or escaping package file: '+name)
    return path


def verify(root):
    root=Path(root).resolve(strict=True)
    inventory={}
    for line in (root/'checksums.sha256').read_text().splitlines():
        match=re.fullmatch(r'([a-f0-9]{64})  (.+)',line)
        if not match:
            raise ValueError('Malformed checksum')
        sha,name=match.groups()
        if name in inventory or name=='checksums.sha256':
            raise ValueError('Duplicate checksum')
        path=safe_file(root,name)
        if digest(path)!=sha:
            raise ValueError('Checksum mismatch: '+name)
        inventory[name]=sha
    actual=set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in package')
        if path.is_file() and path.name!='checksums.sha256':
            actual.add(path.relative_to(root).as_posix())
    if actual!=set(inventory):
        raise ValueError('Incomplete checksum inventory')
    index=json.loads((root/'package-index.json').read_text())
    if index.get('format')!='ran-measured-evidence-v1' or index.get('state')!='complete':
        raise ValueError('Wrong format or incomplete build')
    provenance=json.loads((root/'file-provenance.json').read_text())
    for name,record in provenance['files'].items():
        path=safe_file(root,name)
        if inventory.get(name)!=record['sha256'] or path.stat().st_size!=record['bytes']:
            raise ValueError('Published payload provenance mismatch')
        if record['transformation']=='gzip-lossless':
            original=hashlib.sha256()
            with gzip.open(path,'rb') as handle:
                for block in iter(lambda: handle.read(1024*1024),b''):
                    original.update(block)
            if original.hexdigest()!=record['source_sha256']:
                raise ValueError('Lossless source reconciliation failed')
        elif record['transformation']=='byte-identical' and inventory[name]!=record['source_sha256']:
            raise ValueError('Original source hash mismatch')
    for path in root.rglob('*.json'):
        text=path.read_text()
        if re.search(r'/(?:home|tmp|work|usr)/',text):
            raise ValueError('Machine-local path exposed: '+str(path.relative_to(root)))
    plan=json.loads((root/'provenance/campaign.json').read_text())
    if plan['status']!='complete' or len(plan['jobs'])!=index['jobs'] or any(j['status']!='complete' for j in plan['jobs']):
        raise ValueError('Campaign not complete')
    split=json.loads((root/'splits/ip.json').read_text())
    seen_groups=set();total=0;positives=0
    for role in ('train','validation','test'):
        counts=split['counts'][role];groups=set(counts['groups'])
        if not groups or seen_groups & groups:
            raise ValueError('IP split group leakage')
        seen_groups.update(groups)
        rows=hits=0;observed=set();runs={}
        with gzip.open(safe_file(root,split['table_paths'][role]),'rt',newline='') as handle:
            reader=csv.DictReader(handle)
            if set(split['feature_columns']) & set(split['excluded_from_features']):
                raise ValueError('Feature/target leakage')
            for row in reader:
                seed=int(row['seed']);expected='train' if 4001<=seed<=4010 else 'validation' if 5001<=seed<=5005 else 'test' if 6001<=seed<=6010 else None
                if expected!=role or row['split']!=role or row['source_group_id'] not in groups:
                    raise ValueError('IP seed/split mismatch')
                if row['source_group_id']!='ip-s'+str(seed)+'-r1' or row['run']!='1':
                    raise ValueError('IP identity mismatch')
                if int(row['window_index'])!=runs.get(row['run_id'],0):
                    raise ValueError('Duplicate, missing or reordered IP window')
                runs[row['run_id']]=runs.get(row['run_id'],0)+1
                start=float(row['window_start_s']);end=float(row['window_end_s'])
                if abs(start-(10+int(row['window_index'])*.1))>1e-7 or abs(end-start-.1)>1e-7:
                    raise ValueError('Nonclosed IP window')
                active=sum(int(row[k]) for k in ('attack_tx_packets','attack_rx_packets','attack_drop_packets'))>0
                if row['attack_applied'] not in ('0','1') or int(row['attack_applied'])!=int(active):
                    raise ValueError('IP observed-activity label mismatch')
                for key in split['feature_columns']:
                    if not math.isfinite(float(row[key])):
                        raise ValueError('Nonfinite IP feature')
                observed.add(row['source_group_id']);rows+=1;hits+=int(active)
        if observed!=groups or rows!=counts['rows'] or hits!=counts['positives'] or len(runs)!=counts['runs'] or any(n!=3000 for n in runs.values()):
            raise ValueError('IP count/group reconciliation failed')
        total+=rows;positives+=hits
    if total!=1800000:
        raise ValueError('Incomplete confirmatory IP matrix')
    rf=json.loads((root/'splits/rf.json').read_text());seeds={role:set() for role in ('train','validation','test')}
    for block in rf['blocks']:
        for role,entry in block['splits'].items():
            safe_file(root,entry['path']);seeds[role].add(entry['seed'])
    if len(rf['blocks'])!=60 or seeds['train'] & (seeds['validation']|seeds['test']) or seeds['validation'] & seeds['test']:
        raise ValueError('RF seed split leakage or missing blocks')
    arrays=0
    try:
        import numpy as np
    except ImportError:
        np=None
    if np is not None:
        for path in (root/'evidence').rglob('*.npz'):
            with np.load(path,allow_pickle=False) as data:
                for name in data:
                    array=data[name]
                    if array.dtype.hasobject:
                        raise ValueError('Pickle/object array forbidden')
                    if array.dtype.kind in 'fc' and not np.isfinite(array).all():
                        raise ValueError('Nonfinite NPZ array')
                    if name=='delta' and array.dtype!=np.float64:
                        raise ValueError('Canonical perturbation precision changed')
                    arrays+=1
    status=json.loads((root/'publication-status.json').read_text())
    return dict(integrity_verified=True,ip_rows=total,ip_positives=positives,jobs=index['jobs'],
                files=len(inventory),npz_arrays_checked=arrays,numpy_available=np is not None,
                metadata_ready=status['metadata_ready'],scientific_metrics_recomputed=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('package',type=Path);a=p.parse_args(argv)
    print(json.dumps(verify(a.package),indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
