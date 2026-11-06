"""Export verified compact CSV splits for Kaggle review; never uploads data."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

try:
    from ai.research_ip_multilabel import FAMILIES, FEATURES, _verify_attempt, parse_families, sha256
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ai.research_ip_multilabel import FAMILIES, FEATURES, _verify_attempt, parse_families, sha256
from checks import check_ip_research


ROLE_NAMES = ('train', 'validation', 'test', 'ood')
TARGET_COLUMNS = tuple('target_' + family for family in FAMILIES)
OUTPUT_COLUMNS = ('sample_id', 'group_id', *FEATURES, 'attack_category',
                  'attack_families', *TARGET_COLUMNS)

FEATURE_DESCRIPTIONS = {
    'tx_packets': 'Outgoing IP packets observed during the closed window.',
    'tx_ip_bytes': 'Outgoing IP bytes including IP headers during the window.',
    'ip_rx_packets': 'Locally delivered IP packets during the window.',
    'ip_rx_ip_bytes': 'Locally delivered IP bytes including IP headers.',
    'bottleneck_queue_drops': 'Drops at the bottleneck device queue.',
    'bottleneck_qdisc_drops': 'Drops at the bottleneck queue discipline.',
    'udp_tx_packets': 'Outgoing UDP packets.',
    'tcp_tx_packets': 'Outgoing TCP packets.',
    'icmp_tx_packets': 'Outgoing ICMP packets.',
    'tcp_syn_packets': 'Outgoing TCP packets with SYN set.',
    'tcp_rst_packets': 'Outgoing TCP packets with RST set.',
    'tcp_fin_packets': 'Outgoing TCP packets with FIN set.',
    'application_rx_payload_bytes': 'Application payload bytes received by sinks.',
    'mean_ip_delay_ms': 'Mean measured one-way IP delay in milliseconds.',
    'std_ip_delay_ms': 'Population standard deviation of measured IP delay, ms.',
    'max_ip_delay_ms': 'Maximum measured IP delay in milliseconds.',
    'delay_samples': 'Number of measured IP delay samples.',
    'mean_packet_bytes': 'Mean observed outgoing IP packet size in bytes.',
    'std_packet_bytes': 'Population standard deviation of outgoing packet size, bytes.',
    'max_packet_bytes': 'Maximum observed outgoing IP packet size, bytes.',
    'mean_iat_ms': 'Mean outgoing packet inter-arrival time in milliseconds.',
    'std_iat_ms': 'Population standard deviation of packet inter-arrival time, ms.',
    'max_iat_ms': 'Maximum outgoing packet inter-arrival time in milliseconds.',
}


def _seed_roles(plan, train_seeds, validation_seeds, test_seeds, ood_seeds):
    supplied = {
        'train': train_seeds, 'validation': validation_seeds,
        'test': test_seeds, 'ood': ood_seeds,
    }
    partition = plan.get('seed_partition')
    planned = {}
    if isinstance(partition, dict):
        for role in ROLE_NAMES:
            value = partition.get(role)
            if role == 'test' and value is None:
                value = partition.get('evaluation')
            if value is not None:
                if isinstance(value, dict):
                    value = value.get('seeds', value.get('seed_ids'))
                if value is None or not isinstance(value, (list, tuple)):
                    raise ValueError('Invalid plan seed_partition role: ' + role)
                planned[role] = list(value)
    elif isinstance(partition, list):
        for row in partition:
            if not isinstance(row, dict) or row.get('role') not in ROLE_NAMES:
                raise ValueError('Invalid plan seed_partition rows')
            planned.setdefault(row['role'], []).append(row.get('seed'))
    if not planned:
        job_roles = {}
        for job in plan.get('jobs', []):
            role = job.get('seed_partition') or job.get('role')
            if role in ROLE_NAMES:
                job_roles.setdefault(role, set()).add(job.get('seed'))
        planned = {role: sorted(values) for role, values in job_roles.items()}
    resolved = {}
    for role in ROLE_NAMES:
        given = supplied[role]
        chosen = list(given) if given is not None else planned.get(role)
        if chosen is None:
            raise ValueError(f'Missing {role} seed partition; provide it explicitly or in campaign metadata')
        chosen = list(chosen)
        if not chosen or any(type(seed) is not int or seed <= 0 for seed in chosen):
            raise ValueError(f'{role} seeds must be nonempty positive integers')
        if len(chosen) != len(set(chosen)):
            raise ValueError(f'Duplicate seed in {role} partition')
        if role in planned and set(chosen) != set(planned[role]):
            raise ValueError(f'Explicit {role} seeds disagree with campaign seed_partition')
        resolved[role] = chosen
    owner = {}
    for role, seeds in resolved.items():
        for seed in seeds:
            if seed in owner:
                raise ValueError(f'Seed {seed} overlaps {owner[seed]} and {role}')
            owner[seed] = role
    return resolved


def _verify_all_jobs(campaign_root, plan):
    jobs = plan.get('jobs')
    if not isinstance(jobs, list) or not jobs:
        raise ValueError('Campaign has no jobs')
    records = []
    seen = set()
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get('id'), str) or job['id'] in seen:
            raise ValueError('Campaign has an invalid or duplicate job id')
        seen.add(job['id'])
        if job.get('state') != 'complete':
            raise ValueError('Every campaign job must be complete: ' + job['id'])
        attempt, result, receipt_path, receipt_files, post_logs = _verify_attempt(campaign_root, job)
        records.append({
            'job': job, 'attempt': attempt, 'result': result,
            'receipt_sha256': sha256(receipt_path),
            'verified_file_hashes': receipt_files,
            'post_receipt_mutable_logs': post_logs,
        })
    return records


def _csv_line(values):
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerow(values)
    return stream.getvalue()


class ShardWriter:
    def __init__(self, root, split, columns, max_bytes):
        self.root = root
        self.split = split
        self.columns = columns
        self.max_bytes = max_bytes
        self.base = 'ip_' + split
        self.part = 0
        self.handle = None
        self.bytes = 0
        self.rows = 0
        self.files = []
        self._open()

    def _name(self):
        return f'{self.base}-part-{self.part:04d}.csv'

    def _open(self):
        self.part += 1
        name = self._name()
        self.handle = (self.root / name).open('w', encoding='utf-8', newline='')
        header = _csv_line(self.columns)
        header_size = len(header.encode('utf-8'))
        if header_size > self.max_bytes:
            raise ValueError('Shard size limit is smaller than the CSV header')
        self.handle.write(header)
        self.bytes = header_size
        self.rows = 0
        self.files.append({'path': name, 'rows': 0, 'bytes': header_size})

    def write(self, values):
        line = _csv_line(values)
        size = len(line.encode('utf-8'))
        if size + len(_csv_line(self.columns).encode('utf-8')) > self.max_bytes:
            raise ValueError('One CSV row exceeds the configured shard size limit')
        if self.bytes + size > self.max_bytes and self.rows:
            self.handle.close()
            self._open()
        self.handle.write(line)
        self.bytes += size
        self.rows += 1
        self.files[-1]['rows'] = self.rows
        self.files[-1]['bytes'] = self.bytes

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None
        if len(self.files) == 1:
            source = self.root / self.files[0]['path']
            target = self.root / (self.base + '.csv')
            source.rename(target)
            self.files[0]['path'] = target.name


def _category(labels):
    if not labels:
        return 'normal'
    if len(labels) == 1:
        return labels[0]
    return 'mixed'


def _export_split(records, role, writer):
    seed_set = set(records['seeds'][role])
    selected_jobs = [record for record in records['verified_jobs']
                     if record['job'].get('kind') == 'ip' and record['job'].get('seed') in seed_set]
    available = {record['job']['seed'] for record in selected_jobs}
    missing = sorted(seed_set - available)
    if missing:
        raise ValueError(f'No IP jobs for {role} seeds: ' + ','.join(map(str, missing)))
    row_count = 0
    used_job_ids = set()
    for record in selected_jobs:
        job = record['job']
        if job['id'] in used_job_ids:
            raise ValueError('Duplicate selected job id: ' + job['id'])
        used_job_ids.add(job['id'])
        evidence = check_ip_research.check(record['result'])
        metadata = json.loads((record['result'] / 'ip_metadata.json').read_text(encoding='utf-8'))
        if metadata.get('seed') != job.get('seed') or metadata.get('attack') != job.get('attack'):
            raise ValueError('Raw IP identity does not match campaign job: ' + job['id'])
        for field in ('environment', 'regime'):
            if job.get(field) is not None and metadata.get(field) != job.get(field):
                raise ValueError('Raw IP context does not match campaign job: ' + job['id'])
        window_path = record['result'] / 'ip_windows.csv'
        with window_path.open(newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            if not set(FEATURES + ('attack_families', 'window_index', 'source_group_id')).issubset(reader.fieldnames or []):
                raise ValueError('IP window input is missing compact export columns')
            for raw in reader:
                labels = parse_families(raw['attack_families'])
                sample_id = f"{job['id']}-w{raw['window_index']}"
                group_id = f"s{job['seed']}:{raw['source_group_id']}"
                values = [sample_id, group_id]
                values.extend(raw[name] for name in FEATURES)
                values.extend((_category(labels), '|'.join(labels) if labels else 'none'))
                values.extend(str(int(family in labels)) for family in FAMILIES)
                writer.write(values)
                row_count += 1
        if evidence['checked_windows'] != metadata.get('rows'):
            raise ValueError('Strict IP checker window count does not match metadata')
    if row_count == 0:
        raise ValueError('Selected split contains no IP windows: ' + role)
    return row_count


def _write_support_files(stage, campaign_root, plan, roles, records, split_files,
                         split_counts, input_manifest, max_shard_bytes):
    dictionary = stage / 'feature_dictionary.csv'
    with dictionary.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle, lineterminator='\n')
        writer.writerow(('column', 'meaning', 'role'))
        writer.writerow(('sample_id', 'Unique window row id formed from campaign job id and window index.', 'audit identity'))
        writer.writerow(('group_id', 'Seed plus source_group_id; use for grouped analysis, never as a model feature.', 'audit identity'))
        for feature in FEATURES:
            writer.writerow((feature, FEATURE_DESCRIPTIONS[feature], 'measured numeric feature'))
        writer.writerow(('attack_category', 'normal, one exact family, or mixed when multiple families are observed.', 'categorical target'))
        writer.writerow(('attack_families', 'Pipe-separated observed family labels; none denotes a normal window.', 'multilabel target audit'))
        for family, column in zip(FAMILIES, TARGET_COLUMNS):
            writer.writerow((column, f'Binary observed-activity target for {family}.', 'multilabel target'))

    metadata = {
        'id': 'efeener298/ran-ai-lab',
        'title': 'RAN AI Lab Compact IP Research Windows',
        'license_status': 'pending; no license selected or upload authorized',
        'dataset_status': 'local preview; not uploaded',
    }
    (stage / 'dataset_metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')

    stage_name = plan.get('stage')
    scientific_status = {
        'campaign_stage': stage_name,
        'classification': 'exploratory' if stage_name == 'development' else 'research_collection_candidate',
        'campaign_scientific_status': plan.get('scientific_status'),
        'license_status': 'pending',
        'upload': 'not performed',
    }
    readme = [
        '# Compact IP research preview', '',
        'This package is a documented TABULAR FEATURE VIEW of a completed RAN AI Lab research campaign, not a replacement for the raw signal archive. It contains four seed-disjoint CSV splits. No upload was performed.', '',
        f"Campaign stage: `{stage_name}`; interpretation: **{scientific_status['classification']}**.",
        'Development rows are exploratory. A research-collection stage is a candidate collection and is not independently validated by this export.',
        'Dataset id metadata is `efeener298/ran-ai-lab`; license selection is pending.', '',
        '## Files and labels', '',
        'Each split uses `ip_train.csv`, `ip_validation.csv`, `ip_test.csv`, and `ip_ood.csv` when it fits in one shard. Larger splits use numbered `-part-0001.csv` shards, each bounded by the configured size.',
        'Rows preserve numeric feature strings from the raw window CSV. `attack_category` is `normal`, one family name, or `mixed`; `attack_families` and six `target_` columns preserve every observed family in mixed windows.',
        'The targets come from observed `attack_families`, not scheduled attacks. `sample_id` and `group_id` are audit strings and must not be used as model features.', '',
        '## Feature and privacy boundary', '',
        'Only the 23 primary measured window features are exported. Raw IP/MAC addresses, raw ports, seeds, time boundaries, schedules, attack-only counters, activity/provenance tables, logs, models, and NPZ files are omitted.',
        'See `feature_dictionary.csv` and `manifest.json` for the exact whitelist, counts, hashes, seed partitions, and receipt audit.', '',
        '## Package limits', '',
        'This is a local review artifact, not a Kaggle-ready licensed release. Confirm the license, dataset card, and publication approval before any upload.',
    ]
    (stage / 'README.md').write_text('\n'.join(readme) + '\n', encoding='utf-8')

    artifact_hashes = {}
    for path in sorted(stage.iterdir()):
        if path.is_file() and path.name != 'manifest.json':
            artifact_hashes[path.name] = sha256(path)
    for item in split_files:
        path = stage / item['path']
        item['sha256'] = sha256(path)
    manifest = {
        'format': 'ran-ai-lab-compact-ip-v1',
        'campaign': str(campaign_root),
        'campaign_sha256': sha256(campaign_root / 'campaign.json'),
        'campaign_stage': stage_name,
        'scientific_status': scientific_status,
        'dataset_id': metadata['id'],
        'license_status': 'pending',
        'uploaded': False,
        'features': list(FEATURES),
        'target_columns': list(TARGET_COLUMNS),
        'output_columns': list(OUTPUT_COLUMNS),
        'split_seeds': roles,
        'split_rows': split_counts,
        'sharding': {'maximum_bytes': max_shard_bytes, 'actual_files': split_files},
        'verified_campaign_jobs': input_manifest,
        'files': artifact_hashes,
        'scope': 'Synthetic wired IP telemetry windows; not radio/RIC acceptance data.',
    }
    (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def export_campaign(campaign, output, train_seeds=None, validation_seeds=None,
                    test_seeds=None, ood_seeds=None, max_shard_mb=1000):
    """Verify every receipt and stream the four compact split CSVs atomically."""
    campaign_root = Path(campaign).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError('Refusing to overwrite existing output: ' + str(output))
    if not output.parent.is_dir():
        raise FileNotFoundError('Output parent directory must already exist')
    if type(max_shard_mb) is not int or max_shard_mb <= 0:
        raise ValueError('max_shard_mb must be a positive integer')
    plan_path = campaign_root / 'campaign.json'
    if plan_path.is_symlink() or not plan_path.is_file():
        raise ValueError('Campaign manifest missing or symlinked')
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    if plan.get('state') != 'complete' or plan.get('stage') not in ('development', 'research_collection'):
        raise ValueError('Only completed development or research_collection campaigns are supported')
    roles = _seed_roles(plan, train_seeds, validation_seeds, test_seeds, ood_seeds)
    verified_jobs = _verify_all_jobs(campaign_root, plan)
    available_ip = {record['job'].get('seed') for record in verified_jobs
                    if record['job'].get('kind') == 'ip'}
    requested = {seed for seeds in roles.values() for seed in seeds}
    if not requested.issubset(available_ip):
        raise ValueError('Campaign is missing requested IP seeds: ' + ','.join(map(str, sorted(requested - available_ip))))
    max_shard_bytes = max_shard_mb * 1024 * 1024
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '.staging-', dir=output.parent))
    try:
        input_manifest = []
        for record in verified_jobs:
            job = record['job']
            input_manifest.append({
                'job_id': job['id'], 'kind': job.get('kind'), 'seed': job.get('seed'),
                'state': job.get('state'), 'receipt_sha256': record['receipt_sha256'],
                'verified_file_count': len(record['verified_file_hashes']),
                'post_receipt_mutable_logs': record['post_receipt_mutable_logs'],
            })
        split_files, split_counts = [], {}
        context = {'seeds': roles, 'verified_jobs': verified_jobs}
        for role in ROLE_NAMES:
            writer = ShardWriter(stage, role, OUTPUT_COLUMNS, max_shard_bytes)
            try:
                split_counts[role] = _export_split(context, role, writer)
            finally:
                writer.close()
            for item in writer.files:
                if item['bytes'] > max_shard_bytes:
                    raise ValueError('Generated shard exceeded configured byte limit')
                split_files.append(dict(role=role, **item))
        _write_support_files(stage, campaign_root, plan, roles, verified_jobs,
                             split_files, split_counts, input_manifest, max_shard_bytes)
        if output.exists() or output.is_symlink():
            raise FileExistsError('Refusing to overwrite existing output: ' + str(output))
        os.rename(stage, output)
        return {'output': str(output), 'split_rows': split_counts,
                'split_files': split_files, 'verified_jobs': len(verified_jobs),
                'dataset_id': 'efeener298/ran-ai-lab', 'license_status': 'pending'}
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--train-seeds', nargs='+', type=int)
    parser.add_argument('--validation-seeds', nargs='+', type=int)
    parser.add_argument('--test-seeds', nargs='+', type=int)
    parser.add_argument('--ood-seeds', nargs='+', type=int)
    parser.add_argument('--max-shard-mb', type=int, default=1000)
    args = parser.parse_args(argv)
    result = export_campaign(args.campaign, args.output, args.train_seeds,
                             args.validation_seeds, args.test_seeds,
                             args.ood_seeds, args.max_shard_mb)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
