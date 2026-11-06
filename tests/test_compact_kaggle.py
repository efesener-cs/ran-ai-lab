import csv
import json
from pathlib import Path
import tempfile
import unittest

from ai.research_ip_multilabel import sha256
from checks import check_ip_research
from datasets import export_compact_kaggle as exporter


def write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def make_ip_result(path, seed):
    path.mkdir(parents=True)
    metadata = {
        'schema': 'ip-workload-research-v1', 'seed': seed, 'run': 1,
        'attack': 'mixed', 'environment': 'id', 'regime': 'low',
        'sim_time_s': 2.0, 'warmup_s': 1.0, 'window_s': 0.5, 'rows': 2,
        'clients': 1, 'servers': 1, 'core_segments': 1, 'core_mbps': 10.0,
        'queue_packets': 20, 'access_delay_ms': 1.0, 'core_delay_ms': 2.0,
        'service_ports': 1, 'registered_flows': 2, 'unattributed_packets': 0,
        'labels': 'registered activity provenance for forward/reply packets; no source-IP membership labels',
        'scope': 'synthetic wired workload',
    }
    (path / 'ip_metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    activities = [
        {'activity_id': 1, 'node_index': 0, 'server_index': 0, 'mode': 0,
         'family_mask': 1, 'purpose': 'unauthorized_activity', 'begin_s': 1.1,
         'end_s': 1.8, 'offered_pps': 1.0, 'nominal_payload_bytes': 64,
         'max_payload_bytes': 100},
        {'activity_id': 1000002, 'node_index': 0, 'server_index': 0, 'mode': 2,
         'family_mask': 32, 'purpose': 'unauthorized_activity', 'begin_s': 1.1,
         'end_s': 1.8, 'offered_pps': 1.0, 'nominal_payload_bytes': 64,
         'max_payload_bytes': 100},
    ]
    write_csv(path / 'activities.csv', check_ip_research.ACTIVITY_COLUMNS, activities)
    flows = [
        {'activity_id': 1, 'source_ipv4': '10.0.0.1', 'destination_ipv4': '10.0.0.2',
         'protocol': 17, 'source_port': 1024, 'destination_port': 9000, 'family_mask': 1},
        {'activity_id': 1000002, 'source_ipv4': '10.0.0.1', 'destination_ipv4': '10.0.0.2',
         'protocol': 1, 'source_port': 1025, 'destination_port': 1025, 'family_mask': 32},
    ]
    write_csv(path / 'flow_provenance.csv', check_ip_research.FLOW_COLUMNS, flows)
    nodes = [{'node_index': 0, 'role': 'mixed_activity_sender', 'ipv4': '10.0.0.1'},
             {'node_index': 0, 'role': 'service', 'ipv4': '10.0.0.2'}]
    write_csv(path / 'nodes.csv', check_ip_research.NODE_COLUMNS, nodes)
    windows = []
    for index in range(2):
        row = {column: '0' for column in check_ip_research.WINDOW_COLUMNS}
        row.update(source_group_id=f'ip3-s{seed}-r1', window_index=str(index),
                   window_start_s=str(1.0 + index * .5), window_end_s=str(1.5 + index * .5),
                   attack_applied='0' if index == 0 else '1',
                   attack_scheduled='0' if index == 0 else '1',
                   attack_family='none' if index == 0 else 'udp_flood|icmp_flood',
                   attack_families='none' if index == 0 else 'udp_flood|icmp_flood',
                   tx_packets='123.00', tx_ip_bytes='64', ip_rx_packets='1',
                   ip_rx_ip_bytes='64', mean_packet_bytes='7.250', max_packet_bytes='64',
                   mean_iat_ms='1.125', max_iat_ms='1.125')
        if index == 1:
            row.update(attack_tx_packets='1', attack_rx_packets='0', attack_drop_packets='0')
        windows.append(row)
    write_csv(path / 'ip_windows.csv', check_ip_research.WINDOW_COLUMNS, windows)


def make_campaign(root):
    roles = {'train': [101], 'validation': [102], 'test': [103], 'ood': [104]}
    jobs = []
    for seed in (101, 102, 103, 104):
        job_id = f'ip-{seed}-mixed'
        attempt = root / 'jobs' / job_id / 'attempt-1'
        result = attempt / 'result'
        attempt.mkdir(parents=True)
        worker_log = attempt / 'worker.log'
        worker_log.write_bytes(b'')
        make_ip_result(result, seed)
        files = {p.relative_to(attempt).as_posix(): sha256(p)
                 for p in sorted(attempt.rglob('*'))
                 if p.is_file() and p.name != 'receipt.json'}
        receipt = attempt / 'receipt.json'
        receipt.write_text(json.dumps({'job': job_id, 'files': files}), encoding='utf-8')
        worker_log.write_bytes(b'CHECKED ' + job_id.encode() + b'\n')
        jobs.append({'id': job_id, 'kind': 'ip', 'seed': seed, 'attack': 'mixed',
                     'environment': 'id', 'regime': 'low', 'state': 'complete',
                     'attempts': [{'path': attempt.relative_to(root).as_posix(),
                                   'state': 'complete', 'receipt_sha256': sha256(receipt)}]})
    # A non-IP job proves that campaign-level receipt verification covers every job.
    job_id = 'rf-development-1'
    attempt = root / 'jobs' / job_id / 'attempt-1'
    result = attempt / 'result'
    result.mkdir(parents=True)
    (result / 'report.txt').write_text('verified non-IP receipt\n', encoding='utf-8')
    files = {'result/report.txt': sha256(result / 'report.txt')}
    receipt = attempt / 'receipt.json'
    receipt.write_text(json.dumps({'job': job_id, 'files': files}), encoding='utf-8')
    jobs.append({'id': job_id, 'kind': 'rf', 'state': 'complete',
                 'attempts': [{'path': attempt.relative_to(root).as_posix(),
                               'state': 'complete', 'receipt_sha256': sha256(receipt)}]})
    plan = {'format': 'research-development-v1', 'stage': 'development',
            'scientific_status': 'unvalidated-development', 'state': 'complete',
            'seed_partition': roles, 'jobs': jobs}
    (root / 'campaign.json').write_text(json.dumps(plan), encoding='utf-8')


class CompactKaggleExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.campaign = self.root / 'campaign'
        self.campaign.mkdir()
        make_campaign(self.campaign)

    def tearDown(self):
        self.tmp.cleanup()

    def test_compact_export_preserves_numeric_strings_and_all_mixture_targets(self):
        output = self.root / 'export'
        result = exporter.export_campaign(self.campaign, output, max_shard_mb=1)
        self.assertEqual(result['verified_jobs'], 5)
        self.assertEqual(result['split_rows'], {'train': 2, 'validation': 2, 'test': 2, 'ood': 2})
        self.assertEqual(result['license_status'], 'pending')
        train_path = output / 'ip_train.csv'
        with train_path.open(newline='', encoding='utf-8') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]['tx_packets'], '123.00')
        self.assertEqual(rows[0]['mean_packet_bytes'], '7.250')
        self.assertEqual(rows[0]['attack_category'], 'normal')
        mixed = rows[1]
        self.assertEqual(mixed['attack_category'], 'mixed')
        self.assertEqual(mixed['attack_families'], 'udp_flood|icmp_flood')
        self.assertEqual(mixed['target_udp_flood'], '1')
        self.assertEqual(mixed['target_icmp_flood'], '1')
        self.assertEqual(sum(int(mixed[f'target_{family}']) for family in exporter.FAMILIES), 2)

    def test_export_header_uses_whitelist_and_omits_leakage_columns(self):
        output = self.root / 'export'
        exporter.export_campaign(self.campaign, output, max_shard_mb=1)
        with (output / 'ip_train.csv').open(newline='', encoding='utf-8') as handle:
            header = next(csv.reader(handle))
        self.assertEqual(header, list(exporter.OUTPUT_COLUMNS))
        forbidden = {'source_ipv4', 'destination_ipv4', 'source_port', 'destination_port',
                     'window_start_s', 'window_end_s', 'window_index', 'attack_scheduled',
                     'attack_tx_packets', 'unattributed_packets', 'seed', 'activity_id'}
        self.assertFalse(set(header) & forbidden)
        self.assertEqual(sum(name in header for name in exporter.FEATURES), 23)
        self.assertEqual(sum(name.startswith('target_') for name in header), 6)

    def test_plan_seed_roles_are_used_and_explicit_roles_must_match(self):
        roles = exporter._seed_roles(json.loads((self.campaign / 'campaign.json').read_text()),
                                     None, None, None, None)
        self.assertEqual(roles, {'train': [101], 'validation': [102], 'test': [103], 'ood': [104]})
        with self.assertRaisesRegex(ValueError, 'disagree'):
            exporter._seed_roles(json.loads((self.campaign / 'campaign.json').read_text()),
                                 [101], [102], [999], [104])

    def test_shard_writer_rotates_before_exceeding_byte_limit(self):
        columns = ('sample_id', 'value')
        header_bytes = len(exporter._csv_line(columns).encode('utf-8'))
        row_bytes = len(exporter._csv_line(('row1', '123456789')).encode('utf-8'))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            writer = exporter.ShardWriter(root, 'train', columns, header_bytes + row_bytes)
            writer.write(('row1', '123456789'))
            writer.write(('row2', '123456789'))
            writer.close()
            self.assertEqual(len(writer.files), 2)
            self.assertTrue(all(item['bytes'] <= header_bytes + row_bytes for item in writer.files))
            self.assertEqual([item['path'] for item in writer.files],
                             ['ip_train-part-0001.csv', 'ip_train-part-0002.csv'])

    def test_receipt_tamper_fails_before_publishing_output(self):
        raw = (self.campaign / 'jobs/ip-101-mixed/attempt-1/result/ip_windows.csv')
        raw.write_text(raw.read_text() + 'tamper', encoding='utf-8')
        output = self.root / 'export'
        with self.assertRaisesRegex(ValueError, 'file hash mismatch'):
            exporter.export_campaign(self.campaign, output, max_shard_mb=1)
        self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        output = self.root / 'export'
        output.mkdir()
        marker = output / 'keep.txt'
        marker.write_text('keep', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            exporter.export_campaign(self.campaign, output, max_shard_mb=1)
        self.assertEqual(marker.read_text(), 'keep')

    def test_manifest_hashes_files_and_marks_preview_license_pending(self):
        output = self.root / 'export'
        exporter.export_campaign(self.campaign, output, max_shard_mb=1)
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertEqual(manifest['dataset_id'], 'efeener298/ran-ai-lab')
        self.assertEqual(manifest['license_status'], 'pending')
        self.assertFalse(manifest['uploaded'])
        self.assertEqual(len(manifest['verified_campaign_jobs']), 5)
        for name, digest in manifest['files'].items():
            self.assertEqual(sha256(output / name), digest)
        self.assertTrue((output / 'README.md').is_file())
        self.assertTrue((output / 'feature_dictionary.csv').is_file())
        self.assertFalse(any(path.suffix in ('.npz', '.joblib', '.log') for path in output.iterdir()))


if __name__ == '__main__':
    unittest.main()
