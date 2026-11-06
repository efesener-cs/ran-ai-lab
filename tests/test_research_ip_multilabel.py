"""Stdlib-only contract tests; model libraries load only during actual fitting."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from ai import research_ip_multilabel as multilabel
from checks import check_ip_research


class FakeColumn(list):
    def sum(self):
        return sum(self)


class FakeMatrix:
    def __init__(self, rows):
        self.rows = rows
        self.shape = (len(rows), len(rows[0]))

    def __getitem__(self, key):
        row_slice, column = key
        if row_slice != slice(None):
            raise AssertionError('only whole-column support checks are used')
        return FakeColumn(row[column] for row in self.rows)


def write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def make_result(path, seed):
    path.mkdir(parents=True)
    metadata = {
        'schema': 'ip-workload-research-v1', 'seed': seed, 'run': 1,
        'attack': 'none', 'environment': 'id', 'regime': 'low',
        'sim_time_s': 2.0, 'warmup_s': 1.0, 'window_s': 0.5, 'rows': 2,
        'clients': 1, 'servers': 1, 'core_segments': 1, 'core_mbps': 10.0,
        'queue_packets': 20, 'access_delay_ms': 1.0, 'core_delay_ms': 2.0,
        'service_ports': 1, 'registered_flows': 1, 'unattributed_packets': 0,
        'labels': 'registered activity provenance for forward/reply packets; no source-IP membership labels',
        'scope': 'synthetic wired workload',
    }
    (path / 'ip_metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    activity = [{'activity_id': 1, 'node_index': 0, 'server_index': 0, 'mode': 0,
                 'family_mask': 0, 'purpose': 'authorized_session', 'begin_s': 0.1,
                 'end_s': 1.9, 'offered_pps': 1.0, 'nominal_payload_bytes': 64,
                 'max_payload_bytes': 100}]
    write_csv(path / 'activities.csv', check_ip_research.ACTIVITY_COLUMNS, activity)
    flows = [{'activity_id': 1, 'source_ipv4': '10.0.0.1', 'destination_ipv4': '10.0.0.2',
              'protocol': 17, 'source_port': 1024, 'destination_port': 9000,
              'family_mask': 0}]
    write_csv(path / 'flow_provenance.csv', check_ip_research.FLOW_COLUMNS, flows)
    nodes = [{'node_index': 0, 'role': 'mixed_activity_sender', 'ipv4': '10.0.0.1'},
             {'node_index': 0, 'role': 'service', 'ipv4': '10.0.0.2'}]
    write_csv(path / 'nodes.csv', check_ip_research.NODE_COLUMNS, nodes)
    windows = []
    for i in range(2):
        row = {column: '0' for column in check_ip_research.WINDOW_COLUMNS}
        row.update(source_group_id=f'ip3-s{seed}-r1', window_index=str(i),
                   window_start_s=str(1.0 + i * .5), window_end_s=str(1.5 + i * .5),
                   attack_applied='0', attack_scheduled='0', attack_family='none',
                   attack_families='none', tx_packets=str(seed), tx_ip_bytes='64',
                   ip_rx_packets='1', ip_rx_ip_bytes='64', mean_packet_bytes='64',
                   max_packet_bytes='64', mean_iat_ms='1', max_iat_ms='1')
        windows.append(row)
    write_csv(path / 'ip_windows.csv', check_ip_research.WINDOW_COLUMNS, windows)


def make_campaign(root, seeds):
    jobs = []
    for seed in seeds:
        job_id = f'ip-{seed}-none'
        attempt = root / 'jobs' / job_id / 'attempt-1'
        result = attempt / 'result'
        attempt.mkdir(parents=True)
        worker_log = attempt / 'worker.log'
        worker_log.write_bytes(b'')
        make_result(result, seed)
        files = {p.relative_to(attempt).as_posix(): multilabel.sha256(p)
                 for p in sorted(attempt.rglob('*'))
                 if p.is_file() and p.name != 'receipt.json'}
        receipt_path = attempt / 'receipt.json'
        receipt_path.write_text(json.dumps({'job': job_id, 'files': files}), encoding='utf-8')
        worker_log.write_bytes(b'CHECKED ' + job_id.encode('utf-8') + b'\n')
        jobs.append({'id': job_id, 'kind': 'ip', 'seed': seed, 'attack': 'none',
                     'environment': 'id', 'regime': 'low', 'state': 'complete',
                     'attempts': [{'path': attempt.relative_to(root).as_posix(),
                                   'state': 'complete',
                                   'receipt_sha256': multilabel.sha256(receipt_path)}]})
    (root / 'campaign.json').write_text(json.dumps({
        'format': 'research-development-v1', 'stage': 'development',
        'scientific_status': 'unvalidated-development', 'state': 'complete',
        'jobs': jobs,
    }), encoding='utf-8')


class ResearchIpMultilabelTests(unittest.TestCase):
    def test_family_parser_preserves_mixtures_and_rejects_invalid_labels(self):
        self.assertEqual(multilabel.parse_families('none'), ())
        self.assertEqual(multilabel.parse_families('icmp_flood|udp_flood'),
                         ('udp_flood', 'icmp_flood'))
        with self.assertRaises(ValueError):
            multilabel.parse_families('none|udp_flood')
        with self.assertRaises(ValueError):
            multilabel.parse_families('udp_flood|udp_flood')
        with self.assertRaises(ValueError):
            multilabel.parse_families('unknown_family')

    def test_categorical_label_never_collapses_multi_family_rows(self):
        self.assertEqual(multilabel.categorical_label(()), 'normal')
        self.assertEqual(multilabel.categorical_label(('tcp_connection_churn',)),
                         'tcp_connection_churn')
        self.assertEqual(multilabel.categorical_label(('icmp_flood', 'udp_flood')),
                         'mixture:udp_flood|icmp_flood')

    def test_seed_partitions_must_be_disjoint(self):
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            multilabel.validate_seed_splits([1], [2], [1], [4])
        with self.assertRaisesRegex(ValueError, 'duplicates'):
            multilabel.validate_seed_splits([1, 1], [2], [3], [4])

    def test_metrics_report_exact_mixture_support_and_categorical_confusion(self):
        labels = [[0] * 6, [1, 0, 0, 0, 0, 0], [1, 1, 0, 0, 0, 0]]
        predictions = [[0] * 6, [1, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0]]
        probabilities = [[0.1] * 6, [0.9, 0.1, 0.1, 0.1, 0.1, 0.1],
                         [0.9, 0.4, 0.1, 0.1, 0.1, 0.1]]
        metrics = multilabel.summarize_metrics(labels, predictions, probabilities)
        mixture = 'mixture:udp_flood|udp_ddos'
        self.assertEqual(metrics['categorical']['true_support'][mixture], 1)
        self.assertEqual(metrics['categorical']['confusion_matrix'][mixture]['udp_flood'], 1)
        self.assertEqual(metrics['exact_match_accuracy'], 2 / 3)
        self.assertEqual(metrics['family_metrics']['udp_flood']['support'], 2)

    def test_campaign_index_verifies_receipts_and_strict_ip_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'campaign'
            root.mkdir()
            seeds = [11, 12, 13, 14]
            make_campaign(root, seeds)
            splits = multilabel.validate_seed_splits([11], [12], [13], [14])
            campaign_root, entries, counts, hashes, plan = multilabel.index_campaign(root, splits)
            self.assertEqual(len(entries), 4)
            self.assertEqual(counts, {'train': 2, 'validation': 2, 'evaluation': 2, 'ood': 2})
            self.assertEqual(plan['stage'], 'development')
            self.assertEqual(len(hashes['jobs']), 4)
            self.assertEqual(entries[0]['post_receipt_mutable_logs'], ['worker.log'])
            window_path = entries[0]['window_path']
            window_path.write_text(window_path.read_text() + 'tamper', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'file hash mismatch'):
                multilabel.index_campaign(root, splits)

    def test_calibration_support_is_global_across_batches(self):
        import numpy as np
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            X = np.zeros((4, len(multilabel.FEATURES)))
            Y = np.asarray([[0] * 6, [0] * 6, [1] * 6, [1] * 6], dtype=np.uint8)
            np.save(root / 'X.npy', X)
            np.save(root / 'Y.npy', Y)
            store = {'X_path': root / 'X.npy', 'Y_path': root / 'Y.npy'}
            with patch.object(multilabel, '_probability_batch', return_value=np.full((2, 6), .5)):
                thresholds, evidence = multilabel.calibrate_thresholds([], store, np, batch_size=2)
            self.assertEqual(set(thresholds), set(multilabel.FAMILIES))
            Y[:] = 0
            np.save(root / 'Y.npy', Y)
            with self.assertRaisesRegex(ValueError, 'positive and negative'):
                multilabel.calibrate_thresholds([], store, np, batch_size=2)

    def test_training_spool_and_selection_are_split_isolated_with_sentinel_rows(self):
        import numpy as np

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'campaign'
            root.mkdir()
            make_campaign(root, [11, 12, 13, 14])
            splits = multilabel.validate_seed_splits([11], [12], [13], [14])
            _, entries, counts, _, _ = multilabel.index_campaign(root, splits)
            stage = Path(tmp) / 'stage'
            stage.mkdir()
            stores, ranges, support = multilabel.spool_campaign(entries, counts, stage, np)
            training_seeds = {int(key[0]) for key in ranges['train']}
            heldout_seeds = set()
            for split in ('validation', 'evaluation', 'ood'):
                heldout_seeds.update(int(key[0]) for key in ranges[split])
            self.assertEqual(training_seeds, {11})
            self.assertEqual(heldout_seeds, {12, 13, 14})
            feature_index = multilabel.FEATURES.index('tx_packets')
            train_X = np.load(stores['train']['X_path'], mmap_mode='r')
            train_Y = np.load(stores['train']['Y_path'], mmap_mode='r')
            X_fit, Y_fit, audit = multilabel.select_training_view(
                train_X, train_Y, ranges['train'], support['train'])
            self.assertEqual(set(X_fit[:, feature_index].tolist()), {11.0})
            self.assertLessEqual(audit['kept_rows'], audit['original_rows'])
            self.assertLessEqual(audit['kept_rows'], counts['train'])
            fit_seeds = {group['seed'] for group in audit['groups'] if group['kept_rows']}
            self.assertEqual(fit_seeds, {11})
            for split, sentinel_seeds in (('validation', {12.0}), ('evaluation', {13.0}), ('ood', {14.0})):
                X = np.load(stores[split]['X_path'], mmap_mode='r')
                self.assertEqual(set(X[:, feature_index].tolist()), sentinel_seeds)

    def test_worker_log_transition_is_limited_to_exact_empty_receipt_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'campaign'
            root.mkdir()
            make_campaign(root, [11, 12, 13, 14])
            splits = multilabel.validate_seed_splits([11], [12], [13], [14])
            job = json.loads((root / 'campaign.json').read_text())['jobs'][0]
            attempt = root / job['attempts'][0]['path']
            (attempt / 'worker.log').write_bytes(b'CHECKED wrong-job\n')
            with self.assertRaisesRegex(ValueError, 'file hash mismatch: worker.log'):
                multilabel.index_campaign(root, splits)

    def test_primary_feature_contract_excludes_identity_time_label_and_audit(self):
        forbidden = {'source_group_id', 'window_index', 'window_start_s', 'window_end_s',
                     'attack_scheduled', 'attack_applied', 'attack_tx_packets',
                     'source_ipv4', 'destination_ipv4', 'source_port', 'destination_port',
                     'unattributed_packets', 'unattributed_app_rx_bytes', 'seed'}
        self.assertEqual(multilabel.FEATURES, check_ip_research.PRIMARY_FEATURES)
        self.assertFalse(set(multilabel.FEATURES) & forbidden)

    def test_training_sampling_uses_only_the_passed_training_groups(self):
        X = FakeMatrix([[0.0] * len(multilabel.FEATURES) for _ in range(2)])
        Y = FakeMatrix([[0] * len(multilabel.FAMILIES) for _ in range(2)])
        key = ('11', 'train-job', 'ip3-s11-r1')
        X_train, Y_train, audit = multilabel.select_training_view(
            X, Y, {key: [(0, 2)]}, {key: [0] * len(multilabel.FAMILIES)})
        self.assertIs(X_train, X)
        self.assertIs(Y_train, Y)
        self.assertEqual(audit['kept_rows'], 2)
        self.assertEqual([group['job_id'] for group in audit['groups']], ['train-job'])

    def test_existing_output_is_rejected_before_training(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'campaign'
            root.mkdir()
            make_campaign(root, [1, 2, 3, 4])
            output = Path(tmp) / 'existing'
            output.mkdir()
            with self.assertRaises(FileExistsError):
                multilabel.train_campaign(root, output, [1], [2], [3], [4])


if __name__ == '__main__':
    unittest.main()
