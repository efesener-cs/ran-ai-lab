import csv
import json
from pathlib import Path
import tempfile
import unittest

from checks import check_ip_research as checker


def write_csv(path, columns, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path):
    with path.open(newline='', encoding='utf-8') as handle:
        return list(csv.DictReader(handle))


def make_output(root, attack=True):
    root.mkdir(parents=True)
    metadata = {
        'schema': 'ip-workload-research-v1', 'seed': 42, 'run': 1,
        'attack': 'udp_flood' if attack else 'none', 'environment': 'id',
        'regime': 'overlap', 'sim_time_s': 2.0, 'warmup_s': 1.0,
        'window_s': 0.5, 'rows': 2, 'clients': 2, 'servers': 2,
        'core_segments': 1, 'core_mbps': 10.0, 'queue_packets': 30,
        'access_delay_ms': 1.0, 'core_delay_ms': 2.0, 'service_ports': 12,
        'registered_flows': 2 if attack else 1, 'unattributed_packets': 0,
        'labels': 'registered activity provenance for forward/reply packets; no source-IP membership labels',
        'scope': 'synthetic wired transport/session workloads',
    }
    (root / 'ip_metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    activity_rows = [
        {'activity_id': 1, 'node_index': 0, 'server_index': 0, 'mode': 0,
         'family_mask': 0, 'purpose': 'authorized_session', 'begin_s': 0.1,
         'end_s': 1.9, 'offered_pps': 4.0, 'nominal_payload_bytes': 100,
         'max_payload_bytes': 500},
    ]
    if attack:
        activity_rows.append(
            {'activity_id': 1000001, 'node_index': 0, 'server_index': 1,
             'mode': 0, 'family_mask': 1, 'purpose': 'unauthorized_activity',
             'begin_s': 1.1, 'end_s': 1.8, 'offered_pps': 8.0,
             'nominal_payload_bytes': 100, 'max_payload_bytes': 0})
    write_csv(root / 'activities.csv', checker.ACTIVITY_COLUMNS, activity_rows)
    node_rows = [
        {'node_index': 0, 'role': 'mixed_activity_sender', 'ipv4': '10.0.0.1'},
        {'node_index': 1, 'role': 'mixed_activity_sender', 'ipv4': '10.0.0.5'},
        {'node_index': 0, 'role': 'service', 'ipv4': '10.0.0.2'},
        {'node_index': 1, 'role': 'service', 'ipv4': '10.0.0.6'},
    ]
    write_csv(root / 'nodes.csv', checker.NODE_COLUMNS, node_rows)
    flow_rows = [{'activity_id': 1, 'source_ipv4': '10.0.0.1',
                  'destination_ipv4': '10.0.0.2', 'protocol': 17,
                  'source_port': 1024, 'destination_port': 9000, 'family_mask': 0}]
    if attack:
        flow_rows.append({'activity_id': 1000001, 'source_ipv4': '10.0.0.1',
                          'destination_ipv4': '10.0.0.6', 'protocol': 17,
                          'source_port': 1025, 'destination_port': 9001,
                          'family_mask': 1})
    write_csv(root / 'flow_provenance.csv', checker.FLOW_COLUMNS, flow_rows)
    windows = []
    for index in range(2):
        row = {column: '0' for column in checker.WINDOW_COLUMNS}
        row.update(source_group_id='ip3-s42-r1', window_index=str(index),
                   window_start_s=str(1.0 + index * .5),
                   window_end_s=str(1.5 + index * .5),
                   attack_applied='1' if attack and index == 0 else '0',
                   attack_scheduled='1' if attack else '0',
                   attack_family='udp_flood' if attack and index == 0 else 'none',
                   attack_families='udp_flood' if attack and index == 0 else 'none',
                   tx_packets='3', tx_ip_bytes='300', ip_rx_packets='2',
                   ip_rx_ip_bytes='200', mean_packet_bytes='100',
                   max_packet_bytes='100', mean_iat_ms='1', max_iat_ms='1')
        if attack and index == 0:
            row.update(attack_tx_packets='1', attack_rx_packets='1',
                       attack_drop_packets='0')
        windows.append(row)
    write_csv(root / 'ip_windows.csv', checker.WINDOW_COLUMNS, windows)


class IpResearchCheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.attack = self.root / 'attack'
        make_output(self.attack, attack=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_output_and_explicit_feature_views(self):
        evidence = checker.check(self.attack)
        self.assertEqual(evidence['checked_windows'], 2)
        self.assertEqual(evidence['observed_attack_windows'], 1)
        self.assertEqual(evidence['actors_with_benign_and_malicious_support'], 1)
        self.assertIn('ip_rx_packets', evidence['primary_features'])
        self.assertIn('application_rx_payload_bytes', evidence['primary_features'])
        self.assertIn('dst_port_entropy', evidence['richer_optional_features'])
        for forbidden in ('source_ipv4', 'destination_ipv4', 'source_port',
                          'destination_port', 'attack_tx_packets',
                          'attack_rx_packets', 'attack_drop_packets',
                          'attack_scheduled', 'window_start_s', 'source_group_id'):
            self.assertNotIn(forbidden, evidence['primary_features'])

    def test_paired_run_matches_context_and_benign_activity_only(self):
        clean = self.root / 'clean'
        make_output(clean, attack=False)
        evidence = checker.check(self.attack, paired=clean)
        self.assertEqual(evidence['paired']['matched_benign_activities'], 1)

    def test_attack_flag_must_reflect_observed_support(self):
        rows = read_csv(self.attack / 'ip_windows.csv')
        rows[0]['attack_applied'] = '0'
        write_csv(self.attack / 'ip_windows.csv', checker.WINDOW_COLUMNS, rows)
        with self.assertRaisesRegex(ValueError, 'attack_applied'):
            checker.check(self.attack)

    def test_activity_provenance_tuple_cannot_conflict(self):
        rows = read_csv(self.attack / 'flow_provenance.csv')
        for column in ('source_ipv4', 'destination_ipv4', 'protocol',
                       'source_port', 'destination_port'):
            rows[1][column] = rows[0][column]
        write_csv(self.attack / 'flow_provenance.csv', checker.FLOW_COLUMNS, rows)
        with self.assertRaisesRegex(ValueError, 'conflicts across activities'):
            checker.check(self.attack)

    def test_unknown_count_reconciliation_is_required(self):
        path = self.attack / 'ip_metadata.json'
        metadata = json.loads(path.read_text())
        metadata['unattributed_packets'] = 1
        path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'unattributed packet count'):
            checker.check(self.attack)

    def test_optional_unattributed_app_bytes_are_audit_only_and_reconciled(self):
        path = self.attack / 'ip_metadata.json'
        metadata = json.loads(path.read_text())
        metadata['unattributed_app_rx_bytes'] = 7
        path.write_text(json.dumps(metadata))
        rows = read_csv(self.attack / 'ip_windows.csv')
        for row in rows:
            row['unattributed_app_rx_bytes'] = '7' if row['window_index'] == '0' else '0'
        columns = list(checker.WINDOW_COLUMNS)
        columns.insert(columns.index('unattributed_packets') + 1, 'unattributed_app_rx_bytes')
        write_csv(self.attack / 'ip_windows.csv', columns, rows)
        evidence = checker.check(self.attack)
        self.assertEqual(evidence['unattributed_app_rx_bytes'], 7)
        self.assertNotIn('unattributed_app_rx_bytes', evidence['primary_features'])

    def test_source_ip_membership_label_claim_is_rejected(self):
        path = self.attack / 'ip_metadata.json'
        metadata = json.loads(path.read_text())
        metadata['labels'] = 'source IPs of attackers are malicious'
        path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'no source-IP membership labels'):
            checker.check(self.attack)

    def test_window_identity_and_closed_count_are_required(self):
        rows = read_csv(self.attack / 'ip_windows.csv')
        rows[1]['source_group_id'] = 'ip3-s43-r1'
        write_csv(self.attack / 'ip_windows.csv', checker.WINDOW_COLUMNS, rows)
        with self.assertRaisesRegex(ValueError, 'source group identity'):
            checker.check(self.attack)

    def test_raw_identity_or_port_columns_are_rejected_from_window_contract(self):
        rows = read_csv(self.attack / 'ip_windows.csv')
        for row in rows:
            row['source_ipv4'] = '10.0.0.1'
        write_csv(self.attack / 'ip_windows.csv', checker.WINDOW_COLUMNS + ('source_ipv4',), rows)
        with self.assertRaisesRegex(ValueError, 'unexpected header'):
            checker.check(self.attack)


if __name__ == '__main__':
    unittest.main()
