"""Fail-closed structural and provenance checks for IP research outputs."""
import argparse
import csv
import ipaddress
import json
import math
from pathlib import Path


WINDOW_COLUMNS = (
    'source_group_id', 'window_index', 'window_start_s', 'window_end_s',
    'attack_applied', 'attack_scheduled', 'attack_family', 'attack_families',
    'attack_tx_packets', 'attack_rx_packets', 'attack_drop_packets',
    'unattributed_packets', 'benign_rx_ip_bytes', 'benign_app_rx_bytes',
    'tx_packets', 'tx_ip_bytes', 'ip_rx_packets', 'ip_rx_ip_bytes',
    'bottleneck_queue_drops', 'bottleneck_qdisc_drops', 'udp_tx_packets',
    'tcp_tx_packets', 'icmp_tx_packets', 'tcp_syn_packets', 'tcp_rst_packets',
    'tcp_fin_packets', 'unique_src_ips', 'unique_dst_ips', 'unique_dst_ports',
    'dst_port_entropy', 'application_rx_payload_bytes', 'mean_ip_delay_ms',
    'std_ip_delay_ms', 'max_ip_delay_ms', 'delay_samples', 'mean_packet_bytes',
    'std_packet_bytes', 'max_packet_bytes', 'mean_iat_ms', 'std_iat_ms',
    'max_iat_ms', 'unique_flows',
)
ACTIVITY_COLUMNS = ('activity_id', 'node_index', 'server_index', 'mode',
                    'family_mask', 'purpose', 'begin_s', 'end_s', 'offered_pps',
                    'nominal_payload_bytes', 'max_payload_bytes')
FLOW_COLUMNS = ('activity_id', 'source_ipv4', 'destination_ipv4', 'protocol',
                'source_port', 'destination_port', 'family_mask')
NODE_COLUMNS = ('node_index', 'role', 'ipv4')
COUNT_COLUMNS = {
    'attack_tx_packets', 'attack_rx_packets', 'attack_drop_packets',
    'unattributed_packets', 'benign_rx_ip_bytes', 'benign_app_rx_bytes',
    'tx_packets', 'tx_ip_bytes', 'ip_rx_packets', 'ip_rx_ip_bytes',
    'bottleneck_queue_drops', 'bottleneck_qdisc_drops', 'udp_tx_packets',
    'tcp_tx_packets', 'icmp_tx_packets', 'tcp_syn_packets', 'tcp_rst_packets',
    'tcp_fin_packets', 'unique_src_ips', 'unique_dst_ips', 'unique_dst_ports',
    'delay_samples', 'application_rx_payload_bytes', 'unique_flows',
}
# Numeric model inputs are explicit. No raw identity, port, time, group, label,
# schedule, or attack-only count enters the primary feature view.
PRIMARY_FEATURES = (
    'tx_packets', 'tx_ip_bytes', 'ip_rx_packets', 'ip_rx_ip_bytes',
    'bottleneck_queue_drops', 'bottleneck_qdisc_drops', 'udp_tx_packets',
    'tcp_tx_packets', 'icmp_tx_packets', 'tcp_syn_packets', 'tcp_rst_packets',
    'tcp_fin_packets', 'application_rx_payload_bytes', 'mean_ip_delay_ms',
    'std_ip_delay_ms', 'max_ip_delay_ms', 'delay_samples', 'mean_packet_bytes',
    'std_packet_bytes', 'max_packet_bytes', 'mean_iat_ms', 'std_iat_ms',
    'max_iat_ms',
)
RICHER_OPTIONAL_FEATURES = ('unique_src_ips', 'unique_dst_ips',
                            'unique_dst_ports', 'dst_port_entropy', 'unique_flows')
CONTEXT_KEYS = ('seed', 'environment', 'regime', 'sim_time_s', 'warmup_s',
                'window_s', 'clients', 'servers', 'core_segments', 'core_mbps',
                'queue_packets', 'access_delay_ms', 'core_delay_ms', 'service_ports')
OPTIONAL_AUDIT_COLUMNS = ('unattributed_app_rx_bytes',)


def _table(path, columns):
    with path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(columns):
            raise ValueError(f'{path.name}: unexpected header')
        rows = list(reader)
        if any(None in row or any(v is None for v in row.values()) for row in rows):
            raise ValueError(f'{path.name}: malformed row')
    return rows


def _integer(value, field):
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f'{field}: expected integer') from error
    if not math.isfinite(number) or number != int(number):
        raise ValueError(f'{field}: expected finite integer')
    return int(number)


def _number(value, field):
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f'{field}: expected number') from error
    if not math.isfinite(number):
        raise ValueError(f'{field}: non-finite number')
    return number


def _identity(row):
    return tuple(row[column] for column in ACTIVITY_COLUMNS)


def check(path, paired=None):
    """Validate one raw output directory; return evidence or raise ValueError."""
    root = Path(path)
    metadata = json.loads((root / 'ip_metadata.json').read_text(encoding='utf-8'))
    if metadata.get('schema') != 'ip-workload-research-v1':
        raise ValueError('unsupported IP research schema')
    seed = _integer(metadata.get('seed'), 'seed')
    run = _integer(metadata.get('run'), 'run')
    if seed <= 0 or run <= 0:
        raise ValueError('seed and run must be positive')
    for key in ('sim_time_s', 'warmup_s', 'window_s'):
        _number(metadata.get(key), key)
    sim, warm, width = (float(metadata[k]) for k in ('sim_time_s', 'warmup_s', 'window_s'))
    if width <= 0 or sim <= warm:
        raise ValueError('invalid window interval')
    if warm < 0:
        raise ValueError('warmup time cannot be negative')
    exact_windows = (sim - warm) / width
    n_windows = round(exact_windows)
    if n_windows <= 0 or not math.isclose(exact_windows, n_windows, rel_tol=0, abs_tol=1e-7):
        raise ValueError('simulation interval is not an integer number of closed windows')
    for key in ('clients', 'servers', 'core_segments', 'queue_packets', 'service_ports'):
        if _integer(metadata.get(key), key) <= 0:
            raise ValueError(f'{key} must be positive')
    for key in ('core_mbps', 'access_delay_ms', 'core_delay_ms'):
        if _number(metadata.get(key), key) <= 0:
            raise ValueError(f'{key} must be positive')
    if metadata.get('labels') != 'registered activity provenance for forward/reply packets; no source-IP membership labels':
        raise ValueError('metadata must declare activity provenance and no source-IP membership labels')

    window_path = root / 'ip_windows.csv'
    with window_path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        window_header = reader.fieldnames
        if (not window_header or len(window_header) != len(set(window_header))
                or set(window_header) not in (set(WINDOW_COLUMNS),
                                               set(WINDOW_COLUMNS) | set(OPTIONAL_AUDIT_COLUMNS))):
            raise ValueError('ip_windows.csv: unexpected header')
        windows = list(reader)
        if any(None in row or any(v is None for v in row.values()) for row in windows):
            raise ValueError('ip_windows.csv: malformed row')
    has_unattributed_app = 'unattributed_app_rx_bytes' in (window_header or [])
    activities = _table(root / 'activities.csv', ACTIVITY_COLUMNS)
    flows = _table(root / 'flow_provenance.csv', FLOW_COLUMNS)
    nodes = _table(root / 'nodes.csv', NODE_COLUMNS)
    if len(windows) != n_windows or _integer(metadata.get('rows'), 'rows') != n_windows:
        raise ValueError('declared closed-window count mismatch')
    group_id = f'ip3-s{seed}-r{run}'
    unknown_total = 0
    unknown_app_total = 0
    family_masks = set()
    observed_families = set()
    observed_windows = scheduled_windows = 0
    feature_names = set(window_header or []) - {'source_group_id', 'window_index',
        'window_start_s', 'window_end_s', 'attack_applied', 'attack_scheduled',
        'attack_family', 'attack_families'}
    forbidden_features = {'source_ipv4', 'destination_ipv4', 'ipv4', 'source_port',
        'destination_port', 'attack_tx_packets', 'attack_rx_packets',
        'attack_drop_packets', 'family_mask', 'activity_id',
        'unattributed_app_rx_bytes',
        'attack_scheduled', 'attack_applied', 'attack_family', 'attack_families',
        'source_group_id', 'window_index', 'window_start_s', 'window_end_s'}
    if set(PRIMARY_FEATURES) - feature_names or set(PRIMARY_FEATURES) & forbidden_features:
        raise ValueError('invalid primary feature declaration')
    for index, row in enumerate(windows):
        if row['source_group_id'] != group_id or _integer(row['window_index'], 'window_index') != index:
            raise ValueError('source group identity or window index mismatch')
        start = _number(row['window_start_s'], 'window_start_s')
        end = _number(row['window_end_s'], 'window_end_s')
        if not math.isclose(start, warm + index * width, rel_tol=0, abs_tol=1e-8) or not math.isclose(end, start + width, rel_tol=0, abs_tol=1e-8):
            raise ValueError('window boundaries are not the declared closed windows')
        numeric = {}
        for column in feature_names:
            numeric[column] = (_integer(row[column], column) if column in COUNT_COLUMNS or column in OPTIONAL_AUDIT_COLUMNS
                               else _number(row[column], column))
            if numeric[column] < 0:
                raise ValueError(f'{column}: negative value')
        if row['attack_applied'] not in ('0', '1') or row['attack_scheduled'] not in ('0', '1'):
            raise ValueError('attack flags must be 0 or 1')
        observed = sum(numeric[c] for c in ('attack_tx_packets', 'attack_rx_packets', 'attack_drop_packets')) > 0
        if (row['attack_applied'] == '1') != observed:
            raise ValueError('attack_applied disagrees with observed attack packet/drop support')
        if observed:
            observed_windows += 1
        if row['attack_scheduled'] == '1':
            scheduled_windows += 1
        unknown_total += numeric['unattributed_packets']
        if has_unattributed_app:
            unknown_app_total += numeric['unattributed_app_rx_bytes']
        for key in ('attack_family', 'attack_families'):
            value = row[key]
            if value not in ('none', '') and any(part not in {'udp_flood', 'udp_ddos', 'pulsed_udp', 'udp_port_scan', 'tcp_connection_churn', 'icmp_flood'} for part in value.split('|')):
                raise ValueError(f'unknown {key}')
        if row['attack_applied'] == '0' and row['attack_family'] != 'none':
            raise ValueError('unobserved windows cannot carry observed attack family labels')
        if row['attack_applied'] == '1':
            observed_families.update(row['attack_families'].split('|'))
            if set(row['attack_family'].split('|')) != set(row['attack_families'].split('|')):
                raise ValueError('attack family fields disagree')
    if unknown_total != _integer(metadata.get('unattributed_packets'), 'unattributed_packets'):
        raise ValueError('unattributed packet count does not reconcile to metadata')
    if 'unattributed_app_rx_bytes' in metadata and unknown_app_total != _integer(metadata['unattributed_app_rx_bytes'], 'unattributed_app_rx_bytes'):
        raise ValueError('unattributed application byte count does not reconcile to metadata')

    activity_by_id = {}
    benign_activities = []
    actor_families = {}
    for row in activities:
        aid = _integer(row['activity_id'], 'activity_id')
        if aid <= 0 or aid in activity_by_id:
            raise ValueError('duplicate or invalid activity id')
        node = _integer(row['node_index'], 'node_index')
        server = _integer(row['server_index'], 'server_index')
        mask = _integer(row['family_mask'], 'family_mask')
        if not 0 <= node < _integer(metadata['clients'], 'clients') or not 0 <= server < _integer(metadata['servers'], 'servers'):
            raise ValueError('activity references unknown sender or server index')
        if mask < 0 or mask >= (1 << 6):
            raise ValueError('invalid activity family mask')
        begin, end = _number(row['begin_s'], 'begin_s'), _number(row['end_s'], 'end_s')
        pps = _number(row['offered_pps'], 'offered_pps')
        nominal = _integer(row['nominal_payload_bytes'], 'nominal_payload_bytes')
        maximum = _integer(row['max_payload_bytes'], 'max_payload_bytes')
        if begin < 0 or end <= begin or pps <= 0 or nominal <= 0 or maximum < 0:
            raise ValueError('invalid activity schedule or parameters')
        activity_by_id[aid] = row
        family_masks.add(mask)
        actor_families.setdefault(node, set()).add(mask != 0)
        if mask == 0:
            benign_activities.append(row)
    tuple_owner = {}
    for row in flows:
        aid = _integer(row['activity_id'], 'activity_id')
        if aid not in activity_by_id:
            raise ValueError('flow provenance references unknown activity id')
        activity = activity_by_id[aid]
        mask = _integer(row['family_mask'], 'family_mask')
        if mask != _integer(activity['family_mask'], 'activity family_mask'):
            raise ValueError('flow and activity family masks disagree')
        src, dst = ipaddress.ip_address(row['source_ipv4']), ipaddress.ip_address(row['destination_ipv4'])
        if src == dst:
            raise ValueError('flow has identical endpoints')
        protocol = _integer(row['protocol'], 'protocol')
        sport = _integer(row['source_port'], 'source_port')
        dport = _integer(row['destination_port'], 'destination_port')
        if protocol not in (1, 6, 17) or not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
            raise ValueError('invalid flow tuple')
        identity = (src.packed, dst.packed, protocol, sport, dport)
        if identity in tuple_owner and tuple_owner[identity] != aid:
            raise ValueError('flow tuple conflicts across activities')
        if identity in tuple_owner:
            raise ValueError('duplicate flow tuple provenance')
        tuple_owner[identity] = aid
    if len(flows) != _integer(metadata.get('registered_flows'), 'registered_flows'):
        raise ValueError('registered flow count does not reconcile to provenance rows')

    node_ips, node_roles, role_ips = set(), {}, {}
    for row in nodes:
        index = _integer(row['node_index'], 'node_index')
        role = row['role']
        if role not in ('mixed_activity_sender', 'service'):
            raise ValueError('unknown node role')
        ip = ipaddress.ip_address(row['ipv4'])
        limit = _integer(metadata['clients' if role == 'mixed_activity_sender' else 'servers'], 'node count')
        if not 0 <= index < limit:
            raise ValueError('node index outside declared context')
        identity = (role, index)
        if ip in node_ips or identity in node_roles:
            raise ValueError('duplicate node identity or address')
        node_ips.add(ip); node_roles[identity] = role; role_ips[identity] = ip
    if sum(role == 'mixed_activity_sender' for role in node_roles.values()) != _integer(metadata['clients'], 'clients') or sum(role == 'service' for role in node_roles.values()) != _integer(metadata['servers'], 'servers'):
        raise ValueError('node/context counts disagree with metadata')
    if any(node_roles.get(('mixed_activity_sender', _integer(r['node_index'], 'node_index'))) is None for r in activities):
        raise ValueError('activity sender is not a declared sender node')
    if any(node_roles.get(('service', _integer(r['server_index'], 'server_index'))) is None for r in activities):
        raise ValueError('activity target is not a declared service node')
    declared_attack_families = set()
    for row in activities:
        mask = _integer(row['family_mask'], 'family_mask')
        for bit, name in enumerate(('udp_flood', 'udp_ddos', 'pulsed_udp', 'udp_port_scan', 'tcp_connection_churn', 'icmp_flood')):
            if mask & (1 << bit):
                declared_attack_families.add(name)
    if not observed_families.issubset(declared_attack_families):
        raise ValueError('observed attack family has no matching malicious activity provenance')
    for row in flows:
        activity = activity_by_id[_integer(row['activity_id'], 'activity_id')]
        source = ipaddress.ip_address(row['source_ipv4'])
        destination = ipaddress.ip_address(row['destination_ipv4'])
        sender = role_ips[('mixed_activity_sender', _integer(activity['node_index'], 'node_index'))]
        server = role_ips[('service', _integer(activity['server_index'], 'server_index'))]
        if source != sender or destination != server:
            raise ValueError('flow endpoints do not match their activity sender/server context')
    mixed_actor_count = sum(len(values) == 2 for values in actor_families.values())

    paired_evidence = None
    if paired is not None:
        other = Path(paired)
        om = json.loads((other / 'ip_metadata.json').read_text(encoding='utf-8'))
        if om.get('schema') != 'ip-workload-research-v1' or _integer(om.get('seed'), 'paired seed') != seed:
            raise ValueError('paired comparison requires matching schema and seed')
        if metadata.get('attack') == om.get('attack'):
            raise ValueError('paired run must compare different attack conditions')
        if any(metadata.get(k) != om.get(k) for k in CONTEXT_KEYS):
            raise ValueError('paired context metadata mismatch')
        other_activities = _table(other / 'activities.csv', ACTIVITY_COLUMNS)
        other_nodes = _table(other / 'nodes.csv', NODE_COLUMNS)
        if sorted(tuple(r[c] for c in NODE_COLUMNS) for r in nodes) != sorted(tuple(r[c] for c in NODE_COLUMNS) for r in other_nodes):
            raise ValueError('paired node/context audit mismatch')
        current_benign = sorted(_identity(r) for r in activities if r['family_mask'] == '0')
        other_benign = sorted(_identity(r) for r in other_activities if r['family_mask'] == '0')
        if current_benign != other_benign:
            raise ValueError('paired benign activity definitions mismatch')
        paired_evidence = {'matching_seed': seed, 'matched_benign_activities': len(current_benign), 'node_context_match': True}

    warnings = []
    if not observed_windows:
        warnings.append('no observed attack packet/drop support')
    if not scheduled_windows:
        warnings.append('no scheduled attack windows')
    if not any(mask == 0 for mask in family_masks):
        warnings.append('no benign actor activity support')
    if not any(mask != 0 for mask in family_masks):
        warnings.append('no malicious actor activity support')
    if not mixed_actor_count:
        warnings.append('no actor with both benign and malicious activity support')
    if unknown_total:
        warnings.append(f'{unknown_total} packets have unknown activity provenance')
    if unknown_app_total:
        warnings.append(f'{unknown_app_total} application bytes have unknown activity provenance')
    return {
        'schema': metadata['schema'], 'source_group_id': group_id,
        'checked_windows': n_windows, 'observed_attack_windows': observed_windows,
        'scheduled_attack_windows_audit_only': scheduled_windows,
        'activities': len(activities), 'benign_activities': len(benign_activities),
        'provenance_flows': len(flows), 'unattributed_packets': unknown_total,
        'unattributed_app_rx_bytes': unknown_app_total,
        'actors_with_benign_and_malicious_support': mixed_actor_count,
        'primary_features': list(PRIMARY_FEATURES),
        'richer_optional_features': list(RICHER_OPTIONAL_FEATURES),
        'warnings': warnings, 'paired': paired_evidence,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--paired', type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(check(args.path, args.paired), indent=2))


if __name__ == '__main__':
    main()
