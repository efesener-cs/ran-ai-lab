#!/usr/bin/env python3
"""Validate control evidence and summarize control outcomes separately.

Infrastructure validity asks whether evidence is well formed and the run completed.
Submission/confirmation rates are outcomes and do not determine infrastructure validity.
"""
import argparse
import csv
import json
import math
from pathlib import Path
import sys
from check_live import check as check_live


def read_rows(path):
    if not path.exists():
        return []
    with path.open() as stream:
        return list(csv.DictReader(stream))


def headers(path):
    if not path.exists():
        return None
    with path.open() as stream:
        return set(csv.DictReader(stream).fieldnames or [])


def verify(root, require_live=True, require_submission=False):
    root = Path(root)
    status = json.loads((root / 'run_status.json').read_text())
    dispatch_path = root / 'raw/control_dispatch.csv'
    events_path = root / 'raw/control_events.csv'
    decisions_path = root / 'csv/ai_shadow_decisions.csv'
    requests = read_rows(dispatch_path)
    events = read_rows(events_path)
    decisions = read_rows(decisions_path)

    def key(row):
        return (round(float(row['decision_time_s']), 8), int(row['ue_imsi']), int(row['recommended_cell_id']))

    malformed = False
    validation_errors = []
    def invalid(reason):
        nonlocal malformed
        malformed = True
        if reason not in validation_errors:
            validation_errors.append(reason)
    allowed_actions = {'hold', 'observe', 'recommend_handover'}
    decision_keys = []
    try:
        decision_keys = [key(row) for row in decisions]
        decision_identity = [(time_s, ue) for time_s, ue, _ in decision_keys]
        if len(set(decision_identity)) != len(decision_identity):
            invalid('duplicate decision_time_s/ue_imsi decision; target differences do not make distinct decisions')
        if any(row.get('action') not in allowed_actions for row in decisions):
            invalid('decision action is outside hold/observe/recommend_handover')
        recommended = {key(row) for row in decisions if row.get('action') == 'recommend_handover'}
    except (KeyError, TypeError, ValueError):
        recommended = set()
        invalid('decision rows contain missing or nonnumeric decision key fields')
    submitted = [r for r in requests if r.get('status') == 'submitted']
    events_by_id = {}
    for event in events:
        events_by_id.setdefault(event.get('request_id'), []).append(event)
    matches = []
    confirmed_keys = set()
    for request in submitted:
        ident = request.get('request_id', '')
        result = events_by_id.get(ident, [])
        try:
            source_key = (round(float(request['sim_time_s']), 8), int(request['ue_imsi']), int(request['target_cell']))
            evidence = (len(result) == 1 and result[0].get('event') == 'confirmed_target_connected'
                and result[0].get('ue_imsi') == request['ue_imsi']
                and result[0].get('from_cell') == request['from_cell']
                and result[0].get('target_cell') == request['target_cell'] == result[0].get('observed_cell')
                and request['from_cell'] != request['target_cell']
                and float(result[0]['sim_time_s']) > float(request['sim_time_s'])
                and source_key in recommended)
        except (KeyError, TypeError, ValueError):
            invalid('required control evidence file is missing')
            evidence = False
            source_key = None
        if evidence:
            confirmed_keys.add(source_key)
        matches.append(dict(request_id=ident, ue_imsi=request.get('ue_imsi', ''), request_time_s=request.get('sim_time_s', ''),
            from_cell=request.get('from_cell', ''), target_cell=request.get('target_cell', ''), confirmed=bool(evidence),
            confirmation_time_s=result[0]['sim_time_s'] if evidence else None,
            outcome='confirmed' if evidence else ('unconfirmed' if result else 'no_confirmation_event')))

    # Validate structure and references without treating an unsuccessful control outcome as bad infrastructure.
    malformed = malformed or not dispatch_path.exists() or not events_path.exists()
    try:
        required_request = {'sim_time_s','request_id','ue_imsi','from_cell','target_cell','status'}
        required_event = {'sim_time_s','request_id','ue_imsi','event','from_cell','target_cell','observed_cell'}
        if not required_request.issubset(headers(dispatch_path) or set()): invalid('control_dispatch.csv is missing required headers')
        if not required_event.issubset(headers(events_path) or set()): invalid('control_events.csv is missing required headers')
        if decisions_path.exists() and not {'decision_time_s','ue_imsi','recommended_cell_id','action'}.issubset(headers(decisions_path) or set()): invalid('ai_shadow_decisions.csv is missing required headers')
        for index, d in enumerate(decisions, start=2):
            if not math.isfinite(float(d['decision_time_s'])):
                invalid(f'ai_shadow_decisions.csv row {index} has nonfinite decision time')
            int(d['ue_imsi']); int(d['recommended_cell_id'])
        applications_path = root / 'csv/ue_application_100ms.csv'
        if applications_path.exists():
            app_rows = read_rows(applications_path)
            app_keys = {(round(float(r['window_start_s']), 8), str(r['ue_imsi'])) for r in app_rows}
            if len(app_keys) != len(app_rows): invalid('ue_application_100ms.csv has duplicate window_start_s/ue_imsi rows')
            if not app_rows or 'is_warmup' not in app_rows[0]:
                invalid('ue_application_100ms.csv lacks rows or is_warmup needed for decision coverage')
            else:
                expected_decisions = {(round(float(r['window_end_s']), 8), str(r['ue_imsi']))
                    for r in app_rows if r['is_warmup'] == '0'}
                actual_decisions = {(t, str(ue)) for t, ue, _ in decision_keys}
                missing = expected_decisions - actual_decisions
                extra = actual_decisions - expected_decisions
                if missing:
                    invalid(f'ai_shadow_decisions.csv is missing {len(missing)} post-warmup window_end/UE decisions')
                if extra:
                    invalid(f'ai_shadow_decisions.csv has {len(extra)} decision keys outside post-warmup window_end/UE coverage')
        if not dispatch_path.exists() or not events_path.exists(): invalid('required control evidence file is missing')
        request_ids = [r['request_id'] for r in requests]
        request_by_id = {r['request_id']: r for r in requests if r.get('request_id')}
        for index, r in enumerate(requests, start=2):
            if not math.isfinite(float(r['sim_time_s'])): invalid(f'control_dispatch.csv row {index} has nonfinite time')
            int(r['ue_imsi']); int(r['from_cell']); int(r['target_cell'])
            if r.get('status') not in ('submitted', 'rejected_target', 'rejected_pending', 'rejected_rrc_state',
                                       'already_on_target', 'timeout', 'failed', 'unconfirmed',
                                       'rejected'):
                invalid(f'control_dispatch.csv row {index} has unknown status {r.get("status")!r}')
        for index, e in enumerate(events, start=2):
            if not math.isfinite(float(e['sim_time_s'])): invalid(f'control_events.csv row {index} has nonfinite time')
            int(e['ue_imsi']); int(e['from_cell']); int(e['target_cell'])
            if e.get('event') not in ('confirmed_target_connected', 'timeout'):
                invalid(f'control_events.csv row {index} has unknown event {e.get("event")!r}')
            if e.get('request_id') not in request_ids:
                invalid(f'control_events.csv row {index} references an unknown request_id')
            request = request_by_id.get(e.get('request_id'))
            if request is not None:
                if request.get('status') != 'submitted':
                    invalid(f'control_events.csv row {index} is attached to non-submitted request {e.get("request_id")!r}')
                if e.get('ue_imsi') != request.get('ue_imsi') or e.get('from_cell') != request.get('from_cell') or e.get('target_cell') != request.get('target_cell'):
                    invalid(f'control_events.csv row {index} UE/cells do not match its dispatch request')
                if float(e['sim_time_s']) <= float(request['sim_time_s']):
                    invalid(f'control_events.csv row {index} is not later than its dispatch request')
        # Bad references/values in an allegedly submitted request are malformed evidence.
        for r in submitted:
            if not r['request_id'] or len(events_by_id.get(r['request_id'], [])) > 1:
                invalid(f'submitted request {r.get("request_id")!r} has missing ID or multiple events')
            expected = (round(float(r['sim_time_s']), 8), int(r['ue_imsi']), int(r['target_cell']))
            if expected not in recommended:
                invalid(f'submitted request {r.get("request_id")!r} has no matching model recommendation')
            if int(r['from_cell']) == int(r['target_cell']):
                invalid(f'submitted request {r.get("request_id")!r} has identical source and target')
            for e in events_by_id.get(r['request_id'], []):
                if e.get('ue_imsi') != r['ue_imsi'] or e.get('from_cell') != r['from_cell'] or e.get('target_cell') != r['target_cell']:
                    invalid(f'event for request {r.get("request_id")!r} disagrees with request UE/cells')
                if e.get('event') == 'confirmed_target_connected' and (
                    e.get('observed_cell') != r['target_cell'] or float(e['sim_time_s']) <= float(r['sim_time_s'])):
                    invalid(f'confirmation for request {r.get("request_id")!r} has wrong target or is not later')
    except (KeyError, TypeError, ValueError):
        invalid('control evidence contains missing or nonnumeric required fields')
    checks = {
        'simulation_completed': status.get('status') == 'complete' and status.get('simulation_exit_code') == 0,
        'control_enabled': status.get('ai_control_enabled') is True,
        'decisions_present': bool(decisions),
        'control_evidence_well_formed': not malformed,
        'unique_request_ids': len(set(r.get('request_id') for r in requests)) == len(requests),
    }
    if not checks['unique_request_ids']:
        invalid('control_dispatch.csv contains duplicate request_id values')
        checks['control_evidence_well_formed'] = False
    if require_submission:
        checks['at_least_one_rrc_submission'] = bool(submitted)
    if require_live:
        checks['live_e2_passed'] = check_live(root)['passed']
    infrastructure_valid = all(checks.values())
    confirmed = sum(r['confirmed'] for r in matches)
    outcomes = dict(submitted=len(submitted), confirmed=confirmed,
        unconfirmed=len(submitted) - confirmed, rejected=sum(r.get('status') != 'submitted' for r in requests),
        confirmation_rate=(confirmed / len(submitted) if submitted else None),
        rejected_by_status={status: sum(r.get('status') == status for r in requests)
            for status in sorted({r.get('status') for r in requests if r.get('status') != 'submitted'})})
    outcomes['outcome']='no_submissions' if not submitted else ('all_confirmed' if confirmed == len(submitted) else 'some_unconfirmed')
    # Keep the historical strict success signal for callers that use ``passed`` as
    # a control-success gate; analysis gates on infrastructure_valid instead.
    strict_control_success = bool(submitted) and confirmed == len(submitted)
    result = dict(passed=infrastructure_valid and strict_control_success,
        infrastructure_valid=infrastructure_valid,
        checks=checks, control_outcomes=outcomes, transport='atomic CSV -> ns-3 RRC API; not E2 RC',
        **outcomes, requests=matches, validation_errors=validation_errors,
        note='Confirmation means a later target-connected observation; it does not establish QoS benefit or full-window application.')
    out = root / 'csv'
    out.mkdir(exist_ok=True)
    if decisions and not malformed:
        annotated = []
        for row in decisions:
            decision_key = key(row)
            is_applied = int(decision_key in confirmed_keys)
            annotated.append({**row,
                # Confirmation is timestamped evidence of a later event, not a full-window state claim.
                'network_action_applied': is_applied,
                'decision_control_submitted': int(any(
                    round(float(r['request_time_s']), 8) == decision_key[0]
                    and int(r['ue_imsi']) == decision_key[1] and int(r['target_cell']) == decision_key[2]
                    for r in matches)),
                'decision_target_connected_confirmed': is_applied,
                'decision_confirmation_time_s': next((r['confirmation_time_s'] for r in matches
                    if r['confirmed'] and round(float(r['request_time_s']), 8) == decision_key[0]
                    and int(r['ue_imsi']) == decision_key[1] and int(r['target_cell']) == decision_key[2]), '')})
        with (out / 'ai_control_decisions.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(annotated[0])); writer.writeheader(); writer.writerows(annotated)
    (root / 'control_verification.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run_dir', type=Path, nargs='?'); p.add_argument('--latest', action='store_true')
    p.add_argument('--native', action='store_true', help='Explicitly omit live E2 check for host-only integration tests')
    p.add_argument('--require-submission', action='store_true', help='Strict opt-in: fail when control submitted no requests')
    a = p.parse_args(); root = a.run_dir
    if a.latest:
        roots = sorted((Path(__file__).resolve().parent / 'results').glob('control-native-*' if a.native else 'live-*'))
        if not roots: p.error('No matching run found')
        root = roots[-1]
    if root is None: p.error('Provide a run directory or --latest')
    result = verify(root, not a.native, a.require_submission)
    print(json.dumps({k: v for k, v in result.items() if k != 'requests'}, indent=2))
    success = result['infrastructure_valid'] and (not a.require_submission or result['passed'])
    sys.exit(0 if success else 1)

if __name__ == '__main__': main()
