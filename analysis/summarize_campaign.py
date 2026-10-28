#!/usr/bin/env python3
"""Summarize paired campaign effects with seed-cluster bootstrap intervals."""
import argparse
import csv
import json
import math
from pathlib import Path
import random


STRATA = ('backend', 'experiment_pipeline_sha256', 'predictor', 'defense', 'attack_access', 'robust_budget_db',
          'ues', 'duration_s', 'epsilon_db')


def _float(row, name):
    try:
        value = float(row[name])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'Invalid or missing {name}: {row}') from exc
    if not math.isfinite(value):
        raise ValueError(f'Non-finite {name}: {row}')
    return value


def _value(row, name, default=''):
    value = row.get(name, '')
    return default if value is None or value == '' else str(value)


def _budget(row):
    value = _value(row, 'robust_budget_db', 'off').strip().lower()
    if value in {'off', 'none', 'null', 'false'}:
        return 'off'
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(f'Invalid robust_budget_db: {value}') from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f'Invalid robust_budget_db: {value}')
    return format(number, '.12g')


def _count_value(row, name):
    value = row.get(name, '')
    if value is None or value == '':
        return None
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'Invalid {name}: {value}') from exc
    if not math.isfinite(number) or number < 0 or not number.is_integer():
        raise ValueError(f'{name} must be a nonnegative integer')
    return int(number)


def load_rows(path):
    with Path(path).open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    required = {'suite_id', 'backend', 'experiment_seed', 'experiment_condition',
                'ues', 'duration_s', 'epsilon_db', 'rx_bytes'}
    if not rows:
        raise ValueError('run_summary.csv is empty')
    missing = required - set(rows[0])
    if missing:
        raise ValueError('Missing required columns: ' + ', '.join(sorted(missing)))
    for row in rows:
        row['predictor'] = _value(row, 'predictor', 'ridge').lower()
        row['experiment_pipeline_sha256'] = _value(row, 'experiment_pipeline_sha256', 'unrecorded')
        row['defense'] = _value(row, 'defense', 'none').lower()
        row['attack_access'] = _value(row, 'attack_access', 'two_cell').lower()
        row['robust_budget_db'] = _budget(row)
        row['experiment_condition'] = _value(row, 'experiment_condition')
        row['suite_id'] = _value(row, 'suite_id')
        row['experiment_seed'] = _value(row, 'experiment_seed')
        if not row['suite_id'] or not row['experiment_seed'] or not row['experiment_condition']:
            raise ValueError('suite_id, experiment_seed, and experiment_condition must be nonempty')
        seed_value = _float(row, 'experiment_seed')
        if seed_value < 0 or not seed_value.is_integer():
            raise ValueError('experiment_seed must be a nonnegative integer')
        row['experiment_seed'] = str(int(seed_value))
        rx = _float(row, 'rx_bytes')
        if rx < 0 or not rx.is_integer():
            raise ValueError('rx_bytes must be a nonnegative integer')
        row['_rx'] = int(rx)
        for name in ('ues', 'duration_s', 'epsilon_db'):
            row['_'+name] = _float(row, name)
        if row['_ues'] <= 0 or not row['_ues'].is_integer():
            raise ValueError('ues must be a positive integer')
        if row['_duration_s'] <= 0 or row['_epsilon_db'] < 0:
            raise ValueError('duration_s must be positive and epsilon_db nonnegative')
    return rows


def _stratum(row):
    return tuple(row[k] if k in ('backend', 'experiment_pipeline_sha256', 'predictor', 'defense', 'attack_access', 'robust_budget_db') else row['_'+k]
                 for k in STRATA)


def _percentile(sorted_values, probability):
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * probability
    low = int(pos)
    high = min(low + 1, len(sorted_values) - 1)
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * (pos - low)


def _counts(rows):
    failed_values = [None if row.get('status', '') == '' else
                     int(row.get('status', '').lower() not in {'complete', 'completed', 'success', 'succeeded'})
                     for row in rows]
    failed = None if any(value is None for value in failed_values) else sum(failed_values)
    unconfirmed_values = []
    for row in rows:
        submitted = _count_value(row, 'control_submitted')
        confirmed = _count_value(row, 'control_confirmed')
        if submitted is None or confirmed is None:
            unconfirmed_values.append(None)
        else:
            if confirmed > submitted:
                raise ValueError('control_confirmed cannot exceed control_submitted')
            unconfirmed_values.append(submitted - confirmed)
    unconfirmed = None if any(value is None for value in unconfirmed_values) else sum(unconfirmed_values)
    return {'runs': len(rows), 'failed_runs': failed, 'unconfirmed_controls': unconfirmed}


def summarize(rows, bootstrap_seed=17, resamples=2000):
    if isinstance(resamples, bool) or int(resamples) != resamples or resamples < 1:
        raise ValueError('resamples must be a positive integer')
    rows = [dict(row) for row in rows]
    for row in rows:
        row['predictor'] = _value(row, 'predictor', 'ridge').lower()
        row['experiment_pipeline_sha256'] = _value(row, 'experiment_pipeline_sha256', 'unrecorded')
        row['defense'] = _value(row, 'defense', 'none').lower()
        row['attack_access'] = _value(row, 'attack_access', 'two_cell').lower()
        row['robust_budget_db'] = _budget(row)
        seed_value = _float(row, 'experiment_seed')
        if seed_value < 0 or not seed_value.is_integer():
            raise ValueError('experiment_seed must be a nonnegative integer')
        row['experiment_seed'] = str(int(seed_value))
        for name in ('ues', 'duration_s', 'epsilon_db'):
            row.setdefault('_' + name, _float(row, name))
        if row['_ues'] <= 0 or not row['_ues'].is_integer():
            raise ValueError('ues must be a positive integer')
        if row['_duration_s'] <= 0 or row['_epsilon_db'] < 0:
            raise ValueError('duration_s must be positive and epsilon_db nonnegative')
        rx = _float(row, 'rx_bytes')
        if rx < 0 or not rx.is_integer():
            raise ValueError('rx_bytes must be a nonnegative integer')
        row.setdefault('_rx', int(rx))
    by_pair = {}
    for row in rows:
        pair_key = (_stratum(row), row['suite_id'], row['experiment_condition'])
        if pair_key in by_pair:
            raise ValueError(f'Duplicate suite/condition row: {row["suite_id"]}/{row["experiment_condition"]}')
        by_pair[pair_key] = row

    clean_by_suite = {}
    for (_, suite, condition), row in by_pair.items():
        if condition == 'none':
            clean_by_suite[(suite, _stratum(row))] = row

    # Hash consistency is checked across the whole comparison stratum (including
    # condition and suite), where model differences would invalidate pairing.
    hashes = {}
    for row in rows:
        digest = _value(row, 'model_sha256')
        if digest:
            hashes.setdefault(_stratum(row), set()).add(digest)
    mixed = [key for key, values in hashes.items() if len(values) > 1]
    if mixed:
        raise ValueError(f'Incompatible model hashes in stratum: {mixed[0]}')

    paired = []
    for row in rows:
        if row['experiment_condition'] == 'none':
            continue
        clean = clean_by_suite.get((row['suite_id'], _stratum(row)))
        if clean is None:
            raise ValueError(f'Missing matching clean condition for suite {row["suite_id"]}')
        if clean['experiment_seed'] != row['experiment_seed']:
            raise ValueError(f'Clean and condition seed mismatch for suite {row["suite_id"]}')
        clean_run, condition_run = clean.get('experiment_run', ''), row.get('experiment_run', '')
        if clean_run != '' or condition_run != '':
            try:
                run_match = float(clean_run) == float(condition_run) and math.isfinite(float(clean_run))
            except (TypeError, ValueError):
                run_match = str(clean_run) == str(condition_run)
            if not run_match:
                raise ValueError(f'Clean and condition run mismatch for suite {row["suite_id"]}')
        if clean['_rx'] == 0:
            raise ValueError(f'Zero clean RX denominator for suite {row["suite_id"]}')
        delta = row['_rx'] - clean['_rx']
        counts = _counts([row])
        paired.append({
            'suite_id': row['suite_id'], 'backend': row['backend'],
            'experiment_pipeline_sha256': row['experiment_pipeline_sha256'],
            'predictor': row['predictor'], 'defense': row['defense'],
            'attack_access': row['attack_access'], 'robust_budget_db': row['robust_budget_db'],
            'experiment_seed': row['experiment_seed'], 'ues': row['_ues'],
            'duration_s': row['_duration_s'], 'epsilon_db': row['_epsilon_db'],
            'experiment_condition': row['experiment_condition'],
            'clean_rx_bytes': clean['_rx'], 'condition_rx_bytes': row['_rx'],
            'rx_delta_bytes': delta, 'rx_delta_percent': 100.0 * delta / clean['_rx'],
            'failed_runs': counts['failed_runs'],
            'unconfirmed_controls': counts['unconfirmed_controls'],
        })

    # Repeated suite/epsilon results with one numeric seed are averaged first.
    seed_values = {}
    for row in paired:
        key = tuple(row[name] for name in STRATA) + (row['experiment_condition'], row['experiment_seed'])
        seed_values.setdefault(key, []).append(row['rx_delta_percent'])
    by_cell = {}
    for key, values in seed_values.items():
        cell = key[:-1]
        by_cell.setdefault(cell, {})[key[-1]] = sum(values) / len(values)

    rng = random.Random(bootstrap_seed)
    statistics = []
    for cell in sorted(by_cell, key=lambda item: tuple(map(str, item))):
        seed_effects = by_cell[cell]
        values = [seed_effects[seed] for seed in sorted(seed_effects)]
        estimate = sum(values) / len(values)
        ci = None
        status = 'ok'
        warnings = []
        if len(values) < 2:
            status = 'insufficient_independent_seeds'
            warnings.append('Fewer than two independent seed clusters; confidence interval not estimated.')
        else:
            samples = sorted(sum(rng.choice(values) for _ in values) / len(values)
                             for _ in range(resamples))
            ci = [_percentile(samples, .025), _percentile(samples, .975)]
            if len(values) < 5:
                warnings.append('Fewer than five independent seed clusters; interval is highly uncertain.')
        key_row = dict(zip(STRATA + ('experiment_condition',), cell))
        member_rows = [row for row in paired if all(row[name] == key_row[name]
                                                    for name in STRATA + ('experiment_condition',))]
        statistics.append(key_row | {
            'independent_seed_clusters': len(values), 'paired_suite_count': len(member_rows),
            'mean_paired_rx_delta_percent': estimate, 'bootstrap_ci_95_percent': ci,
            'bootstrap_resamples': resamples if ci is not None else 0,
            'status': status, 'warnings': warnings,
            'failed_runs': (sum(r['failed_runs'] for r in member_rows)
                            if all(r['failed_runs'] is not None for r in member_rows) else None),
            'unconfirmed_controls': (sum(r['unconfirmed_controls'] for r in member_rows)
                                     if all(r['unconfirmed_controls'] is not None for r in member_rows) else None),
        })
    return paired, {'bootstrap_seed': bootstrap_seed, 'resamples': resamples,
                    'independence_unit': 'numeric experiment_seed; repeated suites within seed averaged',
                    'confidence_level': .95, 'p_values_reported': False,
                    'strata': STRATA, 'comparisons': statistics}


def write_outputs(input_path, output, bootstrap_seed=17, resamples=2000):
    rows = load_rows(input_path)
    paired, result = summarize(rows, bootstrap_seed, resamples)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    fields = ['suite_id', 'backend', 'experiment_pipeline_sha256', 'predictor', 'defense', 'attack_access', 'robust_budget_db',
              'experiment_seed', 'ues',
              'duration_s', 'epsilon_db', 'experiment_condition', 'clean_rx_bytes',
              'condition_rx_bytes', 'rx_delta_bytes', 'rx_delta_percent',
              'failed_runs', 'unconfirmed_controls']
    with (output / 'paired_effects.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(paired)
    (output / 'statistics.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    lines = ['# Campaign statistics', '',
             'Effects are paired to the `none` run in the same suite. Bootstrap resamples numeric seeds; repeated suites with one seed are averaged first.',
             'No p-values are computed. Native/live, pipeline fingerprint, predictor, defense, attack access, robust budget, UE count, duration, epsilon, and condition remain separate strata.', '',
             '| Backend | Pipeline SHA256 | Predictor | Defense | Access | Robust budget (dB) | UEs | Duration (s) | Epsilon | Condition | Seeds | Mean RX change (%) | 95% seed-bootstrap CI | Status |',
             '|---|---|---|---|---|---:|---:|---:|---:|---|---:|---:|---|---|']
    for item in result['comparisons']:
        ci = item['bootstrap_ci_95_percent']
        ci_text = 'insufficient independent seeds' if ci is None else f'[{ci[0]:.3f}, {ci[1]:.3f}]'
        lines.append('| ' + ' | '.join(str(v) for v in [item['backend'], item['experiment_pipeline_sha256'], item['predictor'], item['defense'],
            item['attack_access'], item['robust_budget_db'], item['ues'], item['duration_s'],
            item['epsilon_db'], item['experiment_condition'],
            item['independent_seed_clusters'], f"{item['mean_paired_rx_delta_percent']:.3f}", ci_text,
            item['status']]) + ' |')
        for warning in item['warnings']:
            lines.append(f'  - {warning}')
    lines += ['', 'Failed runs and unconfirmed controls are counts from available run-summary columns; null means the source did not include those fields.', '']
    (output / 'summary.md').write_text('\n'.join(lines))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_summary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bootstrap-seed', type=int, default=17)
    parser.add_argument('--resamples', type=int, default=2000)
    args = parser.parse_args(argv)
    write_outputs(args.run_summary, args.output, args.bootstrap_seed, args.resamples)


if __name__ == '__main__':
    main()
