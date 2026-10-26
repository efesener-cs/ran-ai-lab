#!/usr/bin/env python3
"""Evaluate clean recorded SINR telemetry under synthetic input perturbations."""
import argparse
import csv
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path

from ai.baselines import persistence_parameters
from ai.data import load_observations, supervised
from ai.evasion import Evasion
from ai.policy import recommendations
from ai.runtime import RuntimeForecaster


MODES = ('none', 'random', 'bias', 'fgsm', 'pgd', 'exact')


def _model_hash(parameters):
    body = json.dumps(parameters, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(body.encode()).hexdigest()


def split_check(model, test_sources, allow_unverified=False):
    identities = set()
    for source in test_sources:
        identity = source.get('root') or source.get('run_id') or source.get('sha256')
        if identity in identities:
            raise ValueError(f'Duplicate replay evaluation source: {identity}')
        identities.add(identity)
    provenance = model.parameters.get('training_provenance')
    training_sources = provenance.get('sources') if isinstance(provenance, dict) else None
    if not training_sources:
        if not allow_unverified:
            raise ValueError('Model has no training provenance; use --allow-unverified-split to proceed explicitly')
        return {'verified': False, 'reason': 'model training provenance unavailable'}
    validation_sources = provenance.get('validation_sources', [])
    if validation_sources is None:
        validation_sources = []
    if not isinstance(validation_sources, list):
        raise ValueError('Model validation_sources provenance must be a list')
    from train_ai import validate_run_split
    checked = validate_run_split(training_sources, test_sources)
    validation_checked = (validate_run_split(validation_sources, test_sources)
                          if validation_sources else None)
    return {'verified': True, **checked,
            'fit_source_count': len(training_sources),
            'validation_source_count': len(validation_sources),
            'validation_split_provenance': validation_checked}


def make_events(observations):
    times = defaultdict(list)
    for item in observations:
        if not item['warmup']:
            times[item['ue']].append(item['decision_time_s'])
    return [dict(id=f'replay-ue-{ue}', ue_imsi=ue,
                 start_s=min(values), end_s=max(values) + 1e-6)
            for ue, values in sorted(times.items())]


def replay_metrics(samples, clean_observations, model, mode, epsilon, access,
                   attack_seed=311, robust_budget_db=None):
    events = make_events(clean_observations)
    config = dict(mode=mode, epsilon_db=epsilon, access=access, seed=attack_seed,
                  steps=10, restarts=5, events=events)
    engine = Evasion(model, config)
    transformed, audit = engine.transform(clean_observations)
    attacked = {(o['run_id'], o['ue'], o['cell'], o['tick']): o for o in transformed}
    targets = {(s['run_id'], s['ue'], s['cell'], s['tick']): s['target'] for s in samples}
    records = []
    for sample in samples:
        key = (sample['run_id'], sample['ue'], sample['cell'], sample['tick'])
        # Targets are read exclusively from clean supervised() labels; no tainted
        # observation or future feature is used to construct ground truth.
        observed = attacked[key]
        prediction = float(model.predict([observed['features']], [observed['current']])[0])
        records.append(dict(sample=sample, prediction=prediction, target=targets[key]))
    if any(record['target'] != targets[(record['sample']['run_id'], record['sample']['ue'],
                                        record['sample']['cell'], record['sample']['tick'])]
           for record in records):
        raise AssertionError('Clean future target changed during replay')
    errors = [r['prediction'] - r['target'] for r in records]
    groups = defaultdict(list)
    for record in records:
        sample = record['sample']
        groups[(sample['run_id'], sample['ue'], sample['tick'])].append(record)
    correct = 0
    regret = []
    rank_count = 0
    for group in groups.values():
        if len(group) < 2:
            continue
        actual = max(group, key=lambda r: (r['target'], -r['sample']['cell']))
        chosen = max(group, key=lambda r: (r['prediction'], -r['sample']['cell']))
        correct += actual is chosen
        rank_count += 1
        regret.append(actual['target'] - chosen['target'])
    unprotected, _ = recommendations(model, transformed)
    robust, _ = recommendations(model, transformed, robust_budget_db=robust_budget_db)
    action_counts = Counter(row['action'] for row in robust)
    reason_counts = Counter(row['reason'] for row in robust)
    command_key = lambda row: (row['run_id'], row['ue_imsi'], row['decision_time_s'])
    robust_by_key = {command_key(row): row for row in robust}
    blocked = sum(row['action'] == 'recommend_handover' and
                  (command_key(row) not in robust_by_key or
                   robust_by_key[command_key(row)]['action'] != 'recommend_handover' or
                   robust_by_key[command_key(row)]['recommended_cell_id'] != row['recommended_cell_id'])
                  for row in unprotected)
    target_payload = sorted((key, value) for key, value in targets.items())
    target_digest = hashlib.sha256(json.dumps(target_payload, separators=(',', ':')).encode()).hexdigest()
    audit_rows = [r for r in audit if r['event_active']]
    return {
        'mode': mode, 'epsilon_db': epsilon, 'attack_access': access,
        'robust_budget_db': robust_budget_db if robust_budget_db is not None else 'off',
        'samples': len(records), 'forecast_mae_db': sum(abs(v) for v in errors) / len(errors) if errors else None,
        'forecast_rmse_db': math.sqrt(sum(v*v for v in errors) / len(errors)) if errors else None,
        'rank_decisions': rank_count,
        'best_cell_top1_accuracy': correct / rank_count if rank_count else None,
        'mean_best_cell_regret_db': sum(regret) / len(regret) if regret else None,
        'active_ue_windows': len({(r['ue_imsi'], r['decision_time_s']) for r in audit_rows}),
        'recommendation_count': len(robust), 'recommendation_actions': dict(action_counts),
        'recommendation_reasons': dict(reason_counts),
        'robust_holds': reason_counts.get('uncertified_gain', 0),
        'unprotected_recommendation_count': len(unprotected),
        'unprotected_recommendation_actions': dict(Counter(row['action'] for row in unprotected)),
        'robust_recommendation_count': len(robust),
        'robust_blocked_recommendation_count': blocked,
        'clean_mode_robust_utility_cost_recommendations': blocked if mode == 'none' else None,
        'network_actions_applied': 0,
        'clean_target_sha256': target_digest,
        'ground_truth_source': 'clean next-window SINR from supervised(clean_observations)',
    }


def evaluate_run(run_dir, model, source_metadata, epsilon=2, access='two_cell',
                 robust_budget_db=None, attack_seed=311):
    observations, metadata = source_metadata
    samples = supervised(observations)
    if not samples:
        raise ValueError(f'No clean next-window targets in {run_dir}')
    common = dict(run_id=metadata['run_id'], backend=metadata['backend'],
                  experiment_seed=metadata.get('seed'), source_sha256=metadata['sha256'],
                  model_sha256=metadata['model_sha256'])
    results = []
    for predictor, parameters in [('ridge', model.parameters),
                                  ('persistence', persistence_parameters(model.parameters))]:
        predictor_model = RuntimeForecaster(parameters)
        for mode in MODES:
            result = replay_metrics(samples, observations, predictor_model, mode, epsilon,
                                    access, attack_seed, robust_budget_db)
            results.append(common | dict(predictor=predictor,
                predictor_model_sha256=_model_hash(parameters),
                robust_budget_db=robust_budget_db if robust_budget_db is not None else 'off') | result)
    return results


def write_results(results, split, output, model_sha256, limitations):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(k for row in results for k in row))
    with (output / 'replay_metrics.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                             for k, v in row.items()})
    payload = dict(model_sha256=model_sha256, split=split, limitations=limitations,
                   result_count=len(results), results=results)
    (output / 'replay_metrics.json').write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--run-dir', type=Path, action='append', required=True)
    parser.add_argument('--allow-native', action='store_true')
    parser.add_argument('--allow-unverified-split', action='store_true')
    parser.add_argument('--epsilon', type=float, default=2)
    parser.add_argument('--access', choices=['two_cell', 'target_only', 'best_only'], default='two_cell')
    parser.add_argument('--robust-budget-db', type=float)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not math.isfinite(args.epsilon) or not 0 <= args.epsilon <= 5:
        parser.error('--epsilon must be finite and in 0..5')
    if args.robust_budget_db is not None and (not math.isfinite(args.robust_budget_db) or
                                              not 0 <= args.robust_budget_db <= 5):
        parser.error('--robust-budget-db must be finite and in 0..5')
    model_path = args.model.resolve()
    model = RuntimeForecaster.load(model_path)
    model_file_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    sources = []
    for root in args.run_dir:
        observations, metadata = load_observations(root, require_clean=True,
                                                   allow_native=args.allow_native)
        metadata['root'] = str(root.resolve())
        sources.append((observations, metadata))
    test_sources = [dict(s, model_sha256=model_file_hash) for _, s in sources]
    split = split_check(model, test_sources, args.allow_unverified_split)
    results = []
    for (observations, metadata), root in zip(sources, args.run_dir):
        results.extend(evaluate_run(root, model,
            (observations, metadata | {'model_sha256': model_file_hash}),
            epsilon=args.epsilon, access=args.access,
            robust_budget_db=args.robust_budget_db))
    limitations = [
        'Recorded replay only; attacks alter model input in memory and do not alter measured radio telemetry.',
        'Each predictor is attacked adaptively using its own scores; results compare separate predictor-specific attacks.',
        'Future SINR is clean next-window link-quality ground truth; no QoS, throughput, handover-success, or causal network effect is measured.',
        'Robust utility cost counts recommendations suppressed by the score certificate; it is not measured throughput or QoS loss.',
        'Recommendations are score-based replay outputs; network_actions_applied is always zero.',
        'Metrics are reported separately by run, seed, predictor, attack mode, access, and robust budget; no cross-run pooling or window-level confidence intervals.',
        'Synthetic perturbations are bounded SINR telemetry biases, not RF attacks.',
    ]
    write_results(results, split, args.output, model_file_hash, limitations)
    print(f'Wrote {len(results)} separate replay rows to {args.output}')


if __name__ == '__main__':
    main()
