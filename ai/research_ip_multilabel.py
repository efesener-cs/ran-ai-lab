"""Categorical and multilabel IP research baseline over verified campaigns.

This is an exploratory baseline for observed activity-family labels. It uses
only the public primary window feature contract and keeps mixtures multilabel.
"""
import argparse
import csv
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import random
import shutil
import sqlite3
import sys
import tempfile

try:
    from checks import check_ip_research
except ModuleNotFoundError:
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))
    from checks import check_ip_research


FAMILIES = (
    'udp_flood', 'udp_ddos', 'pulsed_udp', 'udp_port_scan',
    'tcp_connection_churn', 'icmp_flood',
)
FEATURES = tuple(check_ip_research.PRIMARY_FEATURES)
THRESHOLD_GRID = tuple(round(0.10 + 0.05 * i, 2) for i in range(17))
MODEL_PARAMETERS = {
    'n_estimators': 200,
    'max_depth': 20,
    'max_leaf_nodes': 4096,
    'min_samples_leaf': 5,
    'max_samples': 0.7,
    'class_weight': 'balanced_subsample',
    'n_jobs': 2,
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def parse_families(value):
    """Parse none or a sorted-preserving family list, rejecting unknown labels."""
    if value in ('', 'none'):
        return tuple()
    labels = tuple(value.split('|'))
    if len(labels) != len(set(labels)) or any(label not in FAMILIES for label in labels):
        raise ValueError('Invalid observed family label: ' + repr(value))
    return tuple(family for family in FAMILIES if family in labels)


def categorical_label(labels):
    labels = tuple(family for family in FAMILIES if family in set(labels))
    if not labels:
        return 'normal'
    if len(labels) == 1:
        return labels[0]
    return 'mixture:' + '|'.join(labels)


def validate_seed_splits(train_seeds, validation_seeds, evaluation_seeds, ood_seeds):
    splits = {
        'train': tuple(train_seeds),
        'validation': tuple(validation_seeds),
        'evaluation': tuple(evaluation_seeds),
        'ood': tuple(ood_seeds),
    }
    for name, seeds in splits.items():
        if not seeds or any(type(seed) is not int or seed <= 0 for seed in seeds):
            raise ValueError(f'{name} seeds must be nonempty positive integers')
        if len(seeds) != len(set(seeds)):
            raise ValueError(f'{name} seed list contains duplicates')
    all_seeds = {}
    for name, seeds in splits.items():
        for seed in seeds:
            if seed in all_seeds:
                raise ValueError(f'seed {seed} overlaps {all_seeds[seed]} and {name}')
            all_seeds[seed] = name
    return splits


def _safe_receipt_file(attempt, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise ValueError('Invalid receipt path')
    path_part = PurePosixPath(relative)
    if path_part.is_absolute() or any(part in ('', '.', '..') for part in relative.split('/')):
        raise ValueError('Noncanonical receipt path')
    path = attempt.joinpath(*path_part.parts)
    if any(part.is_symlink() for part in (path, *path.parents) if part != attempt.parent):
        raise ValueError('Symlink in campaign receipt path')
    if not path.is_file() or not path.resolve().is_relative_to(attempt.resolve()):
        raise ValueError('Missing or escaping campaign receipt path')
    return path


def _verify_attempt(campaign_root, job):
    if job.get('state') != 'complete' or not job.get('attempts'):
        raise ValueError('Campaign IP job is not complete: ' + str(job.get('id')))
    record = job['attempts'][-1]
    if record.get('state') != 'complete' or type(record.get('receipt_sha256')) is not str:
        raise ValueError('Completed campaign job lacks a verified receipt: ' + str(job.get('id')))
    relative = record.get('path')
    if not isinstance(relative, str) or '\\' in relative:
        raise ValueError('Invalid campaign attempt path')
    parts = PurePosixPath(relative)
    if parts.is_absolute() or any(part in ('', '.', '..') for part in relative.split('/')):
        raise ValueError('Noncanonical campaign attempt path')
    attempt = campaign_root.joinpath(*parts.parts)
    if not attempt.is_dir() or not attempt.resolve().is_relative_to(campaign_root.resolve()):
        raise ValueError('Campaign attempt path escapes campaign root')
    receipt_path = attempt / 'receipt.json'
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError('Missing or symlinked campaign receipt')
    if sha256(receipt_path) != record['receipt_sha256']:
        raise ValueError('Campaign receipt hash mismatch: ' + str(job.get('id')))
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    if receipt.get('job') != job.get('id') or not isinstance(receipt.get('files'), dict):
        raise ValueError('Campaign receipt identity/schema mismatch')
    file_hashes = {}
    post_receipt_logs = []
    for name, expected in sorted(receipt['files'].items()):
        path = _safe_receipt_file(attempt, name)
        if not isinstance(expected, str):
            raise ValueError('Invalid campaign receipt digest: ' + name)
        if name == 'worker.log' and expected == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
            # Legacy v1 receipts captured an empty worker log before the parent
            # appended its exact CHECKED line after work() returned.
            if path.read_bytes() == b'CHECKED ' + job['id'].encode('utf-8') + b'\n':
                post_receipt_logs.append(name)
                continue
        if sha256(path) != expected:
            raise ValueError('Campaign receipt file hash mismatch: ' + name)
        file_hashes[name] = expected
    result = attempt / 'result'
    if result.is_symlink() or not result.is_dir():
        raise ValueError('Campaign result directory missing or symlinked')
    return attempt, result, receipt_path, file_hashes, post_receipt_logs


def index_campaign(campaign, seed_splits):
    """Verify campaign receipts and raw tables without retaining window rows."""
    campaign_root = Path(campaign).resolve(strict=True)
    plan_path = campaign_root / 'campaign.json'
    if plan_path.is_symlink() or not plan_path.is_file():
        raise ValueError('Campaign manifest missing or symlinked')
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    if plan.get('format') != 'research-development-v1' or plan.get('state') != 'complete':
        raise ValueError('Only completed verified research campaigns are accepted')
    stage = plan.get('stage')
    if stage not in ('development', 'research_collection'):
        raise ValueError('Unsupported research campaign stage')
    if not isinstance(plan.get('jobs'), list):
        raise ValueError('Campaign manifest has no job list')
    seed_to_split = {seed: name for name, seeds in seed_splits.items() for seed in seeds}
    input_hashes = {'campaign.json': sha256(plan_path), 'checker_sha256': sha256(check_ip_research.__file__), 'jobs': {}}
    entries = []
    row_counts = {name: 0 for name in seed_splits}
    job_ids = set()
    available_seed_rows = set()
    for job in plan['jobs']:
        if not isinstance(job, dict) or job.get('kind') != 'ip':
            continue
        seed = job.get('seed')
        if seed not in seed_to_split:
            continue
        job_id = job.get('id')
        if not isinstance(job_id, str) or job_id in job_ids:
            raise ValueError('Missing or duplicate IP job identity')
        job_ids.add(job_id)
        split = seed_to_split[seed]
        attempt, result, receipt_path, receipt_files, post_receipt_logs = _verify_attempt(campaign_root, job)
        evidence = check_ip_research.check(result)
        metadata_path = result / 'ip_metadata.json'
        window_path = result / 'ip_windows.csv'
        metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
        if metadata.get('seed') != seed or metadata.get('attack') != job.get('attack'):
            raise ValueError('IP output identity disagrees with campaign job')
        for field in ('environment', 'regime'):
            if job.get(field) is not None and metadata.get(field) != job[field]:
                raise ValueError('IP output ' + field + ' disagrees with campaign job')
        file_hashes = {'receipt_sha256': sha256(receipt_path),
                       'metadata_sha256': sha256(metadata_path),
                       'windows_sha256': sha256(window_path)}
        input_hashes['jobs'][job_id] = {
            'seed': seed,
            'attempt': attempt.relative_to(campaign_root).as_posix(),
            'receipt_sha256': file_hashes['receipt_sha256'],
            'metadata_sha256': file_hashes['metadata_sha256'],
            'windows_sha256': file_hashes['windows_sha256'],
            'post_receipt_mutable_logs': post_receipt_logs,
        }
        row_count = int(metadata['rows'])
        row_counts[split] += row_count
        entries.append({'job': job, 'split': split, 'attempt': attempt,
                        'result': result, 'window_path': window_path,
                        'row_count': row_count, 'window_sha256': file_hashes['windows_sha256'],
                        'post_receipt_mutable_logs': post_receipt_logs})
        available_seed_rows.add(seed)
        if not evidence['checked_windows']:
            raise ValueError('Strict checker returned no windows')
    missing_seeds = sorted(set(seed_to_split) - available_seed_rows)
    if missing_seeds:
        raise ValueError('No verified IP jobs for requested seeds: ' + ','.join(map(str, missing_seeds)))
    for name, count in row_counts.items():
        if not count:
            raise ValueError('No IP window rows for split ' + name)
    return campaign_root, entries, row_counts, input_hashes, plan


def spool_campaign(entries, row_counts, stage_dir, np):
    """Stream only features, binary labels, and row identities to disk-backed arrays."""
    scratch = stage_dir / 'scratch'
    scratch.mkdir()
    stores = {}
    group_ranges = {split: {} for split in row_counts}
    group_support = {split: {} for split in row_counts}
    for split, count in row_counts.items():
        x_path = scratch / (split + '-features.npy')
        y_path = scratch / (split + '-labels.npy')
        id_path = scratch / (split + '-rows.csv')
        X = np.lib.format.open_memmap(x_path, mode='w+', dtype=np.float32,
                                      shape=(count, len(FEATURES)))
        Y = np.lib.format.open_memmap(y_path, mode='w+', dtype=np.uint8,
                                      shape=(count, len(FAMILIES)))
        stores[split] = {'X_path': x_path, 'Y_path': y_path, 'id_path': id_path,
                         'X': X, 'Y': Y, 'position': 0}
    handles = {}
    writers = {}
    try:
        for split, store in stores.items():
            handle = store['id_path'].open('w', newline='', encoding='utf-8')
            writer = csv.DictWriter(handle, fieldnames=('job_id', 'seed', 'source_group_id', 'window_index'))
            writer.writeheader()
            handles[split], writers[split] = handle, writer
        for entry in entries:
            split = entry['split']
            store = stores[split]
            start = store['position']
            job = entry['job']
            window_path = entry['window_path']
            if sha256(window_path) != entry['window_sha256']:
                raise ValueError('IP window source changed after campaign verification')
            with window_path.open(newline='', encoding='utf-8') as handle:
                reader = csv.DictReader(handle)
                if not set(FEATURES).issubset(reader.fieldnames or []):
                    raise ValueError('IP primary feature columns are missing')
                count = 0
                for raw in reader:
                    labels = parse_families(raw['attack_families'])
                    values = [float(raw[feature]) for feature in FEATURES]
                    if any(not math.isfinite(value) for value in values):
                        raise ValueError('Non-finite primary feature in ' + job['id'])
                    y = [int(family in labels) for family in FAMILIES]
                    position = store['position']
                    store['X'][position, :] = values
                    store['Y'][position, :] = y
                    source_group = raw['source_group_id']
                    writers[split].writerow({'job_id': job['id'], 'seed': job['seed'],
                                             'source_group_id': source_group,
                                             'window_index': raw['window_index']})
                    group_key = (str(job['seed']), job['id'], source_group)
                    if group_key not in group_ranges[split]:
                        group_ranges[split][group_key] = []
                        group_support[split][group_key] = [0] * len(FAMILIES)
                    group_support[split][group_key] = [old + bit for old, bit in zip(group_support[split][group_key], y)]
                    count += 1
                    store['position'] += 1
                if count != entry['row_count']:
                    raise ValueError('IP window row count changed during read: ' + job['id'])
            group_ranges[split][group_key].append((start, store['position']))
        for split, store in stores.items():
            if store['position'] != row_counts[split]:
                raise ValueError('Spool row count mismatch: ' + split)
            store['X'].flush(); store['Y'].flush()
    finally:
        for handle in handles.values():
            handle.close()
    for store in stores.values():
        del store['X']; del store['Y']
    return stores, group_ranges, group_support


def _average_precision(labels, scores):
    positives = sum(labels)
    if positives == 0:
        return 0.0
    ordering = sorted(range(len(labels)), key=lambda i: scores[i], reverse=True)
    cumulative_tp = 0
    cumulative_fp = 0
    total = 0.0
    start = 0
    while start < len(ordering):
        score = scores[ordering[start]]
        end = start
        group_tp = 0
        while end < len(ordering) and scores[ordering[end]] == score:
            group_tp += labels[ordering[end]]
            end += 1
        cumulative_tp += group_tp
        cumulative_fp += end - start - group_tp
        if group_tp:
            total += (group_tp / positives) * (cumulative_tp / (cumulative_tp + cumulative_fp))
        start = end
    return total


def _f1(tp, fp, fn):
    denom = (2 * tp) + fp + fn
    return (2 * tp / denom) if denom else 0.0


def choose_thresholds(labels, probabilities, grid=THRESHOLD_GRID):
    """Choose each label threshold by validation F1 over the fixed grid only."""
    thresholds = {}
    details = {}
    for column, family in enumerate(FAMILIES):
        truth = [row[column] for row in labels]
        if not any(truth) or all(truth):
            raise ValueError('Validation must contain positive and negative examples for ' + family)
        best = None
        for threshold in grid:
            pred = [int(row[column] >= threshold) for row in probabilities]
            tp = sum(y == 1 and p == 1 for y, p in zip(truth, pred))
            fp = sum(y == 0 and p == 1 for y, p in zip(truth, pred))
            fn = sum(y == 1 and p == 0 for y, p in zip(truth, pred))
            score = _f1(tp, fp, fn)
            candidate = (score, -abs(threshold - 0.5), threshold)
            if best is None or candidate > best:
                best = candidate
                details[family] = {'f1': score, 'threshold': threshold,
                                   'validation_support': sum(truth)}
        thresholds[family] = details[family]['threshold']
    return thresholds, details


def threshold_probabilities(probabilities, thresholds):
    return [[int(value >= thresholds[family]) for family, value in zip(FAMILIES, row)]
            for row in probabilities]


def summarize_metrics(labels, predictions, probabilities):
    """Return multilabel, per-family AP, and exact categorical confusion evidence."""
    if not labels or len(labels) != len(predictions) or len(labels) != len(probabilities):
        raise ValueError('Metric matrices must have the same nonzero row count')
    per_family = {}
    total_tp = total_fp = total_fn = total_errors = 0
    per_f1 = []
    for column, family in enumerate(FAMILIES):
        truth = [row[column] for row in labels]
        predicted = [row[column] for row in predictions]
        tp = sum(y == 1 and p == 1 for y, p in zip(truth, predicted))
        fp = sum(y == 0 and p == 1 for y, p in zip(truth, predicted))
        fn = sum(y == 1 and p == 0 for y, p in zip(truth, predicted))
        support = sum(truth)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / support if support else 0.0
        f1 = _f1(tp, fp, fn)
        ap = _average_precision(truth, [row[column] for row in probabilities])
        per_family[family] = {'precision': precision, 'recall': recall, 'f1': f1,
                              'average_precision': ap, 'support': support,
                              'predicted_support': sum(predicted)}
        total_tp += tp; total_fp += fp; total_fn += fn
        total_errors += sum(y != p for y, p in zip(truth, predicted))
        per_f1.append(f1)
    exact = sum(truth == pred for truth, pred in zip(labels, predictions))
    true_categories = [categorical_label([FAMILIES[i] for i, value in enumerate(row) if value]) for row in labels]
    predicted_categories = [categorical_label([FAMILIES[i] for i, value in enumerate(row) if value]) for row in predictions]
    categories = sorted(set(true_categories) | set(predicted_categories))
    confusion = {actual: {predicted: 0 for predicted in categories} for actual in categories}
    for actual, predicted in zip(true_categories, predicted_categories):
        confusion[actual][predicted] += 1
    true_category_counts = {name: true_categories.count(name) for name in categories}
    predicted_category_counts = {name: predicted_categories.count(name) for name in categories}
    mixture_counts = {
        'true': {name: count for name, count in true_category_counts.items() if name.startswith('mixture:')},
        'predicted': {name: count for name, count in predicted_category_counts.items() if name.startswith('mixture:')},
    }
    return {
        'rows': len(labels),
        'family_metrics': per_family,
        'macro_f1': sum(per_f1) / len(per_f1),
        'micro_f1': _f1(total_tp, total_fp, total_fn),
        'hamming_loss': total_errors / (len(labels) * len(FAMILIES)),
        'exact_match_accuracy': exact / len(labels),
        'categorical': {
            'category_definition': 'normal; exact single family; or explicit mixture:<all observed families>',
            'true_support': true_category_counts,
            'predicted_support': predicted_category_counts,
            'mixture_support': mixture_counts,
            'confusion_matrix': confusion,
        },
    }


def _matrix(rows):
    return [row['features'] for row in rows]


def _labels(rows):
    return [[int(family in row['labels']) for family in FAMILIES] for row in rows]


def _predict(models, features, np):
    X = np.asarray(features, dtype=np.float64)
    result = []
    for model in models:
        probabilities = model.predict_proba(X)
        positive_index = list(model.classes_).index(1)
        result.append(probabilities[:, positive_index].tolist())
    return [list(row) for row in zip(*result)]


def select_training_view(X, Y, group_ranges, group_support, max_rows=500000,
                         sample_seed=671129):
    """Keep whole job/window groups when the fixed training cap is exceeded."""
    original_rows = int(X.shape[0])
    group_sizes = {key: sum(end - start for start, end in ranges)
                   for key, ranges in group_ranges.items()}
    keys = list(group_sizes)
    random.Random(sample_seed).shuffle(keys)
    selected = []
    kept_rows = 0
    for key in keys:
        size = group_sizes[key]
        if kept_rows + size <= max_rows:
            selected.append(key)
            kept_rows += size
    if kept_rows == 0:
        raise ValueError('No whole training groups fit the 500000-row cap')
    if kept_rows > max_rows or kept_rows > original_rows:
        raise ValueError('Training sample exceeds the fixed cap or original training rows')
    kept_set = set(selected)
    label_original = [0] * len(FAMILIES)
    label_kept = [0] * len(FAMILIES)
    per_group = []
    for key in sorted(group_sizes):
        supports = group_support[key]
        label_original = [old + value for old, value in zip(label_original, supports)]
        kept = key in kept_set
        if kept:
            label_kept = [old + value for old, value in zip(label_kept, supports)]
        per_group.append({
            'seed': int(key[0]), 'job_id': key[1], 'source_group_id': key[2],
            'original_rows': group_sizes[key], 'kept_rows': group_sizes[key] if kept else 0,
            'original_label_support': dict(zip(FAMILIES, supports)),
            'kept_label_support': dict(zip(FAMILIES, supports if kept else [0] * len(FAMILIES))),
        })
    if kept_rows == original_rows:
        train_X, train_Y = X, Y
    else:
        import numpy as np
        train_X = np.empty((kept_rows, X.shape[1]), dtype=np.float32)
        train_Y = np.empty((kept_rows, Y.shape[1]), dtype=np.uint8)
        position = 0
        for key in selected:
            for start, end in group_ranges[key]:
                width = end - start
                train_X[position:position + width] = X[start:end]
                train_Y[position:position + width] = Y[start:end]
                position += width
    if label_kept != [int(Y[:, i].sum()) for i in range(len(FAMILIES))] and kept_rows == original_rows:
        raise ValueError('Internal full-sample label support mismatch')
    return train_X, train_Y, {
        'maximum_rows': max_rows,
        'sample_seed': sample_seed,
        'group_unit': 'whole job_id + source_group_id within a disjoint root seed',
        'original_rows': original_rows,
        'kept_rows': kept_rows,
        'subsampled': kept_rows != original_rows,
        'original_label_support': dict(zip(FAMILIES, label_original)),
        'kept_label_support': dict(zip(FAMILIES, label_kept)),
        'groups': per_group,
    }


def _probability_batch(models, X, np):
    return np.asarray(_predict(models, X, np), dtype=np.float64)


def calibrate_thresholds(models, store, np, batch_size=25000):
    """Calibrate the fixed threshold grid using only the validation split."""
    X = np.load(store['X_path'], mmap_mode='r')
    Y = np.load(store['Y_path'], mmap_mode='r')
    totals = [[0, 0, 0] for _ in FAMILIES]
    for start in range(0, Y.shape[0], batch_size):
        end = min(Y.shape[0], start + batch_size)
        truth = np.asarray(Y[start:end], dtype=np.uint8)
        probabilities = _probability_batch(models, X[start:end], np)
        for index, family in enumerate(FAMILIES):
            actual = truth[:, index].astype(bool)
            positives = int(actual.sum())
            if not positives:
                raise ValueError('Validation has no positive examples for ' + family)
            # Accumulating this first is sufficient to establish global negatives.
            totals[index][0] += positives
            totals[index][1] += len(actual) - positives
    for index, family in enumerate(FAMILIES):
        if not totals[index][0] or not totals[index][1]:
            raise ValueError('Validation must contain positive and negative examples for ' + family)
    candidates = [[{'tp': 0, 'fp': 0, 'fn': 0} for _ in THRESHOLD_GRID]
                  for _ in FAMILIES]
    for start in range(0, Y.shape[0], batch_size):
        end = min(Y.shape[0], start + batch_size)
        truth = np.asarray(Y[start:end], dtype=np.uint8)
        probabilities = _probability_batch(models, X[start:end], np)
        for index in range(len(FAMILIES)):
            actual = truth[:, index].astype(bool)
            for threshold_index, threshold in enumerate(THRESHOLD_GRID):
                predicted = probabilities[:, index] >= threshold
                score = candidates[index][threshold_index]
                score['tp'] += int(np.logical_and(actual, predicted).sum())
                score['fp'] += int(np.logical_and(~actual, predicted).sum())
                score['fn'] += int(np.logical_and(actual, ~predicted).sum())
    thresholds, evidence = {}, {}
    for index, family in enumerate(FAMILIES):
        best = None
        for threshold, counts in zip(THRESHOLD_GRID, candidates[index]):
            f1 = _f1(counts['tp'], counts['fp'], counts['fn'])
            candidate = (f1, -abs(threshold - 0.5), threshold)
            if best is None or candidate > best:
                best = candidate
                thresholds[family] = threshold
                evidence[family] = {'f1': f1, 'threshold': threshold,
                                    'validation_support': totals[index][0]}
    return thresholds, evidence


def verify_model_roundtrip(original_models, loaded_models, store, thresholds,
                           np, batch_size=25000):
    X = np.load(store['X_path'], mmap_mode='r')
    for start in range(0, X.shape[0], batch_size):
        end = min(X.shape[0], start + batch_size)
        original = _probability_batch(original_models, X[start:end], np)
        loaded = _probability_batch(loaded_models, X[start:end], np)
        if not np.allclose(original, loaded, rtol=0, atol=1e-12):
            raise ValueError('Model round-trip probability mismatch')
        if threshold_probabilities(original.tolist(), thresholds) != threshold_probabilities(loaded.tolist(), thresholds):
            raise ValueError('Model round-trip decision mismatch')
    return True


PREDICTION_COLUMNS = (
    'split', 'job_id', 'seed', 'source_group_id', 'window_index',
    'true_families', 'predicted_families', 'true_category', 'predicted_category',
    *(f'probability_{family}' for family in FAMILIES),
    *(f'predicted_{family}' for family in FAMILIES),
)


def evaluate_store(split, store, models, thresholds, predictions_path,
                   scratch, np, batch_size=25000):
    """Stream predictions, classification counts, and AP ranking aggregation."""
    X = np.load(store['X_path'], mmap_mode='r')
    Y = np.load(store['Y_path'], mmap_mode='r')
    count = int(Y.shape[0])
    db_path = scratch / (split + '-average-precision.sqlite')
    if db_path.exists():
        db_path.unlink()
    db = sqlite3.connect(db_path)
    db.execute('CREATE TABLE score (family INTEGER NOT NULL, probability REAL NOT NULL, truth INTEGER NOT NULL)')
    db.execute('CREATE INDEX score_order ON score(family, probability DESC)')
    tp = [0] * len(FAMILIES); fp = [0] * len(FAMILIES); fn = [0] * len(FAMILIES)
    support = [0] * len(FAMILIES); predicted_support = [0] * len(FAMILIES)
    hamming_errors = exact = 0
    true_categories, predicted_categories = Counter(), Counter()
    categorical_pairs = Counter()
    file_mode = 'a' if predictions_path.exists() else 'w'
    with predictions_path.open(file_mode, newline='', encoding='utf-8') as output:
        writer = csv.DictWriter(output, fieldnames=PREDICTION_COLUMNS)
        if file_mode == 'w':
            writer.writeheader()
        with store['id_path'].open(newline='', encoding='utf-8') as id_handle:
            id_reader = csv.DictReader(id_handle)
            processed = 0
            for start in range(0, count, batch_size):
                end = min(count, start + batch_size)
                truth = np.asarray(Y[start:end], dtype=np.uint8)
                probabilities = _probability_batch(models, X[start:end], np)
                predictions = (probabilities >= np.asarray([thresholds[f] for f in FAMILIES])).astype(np.uint8)
                rows_in_batch = end - start
                ids = [next(id_reader) for _ in range(rows_in_batch)]
                for index in range(len(FAMILIES)):
                    actual = truth[:, index].astype(bool)
                    predicted = predictions[:, index].astype(bool)
                    tp[index] += int(np.logical_and(actual, predicted).sum())
                    fp[index] += int(np.logical_and(~actual, predicted).sum())
                    fn[index] += int(np.logical_and(actual, ~predicted).sum())
                    support[index] += int(actual.sum())
                    predicted_support[index] += int(predicted.sum())
                hamming_errors += int(np.not_equal(truth, predictions).sum())
                exact += int(np.all(truth == predictions, axis=1).sum())
                db.executemany('INSERT INTO score VALUES (?,?,?)', (
                    (family_index, float(probabilities[row_index, family_index]),
                     int(truth[row_index, family_index]))
                    for row_index in range(rows_in_batch)
                    for family_index in range(len(FAMILIES))))
                for row_index, identity in enumerate(ids):
                    true_families = [family for family, value in zip(FAMILIES, truth[row_index]) if value]
                    predicted_families = [family for family, value in zip(FAMILIES, predictions[row_index]) if value]
                    true_category = categorical_label(true_families)
                    predicted_category = categorical_label(predicted_families)
                    true_categories[true_category] += 1
                    predicted_categories[predicted_category] += 1
                    categorical_pairs[(true_category, predicted_category)] += 1
                    record = {
                        'split': split, 'job_id': identity['job_id'], 'seed': identity['seed'],
                        'source_group_id': identity['source_group_id'],
                        'window_index': identity['window_index'],
                        'true_families': '|'.join(true_families) or 'none',
                        'predicted_families': '|'.join(predicted_families) or 'none',
                        'true_category': true_category,
                        'predicted_category': predicted_category,
                    }
                    record.update({f'probability_{family}': format(float(probability), '.12g')
                                   for family, probability in zip(FAMILIES, probabilities[row_index])})
                    record.update({f'predicted_{family}': int(value)
                                   for family, value in zip(FAMILIES, predictions[row_index])})
                    writer.writerow(record)
                processed += rows_in_batch
            if processed != count:
                raise ValueError('Prediction row count mismatch in ' + split)
            if next(id_reader, None) is not None:
                raise ValueError('Prediction identity file has excess rows in ' + split)
        output.flush()
    db.commit()
    family_metrics = {}
    for index, family in enumerate(FAMILIES):
        positives = support[index]
        cumulative_tp = cumulative_fp = 0
        average_precision = 0.0
        for score, group_tp, group_size in db.execute(
                'SELECT probability, SUM(truth), COUNT(*) FROM score WHERE family=? GROUP BY probability ORDER BY probability DESC',
                (index,)):
            cumulative_tp += int(group_tp)
            cumulative_fp += int(group_size) - int(group_tp)
            if int(group_tp) and positives:
                average_precision += (int(group_tp) / positives) * (cumulative_tp / (cumulative_tp + cumulative_fp))
        precision = tp[index] / (tp[index] + fp[index]) if tp[index] + fp[index] else 0.0
        recall = tp[index] / positives if positives else 0.0
        family_metrics[family] = {
            'precision': precision, 'recall': recall,
            'f1': _f1(tp[index], fp[index], fn[index]),
            'average_precision': average_precision,
            'support': positives, 'predicted_support': predicted_support[index],
        }
    db.close()
    categories = sorted(set(true_categories) | set(predicted_categories))
    confusion = {actual: {predicted: 0 for predicted in categories} for actual in categories}
    for (actual, predicted), value in categorical_pairs.items():
        confusion[actual][predicted] = value
    return {
        'rows': count, 'family_metrics': family_metrics,
        'macro_f1': sum(item['f1'] for item in family_metrics.values()) / len(FAMILIES),
        'micro_f1': _f1(sum(tp), sum(fp), sum(fn)),
        'hamming_loss': hamming_errors / (count * len(FAMILIES)),
        'exact_match_accuracy': exact / count,
        'categorical': {
            'category_definition': 'normal; exact single family; or explicit mixture:<all observed families>',
            'true_support': dict(sorted(true_categories.items())),
            'predicted_support': dict(sorted(predicted_categories.items())),
            'mixture_support': {
                'true': {key: value for key, value in sorted(true_categories.items()) if key.startswith('mixture:')},
                'predicted': {key: value for key, value in sorted(predicted_categories.items()) if key.startswith('mixture:')},
            },
            'confusion_matrix': confusion,
        },
    }


def _write_predictions(path, split_rows, predictions, probabilities):
    columns = ['split', 'job_id', 'seed', 'source_group_id', 'window_index',
               'true_families', 'predicted_families', 'true_category',
               'predicted_category']
    columns.extend(f'probability_{family}' for family in FAMILIES)
    columns.extend(f'predicted_{family}' for family in FAMILIES)
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row, predicted, probability in zip(split_rows, predictions, probabilities):
            predicted_families = [family for family, bit in zip(FAMILIES, predicted) if bit]
            record = {
                'split': row['split'], 'job_id': row['job_id'], 'seed': row['seed'],
                'source_group_id': row['source_group_id'], 'window_index': row['window_index'],
                'true_families': '|'.join(row['labels']) or 'none',
                'predicted_families': '|'.join(predicted_families) or 'none',
                'true_category': row['category'],
                'predicted_category': categorical_label(predicted_families),
            }
            record.update({f'probability_{family}': format(value, '.12g')
                           for family, value in zip(FAMILIES, probability)})
            record.update({f'predicted_{family}': value for family, value in zip(FAMILIES, predicted)})
            writer.writerow(record)


def train_campaign(campaign, output, train_seeds, validation_seeds,
                   evaluation_seeds, ood_seeds):
    """Train and atomically publish an RF multilabel baseline from a campaign."""
    splits = validate_seed_splits(train_seeds, validation_seeds, evaluation_seeds, ood_seeds)
    campaign_root = Path(campaign).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError('Refusing to overwrite existing output: ' + str(output))
    if not output.parent.is_dir():
        raise FileNotFoundError('Output parent directory must already exist')
    campaign_root, entries, row_counts, input_hashes, plan = index_campaign(campaign_root, splits)
    try:
        import joblib
        import numpy as np
        import sklearn
        from sklearn.ensemble import RandomForestClassifier
    except ImportError as error:
        raise RuntimeError('Training requires numpy, scikit-learn, and joblib in this Python environment') from error

    stage_dir = Path(tempfile.mkdtemp(prefix='.' + output.name + '.staging-', dir=output.parent))
    try:
        stores, group_ranges, group_support = spool_campaign(entries, row_counts, stage_dir, np)
        train_store = stores['train']
        train_X_full = np.load(train_store['X_path'], mmap_mode='r')
        train_Y_full = np.load(train_store['Y_path'], mmap_mode='r')
        train_X, train_Y, sampling = select_training_view(
            train_X_full, train_Y_full, group_ranges['train'], group_support['train'])
        if sampling['kept_rows'] > min(500000, row_counts['train']):
            raise ValueError('Training sample escaped the train-only row cap')
        train_seed_set = set(splits['train'])
        fit_groups = [group for group in sampling['groups'] if group['kept_rows']]
        if any(group['seed'] not in train_seed_set for group in fit_groups):
            raise ValueError('A held-out seed group entered model fitting')
        if sum(group['kept_rows'] for group in fit_groups) != sampling['kept_rows']:
            raise ValueError('Training group audit does not reconcile to the fit row count')
        models = []
        for index, family in enumerate(FAMILIES):
            if len(set(np.asarray(train_Y[:, index]).tolist())) < 2:
                raise ValueError('Training requires positive and negative examples for ' + family)
            model = RandomForestClassifier(**MODEL_PARAMETERS, random_state=611000 + index)
            model.fit(train_X, train_Y[:, index])
            models.append(model)
            print('FITTED attack family: ' + family, flush=True)
        thresholds, threshold_evidence = calibrate_thresholds(models, stores['validation'], np)

        model_path = stage_dir / 'model.joblib'
        model_payload = {
            'families': FAMILIES,
            'features': FEATURES,
            'models': models,
            'thresholds': thresholds,
            'threshold_grid': THRESHOLD_GRID,
            'training_parameters': MODEL_PARAMETERS,
            'training_random_states': [611000 + index for index in range(len(FAMILIES))],
            'training_group_sampling': sampling,
        }
        joblib.dump(model_payload, model_path)
        reloaded = joblib.load(model_path)
        if reloaded['families'] != FAMILIES or reloaded['features'] != FEATURES or reloaded['thresholds'] != thresholds:
            raise ValueError('Model round-trip identity mismatch')
        roundtrip_ok = verify_model_roundtrip(models, reloaded['models'], stores['validation'],
                                              thresholds, np)
        evaluation = {}
        predictions_path = stage_dir / 'predictions.csv'
        for split_name in ('train', 'validation', 'evaluation', 'ood'):
            evaluation[split_name] = evaluate_store(split_name, stores[split_name],
                reloaded['models'], thresholds, predictions_path, stage_dir / 'scratch', np)

        stage = plan['stage']
        scientific_status = {
            'campaign_stage': stage,
            'classification': 'exploratory' if stage == 'development' else 'research_collection_candidate',
            'campaign_scientific_status': plan.get('scientific_status'),
            'confirmatory_protocol_recorded': bool(plan.get('confirmatory_protocol_sha256')),
            'claim_limit': ('Development results are exploratory.' if stage == 'development'
                            else 'Research-collection stage is not by itself an independently validated confirmatory result.'),
        }
        metrics = {
            'format': 'research-ip-categorical-multilabel-v1',
            'scientific_status': scientific_status,
            'campaign': str(campaign_root),
            'campaign_sha256': input_hashes['campaign.json'],
            'analysis_code_sha256': sha256(__file__),
            'splits': {name: list(seed_values) for name, seed_values in splits.items()},
            'split_grouping': 'disjoint root RNG seeds; source_group_id and window_index are retained only as row identity',
            'features': list(FEATURES),
            'feature_exclusion_contract': [
                'raw IPv4/MAC identities and raw port values',
                'seed, run, source_group_id, job_id, window index and time boundaries',
                'observed labels, schedule labels and attack-only counts',
                'activity/flow provenance, injected parameters and context metadata',
            ],
            'targets': {'families': list(FAMILIES), 'normal_encoding': 'all six binary targets are zero',
                        'label_source': 'observed attack_families; attack_scheduled is audit-only',
                        'mixtures': 'all observed family bits are preserved; no single-label collapse'},
            'model': {'estimator': 'RandomForestClassifier, one independent binary head per family',
                      **MODEL_PARAMETERS, 'random_states': model_payload['training_random_states'],
                      'scikit_learn_version': sklearn.__version__},
            'threshold_selection': {'source_split': 'validation', 'grid': list(THRESHOLD_GRID),
                                    'rule': 'maximize family-wise validation F1; tie-break nearest 0.5 then higher threshold',
                                    'per_family': threshold_evidence},
            'training_group_sampling': sampling,
            'metrics_by_split': evaluation,
            'input_hashes': input_hashes,
            'roundtrip_verification': {'probabilities_atol': 1e-12,
                                       'validation_decisions_equal': roundtrip_ok},
        }
        metrics_path = stage_dir / 'metrics.json'
        metrics_path.write_text(json.dumps(metrics, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        artifacts = {}
        for path in sorted(stage_dir.iterdir()):
            if path.is_file() and path.name != 'artifact_manifest.json':
                artifacts[path.name] = sha256(path)
        (stage_dir / 'artifact_manifest.json').write_text(
            json.dumps({'files': artifacts}, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        if output.exists() or output.is_symlink():
            raise FileExistsError('Refusing to overwrite existing output: ' + str(output))
        shutil.rmtree(stage_dir / 'scratch')
        os.rename(stage_dir, output)
        return {'output': str(output), 'metrics': metrics, 'artifact_hashes': artifacts}
    except BaseException:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--train-seeds', required=True, nargs='+', type=int)
    parser.add_argument('--validation-seeds', required=True, nargs='+', type=int)
    parser.add_argument('--evaluation-seeds', required=True, nargs='+', type=int)
    parser.add_argument('--ood-seeds', required=True, nargs='+', type=int)
    args = parser.parse_args(argv)
    result = train_campaign(args.campaign, args.output, args.train_seeds,
                            args.validation_seeds, args.evaluation_seeds, args.ood_seeds)
    print(json.dumps({'output': result['output'], 'scientific_status': result['metrics']['scientific_status'],
                      'metrics_by_split': result['metrics']['metrics_by_split']}, indent=2))


if __name__ == '__main__':
    main()
