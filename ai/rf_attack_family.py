"""Categorical none/FGSM/PGD detector for verified moment-MLP RF references.

Seven observed IQ moments only. Separate detectors for sensing, three-class AMC,
and scalar-channel victims; no claim of six-class research AMC, OTA or new methods.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform

FEATURES = ('mean_i', 'mean_q', 'mean_i2', 'mean_q2', 'mean_i4', 'mean_q4', 'mean_iq')
CLASSES = ('none', 'fgsm', 'pgd')
TASKS = ('sensing', 'amc', 'channel')
SPLITS = ('train', 'validation', 'test')
OUTPUT_ROOT = Path('/mnt/onetb/ran-ai-lab')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
    temporary.replace(path)


def load_dataset(directory):
    """Read only the explicit features, categorical target and grouping columns."""
    import numpy as np
    import pandas as pd
    directory = Path(directory)
    metadata = json.loads((directory / 'dataset.json').read_text())
    if metadata.get('feature_columns') != list(FEATURES) or metadata.get('multiclass_target_column') != 'attack_type':
        raise ValueError('Unexpected feature/target contract')
    if set(metadata.get('modes', [])) != {'fgsm', 'pgd'}:
        raise ValueError('Both declared reference attack methods required')
    if json.loads((directory / 'run_status.json').read_text()).get('state') != 'completed':
        raise ValueError('Incomplete detection export')
    result = {}
    columns = list(FEATURES) + ['attack_type', 'task', 'group_id']
    for split in SPLITS:
        entry = metadata['files'][split]
        if entry['path'] != split + '.csv':
            raise ValueError('Unexpected export path')
        path = directory / entry['path']
        if path.is_symlink() or sha(path) != entry['sha256']:
            raise ValueError('CSV hash mismatch')
        with path.open(newline='') as handle:
            header = next(csv.reader(handle))
        if len(header) != len(set(header)) or not set(columns).issubset(header):
            raise ValueError('Duplicate/missing CSV columns')
        pieces = []
        with pd.read_csv(path, usecols=columns, dtype={key: 'float64' for key in FEATURES},
                         keep_default_na=False, chunksize=50000) as reader:
            for chunk in reader:
                if not np.isfinite(chunk[list(FEATURES)].to_numpy()).all():
                    raise ValueError('Nonfinite features')
                for key, allowed in (('attack_type', CLASSES), ('task', TASKS)):
                    if not chunk[key].isin(allowed).all():
                        raise ValueError('Unknown ' + key)
                if chunk['group_id'].astype(str).str.strip().eq('').any():
                    raise ValueError('Empty group')
                pieces.append(chunk)
        if not pieces:
            raise ValueError('Empty split')
        frame = pd.concat(pieces, ignore_index=True)
        for task in TASKS:
            selected = frame[frame.task == task]
            counts = entry['counts'][task]
            if len(selected) != counts['total']:
                raise ValueError('Source count mismatch')
            actual = selected.attack_type.value_counts().to_dict()
            if any(int(actual.get(label, 0)) != counts['by_type'].get(label, 0) for label in CLASSES):
                raise ValueError('Source class count mismatch')
        result[split] = frame
    validate_groups(result)
    return result


def validate_groups(parts):
    seen = set()
    for split in SPLITS:
        groups = set(parts[split]['group_id'].astype(str))
        if not groups or groups & seen:
            raise ValueError('Source groups must be disjoint across splits')
        seen.update(groups)


def metrics(y, prediction, probabilities):
    import numpy as np
    from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support
    precision, recall, f1, support = precision_recall_fscore_support(y, prediction, labels=list(CLASSES), zero_division=0)
    per_class = {}
    for index, label in enumerate(CLASSES):
        positive = np.asarray(y) == label
        ap = float(average_precision_score(positive, probabilities[:, index])) if positive.any() else None
        per_class[label] = dict(precision=float(precision[index]), recall=float(recall[index]),
                               f1=float(f1[index]), support=int(support[index]), average_precision=ap,
                               ap_prevalence_baseline=float(np.mean(positive)))
    return dict(macro_f1=float(np.mean(f1)), per_class=per_class,
                confusion_matrix=confusion_matrix(y, prediction, labels=list(CLASSES)).tolist(),
                confusion_label_order=list(CLASSES), rows=len(y))


def train(campaign, output):
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from simulation.run_research_campaign import verify_receipt
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(output)
    if not output.is_relative_to(OUTPUT_ROOT.resolve()):
        raise ValueError('Outputs must stay on authorized data volume')
    campaign = Path(campaign).resolve(strict=True)
    plan_path = campaign / 'campaign.json'
    plan_hash = sha(plan_path)
    plan = json.loads(plan_path.read_text())
    if plan['state'] != 'complete':
        raise ValueError('Completed campaign required')
    jobs = [j for j in plan['jobs'] if j['kind'] == 'rf_attack']
    if not jobs:
        raise ValueError('No RF reference attack jobs')
    parts = {split: [] for split in SPLITS}
    sources = {}
    for job in jobs:
        if job['state'] != 'complete' or not job['attempts'] or job['attempts'][-1]['state'] != 'complete':
            raise ValueError('Incomplete RF attack job')
        attempt = (campaign / job['attempts'][-1]['path']).resolve(strict=True)
        if not attempt.is_relative_to(campaign):
            raise ValueError('Attempt escapes campaign')
        verify_receipt(campaign, job)
        receipt = json.loads((attempt / 'receipt.json').read_text())
        required = ['verification.json', 'attack-family-data/dataset.json', 'attack-family-data/run_status.json']
        required += ['attack-family-data/' + split + '.csv' for split in SPLITS]
        if not set(required).issubset(receipt['files']):
            raise ValueError('Receipt does not cover verified attack-family export')
        loaded = load_dataset(attempt / 'attack-family-data')
        for split in SPLITS:
            parts[split].append(loaded[split])
        sources[job['id']] = dict(receipt_sha256=sha(attempt / 'receipt.json'),
                                 files={name: receipt['files'][name] for name in required})
    parts = {split: pd.concat(frames, ignore_index=True) for split, frames in parts.items()}
    validate_groups(parts)
    # No output artifacts until all source contracts and split boundaries pass.
    output.mkdir(parents=True, exist_ok=False)
    try:
        save(output / 'status.json', dict(state='fitting'))
        report = dict(schema='rf-attack-family-v1', target='attack_type', classes=list(CLASSES),
                      feature_columns=list(FEATURES), campaign_sha256=plan_hash, source_sha256=sources,
                      implementation_sha256=sha(__file__), results={},
                      environment=dict(python=platform.python_version(), sklearn=sklearn.__version__,
                                       numpy=np.__version__, pandas=pd.__version__, joblib=joblib.__version__),
                      scope='Observed-IQ seven-moment method classification on moment-MLP reference victims only; sensing, historical 3-class AMC and scalar H. Known none/FGSM/PGD only; no OTA, new 6-class AMC or unseen-method claim.',
                      selection='Fixed RF hyperparameters, argmax categorical prediction; no validation/test tuning.',
                      caveats=['Repeated source groups within a split are correlated contexts, not independent samples.',
                               'Method labels express applied perturbation, not attack success or attacker attribution.',
                               'No external validation or group-bootstrap confidence intervals.'])
        for task in TASKS:
            data = {split: frame[frame.task == task] for split, frame in parts.items()}
            if any(len(frame) == 0 for frame in data.values()) or set(data['train'].attack_type) != set(CLASSES):
                raise ValueError('All tasks and training classes required')
            model = RandomForestClassifier(n_estimators=100, max_depth=20, max_leaf_nodes=2048,
                                           min_samples_leaf=5, n_jobs=2, random_state=930101)
            model.fit(data['train'][list(FEATURES)], data['train'].attack_type)
            if list(model.feature_names_in_) != list(FEATURES) or set(model.classes_) != set(CLASSES):
                raise ValueError('Fitted feature/class contract changed')
            model_path = output / (task + '-rf-attack-family-v1.joblib')
            joblib.dump(dict(schema='rf-attack-family-v1', model=model, feature_columns=list(FEATURES),
                             target='attack_type', classes=list(CLASSES), sklearn_version=sklearn.__version__), model_path, compress=3)
            restored = joblib.load(model_path)['model']
            task_result = dict(model_sha256=sha(model_path), model_parameters=model.get_params(), splits={})
            majority = data['train'].attack_type.value_counts().idxmax()
            for split, frame in data.items():
                x = frame[list(FEATURES)]
                probability = model.predict_proba(x)
                np.testing.assert_allclose(restored.predict_proba(x), probability, rtol=1e-12, atol=1e-14)
                prediction = model.predict(x)
                if not np.array_equal(restored.predict(x), prediction):
                    raise ValueError('Restored model changed class decisions')
                ordered = probability[:, [list(model.classes_).index(label) for label in CLASSES]]
                result = metrics(frame.attack_type, prediction, ordered)
                baseline = np.zeros((len(frame), len(CLASSES)))
                baseline[:, CLASSES.index(majority)] = 1
                result['majority_baseline'] = metrics(frame.attack_type, np.full(len(frame), majority), baseline)
                result['majority_baseline']['training_selected_class'] = majority
                result['unique_groups'] = int(frame.group_id.nunique())
                task_result['splits'][split] = result
            report['results'][task] = task_result
            save(output / 'metrics.json', report)
        # Sources/receipts must remain stable throughout loading and fitting.
        if sha(plan_path) != plan_hash:
            raise ValueError('Campaign changed during fitting')
        for job in jobs:
            verify_receipt(campaign, job)
        save(output / 'metrics.json', report)
        save(output / 'status.json', dict(state='complete', schema='rf-attack-family-v1'))
        save(output / 'checksums.json', {p.name: sha(p) for p in output.iterdir() if p.is_file()})
        return report
    except BaseException as error:
        save(output / 'status.json', dict(state='failed', error=str(error)))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaign', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    train(args.campaign, args.output)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
