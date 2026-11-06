"""Read-only package integrity checks; never run experiments or publish data.

This checks packaging, identities and declared splits. It does not independently
recompute model metrics, array budgets or scientific claims.
"""
import argparse
from contextlib import closing
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tempfile


SPEC = Path(__file__).resolve().parents[1] / 'datasets/specs/kaggle_schema.json'


def relative_file(root, name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('Invalid package path: ' + repr(name))
    part = PurePosixPath(name)
    if part.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('Noncanonical package path: ' + name)
    path = root.joinpath(*part.parts)
    if any(p.is_symlink() for p in (path, *path.parents) if p != root.parent):
        raise ValueError('Symlink in package path: ' + name)
    if not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError('Missing or escaping package file: ' + name)
    return path


def read_json(root, name):
    return json.loads(relative_file(root, name).read_text(encoding='utf-8'))


def checksum_inventory(root):
    expected = {}
    for line in relative_file(root, 'checksums.sha256').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        if not match:
            raise ValueError('Invalid checksum line')
        sha, name = match.groups()
        if name in expected or name == 'checksums.sha256':
            raise ValueError('Duplicate or self-referencing checksum: ' + name)
        path = relative_file(root, name)
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != sha:
            raise ValueError('Checksum mismatch: ' + name)
        expected[name] = sha
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in package: ' + str(path.relative_to(root)))
        if path.is_file() and path.name != 'checksums.sha256':
            actual.add(path.relative_to(root).as_posix())
    if actual != set(expected):
        raise ValueError('Checksum inventory does not cover exactly all package files')
    return expected


def validate_metadata(metadata):
    title = metadata.get('title')
    if not isinstance(title, str) or not 6 <= len(title) <= 50:
        raise ValueError('Dataset title must have 6..50 characters')
    if not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_-]+', metadata.get('id', '')):
        raise ValueError('Dataset owner/slug is missing or invalid')
    licenses = metadata.get('licenses')
    if not isinstance(licenses, list) or len(licenses) != 1:
        raise ValueError('Exactly one chosen data license is required')
    if not isinstance(licenses[0], dict) or not licenses[0].get('name'):
        raise ValueError('Chosen license name is missing')


def _identity(values):
    return json.dumps(values, separators=(',', ':'))


def validate_tables(root, index, spec, db):
    tables = index.get('tables', {})
    if set(tables) != set(spec['tables']):
        raise ValueError('Package index must declare all canonical tables, including empty ones')
    db.executescript('CREATE TABLE ids (tab TEXT, key TEXT, PRIMARY KEY(tab,key));'
                     'CREATE TABLE refs (tab TEXT, key TEXT);'
                     'CREATE TABLE groups (tab TEXT, gid TEXT, context TEXT, PRIMARY KEY(tab,gid,context));'
                     'CREATE TABLE rf_origins (sample TEXT PRIMARY KEY, gid TEXT, task TEXT);'
                     'CREATE TABLE rf_links (sample TEXT, gid TEXT, task TEXT);')
    counts, used = {}, set()
    for name, rule in spec['tables'].items():
        entry = tables[name]
        if type(entry.get('rows')) is not int or entry['rows'] < 0:
            raise ValueError('Invalid declared row count: ' + name)
        paths = entry.get('paths')
        if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
            raise ValueError('Declare nonduplicate CSV shard paths: ' + name)
        count, header = 0, None
        for path in paths:
            if path in used or not path.endswith('.csv'):
                raise ValueError('Repeated or non-CSV canonical table shard: ' + str(path))
            used.add(path)
            with relative_file(root, path).open(newline='', encoding='utf-8') as handle:
                reader = csv.DictReader(handle)
                columns = reader.fieldnames
                if not columns or len(columns) != len(set(columns)):
                    raise ValueError('Missing/duplicate CSV columns: ' + path)
                required = set(rule['required_columns']) | set(rule['feature_columns'])
                if not required.issubset(columns) or (header is not None and columns != header):
                    raise ValueError('Missing columns or inconsistent shard headers: ' + path)
                header = columns
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError('Malformed CSV row: ' + path)
                    key = [row[col] for col in rule['primary_key']]
                    if any(not value for value in key):
                        raise ValueError('Empty primary key: ' + name)
                    try:
                        db.execute('INSERT INTO ids VALUES (?,?)', (name, _identity(key)))
                    except sqlite3.IntegrityError as error:
                        raise ValueError('Duplicate primary key: ' + name) from error
                    for col, destination in rule.get('foreign_keys', {}).items():
                        value = row.get(col, '')
                        if not value:
                            if col == 'sample_id':
                                raise ValueError('Missing RF source sample reference')
                            continue  # physical interference may have no victim model
                        target, field = destination.split('.')
                        if spec['tables'][target]['primary_key'] != [field]:
                            raise ValueError('Unsupported foreign-key declaration')
                        db.execute('INSERT INTO refs VALUES (?,?)', (target, _identity([value])))
                    for col in rule['feature_columns']:
                        if not math.isfinite(float(row[col])):
                            raise ValueError('Nonfinite feature: ' + name + '.' + col)
                    if 'attack_applied' in row and row['attack_applied'] not in ('0', '1'):
                        raise ValueError('Attack target must be 0 or 1')
                    for col in ('sample_role', 'dataset_role', 'state'):
                        allowed = rule.get(col + '_values')
                        if allowed and row[col] not in allowed:
                            raise ValueError('Invalid ' + col + ': ' + row[col])
                    if 'source_group_id' in row:
                        if not row['source_group_id']:
                            raise ValueError('Empty source group')
                        db.execute('INSERT OR IGNORE INTO groups VALUES (?,?,?)',
                                   (name, row['source_group_id'], row.get('context_id', '')))
                    if name == 'rf_samples':
                        db.execute('INSERT INTO rf_origins VALUES (?,?,?)',
                                   (row['sample_id'], row['source_group_id'], row['task']))
                    elif name == 'rf_observations':
                        db.execute('INSERT INTO rf_links VALUES (?,?,?)',
                                   (row['sample_id'], row['source_group_id'], row['task']))
                    count += 1
        if count != entry['rows']:
            raise ValueError('Row count mismatch: ' + name)
        counts[name] = count
    if db.execute('SELECT 1 FROM refs r LEFT JOIN ids i ON r.tab=i.tab AND r.key=i.key '
                  'WHERE i.key IS NULL LIMIT 1').fetchone():
        raise ValueError('Unresolved foreign key')
    if db.execute('SELECT 1 FROM rf_links l JOIN rf_origins o ON l.sample=o.sample '
                  'WHERE l.gid != o.gid OR l.task != o.task LIMIT 1').fetchone():
        raise ValueError('RF observation changed source group or task identity')
    return counts


def validate_splits(root, paths, spec, db):
    if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
        raise ValueError('Declare unique split manifests')
    tracks = set()
    for path in paths:
        split = read_json(root, path)
        if not set(spec['split_manifest']['required_fields']).issubset(split):
            raise ValueError('Incomplete split manifest: ' + path)
        track, table = split['benchmark_track'], split.get('table')
        if not track or track in tracks or table not in spec['tables']:
            raise ValueError('Duplicate track or invalid split table')
        tracks.add(track)
        rule = spec['tables'][table]
        for kind in ('feature_columns', 'target_columns'):
            if split[kind] != rule.get(kind, []):
                raise ValueError('Split whitelist mismatch: ' + kind)
        assigned, contexts = set(), {}
        for role in ('train', 'validation', 'test'):
            groups = split[role + '_group_ids']
            allow = split[role + '_context_allowlist']
            if (not isinstance(groups, list) or not groups or
                    any(not isinstance(gid, str) or not gid for gid in groups) or
                    len(groups) != len(set(groups))):
                raise ValueError('Invalid/duplicate split groups')
            if assigned.intersection(groups):
                raise ValueError('Source group leakage between splits')
            assigned.update(groups)
            if not isinstance(allow, list) or len(allow) != len(set(allow)):
                raise ValueError('Invalid context allowlist')
            contexts[role] = set(allow)
            for gid in groups:
                observed = {r[0] for r in db.execute(
                    'SELECT context FROM groups WHERE tab=? AND gid=?', (table, gid))}
                if not observed or not observed.issubset(contexts[role]):
                    raise ValueError('Unknown group or context outside split allowlist')
        if split.get('heldout_ood') and contexts['test'] & (contexts['train'] | contexts['validation']):
            raise ValueError('Held-out OOD context overlaps train/validation')
    return len(tracks)


def verify(package):
    root = Path(package).resolve(strict=True)
    spec = json.loads(SPEC.read_text())
    inventory = checksum_inventory(root)
    for path in spec['release_gate']['required_artifacts']:
        relative_file(root, path)
    index = read_json(root, 'package-index.json')
    if index.get('schema_version') != spec['schema_version']:
        raise ValueError('Package schema version mismatch')
    validate_metadata(read_json(root, 'dataset-metadata.json'))
    with tempfile.TemporaryDirectory(prefix='ran-kaggle-check-') as temporary:
        with closing(sqlite3.connect(str(Path(temporary) / 'identities.sqlite'))) as db:
            counts = validate_tables(root, index, spec, db)
            tracks = validate_splits(root, index.get('split_manifests'), spec, db)
    return dict(structural_verified=True, scientific_verified=False, tables=counts,
                tracks=tracks, hashed_files=len(inventory),
                scope='checksums, CSV shape/counts, identities, foreign keys and declared group/context splits only',
                remaining_gates=['array references/precision/budgets', 'independent model/metric recomputation',
                                 'raw-to-normalized reconciliation', 'content/privacy/license review'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.package)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        parser.exit(1, 'Kaggle structure verification failed: ' + str(error) + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
