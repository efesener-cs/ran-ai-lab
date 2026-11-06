# Compact Kaggle CSV export

`datasets.export_compact_kaggle` makes a small, reviewable CSV export from a completed research campaign. The package is a documented **TABULAR FEATURE VIEW**, not a replacement for the raw signal archive. It verifies every campaign job receipt before writing, then applies the strict IP raw-output checker to each exported IP job. It does not upload data.

## Export a campaign

Pass all four disjoint seed roles explicitly:

```bash
python3 -m datasets.export_compact_kaggle \
  --campaign /mnt/onetb/ran-ai-lab/results/research-campaigns/CAMPAIGN \
  --output /mnt/onetb/ran-ai-lab/exports/compact-preview \
  --train-seeds 930101 930102 \
  --validation-seeds 930103 \
  --test-seeds 930104 \
  --ood-seeds 930105 \
  --max-shard-mb 1000
```

When the campaign includes `seed_partition` metadata, the exporter can use it instead of the four seed arguments. Explicit arguments must match that metadata. Output is staged and published as a fresh directory; an existing output directory is never overwritten.

The default split files are `ip_train.csv`, `ip_validation.csv`, `ip_test.csv`, and `ip_ood.csv`. Splits that exceed the configured byte limit become numbered `-part-0001.csv` shards. Sharding preserves every row and never pads smaller files.

## Row contract

Each row includes a unique `sample_id`, audit-only `group_id`, the 23 measured primary window features, `attack_category`, `attack_families`, and six binary `target_` columns. `normal` means no observed family. A single observed family uses its name. Multiple families use `mixed` in `attack_category`; the pipe-separated `attack_families` and all target bits preserve the full mixture.

Only `attack_families` from observed traffic provenance supplies the targets. Scheduled attacks are not labels. The feature list is fixed by `checks.check_ip_research.PRIMARY_FEATURES`; raw IP/MAC identities, raw ports, seed/time identifiers, attack-only counters, and audit fields are excluded. Numeric strings are copied as written in the raw CSV.

The output contains CSV shards, `feature_dictionary.csv`, `dataset_metadata.json`, `README.md`, and `manifest.json` with row counts, verified input receipts, and SHA256 hashes. Raw logs, models, and NPZ files are not included. Dataset id metadata is `efeener298/ran-ai-lab`; license status remains pending. Resolve licensing and publication approval before any upload.

## Local development preview

A development campaign export is exploratory. A `research_collection` stage is marked as a collection candidate; the stage alone does not establish independent confirmation. The exporter preserves the campaign stage and scientific status in both the README and manifest.

## Packaging rationale and offline launch

The official UNSW-NB15 release uses four main CSV parts plus separate training and
test tables (https://research.unsw.edu.au/projects/unsw-nb15-dataset). There is no
universal 1 GB research-dataset rule: preserve documented schemas and group splits
first, then cap physical shard bytes. This exporter defaults to 1000 MiB maximum,
never a minimum. The current public view covers IP windows; RF observations and
training-condition outcomes remain separate archival domains, not omitted claims
of equivalent packet rows.

The 2026-11-06 preview has 24,000 rows, four sample CSVs, and 6,888,840 bytes
including its dictionary and metadata. The separate user unit
`ran-ai-compact-export-20261106-184407.service` waits for the active collection
and then exports to `/mnt/onetb/ran-ai-lab/exports/kaggle-ran-ai-v2-20261106`.
Its source snapshot and hashes live in `exports/export-jobs/compact-20261106-184407`.
No existing data directory is overwritten and no upload is performed.
