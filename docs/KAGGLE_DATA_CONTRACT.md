# Kaggle benchmark data contract

The seven-table normalized schema below remains a preparatory design. The
implemented measured-evidence exporter is described in the next section; these
two formats must not be confused. `datasets/specs/kaggle_schema.json` defines the draft canonical tables,
row units, feature whitelists, targets and release gates. Existing measured data
and experiment code are not rewritten by this document.

## Implemented measured-evidence package

`python3 lab.py package_benchmark CAMPAIGN --output exports/PACKAGE` packages a
fully completed benchmark. It verifies the frozen runtime and successful receipt
hashes, preserves CSV/XML losslessly as gzip and NPZ byte-for-byte, redacts JSON
machine paths, and records original/published hashes and omitted payloads. It
never runs attacks, retrains a model, resumes collection, or uploads anything.
Source campaign evidence is unchanged. Failed attempts remain in the attempt
ledger; partial payloads stay in the campaign. Logs, binaries, SDKs and repeated
scenario sources are excluded from the data artifact.

This format is `ran-measured-evidence-v1`, **not** the seven-table normalized
`0.1-draft` schema. It preserves raw RF/training/IP tables and audit NPZ arrays,
adds consolidated IP train/validation/test CSVs with a strict feature whitelist,
and flattens the recorded RF/training condition summaries. RF seed splits remain
explicit across profile/SNR variants; IP seed/run groups are disjoint across
splits. Raw RF task labels, poison training targets and observed IP attack labels
remain distinct. No OOD or balancing claims are introduced.

Run `python3 lab.py check_measured_package exports/PACKAGE`, or the included
`python validate_package.py PACKAGE`, to check published hashes, decompressed
original hashes, IP window identities/counts/labels, seed separation, finite
features, and NPZ numeric precision without loading pickle. NumPy is optional in
the standalone checker; its result explicitly reports whether arrays were
checked. This does not independently recompute all scientific metrics.
The separate `check_kaggle_structure` checker remains specific to the proposed
normalized schema and must not be applied to this measured format.

The package contains a data card, dictionary, condition summaries, provenance,
checksums and a loader notebook. Until the owner/slug and data license are chosen,
`dataset-metadata.template.json` and `publication-status.json` explicitly mark
publication pending. No fictitious license or upload-ready metadata is generated.
Generated data/archives stay under ignored `exports/` and must not enter Git.

## Labels have different meanings

The original RF CSV's `label` is an occupancy/modulation target. RF detector CSV
`label` is attack presence. Training-poison CSV `label` is the label shown to the
victim during training and can intentionally be wrong. They cannot share an
unqualified label column in one concatenated table.

The normalized release separates true task targets, training targets, intended
attack, observed input change, actual malicious activity and measured success.
Random perturbations used as controls are not automatically malicious. A selected
zero-budget attack can have intent but no changed input. A failed applied attack
remains attack data. Unknown success is null rather than false.

For IP windows, an applied activity label requires observed attack-origin TX,
server RX or a core drop. Scheduling alone is insufficient. IP success remains
unknown unless a predeclared service-impact criterion is actually measured.
For training integrity, only changed training rows receive the poison flag;
clean test inputs of a poisoned model do not automatically become malicious inputs.
Triggered test probes keep their true task labels and are not poisoned training data.

## Feature and audit separation

Every table has a strict feature whitelist. Group/frame/model IDs, attack labels,
schedule, injected power, original clean features, true channel H, and success
flags are audit/target information. They must not leak into a detector because
an automatic numeric-column selector includes them. Aggregate observed cardinality,
IP bytes or delay are measurements; known attack-endpoint breakdowns are ground truth.

RF input arrays remain separate from IP features. Training model outcomes are
model-level evidence, not frame-level detector samples. A future telemetry table
requires the source/control acceptance gate in BENCHMARK_PLAN.md; missing evidence
cannot be filled with zero or repurposed IP rows.

## Identity and splits

Assign stable sample IDs to original frames and observation IDs to each variant.
All observations of one source group stay in one split. Matched IP modes and
contexts sharing seed/run stay together. A source IQ array is stored once and
referenced by observations/deltas, reducing duplication across attack budgets.

Train-only balancing may create an 80/20 view without replacement; publish the
unsampled inventory and kept counts. Validation/test preserve observed prevalence.
Each ID/OOD task has a separate explicit split manifest. A held-out OOD context
must be absent from that task's train/validation allowlists. Never merge tracks
and randomly split rows again. Record sampling policy and selection seed.

## Precision and evidence

Canonical clean IQ and perturbations remain float64 with NPZ pickle disabled.
Float32 convenience data requires a separately identified derivation and validation
of post-conversion norms and predictions; it is not silently substituted for the
measured precision. Parquet/CSV contain relative array references and scalar features.
Every foreign key, array index, length, checksum and declared row count must resolve.

Keep all failed/timeout/resource-limited attempts in the run ledger. Model IDs
link to frozen architecture/weights, training and validation groups, initialization
seed and model-selection rule. Audit requested and realized budgets/fractions.
Success rates include their numerators and denominators; zero denominator means
null rate. Record source/runtime hashes and library/environment versions.

## Packaging and publication

The final package requires a data card, dictionary, citations, chosen data license,
version/checksum manifest, task split manifests and a loader-validation notebook.
Only package-relative paths are published. Local home paths, credentials, SDK
binaries and private source documents are excluded. Code and data licensing are
separate: NOTICE.md currently states that newly authored repository code has no
repository-wide assigned license. Do not advertise an invented license.

Kaggle's official format requires `dataset-metadata.json` alongside the files,
including title, owner/dataset slug and one chosen license. If resource field
schemas are provided, their order must match every actual column. Owner, slug
and data license remain pending user decisions; no upload-ready metadata or
public release is claimed by the current draft.

Sources:
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md
- https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md
- Local experiment contracts: DATASET.md, RF.md, IP_ATTACKS.md, BENCHMARK_PLAN.md.

## Structural checker (preparatory tooling)

Run `python3 -m checks.check_kaggle_structure PACKAGE_DIRECTORY` on a future
normalized package. This is a read-only check, not an experiment or uploader.
It uses the standard library and a temporary SQLite index so primary/foreign-key
checks do not require retaining every frame ID in Python memory.

The package includes `package-index.json` with the draft `schema_version`, a
`tables` mapping containing all seven table names (including empty tables), and
`split_manifests`, a list of relative JSON paths. Each table entry contains
`paths` (CSV shards with identical headers) and an exact integer `rows` total.
Empty tables retain their required headers. Shard paths are unique across tables.
`checksums.sha256` uses `SHA256`, two spaces, and the relative POSIX filename,
one line per file; it covers every file except itself. Symlinks, absolute paths,
parent traversal, extra unlisted files and duplicate checksum entries fail.

Each split manifest additionally names its canonical `table`. Train, validation
and test group lists must be nonempty, unique, known and mutually disjoint;
their observed contexts must belong to the corresponding allowlists. An OOD
track declares `heldout_ood: true`. The feature/target lists must exactly match
the table's whitelists. RF observations must retain their source sample's group
and task identity. Track-relative group assignment is explicit; the checker
does not invent partitions or silently balance data.

Passing returns `structural_verified: true` and **`scientific_verified: false`**.
Array indices/precision, perturbation budgets, model predictions, metric
denominators, raw-to-normalized counts, privacy review and license validity still
require their independent release checks. Header-only fixtures passing this tool
do not establish dataset quality. The tool validates metadata presence/basic
shape; it does not claim to validate every Kaggle platform restriction.
