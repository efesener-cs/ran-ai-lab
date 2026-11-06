# Adversarial benchmark campaign and Kaggle release plan

Status: the user authorized **two physical CPU cores and approximately 18 hours**
on 2026-11-05. This supersedes the resource/pilot proposals below: the actual
pilot uses 1/2 workers (8 jobs), the queue is capped at two workers on distinct
physical cores, and the wall deadline is 18 hours from first execution.
Kaggle publication and container cloning are not authorized. Docker API access
is unavailable to this agent; collection uses the host and a private relocated
copy of the already-built SDK. The original machine proposal is preserved.

The goal is an independently
repeatable benchmark over the declared threat models, followed by a validated
Kaggle-ready data package. No claim of exhaustive coverage of all RAN AI attacks,
paper reproduction, live DRL/RIC control or OTA validation is made by the current
RF/IP examples. The user's approval covers this bounded RF/IP/training collection.
Upload/publication requires a separate explicit instruction.

## Coverage and evidence gates

| Track | Existing implementation | Release boundary or work required |
|---|---|---|
| RF sensing and AMC | Three synthetic channel/receiver profiles; moment MLP; FGSM, L2 PGD and controls | Narrowband, three AMC classes; receiver-additive white box; not a raw-IQ CNN or OTA attack |
| Channel estimation | Scalar block-flat H and pilot observations; oracle-label MSE attacks | Not OFDM/MIMO/RIS; true-H attacker knowledge must be recorded |
| RF physical interference | Tone, barrage, burst, pilot contamination sidecars | Separate from gradient attacks; no transmitter-to-victim attacker channel |
| Training integrity | New C++ label flip, random feature corruption, static-trigger backdoor; actual retraining | New files are not yet committed; finish independent checks before source freeze |
| Classical IP | Six traffic families plus clean/mixed; measured ns-3 IP/app/queue evidence | Wired IP, not a cellular radio/RIC experiment |
| SINR telemetry and RAN control | Existing runners and historical accepted campaign | Select an explicit original scenario, verify current telemetry/control contract and SDK; historical runs alone do not clear this gate |
| Black-box, universal/sparse attacks, defenses | Not all are implemented in current RF pipeline | Separate, approved development scope; do not label missing implementations complete |
| DRL/GNN, FL/model poisoning, extraction/inversion/privacy attacks | Not implemented by the three new examples | Require additional models, interfaces, metrics and acceptance; outside the proposed v1 unless user expands scope |

This proposal uses the user's report, particularly sections 6, 7, 8, 13 and 15.
The scope decision is pending. A broader choice needs a revised job matrix and
budget; it cannot be satisfied by relabeling ordinary noise or IP traffic.

## Proposed confirmatory matrix

All settings are fixed before looking at new test results. Failed/negative
attacks remain in the ledger. A small number of pilot runs is never a final
statistical benchmark. Parameter sweeps are scenarios, not independent replicates.

### RF

- Profiles: baseline, diverse, stress. Nominal SNR: -5, 0, 10, 20 dB.
- Five independent training repetitions; train/validation/test seed triples
  (1001..1005, 2001..2005, 3001..3005), paired by repetition index.
- 3000/1000/1000 frames per task, 128 complex samples, 80 maximum epochs with
  clean-validation model selection. Three tasks per configuration.
- 60 RF blocks, 33 task/attack/control conditions each = 1980 logical conditions.
- Keep clean, zero budget, equal-power random, FGSM and L2 PGD at -20/-10/-6 dB
  received-IQ power budgets. Record FGSM's nested Linf geometry separately from
  L2 PGD; do not imply identical feasible sets or imperceptibility.
- Check PGD strength on a predeclared diverse/10 dB subset; retain successful
  admissible examples when strengthening the attack. No test-based tuning of
  training parameters or selection of only favorable attack budgets.
- Physical sidecars remain a separately labeled track. The initial generator's
  fixed -10 dB sidecar is not a three-budget physical-jammer sweep.
- Reserve an OOD track using a victim trained on diverse/10 dB and held-out
  channel/SNR settings. This needs evaluation/export work before execution;
  training-set allowlists must actually exclude the held-out context.

The current moment MLP is one baseline. A stronger literature claim should
include analytical task baselines (energy detector, pilot LS, classical AMC) and
an additional raw-IQ architecture, or explicitly limit the paper/dataset claim to
this model family. This is a scope/implementation gate, not already completed work.

### Poisoning and backdoor

- Use diverse/10 dB data for five independent RF repetitions.
- Tasks: sensing and AMC. Training-row replacement fractions: 1%, 5%, 10%, 20%.
- Three transformations: targeted label flip, unoptimized random feature
  corruption baseline, static IQ trigger plus target relabeling. Clean reference
  per task = 26 model conditions/repetition, 130 total.
- Preserve clean validation and clean test. Triggered and equal-energy random
  probes are derived evaluation views, never training/validation contamination.
- Paired reference and poisoned models share initialization seed, sample count,
  optimizer/epoch budget and clean-validation selection protocol.
- Record requested and realized fraction, eligible source count, nested selected
  frame IDs, original/training labels, trigger support/amplitude and actual power.
- Report clean accuracy/macro F1, clean target error, triggered target hit rate,
  clean-model triggered baseline, random-patch baseline and conditional backdoor
  ASR on non-target samples still classified correctly without the trigger.
- A training-poison label is not a binary label for every subsequent clean test
  input. Training-integrity and input-detection tables remain separate.

### IP

- Independent seed groups: train 4001..4010, validation 5001..5005,
  test 6001..6010. All modes and contexts of a seed/run stay together.
- Eight modes: clean, six individual families and mixed.
- Three contexts: small (8 clients, 12 attackers, 2 servers, 10 Mbps core,
  30 Mbps aggregate flood); medium (12,12,3,20,60); large (24,12,4,40,120).
  Access links 100 Mbps; queue-disc limits 100/200/400 packets.
- 310 simulated seconds including 10-second warmup, 100 ms closed windows,
  6 attack intervals and scheduled fraction .2. 3000 measured windows per run.
- 25 seed groups x 3 contexts x 8 modes = 600 simulations and 1.8 million
  candidate window rows before any training-only sampling/deduplication.
- Preserve unsampled raw tables. Exact 80/20 is a detector-training view only;
  validation/test retain their measured prevalence. Preserve attack-family support.
- Report detection PR-AUC, precision/recall/F1, false-positive rate and per-family
  results. Report measured benign application goodput and IP-delay changes against
  matched clean controls; IP delay is not application request latency.

### Telemetry control gate

Do not add older mmWave/RIC measurements to the current IP schema. An original
explicit source must be selected and pass the current closed-window, application,
control-state, dispatch and confirmation contract. Scratch examples containing an
E2 address alone are insufficient. If this gate passes, specify a separate
telemetry matrix, disjoint model-selection/evaluation seeds, matched clean/random/
bias/FGSM/PGD/exact controls and budget/defense conditions. Evaluate action
recommendation, dispatch, confirmation and subsequent application traffic separately.
If this gate remains unresolved, the release must explicitly omit new RAN
closed-loop claims instead of claiming full report coverage.

## Parallel execution proposal

The observed host is a Ryzen 5 7535HS: 6 physical cores / 12 hardware threads,
14 GiB total RAM with about 8.2 GiB available, and about 57 GB free disk at audit.
These are host observations; container quotas still require a pre-execution check.

The default ns-3 engine is sequential. Run independent processes concurrently;
container copies do not themselves parallelize a simulation. Prefer one prepared
container, one immutable runtime/source/SDK snapshot, one shared prebuilt scenario
cache, and private cwd/output/control files per job. Compile once before timing.

- Proposed pilot: four identical workloads executed at worker counts 1, 2, 4,
  12 simulations total. Modes: clean, UDP flood, UDP DDoS, TCP churn; seed 900001
  (never a confirmatory test seed), 120 s, warmup 2 s, existing v2 IP defaults.
- The simulator outputs must agree across concurrency levels. Record wall time,
  peak RSS, CPU use, disk growth and errors, including preparation/copy costs.
- Use distinct physical cores where supported (e.g. logical CPU 0,2,4,6 on the
  observed topology); keep BLAS/OpenMP threads at 1 per worker.
- Begin with 2 workers for real collection; permit 4 only after the pilot shows
  useful throughput gain without memory pressure or evidence mismatches.
- Proposed total job RSS ceiling 5 GiB; stop launching jobs if available memory
  falls below 3 GiB. Actual enforcement must respect ownership and container quotas.
- Keep at least 20 GiB free disk. Proposed campaign+export growth ceiling 25 GiB,
  to be revised from measured pilot file sizes. Large temporary archives must use
  disk-backed campaign scratch, not the host's 7.5 GiB tmpfs `/tmp`.
- A provisional 12-hour wall budget is only a proposal pending the user's budget
  decision and pilot estimates. Stop at the deadline with resumable job states;
  do not mark an unfinished campaign complete.
- No original-container quota changes, cloning, SDK rebuild, process killing or
  deletion of previous results is implicitly authorized. Dedicated container
  copies are considered only if live port/state isolation actually requires them.

The existing all-scenarios worker is sequential. Resource-bounded parallel queue,
locking, retry/resume, per-job isolation and quota/deadline controls must be added
and tested before executing this plan; no existing --workers flag is claimed.

## Statistical evaluation and release gates

Use independent seed/repetition groups as inferential units, not correlated
frames/windows. Show per-seed outcomes and paired 95% confidence intervals for
attack-vs-clean differences; report the method, number of groups and wide intervals.
Training/validation choose model settings and thresholds; test is not used for
parameter selection. Check clean and attack data coverage, missingness, duplicate
identities, temporal alignment, feasible budgets, actual perturbation support,
source/model hashes, and completed/failed/timeout outcomes.

A data release is gated on: declared coverage, frozen sources, approved execution,
passed independent validators, adequate independent repetitions, complete failed-
attempt ledger, documented negative controls, leakage checks, model/detector
baselines, and a notebook that loads only published relative paths. Numerical
results are reported as measured; none are promised in advance.

## Kaggle data product

Maintain distinct RF, IP and training-integrity schemas. Include a telemetry
schema only after the explicit source/control gate passes. Do not concatenate
these incompatible row units into one anonymous CSV or present IP floods as RF AML.

Proposed package:

```text
README.md
DATASET_CARD.md
DATA_DICTIONARY.csv
CITATION.bib
LICENSE.txt
versions.json
checksums.sha256
dataset-metadata.json
runs.parquet
splits/id.json
splits/ood_context.json
rf/samples.parquet
rf/observations.parquet
rf/iq-*.npz
ip/windows.parquet
ip/flows.parquet
training/row_audits.parquet
training/model_outcomes.parquet
notebooks/01_load_and_validate.ipynb
notebooks/02_detection_baselines.ipynb
```

Use immutable sample/source/model/group identifiers and foreign keys to avoid
copying identical clean IQ once per attack budget. Canonical IQ/deltas retain
float64 precision for exact evidence/budget checks; a float32 convenience view
requires explicit quantization metadata and revalidation. NPZ must load without
pickle; Parquet/CSV carry features, labels and relative array references.

Core metadata: domain, task, observation/model/source-frame ID, source group,
repeat/data/model/attack seeds, split/benchmark track, scenario/version/hash,
attack family/method/stage, intended/applied/success flags, clean task target,
training target, poison fraction, budget norm/value/actual power, physical context,
and completion/evidence state. Every domain has an explicit feature whitelist.
Attack truth, IDs, true channel/clean references, schedule, injected power and
success are audit/target columns, never accidental detector input features.

ID and OOD tracks have explicit allowlists. A context held out for OOD is absent
from that track's train/validation sets; consumers must not merge tracks and then
randomly split rows. Keep all variants of a source group together. No resampling
or normalization uses held-out test labels/statistics.

The data card states synthetic origin, methods, row units, prevalence, source
and split policy, known limitations, intended uses and unsupported claims. Do
not ship local home paths, credentials, logs containing secrets, SDK binaries,
full literature PDFs or the private Word report. Use citations rather than
redistributing source documents. Code/data licenses are recorded separately;
data license and Kaggle owner/slug are user decisions before upload readiness.

Kaggle metadata must contain title, owner/slug and exactly one chosen license;
resource field schemas must preserve the actual CSV column order. Build and
validate a local upload package first. No Kaggle API upload/publication is part
of the currently granted execution approval, which has not yet been given.

## Sources

- User-provided report: Downloads/RAN_AI_Adversarial_Saldirilar_Raporu.docx,
  sections 6-8, 13 and 15; literature numbers are not new experiment results.
- Carlini et al., On Evaluating Adversarial Robustness (2019):
  https://arxiv.org/abs/1902.06705
- Kim et al., Channel-Aware Adversarial Attacks Against Deep Learning-Based
  Wireless Signal Classifiers: https://arxiv.org/abs/2005.05321
- Lacava et al., How to Poison an xApp (2025), DOI 10.1016/j.comnet.2025.111727:
  https://mentis.info/publications/how-to-poison-an-xapp-dissecting-backdoor-attacks-to-deep-reinforcement-learning-in-open-radio-access-networks/
- NIST AI 100-2e2025: https://doi.org/10.6028/NIST.AI.100-2e2025
- ns-3 engine documentation: https://www.nsnam.org/docs/manual/html/events.html
- Kaggle CLI metadata specification:
  https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md
- Kaggle CLI dataset commands:
  https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md
