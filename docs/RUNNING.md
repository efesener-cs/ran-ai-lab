# Running on the host

Run commands from the repository root. `main` uses Python, g++, and installed ns-3/O-RAN dependencies directly. Live RIC monitoring additionally needs compatible built FlexRIC/e2sim sources. Docker packaging is kept on `feat/docker-support`, outside this branch's working tree.

## Prepare the environment

Use Python 3.10 or newer. The commands below assume Bash and start from this repository's root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-ai.txt
python3 lab.py --help
```

A Python environment does not install the simulator. Native execution needs a compatible, already built ns-3 tree with `build/include` and `build/lib`, plus a compatible GCC/G++ pair. Live execution also needs built FlexRIC and installed e2sim/SCTP dependencies. See [PROVENANCE.md](PROVENANCE.md) for inspected revisions and compiler constraints. There is no bundled scenario: provide a self-contained C++ file matching [the scenario contract](../scenario/README.md).

Replace all `/path/to/...` placeholders before running examples. Keep the selected scenario and dependency paths available in the same shell:

```bash
SCENARIO=/path/to/compatible.cc
NS3=/path/to/ns-o-ran-ns3-mmwave
```

| Goal | Command | Prerequisite |
|---|---|---|
| Run an arbitrary compatible C++ scenario | `run_scenario` | Built native ns-3; only the supplied program's own CLI is assumed. |
| Collect traffic/application CSVs | `run_experiment` | Lab telemetry and scheduled-load interface; no model needed. |
| Collect native model/control data | `run_controlled` | Telemetry/control contract and a model JSON. |
| Monitor live RIC/E2 | `run_live` | Live dependency stack and E2-capable scenario; model optional. |
| Fit and check a model | `train_ai`, `evaluate_replay` | Accepted clean runs with independent train/validation/test seeds. |
| Compare clean and attacked runs | `run_adversarial_suite`, `collect_campaign` | Compatible source, fitted model, unused evaluation seeds. |

Each command is invoked as `python3 lab.py COMMAND`; use `python3 lab.py COMMAND --help` for its actual flags. Commands do not share every flag: for example, `run_experiment` prints an automatically named result path and has no `--output` option.

## Standalone scenario

```bash
python3 lab.py run_scenario --scenario /path/to/student.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave --output results/student-run \
  -- --simTime=5 --RngSeed=41
```

The source is copied without modification into the result directory, hashed, compiled, and executed in `raw/`. Arguments after `--` belong to the supplied program. Inspect `raw/simulation.log` and `run_status.json`. Successful execution alone is not AI or E2 verification.

Compile without running:

```bash
python3 lab.py build_offline --scenario /path/to/student.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave
```

Native dependencies default to the sibling `ns-o-ran-ns3-mmwave` tree. The builder uses its `build/include` and `build/lib` directories. Each source/build identity has its own cache under `host-build/scenarios/`; the old default executable is not a fallback. See [scenario/README.md](../scenario/README.md) for interface and cache details.

## Native AI control and traffic

AI workflows need a source implementing the lab's trace and, when used, control protocol. Python does not add missing C++ behavior.

```bash
python3 lab.py run_controlled --scenario /path/to/compatible.cc \
  --duration 3 --ues 6 --model ai/artifacts/pilot/model.json
python3 lab.py check_control results/NATIVE_RUN --native

python3 lab.py run_experiment --scenario /path/to/compatible.cc \
  --duration 3 --ues 12 --warmup 1 --seed 7 --run 1 --attacks 0
```

`run_controlled` starts the model and atomic CSV-to-RRC bridge. `run_experiment` collects application/radio CSVs without model control; nonzero `--attacks` requires the scenario's scheduled UDP load interface. That traffic mechanism is distinct from model-input evasion.

## Host-native live RIC monitoring

```bash
python3 lab.py run_live --scenario /path/to/compatible.cc --duration 3 --ues 6 \
  --flexric /path/to/flexric --ns3 /path/to/live-ns3 --e2-nodes 5 \
  --output results/live-clean
python3 lab.py check_live results/live-clean
```

These paths point to host installations, not container paths. FlexRIC must have a compatible E2AP v1/KPM v3 build cache, and ns-3 must have the expected newer KPM integration. Explicit paths avoid ambiguous discovery.

Each live run creates `raw/`, `csv/`, and a `work/` directory under its result root. Build preparation copies FlexRIC sources into `work/`; supplied dependency trees are not edited. RIC addresses are leased on loopback, and cleanup stops only the run's own process group. Linux SCTP and a compatible GCC/G++ pair are required. No dependency installation or Docker startup is performed.

`--e2-nodes` is the minimum expected distinct-node count (default five). It must fit the supplied topology. Add `--ai-model MODEL` for shadow inference or `--ai-model MODEL --apply-ai-control` for active CSV-to-RRC control. Only completed windows feed the model. Control is not E2 RC and batch timing is not an end-to-end near-RT deadline measurement.

## Collect the first training data

The training loader accepts completed verified live runs, or native control runs explicitly enabled with `--allow-native`. A standalone run or `run_experiment` CSV is not sufficient input for this loader.

If no fitted model is available yet, use the synthetic fixture only to drive a native bootstrap collection. The scenario must still implement the full telemetry/control contract:

```bash
for split_seed in train:11 validation:23 test:37; do
  split=${split_seed%:*}
  seed=${split_seed#*:}
  python3 lab.py run_controlled --scenario "$SCENARIO" --ns3 "$NS3" \
    --duration 3 --ues 6 --warmup 1 --seed "$seed" \
    --model tests/fixtures/model.json --output "results/bootstrap-$split"
done
```

The fixture contains synthetic weights. It provides collection plumbing, not a trained-model result. The collected trajectories reflect this bootstrap policy. All three runs must complete successfully and contain valid traces/control evidence before training. If three seconds gives too few valid future-window samples for the supplied scenario, choose a longer duration consistently and collect fresh runs.

For a live bootstrap, collect three `run_live` runs without `--ai-model`, using disjoint seeds and fresh output paths, and verify each with `check_live`. Use those paths in training and omit `--allow-native`.

## Train and replay

Using the native bootstrap runs above:

```bash
python3 lab.py train_ai --allow-native \
  --run-dir results/bootstrap-train --validation-run-dir results/bootstrap-validation \
  --test-run-dir results/bootstrap-test --alpha-grid 0.1 1 10 100 \
  --output ai/artifacts/independent

python3 lab.py evaluate_replay --allow-native --model ai/artifacts/independent/model.json \
  --run-dir results/bootstrap-test --epsilon 2 --output results/replay
```

The training output contains `model.json` and `evaluation.json`; use the fitted `model.json` for subsequent control and suites. Native sources need `--allow-native`. Training, validation, and test groups must have disjoint recorded seeds, run identities, source paths, and CSV hashes. Alpha is chosen on validation MAE; the test split does not select the model. Default same-run UE splitting remains a pilot, not independent network evaluation. Replay changes model inputs without changing measured traffic or applying controls.

## Matched suites and campaigns

```bash
python3 lab.py run_adversarial_suite --scenario "$SCENARIO" --ns3 "$NS3" \
  --backend native --duration 3 --ues 6 --seed 41 --epsilon 2 \
  --model ai/artifacts/independent/model.json \
  --modes none random bias fgsm pgd exact --output results/suite41

python3 lab.py collect_campaign --scenario "$SCENARIO" --ns3 "$NS3" --backend native \
  --model ai/artifacts/independent/model.json --duration 10 --ues 24 \
  --seeds 41 53 67 --epsilons 0 2 --modes none random bias fgsm pgd exact --plan-only
python3 lab.py collect_campaign --resume results/campaign-TIMESTAMP
```

Use `--backend live` with installed host dependencies for live RIC collection. A suite snapshots the source and model, records hashes, and gives each condition the same inputs and seed/run. Native executable hashes must match across conditions. Epsilon zero is a separate no-bias control. `none` is required; modes must be distinct.

A campaign snapshots the scenario once, preserves every attempt, skips completed suites on resume, and verifies source/model identity. Changing the captured scenario is rejected even with `--allow-code-change`. Legacy plans without an external source snapshot need a new plan for new collection; their existing measurements remain untouched.

On completion, collection stops. There are no automatic plots, SQL imports, merged application/radio analysis tables, or bootstrap summaries on `main`. Per-run CSVs, suite `dataset.csv`, `comparison.json`, and manifests are the inputs for later user-written EDA. See [DATASET.md](DATASET.md) for their row units and timing.

## Locate outputs and prepare later EDA

For explicit-output runners, choose a new directory for every attempt. For automatically named runs/campaigns, copy the path printed by the command. Do not rename recorded run directories: CSV `run_id` values are tied to those identities.

| Location | Inspect it for |
|---|---|
| `RUN/run_status.json` | Completion/failure, configuration, source/binary identity, and applicable verification flags. |
| `RUN/scenario.cc` | The exact source snapshot used by this run. |
| `RUN/raw/simulation.log` | Simulator output and failures. Live runs additionally retain build, RIC, xApp, and optional shadow logs. |
| `RUN/csv/ue_application_100ms.csv` | Per-UE application bytes/goodput; use this table for traffic totals. |
| `RUN/csv/ran_features_100ms.csv` | Per-cell radio features; application context repeats across cell rows. |
| `RUN/csv/quality_report.json`, `dataset_report.json` | Export coverage, missing values, counts, and caveats. |
| `SUITE/dataset.csv`, `comparison.json`, `manifest.json` | Combined condition rows, matched differences, and suite provenance. |
| Campaign `campaign.json` | Scheduled jobs, attempts, source/model identities, and resume state. |

`run_experiment`, `run_controlled`, and `run_live` invoke CSV export. `run_scenario` only records the supplied program's outputs. To regenerate CSVs from a stopped/completed run that actually emitted the lab's required raw traces, use the original simulation duration:

```bash
python3 lab.py export_dataset results/EXISTING_RUN --duration 3
```

This writes derived files under that run's `csv/`; it does not rerun the network or change a failed simulation into a valid run. Keep existing evidence when deciding whether to regenerate. Do not run export concurrently with collection. See [DATASET.md](DATASET.md) before joining or aggregating CSVs.

## Common usage problems

| Symptom | What to check |
|---|---|
| Output directory already exists | Select a new `--output`; runners preserve the previous attempt. Use campaign `--resume` for campaign continuation. |
| Missing headers/libraries or compile error | Check the selected ns-3 build and source/API compatibility. Python requirements do not supply C++ SDKs. |
| Unknown scenario flag or missing raw trace | The source does not implement the selected runner's contract. Use `run_scenario` for standalone programs, or implement the missing interface in the source. |
| Training rejects a CSV/run | Check run completion, accepted backend/control evidence, clean inputs, recorded seeds, canonical run IDs, and split independence. Ordinary traffic CSVs are not automatically training inputs. |
| Suite rejects an evaluation seed | Pick seeds absent from the model's training, validation, and test provenance. |
| Live E2 verification fails | Inspect RIC/xApp/simulation logs, E2AP/KPM versions, SCTP availability, distinct node identities, and `--e2-nodes`. |
| Campaign detects changed code/model | Preserve its recorded inputs; use a new campaign for changed conditions. `--allow-code-change` records a revision boundary, but does not permit changing the captured scenario. |

## Verification and tests

```bash
python3 lab.py check_live results/LIVE_RUN
python3 lab.py check_control results/LIVE_RUN
python3 lab.py check_control results/NATIVE_RUN --native
python3 lab.py check_evasion results/RUN
python3 -m unittest discover -p 'test_*.py'
git diff --check
```

Evidence validation is separate from attack effectiveness. A rejected or unconfirmed control outcome is not silently relabeled as an infrastructure success. Unit/compiler tests do not establish compatibility of a new scenario with real ns-3/FlexRIC dependencies; run that acceptance separately when a compatible scenario is available.
