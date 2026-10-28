# Running experiments

Run commands from the repository root. Supply an external C++ scenario explicitly; there is no bundled/default topology or Python scenario generator. Models and measurements remain local.

## Start with standalone execution

Use Linux, Python 3.10+, g++, and a compatible built native ns-3 tree. The default dependency location is the sibling `ns-o-ran-ns3-mmwave`; override it with `--ns3`.

```bash
python3 lab.py run_scenario --scenario /path/to/student.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave --output results/student-run \
  -- --simTime=5 --RngSeed=41
```

The source is copied unchanged into the run, compiled, and executed in `raw/`. Scenario-specific arguments after `--` are passed unchanged. Inspect `raw/simulation.log` and `run_status.json`. A successful exit is a program-execution result, not AI or E2 verification.

Compile without running:

```bash
python3 lab.py build_offline --scenario /path/to/student.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave
```

The printed executable comes from a source/build-specific cache, never the historical default binary. See the [scenario contract](../scenario/README.md) for compilation assumptions and cache metadata.

## AI-capable scenarios

The following commands require a source that explicitly implements the lab's closed 100 ms trace windows, simulator flags, and (for active control) CSV-to-RRC bridge. Python does not insert those features. Missing or invalid records fail validation. Native and live dependency trees differ; keep their performance results separate.

### Clean live collection

The host launcher needs Docker access and a prepared `flexric` container with compatible ns-3/O-RAN, FlexRIC, and e2sim builds. For automatic dependency-image builds, see [CONTAINERS.md](CONTAINERS.md).

```bash
python3 lab.py run_live --scenario /path/to/compatible.cc \
  --duration 3 --ues 6 --e2-nodes 5 \
  --flexric /work/flexric-duranta \
  --ns3 /work/ns-O-RAN-flexric/mmwave-LENA-oran
python3 lab.py check_live --latest
```

The host source is copied to the container without editing. Explicit dependency paths are optional if discovery finds exactly one compatible tree. `--e2-nodes` sets the expected number of distinct E2 nodes (default five), which must match the supplied topology. The launcher retrieves diagnostics even after failure. Each run uses its own build directory and RIC loopback address rather than stopping unrelated processes.

### Training and shadow mode

```bash
python3 -m ai.train --run-dir results/CLEAN_RUN
python3 lab.py run_live --scenario /path/to/compatible.cc --duration 3 --ues 6 \
  --ai-model ai/artifacts/pilot/model.json
python3 lab.py check_ai_shadow --latest
```

Without explicit training input, the latest E2-verified live run is selected and attacked data is rejected. Without a separate test run, the default holds out UE groups from the same run: this is a pilot, not independent network evaluation.

For separate training, validation, and test sources:

```bash
python3 -m ai.train --allow-native \
  --run-dir results/native-clean-seed41 \
  --validation-run-dir results/native-clean-seed53 \
  --test-run-dir results/native-clean-seed67 \
  --alpha-grid 0.1 1 10 100 1000 \
  --output ai/artifacts/independent
```

`--allow-native` accepts suitable completed native control runs and does not establish E2 verification. Split paths, run identities, CSV hashes, and seeds must be disjoint across groups. Alpha is fit on training data and selected by validation MAE; the final model is fit on training data only. Test data never selects alpha. Validation requires an explicit test group; otherwise `--alpha` is used. See [EVALUATION.md](EVALUATION.md).

### Native load and control

```bash
python3 lab.py run_experiment --scenario /path/to/compatible.cc \
  --duration 3 --ues 12 --warmup 1 --seed 7 --run 1 --attacks 0

python3 lab.py run_controlled --scenario /path/to/compatible.cc \
  --duration 3 --ues 6 --model ai/artifacts/pilot/model.json
```

`run_experiment` needs the application/radio trace contract. With attacks above zero, the source must also implement scheduled UDP load via `--attackPlan`; these events differ from model-input evasion. `run_controlled` needs the RRC command/evidence bridge. Both snapshot the source and select its compiled executable before execution. `--ns3` can select a different built native dependency tree.

### Matched evasion suites

```bash
python3 lab.py run_adversarial_suite --scenario /path/to/compatible.cc \
  --backend live --duration 3 --ues 6 --seed 41 --epsilon 2 \
  --model ai/artifacts/pilot/model.json \
  --modes none random bias fgsm pgd exact --access two_cell \
  --predictor ridge --robust-budget-db 1 --output results/suite41
```

Use `--backend native` for host control. Suites require 3–120 UEs, at least three seconds, distinct modes, and exactly one `none`. Use a separate epsilon-zero control suite. Access scopes are `two_cell`, `target_only`, and `best_only`. Persistence uses current SINR rather than a learned residual. Evaluation seeds must be held out from model fitting and selection unless exploratory reuse is explicitly requested.

The suite captures `scenario.cc`, records `scenario_sha256`, and gives every condition the same snapshot. Native executable hashes must also match. Each run preserves source identity in its status. Existing data collected with the removed bundled scenario remains historical data.

FGSM takes one step; PGD defaults to ten steps and five starts. `exact` optimizes a single-window ranking margin with fixed history, not throughput. `--max-step-db` limits active bias changes but bias resets outside attack support. A robust decision budget bounds one-step forecast gain under trusted-model/other-feature assumptions; it does not guarantee QoS or future decisions.

Active control changes handover behavior, so the clean run needs matching settings. Simulation may wait for commands. CSV-to-RRC control is not E2 RC, and 100 ms simulation windows are not an end-to-end wall-clock latency guarantee.

## Campaigns

```bash
python3 lab.py collect_campaign --scenario /path/to/compatible.cc \
  --backend native --model ai/artifacts/pilot/model.json --duration 10 --ues 24 \
  --seeds 41 53 67 --epsilons 0 2 --predictors ridge persistence \
  --robust-budgets-db off 2 --modes none random bias fgsm pgd exact --plan-only
python3 lab.py collect_campaign --resume results/campaign-TIMESTAMP
```

Inspect the newly printed plan before resuming it. This example plans 24 suites / 144 runs. The campaign captures the scenario once and checks the snapshot on resume and before every job. Editing the original source does not change the plan. A changed snapshot is rejected even with `--allow-code-change`, which applies to reviewed repository-source revisions only.

Legacy plans without a scenario snapshot cannot be resumed by the new runner. Keep their measurements for analysis and start a new explicit-source plan for new collection. Completed suites are skipped, incomplete suites get a new attempt, and failed evidence remains preserved.

## Verification, analysis, and replay

```bash
python3 lab.py check_live results/LIVE_RUN
python3 lab.py check_control results/LIVE_RUN
python3 lab.py check_control results/NATIVE_RUN --native
python3 lab.py check_evasion results/RUN
python3 lab.py analyze_experiments results/SUITE --output results/analysis-local
python3 lab.py summarize_campaign results/analysis-local/run_summary.csv \
  --output results/analysis-local/statistics
python3 lab.py evaluate_replay --model ai/artifacts/pilot/model.json \
  --run-dir results/CLEAN_RUN --epsilon 2 --output results/replay
```

Evidence validity is separate from attack effectiveness. Submission and later target-connection confirmation are separate outcomes. Traffic totals use the application table, not repeated per-cell values in radio rows. Keep backend, pipeline/scenario, predictor, access, defense, duration, UE count, and epsilon strata separate. Seed-cluster intervals require independent seeds; repeated clean runs at different budgets are not independent trials.

Replay changes inputs in memory and does not change measured traffic or apply network controls. Split provenance is checked; legacy missing provenance requires explicit `--allow-unverified-split`. Use `--allow-native` when appropriate. See [DATASET.md](DATASET.md) for timing, missingness, and leakage rules.

## Optional database layer

CSV, PNG, and HTML outputs need no database. Analysis generates per-run SQL import files under `postgres/`. Use your own PostgreSQL connection to import them. A changed CSV hash under an existing run ID is rejected; keep raw and enriched imports distinct. Panel examples are in `database/grafana_step5.sql`. Display dates are anchors, not capture timestamps. TimescaleDB is optional; generating SQL does not verify database or Grafana connectivity.

## Checks

```bash
python3 -m unittest discover -p 'test_*.py'
git diff --check
```

Tests use synthetic traces and small compiler fixtures; none require a saved pilot or an external ns-3 source tree. The generic external-source test compiles and executes a tiny standalone C++ fixture against a synthetic library. This exercises input/copy/build/argument handling, not a real radio simulation. Full Docker/ns-3 acceptance requires a compatible supplied scenario.
