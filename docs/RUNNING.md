# Running on the host

Run commands from the repository root. `main` uses Python, g++, and installed ns-3/O-RAN dependencies directly. Live RIC monitoring additionally needs compatible built FlexRIC/e2sim sources. Docker packaging is kept on `feat/docker-support`, outside this branch's working tree.

Install Python requirements:

```bash
python3 -m pip install -r requirements-ai.txt
```

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

## Train and replay

```bash
python3 -m ai.train --allow-native \
  --run-dir results/native-train --validation-run-dir results/native-validation \
  --test-run-dir results/native-test --alpha-grid 0.1 1 10 100 \
  --output ai/artifacts/independent

python3 lab.py evaluate_replay --allow-native --model ai/artifacts/independent/model.json \
  --run-dir results/native-test --epsilon 2 --output results/replay
```

Native sources need `--allow-native`. Training, validation, and test groups must have disjoint recorded seeds, run identities, source paths, and CSV hashes. Alpha is chosen on validation MAE; the test split does not select the model. Default same-run UE splitting remains a pilot, not independent network evaluation. Replay changes model inputs without changing measured traffic or applying controls.

## Matched suites and campaigns

```bash
python3 lab.py run_adversarial_suite --scenario /path/to/compatible.cc \
  --backend native --duration 3 --ues 6 --seed 41 --epsilon 2 \
  --model ai/artifacts/independent/model.json \
  --modes none random bias fgsm pgd exact --output results/suite41

python3 lab.py collect_campaign --scenario /path/to/compatible.cc --backend native \
  --model ai/artifacts/independent/model.json --duration 10 --ues 24 \
  --seeds 41 53 67 --epsilons 0 2 --modes none random bias fgsm pgd exact --plan-only
python3 lab.py collect_campaign --resume results/campaign-TIMESTAMP
```

Use `--backend live` with installed host dependencies for live RIC collection. A suite snapshots the source and model, records hashes, and gives each condition the same inputs and seed/run. Native executable hashes must match across conditions. Epsilon zero is a separate no-bias control. `none` is required; modes must be distinct.

A campaign snapshots the scenario once, preserves every attempt, skips completed suites on resume, and verifies source/model identity. Changing the captured scenario is rejected even with `--allow-code-change`. Legacy plans without an external source snapshot need a new plan for new collection; their existing measurements remain untouched.

On completion, collection stops. There are no automatic plots, SQL imports, merged application/radio analysis tables, or bootstrap summaries on `main`. Per-run CSVs, suite `dataset.csv`, `comparison.json`, and manifests are the inputs for later user-written EDA. See [DATASET.md](DATASET.md) for their row units and timing.

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
