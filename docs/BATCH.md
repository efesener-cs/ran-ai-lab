# Run all provided benchmark scenarios

From any directory, run the project script:

```bash
bash /home/tarnished/Projects/ran-ai-lab/run-all-scenarios.sh
```

No manual source paths, `docker cp`, runtime folders or result names are needed.
It uses the existing `ran-lab` container, starts it if stopped, snapshots the
maintained Python runtime and the two explicitly provided examples, and creates
a unique `results/all-scenarios/run-TIMESTAMP-RANDOM/` directory. Old runs are
never deleted. `results/all-scenarios/latest` points to the newest started run.
The actual absolute path is printed at startup and completion.

The opt-in examples are tracked at `examples/scenarios/rf-ai-frames.cc` and
`examples/scenarios/ip-network-attacks.cc`. Generic standalone/live/AI runners
still require an explicit `--scenario`; they have no implicit fallback topology.
The shell launcher is thin; `simulation/` owns execution and supervision.

## What runs

- RF `baseline`, `diverse`, `stress`: independent train/validation/test seeds
  11/23/37, 2400/600/600 frames per task, 128 complex samples, 80 epochs, 30 PGD
  steps. Each profile runs 33 attack/control conditions, checks the evidence and
  exports a detector dataset with 80/20 clean/applied attack per split. Physical
  interference sidecars are separate from FGSM/PGD and preserve source group IDs.
- IP `none`, UDP flood, UDP DDoS, pulsed UDP, UDP scan, TCP churn, ICMP flood,
  mixed: each runs with seed 11, 23, 37 (24 runs), 120 simulated seconds, 2-second
  warmup, 6 attack intervals, 29 nodes and scheduled attack fraction .2.
- IP window tables are combined only after all required runs validate. Seed 11
  is train, 23 validation, 37 test. Identical benign matched windows are deduplicated
  in train; training is sampled without replacement to exact 80/20, preserving
  every observed attack type. Validation/test retain their observed prevalence.
  Raw per-condition measurements remain untouched.

This workflow does not launch the older SINR/RIC campaign: that requires a separate
compatible E2/control scenario and a fitted forecasting model. It does not train
an IP detector. RF models remain the documented moment MLPs. Quick mode is a
plumbing test, not model-quality evidence.

## Result layout

```text
run-TIMESTAMP-RANDOM/
  launcher.json             source/runtime hashes, staged SDK provenance, exit state
  launcher.log              Docker preparation and result-copy diagnostics
  batch.log                 live stage progress
  inputs/                   exact .cc inputs
  runtime/                  exact Python snapshot
  batch-config.json         selected execution settings
  result/
    SUMMARY.md              human-readable task status and log links
    summary.json            structured commands, outcomes and evidence
    logs/                   full stdout/stderr per stage, including compiler failures
    rf/{baseline,diverse,stress}/
    ip/seed-{11,23,37}/{MODE}/
    datasets/rf/{PROFILE}/{train,validation,test}.csv
    datasets/ip/{train,validation,test}.csv
```

A rejected SDK candidate is diagnostic if a later candidate passes. A failed
scenario, verification/export or result copy causes nonzero exit and failed status.
Dependent exports are skipped after failure; unrelated scenarios continue.
On interrupt, the launcher signals only its own worker process group and retrieves
available results. Remote work directories are retained for diagnostics.

## Existing SDK and Python dependencies

No image build, ns-3 rebuild, FlexRIC rebuild or system SDK overwrite occurs.
Unless `--ns3` explicitly chooses a path, the Docker workflow first looks for the
already prepared host SDK at `~/ran-ai-lab-shared/work/ns-o-ran-ns3-mmwave`, guarded
by its parent's `READY.json`. It stages only the required 7 IP modules and their
ns-3 shared-library dependencies, copies source/include inputs and relocates
forwarding headers inside that private copy. Library hashes are retained.
This SDK is uploaded into this run's private container directory; the original
`/work` sources/libraries are not changed. If unavailable, known existing native
SDK paths are tried. Each candidate must compile the actual IP source and run its
help command (which checks loading/ABI). Failures retain compiler/linker stderr.
If every candidate fails, RF can still finish but IP is marked unsuccessful.

Python/compiler preflight runs before experiments. If NumPy is missing for RF,
pip installs it under this run's `result/python-deps` rather than changing system
Python. A container without pip, g++, required OS libraries or any compatible SDK
still needs environment preparation; the script records the actual error and
never reports that as a successful attack experiment. Docker is not operated by
unit checks. Container execution of this new batch launcher remains unverified;
host end-to-end and SDK staging/header relocation have been tested.

## Optional settings

```bash
bash run-all-scenarios.sh --container OTHER_NAME
bash run-all-scenarios.sh --quick
bash run-all-scenarios.sh --only ip
bash run-all-scenarios.sh --backend host --quick
bash run-all-scenarios.sh --ns3 /container/path/to/compatible/ns3
bash run-all-scenarios.sh --prepared-sdk /host/path/to/prebuilt/ns3
bash run-all-scenarios.sh --output-root /host/path/to/results
bash run-all-scenarios.sh --seeds 41 53 67 --ip-duration 300
```

`--quick` keeps all profiles/modes/seeds but uses 180/60 RF samples, 3 epochs,
3 PGD steps, 64 IQ samples and 12-second IP runs. It overrides the numeric training
and duration settings. `--backend host` selects a host SDK and runs no Docker
commands. `--help` lists the remaining sample/epoch/step settings. Alternate
scenario directories must implement the documented v2 CSV/label interfaces.
# Resumable two-core research campaign

`collect_campaign --resume PATH` is the existing telemetry matched-suite
continuation command. It preserves attempts and skips completed suites, but does
not collect the RF/IP/training matrix. Do not apply it to an all-scenarios output
or replace a historical campaign's configuration.

For the explicitly approved RF/IP/training matrix:

```bash
python3 lab.py run_benchmark --prepare-only --ns3 /path/to/built/native-ns3
python3 lab.py run_benchmark --resume results/benchmark/run-TIMESTAMP-SUFFIX
```

Preparation captures an immutable runtime, unchanged C++ inputs, the machine
proposal, and a private relocated prebuilt SDK. Resume re-executes that captured
runtime, validates hashes, checks completed artifact receipts and retains each
failed/interrupted attempt. One controller holds an exclusive campaign lock.
Each worker has a private working/output directory and a separate process group.
The shared dependencies and historical results are not modified.

The approved configuration uses two distinct physical CPU cores, at most two
workers, and one BLAS/OpenMP thread per worker. Eight matched pilot simulations
compare four workloads at concurrency one and two. Their window CSV hashes must
agree before confirmatory collection. The queue includes 60 RF blocks, five
26-condition poisoning/backdoor studies, and 600 IP runs. RF and training studies
run their independent checkers; IP rows, labels, metadata and context are checked.
Completed means collected and checked within this scope, not a finished Kaggle
release or live RAN acceptance.

The wall deadline is 18 hours from the first queue execution; resume does not
reset it. Memory/disk limits are polled at ten-second intervals: 3 GiB available
RAM minimum, 5 GiB summed worker-process RSS ceiling, 20 GiB free disk minimum,
25 GiB campaign file-size ceiling. These are monitored limits, not kernel cgroup
quotas; a short sampling overshoot is possible. CPU affinity bounds every worker
and its children. At timeout/resource pressure/interrupt the controller stops
only its own process groups and preserves partial attempts. A resume after budget
expiry is rejected, rather than silently granting another 18 hours.

`campaign.json` records current state, per-job attempts/log paths, CPU assignments,
timings, hashes and the deadline. Job logs live at
`jobs/JOB_ID/attempt-N/job.log`. Reuse the exact output path printed by preparation
when continuing; new collection never deletes an earlier run. Kaggle packaging,
licensing and publication remain separate release gates.
