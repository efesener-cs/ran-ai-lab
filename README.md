# RAN AI Lab

A CSV-based lab for testing whether bounded SINR telemetry manipulation changes forecasts, cell-selection decisions, and simulated application traffic.

`main` runs directly on Linux. This optional `feat/docker-support` branch adds dependency images and a prepared-container launcher. It retains CSV collection without database imports or automatic EDA/statistics. See [container setup](docs/CONTAINERS.md).

## Supply a scenario

Use a self-contained C++ source and an already built compatible ns-3 tree:

```bash
python3 lab.py run_scenario --scenario /path/to/student.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave --output results/student-run \
  -- --simTime=5 --RngSeed=41
```

The file is copied unchanged, hashed, compiled, and run. Arguments after `--` are forwarded unchanged. Standalone execution assumes no AI, telemetry, or RIC interface.

For AI experiments, implement the [scenario contract](scenario/README.md) and train a model from compatible clean data:

```bash
python3 lab.py run_adversarial_suite --scenario /path/to/compatible.cc \
  --backend native --model ai/artifacts/pilot/model.json \
  --duration 3 --ues 6 --seed 41 --epsilon 2
```

The suite runs matched clean/attacked conditions and retains per-run CSVs, a combined radio `dataset.csv`, and `comparison.json`. Campaigns schedule suites and stop after collection. Further EDA is a separate user step.

## How it works

```text
Supplied ns-3 source → closed measurements → optional SINR input attack
                                                   ↓
                                            next-window forecast
                                                   ↓
                                            cell-selection policy
                                                   ↓
                                    shadow log or CSV → ns-3 RRC
                                                   ↓
                                    connection and traffic evidence
```

`run_live` starts the RIC, KPM monitoring xApp, and compatible scenario on the host using installed FlexRIC/ns-3/e2sim dependencies. Model input is still ns-3 trace windows; applied control is CSV-to-RRC, not E2 RC. Prediction ranking, executable commands, confirmed handovers, and received traffic remain separate outcomes.

## Install Python dependencies and test

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-ai.txt
python3 -m unittest discover -p 'test_*.py'
git diff --check
```

The suite uses synthetic telemetry and small C/C++ fixtures. It needs compatible compilers but no saved campaign, external ns-3 tree, Docker daemon, or database server. Actual network runs require installed simulator dependencies and a compatible supplied source.

## Code layout

| Location | Purpose |
|---|---|
| `lab.py` | Shared command entry point. |
| `scenario/` | Source validation, exact snapshots, and native compilation. |
| `simulation/` | Host-native runners, live supervision, traffic schedules, suites, and campaigns. |
| `ai/` | Training, replay, shadow inference, features, policy, attacks, and robustness. |
| `datasets/` | Raw measurement conversion and CSV export. |
| `checks/` | Monitoring, shadow, control, and evasion evidence checks. |
| `labcore/` | Shared paths, commands, fingerprints, and live dependency helpers. |
| `tests/` | Unit and synthetic pipeline tests. |

Models, measurements, reports, exports, and build products remain local and excluded from Git. Existing exported datasets are preserved as historical data; removing their original EDA code does not change those files.

## Documentation

- [Scenario contract](scenario/README.md)
- [Running experiments](docs/RUNNING.md)
- [CSV outputs and field meanings](docs/DATASET.md)
- [Experiment protocol](docs/EVALUATION.md)
- [Related work](docs/RESEARCH.md)
- [Dependency provenance](docs/PROVENANCE.md)
- [Attribution](NOTICE.md)

## Optional prepared-container launcher

`python3 lab.py run_docker --container flexric --scenario /path/to/compatible.cc --output results/docker-run` copies the maintained runtime into an existing container and retrieves outputs. `run_live` always supervises processes in its current Linux environment, including when called inside a dependency image.
