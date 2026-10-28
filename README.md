# RAN AI Lab

A lab for studying whether manipulated radio measurements change AI-assisted cell selection and simulated application traffic. The model forecasts the next 100 ms of SINR; a separate policy decides whether to recommend a cell change. Clean and attacked conditions are compared with matched settings.

## Bring your own scenario

Supply a self-contained ns-3 C++ source. The project compiles and runs it unchanged; it no longer generates or bundles a network topology.

With a compatible native ns-3 tree already built:

```bash
python3 lab.py run_scenario --scenario /path/to/scenario.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave --output results/my-scenario \
  -- --simTime=5 --RngSeed=41
```

Arguments after `--` go directly to the supplied program. This standalone path records execution and raw outputs without assuming an AI, telemetry, or RIC interface.

For AI experiments, the scenario must implement the [measurement and control contract](scenario/README.md). For example, a compatible source can be used with:

```bash
python3 lab.py run_adversarial_suite --scenario /path/to/scenario.cc \
  --backend native --model ai/artifacts/pilot/model.json \
  --duration 3 --ues 6 --seed 41 --epsilon 2
```

Train the model on compatible clean data first; the model path above is a local artifact, not a bundled pretrained policy.

There is no automatic conversion of an arbitrary ns-3 example into a closed-loop AI experiment. A missing source or unsupported trace/control interface fails explicitly.

## Data and decision path

```text
Supplied ns-3 scenario → closed measurement windows → optional input attack
                                                        ↓
                                                 SINR forecast
                                                        ↓
                                                cell-selection policy
                                                        ↓
                                      shadow log or CSV → ns-3 RRC
                                                        ↓
                                      connection and traffic evidence
```

The live backend adds FlexRIC/E2/KPM monitoring. AI input still comes from ns-3 trace windows and active control uses a CSV bridge. Direct KPM-to-model input and E2 RC actuation are not implemented. Forecast ranking, command changes, handover confirmation, and received traffic are separate outcomes. Changing a telemetry value does not directly change the RF signal.

## Setup and checks

Linux and Python 3.10+ are supported. Simulation also needs compatible built ns-3/O-RAN libraries; live operation additionally requires FlexRIC and e2sim. The [container guide](docs/CONTAINERS.md) builds those dependencies without embedding a default scenario.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-ai.txt -r requirements-analysis.txt
python3 -m unittest discover -p 'test_*.py'
git diff --check
```

Tests use synthetic measurements and small C/C++ fixtures. They need a compatible compiler but no saved campaign, external ns-3 source tree, Docker daemon, or network simulation.

## Layout

| Location | Responsibility |
|---|---|
| `lab.py` | Shared CLI; `python3 lab.py --help` lists commands. |
| `scenario/` | Validate supplied C++ sources, preserve exact snapshots, and compile native executables. |
| `simulation/` | Standalone/native/live launchers, process supervision, suites, campaigns, and traffic schedules. |
| `ai/` | Training, replay, shadow inference, features, policy, attacks, and robustness bounds. |
| `datasets/` | Measurement export. |
| `analysis/` | Paired comparisons, plots, and seed-level statistics. |
| `checks/` | Monitoring, control, shadow, and evasion evidence validation. |
| `labcore/` | Shared paths, command dispatch, fingerprints, runtime packaging, and dependency helpers. |
| `tests/`, `docker/`, `database/` | Tests, container tooling, and optional database integration. |

Models, result directories, reports, exports, and build caches remain local and are excluded from Git. Earlier experiment results describe their original scenarios; they are not evidence that a new supplied scenario has been validated.

## Documentation

- [Scenario input contract](scenario/README.md)
- [Running experiments](docs/RUNNING.md)
- [Container setup](docs/CONTAINERS.md)
- [Dataset fields and split rules](docs/DATASET.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Related work](docs/RESEARCH.md)
- [Dependency provenance](docs/PROVENANCE.md)
- [Attribution and license scope](NOTICE.md)
