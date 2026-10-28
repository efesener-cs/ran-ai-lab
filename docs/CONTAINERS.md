# Container setup with an external scenario

The host needs Linux, Docker Engine, and Bash. Images install Python, ns-3, e2sim, and analysis/training dependencies. The live target also installs FlexRIC. They do not contain a default network scenario or compile one during image build.

The `native` target uses ns-3.38; `live` uses ns-3.42 with E2AP v1/KPM v3 monitoring. Native execution inside Docker remains native. Keep their performance results separate. Control uses CSV-to-RRC, not E2 RC.

## Build dependency images

```bash
docker build --target native -t ran-ai-lab:native --build-arg BUILD_JOBS=2 .
docker build --target live -t ran-ai-lab:live --build-arg BUILD_JOBS=2 .
bash docker/lab.sh native "$PWD/results/container-native" -m unittest discover -p 'test_*.py'
```

The first build downloads and compiles dependencies. Commits are pinned in `Dockerfile`; Ubuntu packages and indirect Python dependencies are not complete snapshots. Retain an image digest for a shareable environment. `/opt/dependency-revisions.txt` and `/opt/python-packages.txt` record versions. Set `RAN_AI_IMAGE=registry/image@sha256:...` to use a retained image.

`lab.sh` runs as the host user and mounts output `results`, `models`, and `exports` directories. It does not mount a Docker socket or use privileged/host-network mode. An existing `flexric` container is not part of this image workflow.

## Mount and run your source

Set `RAN_AI_SCENARIO` to the host C++ file. The launcher mounts it read-only at `/opt/ran-ai-input/scenario.cc`:

```bash
RAN_AI_SCENARIO=/path/to/student.cc \
  bash docker/lab.sh native "$PWD/results/container-native" \
  lab.py run_scenario --scenario /opt/ran-ai-input/scenario.cc \
  --output results/student-run -- --simTime=5
```

The program must match the image's ns-3 APIs. Source bytes are copied without editing. Build caches use the mounted results directory via `RAN_AI_BUILD_ROOT`; the immutable image source tree need not be writable. Extra scenario-local headers are not mounted automatically, so supply a self-contained source.

For live monitoring, the scenario must implement compatible E2 agents and the [lab telemetry contract](../scenario/README.md):

```bash
RAN_AI_SCENARIO=/path/to/compatible.cc \
  bash docker/lab.sh live "$PWD/results/container-live" \
  lab.py run_live --scenario /opt/ran-ai-input/scenario.cc \
  --duration 3 --ues 6 --e2-nodes 5 --seed 11 --output results/train-clean
bash docker/lab.sh live "$PWD/results/container-live" lab.py check_live results/train-clean
```

Use the same output root to retain stable paths across collection, training, and resume. Pick a fresh run name for retries. Diagnostics are retrieved after failures. Each live run uses run-local build preparation and a separate RIC loopback address. Keep sources/models fixed while collection runs.

## Train and compare

Collect clean runs with disjoint seeds (for example 11/23/37) using compatible control/telemetry. For native bootstrap collection, the synthetic `tests/fixtures/model.json` may drive the initial control loop; it is not a trained research model or a model-quality result.

```bash
bash docker/lab.sh native "$PWD/results/container-native" \
  -m ai.train --allow-native --run-dir results/train-clean \
  --validation-run-dir results/validation-clean --test-run-dir results/test-clean \
  --alpha-grid 0.1 1 10 100 1000 --output ai/artifacts/native

RAN_AI_SCENARIO=/path/to/compatible.cc \
  bash docker/lab.sh native "$PWD/results/container-native" \
  lab.py collect_campaign --scenario /opt/ran-ai-input/scenario.cc \
  --backend native --model ai/artifacts/native/model.json --duration 10 --ues 24 \
  --seeds 41 53 67 --epsilons 0 2 --modes none random bias fgsm pgd exact --plan-only
```

Resume using the newly printed campaign path. Once captured, its scenario snapshot lives under the mounted results directory and is reused; changing the original source does not replace it.

## Full acceptance requires a compatible supplied source

```bash
RAN_AI_SCENARIO=/path/to/compatible.cc \
  bash docker/lab.sh native "$PWD/results/acceptance-native" \
  docker/smoke.py --backend native --scenario /opt/ran-ai-input/scenario.cc
```

Use `live` and `--backend live` for the other environment. The test collects separate clean splits, trains a model, runs six conditions, and analyzes them. It needs the full lab trace/control protocol; the standalone compiler fixture cannot replace a network scenario. The manual GitHub workflow requires a repository-relative `scenario_path` input and mounts that file explicitly.

Unit checks do not prove a dependency image builds or a real simulation succeeds. A new external scenario must pass actual integration acceptance before making new network-performance claims. Previous bundled-scenario results are historical observations, not validation of the new source. Avoid shared builds or integration runs while another experiment is active.
