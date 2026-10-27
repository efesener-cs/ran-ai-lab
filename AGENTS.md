# Agent instructions

## Project and architecture
- Research lab for ns-3/O-RAN, FlexRIC/KPM, and adversarial SINR forecasting; Python 3.10+.
- `run_live.py` copies a self-contained runner into the existing FlexRIC container; `container_run.py` builds and supervises RIC, xApp, simulation, and the shadow bridge.
- `run_controlled.py` runs native ns-3 control; `run_experiment.py` runs stochastic traffic experiments.
- `collect_campaign.py` schedules sequential matched suites through `run_adversarial_suite.py` and records hashes and attempts.
- `ai/` contains telemetry, model, policy, attack, and robustness logic. `build_csv.py` / `export_dataset.py` create datasets; analysis and statistics are separate stages.
- Read README.md and docs/RUNNING.md before changing execution behavior; docs/DATASET.md and docs/EVALUATION.md define scientific contracts.

## Protect active experiments
- Never modify, move, delete, resume, or stop `results/campaign-20261025-231925-201987` or its processes/container workspaces unless explicitly authorized for that campaign.
- Campaigns hash every root Python file, every ai/*.py file, and ran-ai-scenario.cc before each suite. Even adding a test can abort an active campaign.
- Make source changes in a separate branch AND separate worktree while an experiment is active. A branch alone does not isolate files. Do not switch the active experiment's checkout.
- Do not start Docker/ns-3 integration runs, rebuild shared binaries, or kill processes as part of routine checks while an experiment runs.
- Preserve models, training/validation/test provenance, referenced runs, successful baselines, and all campaign attempts. Inspect references before removing results. Restrict cleanup to explicitly identified obsolete failures and record paths/reasons outside results.

## Development conventions
- Keep existing CLI names, flags, output schemas, and container copy dependencies compatible. New runtime helpers must also be copied by run_live.py.
- Entry-point scripts should expose main() and use an __main__ guard; importing modules must not run simulations, parse arguments, build binaries, or create artifacts.
- Keep JSON publication atomic where readers run concurrently. Preserve fail-closed validation, warmup handling, closed telemetry windows, paired controls, and seed separation.
- Do not call replay a causal QoS experiment, CSV control E2 RC, or batch processing time end-to-end near-RT latency.
- Do not delete Python files based only on filenames: scripts can be CLI tools, generators, or container dependencies.

## Checks
- From the isolated checkout: `python3 -m unittest discover -p 'test_*.py'`.
- `python3 scripts/check_publish.py` checks the Git index; it does not inspect unstaged edits. Also run `git diff --check`.
- Tests requiring saved telemetry/upstream sources may skip in a clean worktree; report skips separately from passing tests. Never copy active results into tests.
- Generated results, models, binaries, local reports, credentials, and database imports stay outside Git (see .gitignore).
