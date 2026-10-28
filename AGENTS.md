# Agent instructions

## Project and architecture
- Research lab for ns-3/O-RAN, FlexRIC/KPM, and adversarial SINR forecasting; Python 3.10+.
- `lab.py` dispatches CLI commands. Keep command names, flags, and output schemas stable; implementation belongs in domain packages.
- `simulation/` owns live/native runners, process supervision, traffic schedules, matched suites, and campaigns.
- `scenario/` accepts external self-contained C++ sources, preserves exact snapshots, and compiles native executables. Do not generate, patch, or silently fall back to a bundled network scenario. Standalone execution uses `run_scenario`; AI runners require the explicit trace/control contract in scenario/README.md.
- `ai/` owns telemetry features, training, replay, shadow inference, policy, attacks, and robustness.
- `datasets/` exports measured CSV tables; `checks/` validates evidence. `analysis/` and `database/` were removed at the user's request; EDA is a separate user step.
- `labcore/` owns shared paths, command construction, source fingerprints and host-native dependency helpers. This optional branch adds Docker tooling; keep its launcher on the same host-native live supervisor and preserve source-copy dependencies in labcore/runtime_bundle.py.
- Read README.md and docs/RUNNING.md before changing execution behavior; docs/DATASET.md and docs/EVALUATION.md define scientific contracts.

## Protect active experiments
- If the user has not stated whether an experiment is active in the current session, ask before changing source files, switching branches, or running checks that could affect experiments. Do not infer experiment status from old campaign paths or previous sessions. Once the user states the status, use it unless they report a change.
- Campaigns hash the maintained package sources, tests, scenario, and execution configuration before each suite. Even adding a test can abort an active campaign.
- Use `/home/tarnished/Projects/ran-ai-lab` as the shared workspace. Do not create external worktrees or working copies unless the user explicitly requests them. If an experiment is active, ask the user how to proceed before changing its source files or checkout.
- Do not start Docker/ns-3 integration runs, rebuild shared binaries, or kill processes as part of routine checks while an experiment runs.
- Preserve models, training/validation/test provenance, referenced runs, successful baselines, and all campaign attempts. Inspect references before removing results. Restrict cleanup to explicitly identified obsolete failures and record paths/reasons outside results.

## Development conventions
- Keep `docs/` limited to current setup, usage, and scientific contracts. Keep project evolution in `reports/reports.md` and the author's report in `reports/rapor.md`. Do not create dated step walkthroughs, duplicate report backups, or separate cleanup reports unless explicitly requested.
- Keep the remaining CLI names, flags, CSV schemas, and native/live host paths coherent. Do not restore automatic EDA or database imports. Keep Docker dependencies confined to this optional feature.
- Entry-point scripts should expose main() and use an __main__ guard; importing modules must not run simulations, parse arguments, build binaries, or create artifacts.
- Keep JSON publication atomic where readers run concurrently. Preserve fail-closed validation, warmup handling, closed telemetry windows, paired controls, and seed separation.
- Do not call replay a causal QoS experiment, CSV control E2 RC, or batch processing time end-to-end near-RT latency.
- Do not delete Python files based only on filenames: scripts can be CLI tools, generators, or container dependencies.

## Checks
- From the project workspace, after establishing experiment status: `python3 -m unittest discover -p 'test_*.py'`.
- Run `git diff --check`. The former publication-only scripts directory has been removed at the user's request; do not recreate it or its CI invocation.
- Tests generate synthetic telemetry and KPM fixtures; they must not require saved experiments or external ns-3 sources. Preserve those checks rather than skipping them. Never copy results into tests. Compiler checks require a compatible installed compiler.
- Generated results, models, binaries, local reports and credentials stay outside Git (see .gitignore).
