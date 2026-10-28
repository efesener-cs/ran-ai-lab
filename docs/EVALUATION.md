# Evaluation protocol

This repository studies how bounded telemetry bias affects forecasts, decisions, and application traffic in synthetic ns-3 runs. It does not establish field RF attack effects, commercial-network generalization, or QoS guarantees. The live backend verifies FlexRIC/E2 monitoring; model input still comes from closed ns-3 trace windows, and control uses CSV-to-ns-3 RRC rather than E2 RC.

## Matched conditions

Each new suite requires an external `--scenario` implementing the [lab input/output contract](../scenario/README.md). Its exact source is captured as `scenario.cc`; `scenario_sha256` is included in the pipeline fingerprint. Conditions use that same snapshot and native executable identity. Older measurements remain analyzable, but they do not establish effects for a new scenario.

`simulation/run_adversarial_suite.py` holds the model, seed/run, UE count, duration, and event schedule fixed across conditions. Modes are `none`, `random`, `bias`, `fgsm`, `pgd`, and `exact`; all six are enabled by default. Modes must be distinct and include exactly one `none`. Suites require 3–120 UEs and at least 3 seconds.

`--epsilon` is the raw SINR bias budget, 0–5 dB. Epsilon-zero suites are a separate no-bias control. Keep different epsilon, seed, and backend results identifiable.

```bash
python3 lab.py run_adversarial_suite --scenario /path/to/compatible.cc --backend native --duration 3 --ues 6 \
  --seed 41 --run 1 --epsilon 2 --modes none random bias fgsm pgd exact \
  --access two_cell --predictor ridge --output results/suite-e2

python3 lab.py run_adversarial_suite --scenario /path/to/compatible.cc --backend native --duration 3 --ues 6 \
  --seed 41 --run 1 --epsilon 0 --modes none random bias fgsm pgd exact \
  --output results/suite-e0
```

Access scopes are `two_cell`, `target_only`, and `best_only`. The persistence predictor uses the current SINR through zero residual weights and bias while retaining the model schema. Model files and hashes are saved with suite manifests.

FGSM takes one step. PGD defaults to ten projected steps and five starts, retaining the best iterate across starts. Adjust these with `--steps` and `--restarts`. The objective is the current decision's forecast ranking, rather than a future measured SINR or application-loss target.

`--max-step-db` constrains active bias changes relative to the previous tick. Bias resets to zero outside an event or accessible cell support, so this is not a continuous whole-run slew guarantee.

`exact` and the optimizer reference solve the accessible current-window cell-bias problem for the target-minus-original-best forecast margin with past bias fixed. They do not optimize a multi-window trajectory, QoS, or control success.

## Robust decision budget

`--robust-budget-db B` computes one-step forecast intervals assuming current and previous SINR biases can independently lie in `[-B, B]`. A handover is recommended only if the worst-case score gain clears hysteresis; otherwise the policy holds.

Model parameters and other telemetry features are assumed trusted. The interval bounds the one-step score difference, not physical SINR, throughput, QoS, handover confirmation, or later policy decisions. Accepted budgets are 0–5 dB. Decision rows record the budget and `certified_gain_lower_db`; forecast CSVs retain point predictions. `off` disables this rule, whereas `0` applies it with zero uncertainty. These are separate conditions.

## Independent training and testing

Default training holds out UE groups from the same run and labels this `same_run_held_out_UE_pilot`. For independent evaluation, use separate runs and seeds:

```bash
python3 -m ai.train --allow-native \
  --run-dir results/native-clean-seed41 \
  --validation-run-dir results/native-clean-seed53 \
  --test-run-dir results/native-clean-seed67 \
  --alpha-grid 0.1 1 10 100 1000 \
  --output ai/artifacts/native-seed41-val53-test67
```

Native sources need explicit `--allow-native`, which does not verify live E2. Alpha candidates are fit on training data, selected by validation MAE, and the selected model is fit on training data only. Test data is excluded from selection. The three example seeds do not themselves establish broad external validity.

Training, validation, and test inventories must not share paths, run IDs, CSV hashes, or seeds. Missing seeds are rejected for independent evaluation. Source provenance records all splits separately.

## CSV evidence, replay, and later EDA

Main stops after CSV collection and evidence validation. A suite retains its per-run tables, combined radio `dataset.csv`, and `comparison.json`; campaigns no longer launch analysis or statistics programs.

```bash
python3 lab.py check_control results/suite-e2/suite-e2-pgd --native
python3 lab.py check_evasion results/suite-e2/suite-e2-pgd
python3 lab.py evaluate_replay --model ai/artifacts/native-seed41-val53-test67/model.json \
  --run-dir results/native-clean-seed67 --allow-native --epsilon 2 \
  --access two_cell --robust-budget-db 1 --output results/replay-seed67
```

For later user-written EDA, compare each condition against its paired `none`, use application rows for received-byte totals, and treat independent seeds as repetitions rather than adjacent UE/window rows. Keep backend, scenario/source, predictor, access, defense, budget, UE count, duration, and epsilon groups separate. No automatic p-values or bootstrap intervals are produced on main.

Replay verifies model split provenance against test sources. A legacy model missing provenance requires explicit `--allow-unverified-split`. Replay reports each run/predictor/mode/access/budget separately, with measured next-window SINR as its target. In-memory perturbation does not change measured radio/application traffic or apply network controls. It cannot establish causal QoS loss or handover success.

Control verification separates infrastructure validity from submitted, confirmed, rejected, and unconfirmed outcomes. Its stricter `passed` flag requires at least one submission and confirmation of every submission. A later target-connected event confirms state at that time; it is not evidence of target-cell occupancy throughout a window or of QoS improvement. Healthy all-hold runs need not satisfy that strict flag.

## Time alignment and missingness

Decisions are timestamped at the end of a closed 100 ms window. Audit `event_active` and `input_perturbed` describe the input at that decision. The window's received bytes predate the new decision. Current collection leaves application/decision joins to later EDA. Historical exports contain `prior_decision_*` fields aligned to the application window start. Subsequent control confirmations carry their own timestamps.

Radio `aml_audit_available=0` means the audit join is missing; empty AML fields are not zeros. In a present audit, zero event/perturbation flags explicitly describe an inactive/unmodified input. In historical normalized exports, application `aml_*_same_window` flags fill with zero on a missing join, so they alone cannot establish availability; `aml_input_audit_available` records that distinction. These application joins are not generated by the current collector. Empty `active_event_ids` in a present audit means no applied active event, including `none`. Empty prior decision time means no matched decision; empty action does not mean `hold`.

## Source revisions and timing scope

Campaigns hash sources between jobs. Do not edit during execution. If a reviewed source change is necessary before resuming, `--allow-code-change` records an explicit boundary; it does not relabel old runs as reproduced by new code. Manifests retain recorded source/model/scenario identities for subsequent inspection; future EDA should use that recorded provenance rather than assigning the current checkout to old runs.

`experiment_pipeline_sha256` is part of historical normalized exports. New runs preserve source/model/scenario and executable information in their manifests/status files for later grouping. Do not pool different execution pipelines in EDA. Missing post-warmup decision/audit coverage fails validation; empty initial warmup audit is not a clean-measurement claim.

`batch_processing` in `ai_shadow_status.json` measures wall-clock work after polling: attacks, reference/observed policy, and CSV publication. It excludes telemetry generation, poll waiting, and RRC confirmation. It is not end-to-end near-RT latency or deadline evidence.
