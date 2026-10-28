# Dataset fields and use

A suite pairs `none` with the selected evasion conditions: `random`, `bias`, `fgsm`, `pgd`, and `exact`. The default includes all six. Seed/run, UE count, duration, model, event schedule, and other settings stay fixed within a suite. See [EVALUATION.md](EVALUATION.md) for the experiment protocol.

New suites capture an external scenario and record `scenario_sha256` in the manifest; run status includes its source metadata. Different scenario/pipeline identities are kept separate in statistical summaries. Existing dataset rows retain the identities of their original experiments.

## Tables

| File | Row unit | Purpose |
|---|---|---|
| `application_dataset.csv` | run × UE × 100 ms | Measured PacketSink RX bytes, application goodput, mobility, RRC observations, and experiment labels. Use this table for traffic totals. |
| `radio_dataset.csv` | run × UE × NR cell × 100 ms | Radio measurements and clean/observed predictor-input audits. Application values repeat over four cell rows; do not sum them here. |
| `run_summary.csv` | run | Post-warmup RX bytes, aggregate goodput, paired-clean byte differences, and attack/control counts. |
| `target_gap.csv` | active UE decision window | Clean-best minus target forecast before and after perturbation. A negative observed gap means the target outranks the original best; ties depend on the ranking tie-break. |

## Shared fields

| Field | Meaning |
|---|---|
| `run_id`, `suite_id` | Run identity and the matched suite linking conditions. |
| `backend` | `live` or `native`; distinct performance populations. |
| `experiment_seed`, `experiment_run` | ns-3 RNG seed and run. |
| `experiment_condition` | Assigned condition: `none`, `random`, `bias`, `fgsm`, `pgd`, or `exact`. It does not mean every row is actively attacked. |
| `epsilon_db` | Assigned raw SINR bias budget; actual delta is zero in `none`. |
| `model_sha256` | Hash of the model file actually used. |
| `experiment_pipeline_sha256` | Fingerprint of simulation/inference sources and binary/image identity. Full source hashes remain in provenance. |
| `window_start_s`, `window_end_s` | Simulation-time window boundaries, not wall-clock capture times. |
| `ue_imsi`, `nr_cell_id` | Simulated UE and measured NR cell identifiers. |
| `rx_bytes`, `app_goodput_mbps` | UE application RX bytes and Mbps in the window. |
| `ue_rx_bytes`, `ue_app_goodput_mbps` | The same application measurements repeated in radio rows. |
| `is_warmup`, `ue_is_warmup` | Warmup flag; rows are retained but excluded from summary metrics. |
| `traffic_profile`, `direction` | TCP bulk, UDP bursty video, or UDP telemetry; DL or UL. |
| `x_m`, `y_m`, `speed_mps` | UE position in meters and speed in m/s; prefixed with `ue_` in radio rows. |
| `ue_nr_rrc_cell_id`, `ue_nr_rrc_state` | Observed NR RRC cell and state in the window. |
| `ue_control_required` | Whether the external control barrier expects a command for this window. |
| `attack_present`, `attack_type` | Legacy UDP-load labels; these are not model-input evasion labels. |
| `aml_event_active` | Whether the evasion schedule is active for the UE at this decision. |
| `aml_input_perturbed` | Whether current or previous window bias affects the model input. |
| `aml_audit_available` | Whether a radio-window attack audit is present. Zero means missing audit, not a verified clean input. |
| `aml_input_audit_available` | Whether an application window has a model audit at its end time. |
| `aml_input_event_active_same_window`, `aml_input_perturbed_same_window` | Application labels joined to the same closing window. Missing joins fill these flags with zero; the flags alone do not prove audit availability. |
| `prior_decision_time_s`, `prior_decision_action` | Previous decision aligned to the application window start. An empty time means no matching decision; an empty action does not mean `hold`. |
| `prior_decision_target_connected_confirmed`, `prior_decision_confirmation_time_s` | Later target-connection confirmation for that decision and its event time, not continuous target-cell occupancy throughout the window. |

## Radio and attack-audit fields

`sinr_*_db` summarizes raw SINR samples by mean, standard deviation, minimum, maximum, and last value. `sinr_sample_count` records sample coverage. `cell_dl_*` summarizes cell-level PHY transport blocks, corrupt fraction, bytes, successful bytes, MCS, RV, receiver SINR, and TBLER. These cell-level values are not per-UE application goodput.

`last_recorded_path_cell_id` and related fields summarize recorded path events. They do not replace RRC control confirmation.

`aml_mode`, `aml_epsilon_db`, and `aml_active_event_ids` identify the method, budget, and active events. `aml_delta_sinr_db` and `aml_previous_delta_db` hold current and previous window biases. `aml_raw_sinr_mean_db` is the raw mean; `aml_model_sinr_mean_db` is the mean presented to the model. `aml_clean_prediction_db` and `aml_observed_prediction_db` compare inputs on the same network state of the attacked trajectory. They are not the separate matched `none` run. `aml_clean_best_cell` and `aml_attack_target_cell` identify the clean best and target cells.

The `aml_clean_` and `aml_model_` prefixes expose the same eight predictor features:

1. `sinr_mean_db`: window mean SINR, dB.
2. `sinr_last_db`: last sample, dB.
3. `sinr_std_db`: within-window standard deviation, dB.
4. `mean_change_db`: current minus previous mean, dB.
5. `last_minus_mean_db`: last sample minus mean, dB.
6. `cell_dl_tb_count`: cell-level DL transport-block count.
7. `cell_dl_corrupt_fraction`: corrupt DL block fraction; empty when no blocks are observed.
8. `cell_corrupt_fraction_missing`: missing-fraction indicator, 0 or 1.

An attack adds a constant bias to all accessible SINR samples in a window. Standard deviation and last-minus-mean stay unchanged. The mean-change feature also depends on previous bias, so an attack can affect the following window's features. Bias resets when attack support is inactive.

Missing numeric values stay empty in CSV. The model fills missing features using training medians; export does not invent zero radio measurements. For a matched audit, `event_active=0` explicitly means an inactive event and an empty `active_event_ids` means no applied active evasion event, including mode `none`. A missing audit is different. Post-warmup decision/audit coverage is required for validation. Missing audit in the initial warmup window is not a clean-input assertion.

## Timing

Audit `decision_time_s` is the end of a closed 100 ms window. The event mask is evaluated at that decision time. Same-window AML flags describe the input used for the decision, not a causal effect on traffic already received during that window. `prior_decision_*` fields align the previous decision to the next application window's `window_start_s`. A later target-connected event confirms connection at that event time only.

`bearer_intervals.csv` preserves original PDCP/RLC measurement intervals. Present raw files may contain no records; export then writes a header-only table and records `bearer_intervals_available` and `bearer_intervals_by_layer` in `quality_report.json`. An absent required raw file is an error. No artificial bearer measurements are inserted.

## Splits and statistics

Use `python3 -m ai.train` with separate `--run-dir`, `--validation-run-dir`, and `--test-run-dir` inputs for independent tuning/testing. Native sources require `--allow-native`; this does not establish live E2 verification.

The alpha grid fits each candidate on training data and selects by validation MAE. The final model is fit on training data with the selected alpha; test data never participates in selection. Training, validation, and test must have different seeds. Duplicate sources, shared CSV hashes, or missing/overlapping split seeds are rejected. Default same-run UE splitting is explicitly a pilot, not independent-run evidence.

Keep adjacent windows, cell rows, and all matched conditions of the same seed together when assigning folds. Clean runs repeated at different epsilon budgets are not independent trials. Compute effects against the clean run within each suite before summarizing independent seeds.

Backend, pipeline fingerprint, predictor, access, defense, duration, UE count, and epsilon remain separate statistical strata. Robust budget `off` disables the defense; budget `0` still applies the interval decision rule with zero bias uncertainty. Bootstrap summaries require at least two independent seeds, warn about small samples, and do not establish broad generalization or immunity from short pilots alone.
