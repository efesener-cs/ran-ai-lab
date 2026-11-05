# RF adversarial experiments (sections 6.5–6.7)

`run_rf` trains and attacks three neural networks on synthetic received IQ frames.
It is a digital white-box receiver-input experiment. It does not run an ns-3
network topology, connect a RIC, transmit RF or measure application traffic.
Do not combine these numbers with the SINR forecasting/QoS experiments.

The external self-contained C++ generator supplied for this experiment is at
`/home/tarnished/Projects/ran-ai-lab/examples/scenarios/rf-ai-frames.cc`. Keep it alongside
shared project inputs. There is no implicit scenario or source fallback.
Only standard C++17 and NumPy are required; the existing container provides them.
The generator is an analytical RF program, not a replacement for an E2 scenario.
The rewritten v2 generator defaults to `diverse`; use `--rf-profile baseline` for
symbol-rate AWGN or `--rf-profile stress` for a harder distribution. The Python
victim remains the explicitly documented small moment-based MLP; a richer data
generator does not automatically make it a CNN or a RAN experiment.

## Physical profiles and separate interference data

`diverse` uses a root-raised-cosine transmit pulse (2 samples/symbol, span 8,
rolloff .35), 3-tap exponentially weighted Rician fading (K=8 dB), per-frame
SNR jitter ±4 dB, gain ±3 dB, phase ±15 degrees, CFO ±.001 cycles/sample and
linear fractional timing interpolation ±.2 samples. Guard samples avoid pulse
startup transients. Unit-power constellations and expected tap power are used;
each received frame is not normalized to hide fading.

`baseline` disables pulse shaping/receiver offsets, uses one AWGN tap and fixed
SNR/gain. `stress` raises nuisance ranges and uses five-tap Rayleigh fading.
The v2 stream layout differs from v1, so baseline is a comparable configuration,
not a byte-for-byte reproduction of historical samples. `--snr-db` is nominal
unit transmit-power/noise ratio before fading/gain, not measured received SNR.

The existing scalar-H contract is retained for channel estimation: a block-flat
complex Gaussian H, known repeated pilot, gain variation and noise. CFO, timing
and multipath do **not** apply to this task; those require a new time/frequency
resolved H target and estimator. The generator emits no wideband occupancy map,
MIMO/RIS channels, propagation to an attacker or hardware measurements.

Each clean `SPLIT.csv` now has three sidecars:

- `SPLIT.csv.frames.csv`: nuisance settings per frame; audit only.
- `SPLIT.csv.meta.json`: exact generator configuration and physical definitions.
- `SPLIT.csv.interference.csv`: a separately labeled observed-IQ table. By default
  80% of each task is untouched, 20% receives physical interference: tone, barrage
  or burst jamming for sensing/AMC; pilot contamination for channel estimation.

Interference sidecar columns include `group_id,task,id,label,attack_type,
signal_label,h_i,h_q,actual_power_ratio,i0,q0,...`. `label` is binary applied
interference; `signal_label` remains the original RF class. Only IQ is an input;
labels, H and actual perturbation power are not detector features. No attack
success is fabricated because the generator does not run a victim model.
Coherent pilot contamination of an unknown scalar H can resemble another valid
channel realization; labels do not guarantee that an IQ-only detector can
identify it. This receiver-additive interference is distinct from Python FGSM/PGD. It is not
inserted into the clean CSV or used to train the current victim automatically.

Domain-separated RNG streams keep clean data invariant to interference fraction,
power and type selection. The generator rejects overwrites, invalid/duplicate
arguments and nonfinite settings; sidecars are published atomically per file,
with metadata last. It accepts `--NAME VALUE` and `--NAME=VALUE`.

The RF runner exposes `--rf-profile` plus repeated physical settings, for example
`--generator-arg=--channel-taps=5 --generator-arg=--rrc-span=10`.
Only allowlisted physical settings are forwarded; callers cannot override the
split seed, sample count, length or output path. Use `--generator-arg=--attack-fraction=0`
to disable sidecar interference. Per-split metadata is retained in `manifest.json`.

| Section | Data/model | Attack objective | Measurements |
|---|---|---|---|
| 6.5 spectrum sensing | Vacant noise vs occupied pulse-shaped/faded QPSK | Target `1-y`, both directions | Accuracy, conditional targeted ASR per direction |
| 6.6 AMC | BPSK/QPSK/16QAM with configurable receiver/channel impairments | BPSK→QPSK→16QAM→BPSK | Accuracy, conditional targeted ASR per pair |
| 6.7 channel estimation | `Y=H*p+noise`, known repeated `p=(1+j)/sqrt(2)`, flat complex Gaussian H | Increase MSE of estimated complex H | Complex aggregate NMSE and real-component MSE |

Each network is `7 IQ moments → tanh(32) → tanh(32) → logits/H`.
The seven moments are mean I, mean Q, mean I², mean Q², mean I⁴, mean Q⁴,
and mean IQ. Scaling uses training statistics only. Gradients differentiate
through both neural layers, scaling and moments back to the original IQ samples.
The model has no access to frame IDs, seed or attack labels as features.
Difficulty depends on the profile and nominal SNR; a zero ASR at a low budget is
an accepted result. No assumption requires all directions to succeed.

The fixed-budget comparisons are clean, zero-budget PGD, random direction on the
L2 sphere, FGSM, and two-start L2 PGD. Classification minimizes target cross
entropy; channel estimation maximizes true-H MSE. PGD retains the strongest
objective per frame including the clean input. FGSM uses a Linf step
`r/sqrt(number_of_real_IQ_components)`, contained in the same L2 ball.
These methods share an L2 power ceiling but different feasible search geometry.

Budget: `r² = 10^(PSR_dB/10) * ||received_clean_IQ||²` for each frame.
The denominator includes thermal noise. For vacant frames it is noise energy;
it is not primary-user signal power. −20/−10/−6 dB correspond to approximately
1%/10%/25.1% added power ceilings. Do not call all three imperceptible or low power.
The attacker directly controls the receiver input and knows the model. In
particular, occupied→vacant can exploit coherent cancellation unavailable to an
unsynchronized transmitter. The data can include receiver timing/CFO, transmit pulse shaping and multipath,
but the attacker still acts directly at the receiver input. There is no attacker
propagation/synchronization model, ADC clipping or hardware validation.

## Run in the existing shared container

From the host checkout on `feat/docker-support`, after stopping active campaigns:

```bash
cd /home/tarnished/Projects/ran-ai-lab
python3 lab.py run_docker --runner rf --container ran-lab \
  --scenario /home/tarnished/Projects/ran-ai-lab/examples/scenarios/rf-ai-frames.cc \
  --output results/rf-container-v2-01 \
  --train-samples 2400 --eval-samples 600 --length 128 \
  --seeds 11 23 37 --snr-db 10 --rf-profile diverse \
  --psr-db -20 -10 -6 --epochs 80 --steps 30
python3 lab.py check_rf results/rf-container-v2-01
```

Use the actual container name if it differs from `ran-lab`.
The existing `run_docker` launcher copies current maintained Python packages
and the exact supplied `.cc` into a run directory in the prepared container.
`--runner rf` invokes `run_rf` instead of live supervision. It compiles only the
small supplied generator, trains the RF models and retrieves outputs on success
or failure. It does not rebuild ns-3/FlexRIC, install dependencies or modify the
shared SDK. Like its existing behavior, the launcher starts the named container
if it is stopped. Select a fresh result directory for each attempt.
The container already needs working `g++`, Python and NumPy.

Copy/share the changed checkout files as well as the external `.cc` when giving
this command to colleagues. An older checkout/archive does not contain `run_rf`
or `--runner rf`. This feature has not been inserted into the previously shared
archive or a Windows Docker volume. `Run-Windows.ps1` currently runs ns-3
native/live scenarios; it cannot run this analytical RF pipeline by itself.

For an ordinary host run, replace the first command with:

```bash
python3 lab.py run_rf \
  --scenario /home/tarnished/Projects/ran-ai-lab/examples/scenarios/rf-ai-frames.cc \
  --output results/rf-host-01
python3 lab.py check_rf results/rf-host-01
```

## Evidence and scope

- `run_status.json`: completed/failed and explicit non-network/non-OTA scope.
- `manifest.json`: configuration, separate split seeds, input/source/binary and
  implementation hashes, versions and executed compilation/generation commands.
- `train.csv`, `validation.csv`, `test.csv`: raw IQ, source labels and true H.
- `*-model.npz`: fitted parameters plus training feature mean/scale.
- `*-audit.npz`: each test delta, target and attacked prediction.
- `predictions.csv`: paired predictions, norms and actual per-frame power ratios.
- `summary.json`: condition metrics and validation-selected epoch.
- `evidence.json`: SHA256 index of retained artifacts.

Train/validation/test seeds must differ; identical IQ frames across splits are
rejected. Validation chooses the training epoch; test samples do not choose
hyperparameters. Targeted ASR counts only samples classified correctly when
clean. A targeted hit and an arbitrary misclassification are different outcomes.
Channel NMSE is `sum|Hhat-H|²/sum|H|²`; it is a linear ratio, not dB. Training MSE
and reported MSE average over the two real components. No downstream beamforming,
scheduling, throughput, RIS, MIMO or OFDM degradation is established here.

`check_rf` checks artifact hashes, split content separation, stored targets,
per-frame power budgets, saved model inference and metrics by recomputation.
The unsigned local hash index detects accidental edits, not a malicious rewrite
of the entire evidence set. Numerical unit checks include finite differences
for raw-IQ and parameter gradients. For v2, `check_rf` also validates every
physical-interference sidecar row: group/source identity, unchanged signal/H
truth, applied-label/IQ consistency, type, mixture and actual power budget. Compiler/stdlib/NumPy versions can change
exact random samples or fitted values across machines.

This implementation covers narrowband binary sensing, three modulation classes
with configurable receiver/channel impairments and block-flat channel pilots. Wideband targeted sensing, universal,
sparse, shift-invariant AMC attacks and adversarial training/distillation are
further experiments; they are not claimed as implemented or reproduced.
Literature context includes [channel-aware signal-classifier attacks](https://user.eng.umd.edu/~ulukus/papers/journal/aml-channel-aware.pdf)
and [2022 channel-estimation/distillation work](https://ieeexplore.ieee.org/document/9888103/).
The present benchmark does not reproduce their datasets or numerical results.

## Labeled datasets for an attack detector

The raw `train.csv`, `validation.csv`, `test.csv` above are clean victim-model
inputs. Their `label` is spectrum occupancy or modulation class, not attack
presence. Channel truth is `h_i,h_q`. `predictions.csv` logs the attack `mode`, but
contains predictions rather than a complete observed-IQ training table.

Create a separate detector dataset without modifying the original evidence:

```bash
python3 lab.py export_rf_detection results/rf-host-verified \
  --output results/rf-detection-80-20 --attack-fraction 0.2 \
  --modes fgsm pgd --psr-db -10 --seed 101
```

Use your verified container result instead of `results/rf-host-verified` if desired.
The exporter rechecks the input experiment, then generates attacks for each
original split independently. It writes one version of each source frame: clean
or attacked, never two siblings assigned to different splits. The fitted victim
model and original split identities remain fixed. For v2 generators, exported
`group_id` matches the C++ physical-interference sidecar; all variants of one
source frame must remain in the same split when combining those datasets. It does not train a detector.

Each split contains exactly the rounded requested mixture **per task**. For the
2400/600/600 source defaults: 1920/480 train clean/attack and 480/120 in each
validation/test task. FGSM and PGD share the attack count as evenly as possible.
No random-noise or zero-budget control is labeled malicious. A selected attack
that produces no delta fails export instead of creating a false positive label.

| Column | Meaning | Model input? |
|---|---|---|
| `label` | 0 clean, 1 intentional perturbation applied | Target only |
| `task` | sensing / amc / channel | Context; train separate detectors per task |
| `attack_type` | none / fgsm / pgd | Multiclass target or audit only |
| `attack_applied` | Actual nonzero IQ perturbation | Audit only |
| `attack_success` | Target hit on clean-correct classifier, or increased H MSE | Audit only |
| `signal_label` | Original occupancy/modulation label or complex H | Audit/other task target only |
| `group_id`, `split`, `frame_id` | Original source identity and split | Split/audit only |
| `psr_db`, `actual_power_ratio` | Generator knowledge of perturbation | Audit only |
| Seven `mean_*` columns | Moments of observed IQ | Detector features |
| `i0,q0,...` | Observed clean or perturbed receiver samples | Alternative raw-IQ features |

Use `dataset.json`'s explicit `feature_columns` or `alternative_raw_iq_columns`.
Do not automatically take every numeric column as input. Attack labels,
ground-truth H, success and perturbation power would leak generator knowledge.
An unsuccessful perturbation remains an attack; `attack_success` is not the
binary attack-detection label. Existing victim-model `train_ai` does not accept
these detection tables: train a separate detector with `label` as target.
For adversarial **task-model training**, keep the original occupancy/modulation/H
targets instead; attack presence is not the task's desired prediction.

The 80/20 mixture is a configurable starting prevalence, not an optimum and not
a train/test split. Preserve independent seeds/groups first. Tune training
mixture, class weights and thresholds on validation; keep a separately reported
test at representative prevalence and evaluate rare attacks/unseen conditions.
Report attack precision/recall, F1, PR-AUC, false-positive rate and per-method
results. Always predicting clean gives 80% accuracy here. See
[metric guidance](https://developers.google.com/machine-learning/crash-course/classification/accuracy-precision-recall)
and [group/time separation](https://scikit-learn.org/stable/modules/cross_validation.html).
