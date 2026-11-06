# Independent RF research dataset contract

This new NumPy-only generator is **development-unvalidated synthetic**. It does
not replace or relabel the historical three-class moment-MLP/scalar-H experiment
in [RF.md](RF.md). No classifier is fitted and no accuracy is prescribed.

## Sources and design consequences

Primary sources checked during implementation:

- [DeepSig dataset authors](https://www.deepsig.ai/datasets/) warn about errata in
  historical RadioML and recommend independently generated or recorded data.
  No RadioML samples, code or licensed dataset are included here.
- [MathWorks pulse-shaping documentation](https://www.mathworks.com/help/comm/ug/raised-cosine-filtering.html)
  explains finite filter span, symbol oversampling and transient removal. Here
  the explicit square-root-raised-cosine formula has span 8 symbols, unit tap
  energy, configurable rolloff and samples/symbol; transmit amplitude is scaled
  by sqrt(samples/symbol). No matched receive filter is applied.
- [MathWorks OFDM channel-estimation documentation](https://www.mathworks.com/help/comm/ug/ofdm-channel-estimation.html)
  motivates known pilots, CP removal and frequency interpolation. Here a SISO
  linear convolution is implemented in time and checked against H=FFT(taps).
  This is a focused design review, not reproduction of published performance.

## Physical definitions and defaults

All tasks use independently seeded label, nuisance, symbol, noise and channel
and separate quiet-calibration streams, derived with SHA256 from version/task/split/root-seed/role. Bursts have
four frames by default. Labels, channel and nuisance settings are constant in
a burst; payload and receiver noise vary. These are independent guarded payload
segments from one stationary emission regime, not overlapping continuous IQ.
Treat whole bursts as groups for splitting and uncertainty estimation. Independent
root seeds are required across named splits, and split names also domain-separate
streams. Merely changing the split name is insufficient scientific independence.

Nuisance columns, in order, are nominal SNR dB, noise uncertainty dB, phase radians,
CFO cycles/sample and timing samples. Defaults: nominal SNR uniform [-8,20] dB,
noise uncertainty uniform [-2,2] dB, phase uniform [-pi,pi], CFO uniform
[-.002,.002], fractional timing uniform [-.4,.4]. Noise is independent circular
complex Gaussian with variance `10**((noise_uncertainty_db - snr_db)/10)`.
SNR references expected unit transmit power before fading, not measured received
power. Channel taps are independent circular complex Gaussian with expected
powers proportional to exp(-tap_index), sum one; realized channels/frames are
not normalized. Default four taps. Distributions are engineering assumptions,
not fitted propagation/hardware distributions. Phase/CFO/timing are applied only
to sensing and AMC; channel task stores those unused draws for a uniform audit
schema but does not apply them. No IQ imbalance, clipping, Doppler evolution or
transmitter hardware fingerprint is modeled.

**Sensing:** four parallel ideal channelized baseband bands, each with 128 complex
samples. Independent Bernoulli occupancy per band per burst (default p=.5).
Occupied signals use independent QPSK symbols and the common pulse/channel model;
vacant observations contain noise only. Bands share burst nuisance/channel and
have independent symbols/noise. This is a multiband occupancy map at an ideal
channelizer output, not a synthesized contiguous wideband RF waveform. There is
no adjacent-band leakage, interfering transmitter, or RF channelizer model.

Energy is mean |IQ|². Given vacant-band variance v and L independent complex
samples, `L*energy/v` is Gamma(shape=L, scale=1). The exact integer-Gamma survival
function is inverted without SciPy to set PFA=.05. The saved conservative
threshold uses the largest configured noise variance across all SNR/noise
uncertainty settings. Checker reports empirical vacant FPR and occupied detection
rate for this fixed threshold. The conservative rule can have low detection
power; no test data tunes it. The additional calibrated baseline uses only a separate observable quiet receiver
reference capture: 2048 complex samples per emission group by default, bounded
by `--calibration-length` [128,65536]. It is repeated across that group's frames
in observations.npz for direct alignment and shares the receiver noise variance,
but has no signal. Its independent RNG role prevents changing calibration length
from changing received task data. This assumes a guaranteed quiet reference
interval and stationary receiver noise between reference and task capture; this
assumption needs validation on hardware. It is neither true audit variance nor
an estimate computed from possibly occupied task IQ.

Estimate variance as mean |quiet_calibration|², then multiply it by the
unit-variance known-noise Gamma threshold. This plug-in threshold has approximate
PFA with finite calibration, not exact .05 coverage; reference uncertainty is
not integrated out. Checker reports `calibrated_vacant_fpr` and
`calibrated_occupied_detection_rate` alongside the worst-case threshold baseline.
No label or nuisance parameter selects an example's calibrated threshold.
Per-nuisance thresholds from audit parameters would be oracle calibration.
Full curves, exact finite-reference F-ratio calibration, and group-bootstrap
uncertainty remain future evaluation work.

**AMC:** six equiprobable-by-group classes BPSK, QPSK, 8PSK, 16PSK, 16QAM and
64QAM. PSK points lie on the unit circle; square QAM constellations have unit
expected symbol energy. Classes cycle then shuffle before payload generation;
a final partial burst can produce slight frame imbalance. Checker reports measured per-class frame/group counts and nuisance min/max/mean
in the audit column order above. These summaries repeat burst nuisance rows, so
frames are not independent samples; finite class differences do not establish
sampler dependence. Uniform guessing has
expected accuracy 1/6; report empirical majority prevalence separately. Same
RRC, phase, CFO, fractional timing (linear interpolation) and finite multipath
models apply independently of class. Pulse and channel transients are guarded.
There is no arbitrary accuracy target. Analog/FSK/OFDM modulation families and
real transmitter-held-out validation are not covered.

**Channel:** one synchronized SISO OFDM symbol per frame, N=128 default, CP=16,
comb pilots every four subcarriers. Known pilot value (1+j)/sqrt(2); independent
QPSK data on other subcarriers. Unitary IFFT -> CP -> linear multipath convolution
-> CP removal -> unitary FFT; complex AWGN is added in frequency (equivalent to
white time noise under the unitary FFT). CP must cover maximum tap delay. True
frequency response H=FFT(taps), using unnormalized FFT, is a regression label.
Baseline divides received pilots by known pilots then periodically linearly
interpolates real/imaginary components; NMSE is sum|Hhat-H|²/sum|H|². Sparse pilot
interpolation has noiseless bias; full-pilot noiseless LS is exact up to floating
point error. No synchronization error, MIMO array, ray tracing, OTA, standard
compliance, beamforming or downstream throughput result is claimed.

## Artifact boundary and validation

Each fresh output directory holds compressed lossless NPZ and a JSON manifest:

| Artifact | Contents | Model access |
|---|---|---|
| observations.npz | received float64 [...,2]; sensing quiet_calibration [frames,calibration_length,2]; channel known pilots [N,2] | inputs |
| labels.npz | int64 class/occupancy or float64 H [...,2] | targets |
| audit.npz | float64 nuisance [frames,5], taps [frames,taps,2], channel LS estimate | audit only |
| identities.npz | int64 local frame and burst IDs | group/split only |
| generator_source.py | exact generator source snapshot, SHA256 checked | provenance only |
| manifest.json | config, role seeds, identity namespace, array shapes/dtypes, counts, SHA256, generator hash, environment, calibration/baseline | provenance only |

Complex arrays store real/imaginary components on their last axis. Never select
all numeric arrays as features. True H, taps, nuisance, labels and identifiers
are unavailable to the task model. Identity is namespace plus local group ID;
keep all variants of a burst together. Publication of manifest is atomic and
last; interrupted directories remain incomplete and cannot be overwritten.

Checker uses allow_pickle=False and an exact archive-key/schema allowlist,
checks finite float64/int64 values, shapes, file and current generator hashes,
role seeds/counts/split identity, and full deterministic regeneration. It also
independently checks H against taps, recomputes LS interpolation/NMSE and the
energy threshold. `--other DIR` checks namespace reuse, fresh root seeds across
splits, and exact duplicate observed frames. Check all relevant splits together;
a lone directory cannot prove global independence. Hashes are unsigned integrity
checks. Regeneration is a consistency check, not independent scientific model
validation; NumPy/platform changes can change exact replay. Checker materializes
arrays, so large collections should be generated as bounded independent shards.

## Commands

From the repository root (use fresh directories for each attempt):

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 -m unittest tests.test_rf_research -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 -m datasets.generate_rf_research \
  --task sensing --seed 6101 --samples 120 --split development \
  --output /mnt/onetb/ran-ai-lab/results/research-development/rf/sensing-6101
python3 -m checks.check_rf_research /mnt/onetb/ran-ai-lab/results/research-development/rf/sensing-6101
```

Use `--task amc --seed 6102` or `--task channel --seed 6103` with corresponding
fresh paths. CLI `--help` lists all physical options. The split flag records
identity; `ood` does not invent an OOD distribution. Explicitly preregister changed
physical ranges/families before any later OOD generation. The accepted development
fixtures are inspected engineering checks, not blind holdouts or confirmatory
collections. External real-data validation, transmitter/site/channel distribution
validation, leakage baselines and group confidence intervals remain open gates.

## Development acceptance evidence

The commands above were run at 120 frames/30 bursts per task with seeds
6101/6102/6103 respectively. The original targeted seven-test suite passed. These historical artifacts predate
the observable calibration addition; the current generator hash deliberately
rejects them rather than silently reinterpreting them. Generator plus
checker elapsed approximately .154/.038/.031 seconds in one sequential process;
process high-water RSS was 41,184 KiB (not a per-task RSS measurement). Total
artifact bytes including manifests: sensing 948,727; AMC 242,882; channel 539,477.
Sensing conservative PFA=.05 threshold yielded observed vacant FPR=0 and occupied
detection=0 in this tiny fixture: this threshold is deliberately worst-case across
26 dB of nominal SNR plus noise uncertainty, and is not an effective validated
operating point. Do not tune it on this fixture and call the resulting score a
holdout result. OFDM LS/interpolation aggregate NMSE was .5912254243326864 under
the broad default SNR range. This number is a baseline observation, not a quality
threshold or evidence of realistic deployment behavior.

The observable-calibration revision adds a counterfactual reference invariance
test (occupancy/class changes do not change reference data), calibration-length
invariance of task IQ, and a null FPR check across 800 independent emission
groups with varying noise/SNR. Eight targeted tests pass. New artifact snapshots
include generator_source.py; the historical acceptance directories stay immutable.

New inspected development acceptance: `sensing-calibrated-6201`, seed 6201,
120 frames/30 groups, default physical settings and 2048 reference samples/group.
Generation plus checker took about .244 seconds; all artifacts total 4,729,549
bytes including the source snapshot. Fixed plug-in calibrated baseline yielded
vacant FPR=.0625 and occupied detection=.9301470588235294; the simultaneous
worst-case baseline remained 0/0. These small, correlated-by-burst empirical
rates are descriptive evidence only, not calibrated confidence bounds, an
optimized operating point or a release-quality validation result. No parameter
was tuned to these outcomes.
