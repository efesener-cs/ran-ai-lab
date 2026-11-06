# Research dataset protocol

The target is representative, auditable data and generalization across independent
conditions. No acceptance rule forces a simple classifier below 90%, nor a model
into 50–60%. At current IP prevalence a constant-clean classifier has about 83%
accuracy. Binary uniform guessing has expected 50% accuracy regardless of the
number of measured features; average-precision chance level follows prevalence.
Low performance can indicate poor representation, ambiguous observations,
distribution shift or labeling bugs. Feature count alone is not a diagnosis.

## Literature evidence and consequences

| Primary source | What the source actually does | Consequence here |
|---|---|---|
| [CICIDS2017, UNB](https://www.unb.ca/cic/datasets/ids-2017.html) | User-behavior background profiles over HTTP/HTTPS/FTP/SSH/email; full network configuration, packets and derived labeled flows. | Model sessions and changing legitimate demand, not only persistent sockets plus obvious flood intervals. Do not claim that transport traffic generators implement HTTP/TLS/application exploits. |
| [UNSW-NB15, UNSW](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | A hybrid of real normal activities and synthetic attacks; packet capture, flow analysis, ground-truth events, 49 derived features. | Keep independent activity provenance and a documented observation pipeline. More features are useful only when available at the declared observation point. |
| [Engelen et al., CICIDS troubleshooting](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) | Documents flow/label/flag/timeout errors and their consequences. | Independently verify flag counters, warmup boundaries, packet provenance and label extraction; do not trust a scheduled attack interval as observed evidence. |
| [LITNET-2020 authors' paper](https://epubl.ktu.edu/object/elaba:61188126/61188126.pdf) | Annotated real-world network flow collection. | Simulation cannot be advertised as real captured traffic. External validation remains a separate gate. |
| [IoT-23, Stratosphere](https://www.stratosphereips.org/datasets-iot23) | Real benign device captures and malware captures with analysis-based labels. | Separate capture/scenario groups, document the actual label evidence, and avoid pretending all devices or malicious families generalize from one generated template. |
| [Cross-dataset generalization study](https://arxiv.org/abs/2402.10974) | Reports near-perfect within-dataset classification but poor transfer across datasets. | Independent seeds are necessary but not sufficient: report unseen environment, workload and attack-regime tests. |
| [RadioML, DeepSig](https://www.deepsig.ai/datasets/) | Historical synthetic RF examples including modulation/channel effects; authors warn of errata and recommend new independently generated or real data. | Use as a documented historical comparison, not an unquestioned quality target. Preserve its separate data license if downloaded. |
| [DeepMIMO](https://github.com/DeepMIMO/DeepMIMO) | Site-specific ray-tracing/channel data tooling. | A flat scalar channel model is not MIMO/OFDM channel-estimation evidence. Spatial/scenario separation and explicit H targets are required. |
| [OpenRAN Gym datasets](https://openrangym.com/datasets) | Separate Colosseum/O-RAN and radio datasets. | RF classifier scores, wired-IP detection, telemetry attacks and actual RAN control outcomes remain separate tracks and claims. |

These sources motivate design choices; they do not make an unmeasured local
parameter distribution empirically calibrated. This is a focused primary-source
review, not an exhaustive systematic review or reproduction of their numbers.

## Storage and execution

User-authorized storage root: `/mnt/onetb/ran-ai-lab`. Preserve historical data;
verify copies before removing original directory entries and keep compatibility
symlinks for frozen absolute paths. All new campaign, model, temporary bulk data,
SDK snapshots and exports belong under this root. Never keep a full uncompressed
package plus a redundant ZIP unless explicitly needed. Publish a manifest and
sharded lossless data as the normal representation. Packet/flow-monitor capture
is an opt-in small audit subset; record whether a run has raw-packet evidence.

Four independent workers on different physical cores are authorized. Start with
1/2/4-worker matched development pilots and measure elapsed time, peak aggregate
RSS and deterministic hashes. Keep BLAS/OpenMP at one thread. One controller,
immutable source/config snapshots, per-job output and process groups, an exclusive
lock, attempt ledgers, resource polling and graceful resume remain mandatory.
At least 50 GiB free storage and 3 GiB available RAM are reserved; stop launching
jobs on pressure. Do not kill unrelated processes. No arbitrary old wall deadline
is applied after the user's removal of the RAN time limit.

## Identity-free observation contracts

Raw IP/MAC, numeric or hashed addresses, source/destination port numbers,
scenario/run/seed IDs, exact simulation timestamps, actor/role flags, topology
settings, injected rates, attack schedules and model outputs are not model
features. Identifiers remain in separate audit/split tables. Renaming an IP is
not an augmentation that creates an independent test example. Addresses and
node assignments must vary independently of class; packets must be classified
by their generating activity rather than assuming every packet from a machine
is malicious. A device can produce authorized and malicious traffic.

Aggregate measured cardinalities and port entropy may be evaluated as an
explicit optional feature set, since they contain behavioral information; they
are not direct port numbers. Report a second feature set without such
cardinality/protocol shortcuts. A detector cannot access attack-only counters,
true H, clean counterparts, perturbation power or intervention labels.

## Full project tracks

1. **IP traffic:** legitimate ICMP, recurring short TCP sessions, variable UDP and
   TCP sessions, service discovery/fanout, flash crowds and benign congestion.
   Session durations, sizes, rates, destinations and starts vary independently
   of labels. Malicious regimes span low/intermittent/high load with benign-rate
   overlap. Shared nuisance parameters and backgrounds are paired across clean
   and attacked conditions. Packet provenance defines observed activity; impact
   is measured separately. No artificial label noise to force difficulty.
2. **RF sensing:** occupied/vacant and multiband occupancy, independently sampled
   noise uncertainty, signal/interferer/channel/hardware parameters, multiple
   occupancy/received-power regimes and coherent burst grouping. Energy detector
   and calibrated detection/FPR curves accompany learned models.
3. **AMC:** an explicit richer constellation set, pulse/channel/CFO/timing/IQ
   impairments, group-held-out transmitters/channel conditions and separately
   reported SNR ranges. Raw-IQ learners and moment baselines are distinct.
4. **Channel estimation:** known pilots, explicitly specified multipath/OFDM
   observations and frequency-resolved H labels, LS/interpolation and optional
   statistical channel baselines. MIMO/beamforming claims require corresponding
   array/channel and downstream implementations; do not rename scalar H.
5. **Adversarial/training integrity:** clean and zero-budget controls, equal-budget
   benign corruptions, gradient attacks and meaningful adaptive/transfer checks;
   fixed threat/knowledge/geometry. Preserve true task targets, attack intent,
   realized changes and conditional success denominators separately. Training
   poison is confined to training and evaluated on untouched clean/trigger probes.
6. **RAN telemetry/control:** explicit compatible scenario plus measured KPM/window
   and decision/action/confirmation/application contracts. A wired IP run or RF
   array cannot substitute for closed-loop acceptance. SDK/Docker access and
   actual scenario compatibility must be verified before this track runs.

## Development and confirmatory separation

Development pilots use their own scenarios/seeds and may be inspected to find
implementation shortcuts. Freeze simulator/extractor versions, parameters,
feature sets, splits and attack budgets before confirmatory generation. Test
seeds for a revised generator are fresh: the inspected prototype test is no
longer a blind holdout for redesign decisions.

Publish ID, unseen workload/network, unseen impairment/channel, and unseen
attack-regime/family tasks separately. Keep every source session, device/scenario
and all matched variants in one group. Split before windowing, overlapping
histories, balancing or preprocessing. Test retains declared natural prevalence.
External real-data validation requires matched feature/label definitions and
licenses; no arbitrary concatenation of datasets into one random split.

Baselines: majority/random prevalence, simple thresholds, shallow trees, Random
Forest and an appropriate raw temporal/IQ learner. Select features, models and
thresholds only on development/validation. Report macro/per-family F1, precision,
recall, AP, balanced accuracy, FPR, event-level detection delay, regression NMSE
and calibrated sensing curves as applicable. Use independent-seed/session
bootstrap uncertainty, not independent-window confidence intervals.

Acceptance checks cover observed benign protocol/fanout support, distribution
overlap, counterfactual class-neutral nuisance sampling, deduplication, feature
leakage, labels, source/target counts and hashes, and an error taxonomy. A high
score triggers diagnosis; passing/failing is based on evidence, not an arbitrary
score range. Prototype, scientifically validated synthetic, and externally
validated releases must remain distinguishable.
