# Related work and research scope

These sources were identified in the project's research notes. They provide context and possible comparisons; listing a repository does not mean its checkpoints have been loaded or its experiments reproduced here. This is a focused reading list, not a systematic literature review.

## Directly related systems

| Work | Focus | Relationship to this project |
|---|---|---|
| [AdvO-RAN](https://github.com/Restuccia-Group/AdvO-RAN), [MobiHoc 2025 paper](https://doi.org/10.1145/3704413.3764425) | Adversarial and robust deep reinforcement learning for O-RAN control; policy snapshots, observation perturbations, and training workflows. | A candidate baseline in its own observation/action environment. Its policy is not interchangeable with the local Ridge forecaster and cell-selection policy. |
| [MalO-RAN: How to Poison an xApp](https://github.com/wineslab/mal-o-ran) | Training-time backdoors in DRL xApps, evaluated using Colosseum. | A separate threat model requiring access to training data or training. Inference-time telemetry bias does not reproduce poisoning. |
| [Chiejina et al., System-level Analysis of Adversarial Attacks and Defenses on Intelligence in O-RAN based Cellular Networks, WiSec 2024](https://arxiv.org/abs/2402.06846) | Attacks on spectrogram/KPM inputs to interference-classification xApps, with an over-the-air LTE/5G testbed and network-level evaluation. | Motivates measuring downstream network effects as well as model accuracy. This repository uses simulation and a different decision task. |
| [ns-o-ran-gym](https://github.com/wineslab/ns-o-ran-gym) | Gymnasium environments for traffic steering and energy saving, with KPM storage and file-based actions. | Environment infrastructure rather than evidence of an effective pretrained policy in every scenario. File-based actions are not E2 RC actuation. |
| [NetsLab RRC Signalling Storm Dataset](https://netslab.ucd-cs.ie/rrc-signalling-storm-dataset/) | Physical OAI testbed measurements for UE reboot and DU restart handover storms. | Useful context for a different control-plane threat. Ideal RRC simulation does not reproduce real O-CU/O-DU resource load or NAS behavior. |

Pretrained policies require matching feature order, normalization, time windows, encoders, and action meanings. A PRB/slicing policy cannot be attached to the current cell-selection scenario merely because both use O-RAN terminology.

## Attack foundations

- [Goodfellow et al., Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572): gradient-sign perturbations. This project adapts the objective to a target cell's forecast margin rather than classification loss.
- [Madry et al., Towards Deep Learning Models Resistant to Adversarial Attacks](https://arxiv.org/abs/1706.06083): bounded adversarial optimization. A particular PGD configuration is not a guarantee of finding every model's worst case.
- [Athalye et al., Obfuscated Gradients Give a False Sense of Security](https://arxiv.org/abs/1802.00420): failed attacks alone do not establish robustness; defenses need appropriate adaptive evaluation.

## Keep experiment types distinct

The implemented evasion experiment changes accessible SINR inputs within an explicit dB budget. Model ranking, policy output, applied controls, and application traffic are separate outcomes. Clean runs, equal-budget random perturbations, simple bias, gradient attacks, and the single-window exact reference provide different comparisons.

Other possible studies need their own assumptions and implementation:

- Legitimate heavy traffic is a control for load effects, not automatically an attack.
- Scheduled UDP load changes traffic inside ns-3; it is not telemetry evasion.
- Replay/stale, missing, or delayed telemetry requires explicit timing and fallback evaluation. Communication failures and deliberate attacks need distinct labels.
- Poisoning/backdoors need a training pipeline, trigger, and target behavior.
- Signalling storms require a suitable control-plane model or testbed.
- RF jamming requires a radio interference model or physical testbed; editing a SINR field does not change RF propagation.

## Why host traffic tools do not automatically enter ns-3

Simulated UE IP addresses are not automatically attached to the Linux/container network. E2 connectivity is not a user-plane bridge. Sending traffic to the RIC host tests host load rather than simulated UE traffic.

Injecting real packets requires explicit emulation plumbing, routing, and synchronization, such as [TapBridge](https://www.nsnam.org/docs/models/html/tap.html) or [FdNetDevice](https://www.nsnam.org/docs/release/3.44/models/html/emulation-overview.html). The local load experiments instead generate bounded packets inside ns-3 with simulator-time schedules. They do not model Linux SYN backlogs or web-server resource consumption.

## Questions this lab can investigate

How do limited cell access, bounded bias, temporal history, and decision thresholds change the relationship between forecast manipulation and application traffic? Compare against persistence, use separate training/validation/test seeds, preserve matched controls and failed attempts, and report uncertainty at the independent-seed level.

The current engineering contribution is an auditable simulation-to-decision-to-outcome pipeline. Using FGSM/PGD on RAN telemetry is established prior work; algorithmic novelty or field generalization requires additional evidence.
