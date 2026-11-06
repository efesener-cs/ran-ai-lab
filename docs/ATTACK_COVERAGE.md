# Attack coverage and prediction targets

Source inventory: user's `RAN_AI_Adversarial_Saldirilar_Raporu.docx`, located in
Projects/tubitak. Sections5–9 define the taxonomy,15 the experimental framework,
and16 the priority reading list. Its literature claims are leads for primary
source verification, not proof of local reproduction. The previous IP binary
Random Forest was an auxiliary transport-traffic baseline, not coverage of the
report's complete adversarial-RAN project.

## Coverage ledger

| Report family | Required experimental unit | Actual current status |
|---|---|---|
| Evasion: white/black box, targeted/untargeted, iterative/optimization/UAP | Victim input, clean counterpart, model/knowledge/budget and conditional outcomes | Prototype receiver-IQ FGSM/PGD exists. New RF observations/checkers exist. Black-box, UAP, sparse/shift-invariant, channel-aware transmitter and full system-level studies are not all implemented. |
| Data poisoning: label/feature/clean-label/availability | Training subset/condition and resulting model | Prototype label flip, unoptimized random feature-corruption control and actual retraining exist. Clean-label/optimized availability poisoning not yet implemented. |
| Backdoor: static/dynamic triggers, SleeperNets/TrojDRL | Training condition, triggered/clean probes and victim policy/model | Local static IQ-trigger prototype exists. Dynamic DRL backdoors and named paper reproductions are not implemented. |
| Model poisoning: parameter/federated/policy | Participant/model update or policy intervention | Not implemented in the new collection. |
| Model extraction | Budgeted query transcript and surrogate fidelity | Not implemented. |
| Model inversion | Reconstruction/attribute inference and explicit privacy target | Not implemented. |
| Membership inference | Member/nonmember records, model outputs and privacy attack | Not implemented. |
| Adversarial RL: state/policy/action, GNN+DRL, slicing | Episode, policy decisions, rewards/resources and network outcomes | Current compatible closed-loop scenario gate remains open; no new accepted DRL/GNN/slicing attack collection. |
| Cross-layer/cross-domain | Linked interventions and measured propagation across tracks | Not implemented as a new cross-domain causal benchmark. Separate datasets cannot be relabeled as this evidence. |

The report also mentions supply-chain, transfer-learning, model skewing and
output-integrity threats in its O-RAN security discussion. Keep these in the
inventory; they require explicit implementation and evidence rather than an
invented per-packet label. Static RF jamming, digital receiver perturbation,
KPM manipulation and classical wired traffic are distinct interventions.

## Correct target design

Current implemented IP model target: **observed malicious activity0/1**. Attack
families already exist as audit truth but have not yet been used as the model's
categorical/multilabel target. This must not be described as a completed attack
identification model.

Next IP target: six binary family heads for UDP flood, UDP DDoS, pulsed UDP,
port probing, TCP connection churn and ICMP flood. Normal is all heads zero.
Multiple active families retain multiple labels. Report a normal+six-family
categorical score on single-family cases and a full multilabel score including
mixtures, with exact excluded/retained counts. Preserve binary detection as a
secondary comparison; do not conceal mixtures under one arbitrary family.

Across the whole project, keep domain, attack stage/family/method, victim task,
knowledge, objective and impact as separate axes. Evasion, adversarial RL and
cross-domain impact can overlap; they are not universally mutually exclusive
classes. Spectrum occupancy and modulation class are victim-task targets, not
attack-family labels. Poisoned training targets differ from true labels, and a
poisoned model's clean test input is not automatically a poisoned input.

Use domain-appropriate models and observation units: packet/flow/window for IP,
RF burst for receiver observations, training condition/model/update for integrity
attacks, query transcript for privacy/extraction, episode/action for control.
A classifier trained on a mixture of these incompatible representations could
learn the domain rather than the attack. No claim that FGSM versus PGD is always
identifiable from one received signal is made; unknown/indeterminate mechanisms
must remain possible.

Report macro/per-family F1, AP, balanced accuracy, false alarms, confusion matrices
and multilabel Hamming/exact-match metrics as appropriate, plus unknown-family
and unseen-context evaluations. Raw IP/MAC/direct ports, IDs, schedules,
injected budgets, true H and attack-only counters remain excluded from X.

Priority literature named by the report includes Habler2025, Lacava/MalO-RAN2025,
Chiejina2024, Balakrishnan2024, Aizikovich/Rogue Cell2025, Adesina2023, Kim2020,
Hoang2024 and Altintas2026. Verify each original paper/repository and map its
victim, threat model, observations, intervention, data and metric before claiming
reproduction. This ledger is an implementation roadmap, not a completion claim.
