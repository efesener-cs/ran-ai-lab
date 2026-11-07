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
| Evasion: white/black box, targeted/untargeted, iterative/optimization/UAP | Victim input, clean counterpart, model/knowledge/budget and conditional outcomes | FGSM/PGD plus five-seed transfer, train-only universal (per-frame clipped), sparse8, shift-EOT and known flat attacker-channel reference now run. CSV/model outcome checks pass. No score-query evasion, arbitrary-channel/OTA or full system-level claim. |
| Data poisoning: label/feature/clean-label/availability | Training subset/condition and resulting model | Label flip/random corruption/static backdoor plus 120 new single-level clean-label targeted-input, availability-loss and dynamic-trigger retraining conditions run and verify. No bilevel optimized poison claim. |
| Backdoor: static/dynamic triggers, SleeperNets/TrojDRL | Training condition, triggered/clean probes and victim policy/model | Static IQ plus random-position/phase IQ backdoor runs. DRL backdoors and named-paper reproductions remain missing. |
| Model poisoning: parameter/federated/policy | Participant/model update or policy intervention | Synthetic 10-client/20-round FedAvg and coordinate-median sign-flip/model-replacement references run; 60 saved models verified. Not operational O-RAN FL or policy poisoning. |
| Model extraction | Budgeted query transcript and surrogate fidelity | Label-query extraction at128/512/2048 budgets, separate RF surrogate, held-out fidelity; known input training pool access is explicit. 30 extraction conditions replay/refit-verified. |
| Model inversion | Reconstruction/attribute inference and explicit privacy target | Output-conditioned seven-moment feature reconstruction runs against class-mean baseline. This is a partial attribute/feature inversion reference; white-box class-prototype inversion also runs (800prototypes,25class conditions); no approximate private-record recoveries at normalized MSE<1e-3. This does not establish arbitrary private waveform recovery. |
| Membership inference | Member/nonmember records, model outputs and privacy attack | Known-member/known-nonmember and true-label loss attack, class-matched balanced calibration/evaluation; disjoint frame roles. Ten held-out evaluations average AUC about0.499 (near chance). |
| Adversarial RL: state/policy/action, GNN+DRL, slicing | Episode, policy decisions, rewards/resources and network outcomes | Current compatible closed-loop scenario gate remains open; no new accepted DRL/GNN/slicing attack collection. |
| Cross-layer/cross-domain | Linked interventions and measured propagation across tracks | Not implemented as a new cross-domain causal benchmark. Separate datasets cannot be relabeled as this evidence. |

The report also mentions supply-chain, transfer-learning, model skewing and
output-integrity threats in its O-RAN security discussion. Keep these in the
inventory; they require explicit implementation and evidence rather than an
invented per-packet label. Static RF jamming, digital receiver perturbation,
KPM manipulation and classical wired traffic are distinct interventions.

## Correct target design

Current IP target uses six binary family heads: UDP flood, UDP DDoS, pulsed
UDP, port probing, TCP connection churn and ICMP flood. Normal is all heads zero;
mixtures retain multiple labels. A corrected development fit uses strictly disjoint
training/validation/test/OOD groups. Its held-out macro-F1 is 0.244 (OOD 0.081);
these exploratory figures do not establish final dataset quality. The earlier
binary model remains an auxiliary comparison. The offline production campaign
collects a larger preregistered matrix, then automatically fits categorical models.
RF attack-method classification is separate, per victim task, over none/FGSM/PGD
reference records and seven observed IQ moments; it is not evidence of all report
families or over-the-air robustness.

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

## Additional serving/transfer references

Local served-model artifact replacement, trusted-hash comparison and output-label
remapping now run (40 conditions), with clean/random-output controls. Twenty
transfer fine-tuning conditions use fresh stress-domain seeds1810001/1820001/
1830001 plus repetition offsets, paired clean/20%triggered training and clean
validation selection. Saved-model/request metrics are independently recomputed.
These are local integrity references, not a compromised software dependency or
real deployment intrusion. Source/evidence: deliverables/ran-ai-csv-review/
{extended-rf,query-privacy,extended-training,federated-poison,serving-transfer-v2}.
Actual code and output hashes accompany their experiment records. New victim-task
CSV export and old benchmark consolidation are separate data-processing stages.

## Extended method detector

All eight RF detector classes now have original train/validation/test views;
450,000 inventory rows and a30,000row one-version-per-frame80/20 training view
are independently checked. Validation/test retain full controlled condition
inventory; no deployment prevalence claim. True labels, success and budgets stay
excluded from features. Source-frame and victim-split caveats remain explicit.
