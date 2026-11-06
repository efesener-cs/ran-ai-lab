# Offline collection and categorical models

This is a preregistered synthetic research collection candidate, not a claim of
external validation or completion of every adversarial-RAN literature family.
The complete requested taxonomy and honest gaps remain in ATTACK_COVERAGE.md.

## Frozen matrix

76 independent IP scenario groups:24 train,12 validation,24 ID test and16
held-out network groups. Each group has one clean control plus seven traffic
conditions in low/overlap/high regimes (22 cases). All variants remain in the
same role. Fresh role seed ranges are disjoint from development pilots.

| Track | Jobs | Evidence |
|---|---:|---|
| IP transport families | 1672 | 1800 closed100ms windows/run,3,009,600 total candidate windows, activity/flow provenance |
| New sensing/6-class AMC/OFDM channel data | 228 | 2000 frames/job, separate observational/label/audit arrays, changed OOD priors |
| RF reference victim attacks | 10 | Known moment-MLP victims,FGSM/PGD/zero/random controls, explicit budgets, independent checks |
| Training-integrity references | 5 | Label flip,random feature-corruption control,static IQ trigger,actual retraining and probe checks |

Total1915 independent jobs; these counts are not independent statistical
replicates. RF references use the documented older three-class AMC/scalar-channel
victims and do not silently replace the new six-class/OFDM task models. They are
not OTA attacks, DRL backdoors, federated poisoning or full RAN control studies.
Two matched IP cases retain first-core PCAP plus an independent parser audit;
raw packet evidence is an audit subset, not a claim of PCAP for every run.

Post-collection, a Random Forest family detector uses only the explicit measured
IP features. Six family targets preserve overlapping attacks; normal is no
active family. Categorical single-family and full multilabel/mixture metrics are
reported separately. Raw IP/MAC/direct port numbers, IDs, schedules, injected
settings and attack-only counters remain excluded. Validation alone selects
family thresholds; test/OOD do not tune anything. A bounded training-only view
may cap training rows, with all raw rows retained and counts/policy recorded.

A separate task-specific RF detector predicts `none/fgsm/pgd` from seven observed
IQ moments in verified reference exports. It never uses true task labels,
perturbation power, success flags or seed/frame IDs as inputs. Known victim/method
recognition does not establish unseen-model or unknown-attack generalization.

## Persistent execution

The user-manager transient service invokes `systemd-inhibit` and an offline
supervisor. Collection and both categorical model stages need no Internet.
They require an awake powered computer and local data/SDK/model dependencies.
CPU affinity uses four distinct physical cores; all numerical libraries use one
thread per worker. Model fitting uses at most two parallel CPU jobs.

The unit has a4CPU quota,6GiB MemoryMax and128TasksMax. The controller reserves
3GiB available RAM and50GiB free storage, with a6GiB monitored aggregate worker
RSS ceiling and100GiB output-growth ceiling. Bounds are not a dataset license
or quality guarantee. On resource pressure it preserves attempts and waits;
on genuine execution/verification failure it stops and records the error.
No unbounded retry loop for deterministic failed jobs is configured.

Runtime, scenarios, protocols, binary and SDK hashes are frozen. One exclusive
controller lock prevents duplicate launches. Completed receipts are rechecked;
failed/interrupted attempts remain. Live stdout logs are excluded from new
receipt manifests. Historical development receipts accept only their explicitly
documented empty-log-to-exact-CHECKED-line transition; data hashes remain strict.

The normal `systemctl` client may fail under this tool's PID namespace. The
scoped `simulation.user_service` helper uses the same authorized user-manager
D-Bus API through gdbus and reports ActiveState/SubState/MainPID/Result.
It does not grant root access or upload anything. Existing containers are not
recreated; the current data volume is host-native and not bound into ran-lab.

Progress is in campaign.json,offline-status.json,controller.log and per-attempt
logs/receipts. Final models live under models/ with versioned attempts and metrics.
No full duplicate package/ZIP is automatically produced. Publication and licensing
remain separate user decisions; missing DRL/GNN/FL/privacy/extraction and current
closed-loop RAN source gates are not faked by adding empty categorical labels.
