# Activity-provenance IP research workload

This new scenario is independent of the preserved prototype. The design and
primary-source rationale are in DATASET_RESEARCH_PROTOCOL.md. It generates
synthetic wired transport/session traffic, not real application payloads, host
exploits, cellular radio, or RIC behavior. HTTP/TLS semantics are not modeled.

Explicit source: `examples/scenarios/ip-workload-research.cc`. Example development
execution (all bulk data and build cache stay on the authorized data volume):

```bash
python3 lab.py run_research_campaign \
  --scenario examples/scenarios/ip-workload-research.cc \
  --ns3 /path/to/prebuilt/ns3-sdk --workers 4
python3 lab.py run_research_campaign --resume /mnt/onetb/ran-ai-lab/results/research-campaigns/development-ID
```

The current command collects **development only**: six matched IP workloads at
concurrency1/2/4 and two small independent developments of each RF task. It
checks actual simulator-output hashes across concurrency levels and preserves
failures. It does not create a confirmatory test set, fit a detector, upload data,
or establish the final dataset's scientific quality. A controller lock, frozen
runtime/source/binary/SDK hashes and per-attempt receipts protect resume. There
is no resettable wall deadline. Polling reserves3GiB available RAM and50GiB free
storage, with6GiB aggregate worker-tree RSS ceiling; CPU affinity uses distinct
physical cores and library threads=1. These are monitored bounds, not cgroups.

## What changed in the generator

Normal devices emit ICMP diagnostics, authorized UDP inventory, recurring TCP
and UDP sessions with finite payload budgets, and independently scheduled flash
crowds. Normal offered load can congest queues. Legitimate session opening
continues after warmup. Traffic intensity, payload, duration, timing, destination,
service catalog and route/link properties vary across scenario seeds.

The same sender can emit both normal and malicious activities. The source does
not label a node/IP as inherently malicious. A registered activity maps a socket
five-tuple (or ICMP identifier) to provenance; reverse packets and quoted ICMP
unreachables resolve the same activity. Direct IP/MAC/port/seed/time/actor IDs
never enter the model feature contract. Addresses are private synthetic addresses
with per-scenario prefix/assignment variation, not actual Internet captures.
Within a scenario a device address stays consistent. Per-activity local socket
IDs are allocated before execution so attacks do not shift later benign tuple
assignments in a matched pair.

Shared background and context RNGs are independent of the selected attack mode;
attack-specific streams are separate. Clean/attacked runs therefore share their
planned normal activity definitions and node configuration. Actual packet timing,
TCP behavior and received traffic can diverge because of intervention effects.
The paired checker compares plans/context, not equality of those outcomes.

Six transport families are represented: UDP flood/distributed flood/pulsed load,
port probing, bounded full TCP connection churn, and ICMP load. `low`, `overlap`
and `high` offered-rate regimes deliberately overlap normal behavior. TCP churn
is not half-open SYN exhaustion; inventory and port probes are transport-level
activity. Malicious labels express unauthorized scheduled activity provenance,
not a guarantee that such intent can always be identified from an aggregate
window. Indistinguishable observations are a detection-limit issue, not a reason
to corrupt labels or inject noise. Network defaults are declared synthetic
priors, not fitted empirical traffic distributions.

## Labels and measurements

`attack_applied` means at least one known attack-origin TX/RX/core-drop in the
closed window. `attack_scheduled` is audit only. Pending handshakes, retransmits
and queued data can continue after a planned activity ends, so schedule and
observed labels need not agree. TCP applications do not abort pending handshakes
on a short application timer; late connections are closed without sending.
Unknown provenance is separately counted and must be examined rather than
silently interpreted as verified benign traffic.

`ip_rx_packets/ip_rx_ip_bytes` are delivered packets across all instrumented
endpoints, including replies and TCP control traffic. One-way IP delays use the
local outbound timestamp; they are not application request latency. Core queue
and device drops are aggregated over all instrumented core segments/directions,
not one uniquely identified bottleneck. `unique_flows` counts directional
observable protocol five-tuples, with zero transport ports for ICMP; it is not
the activity count. Application payload bytes are counted at receiving sinks;
benign-only application audit uses peer/local socket provenance because TCP
reassembly does not preserve packet tags. IP bytes include headers.

The raw CSV contains an explicit primary observed-feature list returned by
`checks.check_ip_research`. A richer optional view adds aggregate endpoint/port
cardinality, port entropy and directional flow counts. These behavioral summaries
are not direct addresses or port numbers. Report both views; audit labels,
attack-only counters, injected rates and clean counterparts remain forbidden.

## Evidence and development gates

- `ip_windows.csv`: measured closed windows and separate audit/target columns.
- `activities.csv`: planned session intent/configuration, never detector input.
- `flow_provenance.csv`: activity-to-socket mapping, including family masks.
- `nodes.csv`: private address/node context for audit only.
- `ip_metadata.json`: realized nuisance context, scope and counts.

`python3 -m checks.check_ip_research RESULT --paired MATCHED_CLEAN_RESULT` checks
closed-window identities, finite numeric data, label/counter consistency, activity
and tuple ownership, sender/target context, and paired background definitions.
Structural success is not statistical representativeness. Raw-PCAP and external
flow-extractor validation, unseen workloads/network priors, longer sessions,
independent group uncertainty and real-data comparisons remain necessary gates.

The first20s development pair fixed concrete TCP lifecycle and application-byte
provenance defects. It had zero unknown provenance,375 matched normal activities,
normal ICMP150/150 windows, normal SYN106/150, normal port-cardinality maximum47
and normal core qdisc drops81/150. These are tiny development diagnostics, not
final detection scores or independent performance claims.
