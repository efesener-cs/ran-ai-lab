# Non-RAN IP traffic scenarios

External self-contained source:
`/home/tarnished/Projects/ran-ai-lab/examples/scenarios/ip-network-attacks.cc`.
It uses ns-3 sockets only. No RAN/RIC, RF neural model or real host traffic is
involved. `run_scenario` preserves the exact source and builds only this `.cc`;
no SDK rebuild is required. C++17 and a compatible built ns-3.38+ are required.

## Topology and normal traffic

The rewritten v2 scenario defaults to 12 benign clients, 12 attacker nodes,
2 routers and 3 servers: 29 nodes. Clients/attackers connect through access links
to the first router, the core bottleneck joins the routers, and a server farm
connects to the second. Default rates are 100 Mbps access / 20 Mbps core, with
per-access propagation jitter around 1 ms and 5 ms core delay. Both core
directions have a bounded 200-packet FIFO queue disc and 5-packet device queue.
These rates, delays, counts and queue depth are configurable.

Benign traffic has four profiles: small periodic UDP, bursty UDP, bursty TCP and
long-lived bulk TCP. Offered rates, startup times and On/Off periods vary using
explicit seeded streams. Bulk TCP may saturate the link even in clean runs:
congestion/drops alone are not attack labels. TCP traffic here does not implement
HTTP, authentication, application request parsing or service-capacity limits.
`ip_traffic_profiles.csv` records each benign flow's configuration.

## Attacks and time plans

| `--attack` | Implemented behavior |
|---|---|
| `none` | Matched normal traffic, no attack sources |
| `udp_flood` | One UDP source at `attackMbps` |
| `udp_ddos` | Multiple UDP sources sharing aggregate `attackMbps` |
| `pulsed_udp` | UDP bursts using `pulseOn`/`pulseOff` |
| `udp_port_scan` | UDP probes across 1000 closed ports at `probePps` |
| `tcp_connection_churn` | Ordinary TCP connect/hold/close at `churnPps` |
| `icmp_flood` | Simulated ICMP echo requests, with normal echo replies |
| `mixed` | Separate intervals cycling through all six families |

`attackMbps` defaults to 60 Mbps; DDoS divides that same aggregate rate among
participants. TCP churn records connection attempts, successful handshakes,
failures and local-cap rejections. Pending sockets have timeouts, bounded hold
times and a 512-socket local cap; stopped applications cancel their timers.
Churn is not half-open SYN flooding or proof of victim resource exhaustion.

`episodes` (default 6) partitions the measured timeline into non-overlapping
segments with seeded randomized attack starts. Total scheduled windows are the
rounded `attackFraction` (default .2). Mixed requires >=12 attackers and >=6
nonempty intervals; attackers are dedicated to one family so delayed packets
can retain their true type. Adjacent/delayed families can overlap in observation;
`attack_type=mixed` and `attack_types` then retain the observed family set.

Changes to attack mode do not change the normal-traffic random streams. All
variants with the same `(RngSeed,RngRun)` share `group_id` and must remain in the
same train/validation/test split. Same-seed clean and attacked runs are matched
controls, not independent test sets. Multiple independent groups are required.

## Run on the host

```bash
python3 lab.py run_scenario \
  --scenario /home/tarnished/Projects/ran-ai-lab/examples/scenarios/ip-network-attacks.cc \
  --ns3 /home/tarnished/Projects/ns-o-ran-ns3-mmwave \
  --output results/ip-mixed-v2-41 \
  -- --attack=mixed --simTime=180 --warmup=5 --episodes=6 \
  --clients=24 --attackers=12 --servers=4 \
  --bottleneckMbps=30 --accessMbps=100 --attackMbps=90 \
  --attackFraction=0.2 --RngSeed=41 --RngRun=1
```

`--PrintHelp` lists all options. `simTime` is simulated time, not a wall-clock
sleep. Longer time alone does not establish realistic traffic or generalization.
Use fresh output paths. The source refuses to overwrite CSV/metadata/flow files
in an existing working directory. CSV/JSON outputs use temporary files and
atomic renames; metadata is published last. Default duration is 120 seconds,
window .1 seconds and warmup 2 seconds. All measured windows must be complete.
Optional `--pcap=true` records core-link packets; `--flowMonitor=false` disables
the supplementary flow table/XML when collection volume is large.

## Existing prepared container (host terminal)

After the earlier RF launcher has copied the current runtime to
`/tmp/ran-ai-rf-container-01`, these commands reuse its standalone runner:

```bash
docker cp /home/tarnished/Projects/ran-ai-lab/examples/scenarios/ip-network-attacks.cc \
  ran-lab:/tmp/ip-network-attacks.cc
docker exec ran-lab python3 /tmp/ran-ai-rf-container-01/lab.py run_scenario \
  --scenario /tmp/ip-network-attacks.cc --ns3 /work/ns-o-ran-ns3-mmwave \
  --output /tmp/ip-mixed-v2-01 \
  -- --attack=mixed --simTime=180 --warmup=5 --episodes=6 \
  --clients=24 --attackers=12 --servers=4 --attackFraction=0.2 \
  --RngSeed=41 --RngRun=1
docker cp ran-lab:/tmp/ip-mixed-v2-01 ./results/ip-mixed-v2-01
```

Use the actual container and prepared ns-3 paths. This is not the live E2 runner.
Docker was not operated during the rewrite; acceptance was on host ns-3.38.
Previously shared Windows users can pass the new `.cc` to `Run-Windows.ps1 -Mode
native` with these scenario flags. The shared archive/image/Windows volume was
not updated by editing the external source; share the new file explicitly.
The previously copied `results/ip-udp-01/run_status.json` records a compilation
failure, not a successful container simulation. Its saved error omits the actual
compiler/linker diagnostics, so the root cause is not established. The example
SDK path must refer to libraries/headers compatible with that container; a new
`.cc` does not repair an incompatible native SDK. Host acceptance does not
establish acceptance in that container.

## Output and label contract

- `ip_windows.csv`: closed post-warmup measurement windows. Existing v1 columns
  are preserved; v2 appends features and observed/scheduled family sets.
- `ip_attack_events.csv`: exact scheduled intervals and family, with group ID.
- `ip_traffic_profiles.csv`: benign traffic configuration, audit only.
- `ip_dataset.json`: configuration, feature whitelist, excluded metadata,
  connection counters and scheduled/observed ratios.
- `ip_flows.csv`, `ip-flow-monitor.xml`: optional TCP/UDP per-flow evidence including
  warmup; FlowMonitor does not classify ICMP, which remains visible in windows/PCAP. In-flight-at-end counts are separate from FlowMonitor loss reports.

`label=1` requires actual attack-origin IP transmission, server delivery, or a
core queue drop of a tagged attack packet. Labels come from known controlled
source roles; no inference of intent from congestion is used. `attack_tx_packets`,
`attack_rx_packets`, `attack_drop_packets`, benign breakdowns, family sets and
schedule are audit-only. An unsuccessful scan/flood/churn remains attack traffic.
No effect on service availability or classification is inferred just from label 1.

Features include IP TX/RX counts/bytes, UDP/TCP/ICMP counts, SYN/RST/FIN counts,
unique source/destination/port counts, port entropy, core drop events, aggregate
application payload bytes and IP delay mean/std/max with sample count.
Packet tags carry origin time through the simulated network without adding wire
bytes. Delay is origin IP transmission to server IP delivery; for retransmitted
packet copies a preserved tag can include retransmission wait. It is not a
request-response or end-to-end application latency measurement.

`server_rx_ip_bytes` includes IP/transport headers; `server_app_rx_bytes` is sink
payload only. Ground-truth `benign_rx_ip_bytes` and `benign_app_rx_bytes` are
excluded from features. Observed family sets can include queued traffic after
scheduled stop. A pulsed off period can contain no attack traffic. Scheduling
20% of time therefore cannot guarantee 20% positive rows; never relabel data to
force that count. For an 80/20 detector training mixture, split whole independent
groups first, then sample the training part. Report test prevalence and metrics.
Do not mix these IP feature rows with RF IQ rows under a shared feature schema.

HTTP floods, Slowloris, authentication brute force, DNS amplification, ARP/DNS
spoofing and application exploits are not implemented. They require explicit
protocol/victim behavior. Poisoning, backdoors, model extraction and membership
inference belong to a separate ML experiment, not these traffic sources.
