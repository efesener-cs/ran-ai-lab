# External scenario interface

This package accepts a caller-supplied, self-contained ns-3 C++ source file. It does not generate a topology, patch the supplied C++ text, or ship a default network scenario. The `.cc`, `.cpp`, or `.cxx` file is copied byte-for-byte and its SHA256 is recorded.

## Run a scenario on its own

With a compatible native ns-3 tree already built:

```bash
python3 lab.py run_scenario --scenario /path/to/student-scenario.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave --output results/student-run \
  -- --simTime=5 --RngSeed=41
```

Arguments after `--` belong to the supplied program and are forwarded unchanged. This path assumes no particular topology, telemetry, RIC connection, or AI control. It writes `scenario.cc`, `run_status.json`, and `raw/simulation.log` in a new result directory; other raw outputs belong to the scenario itself. It does not label a successful program exit as an AI or RIC experiment.

For compilation only:

```bash
python3 lab.py build_offline --scenario /path/to/student-scenario.cc \
  --ns3 /path/to/ns-o-ran-ns3-mmwave
```

The native builder uses C++17, `build/include`, and the built libraries under `build/lib`. The default dependency tree is the sibling `ns-o-ran-ns3-mmwave`. A custom source must match that tree's APIs. Library headers are available through those include directories; additional project-local headers are not copied automatically. Supply a self-contained source rather than relying on relative sibling files.

Builds are cached under `host-build/scenarios/` on the host, or under `RAN_AI_BUILD_ROOT` when set. Container tooling directs this to the mounted results directory. Cache identity includes source bytes, compiler path, dependency paths, and library size/mtime signatures. A binary hash guards cache reuse, and a lock serializes identical builds. These signatures are cache inputs, not a hermetic dependency-content guarantee. Build metadata lives next to the executable. The historical `host-build/ran-ai-offline` executable is never selected as a fallback.

## Opt into AI experiments

The AI launchers expect a telemetry/control protocol. A generic ns-3 example does not gain that protocol merely by compiling. The source author must implement it explicitly. Python does not insert missing measurements, application counters, or RRC calls.

`run_controlled`, `run_experiment`, and `run_adversarial_suite` pass:

- `liveRic`, `simTime`, `ueCount`, `warmup`, `RngSeed`, and `RngRun`.
- `applyAiControl=true` for active control.
- `attackPlan=PATH` for the scheduled UDP-load runner.

The live supervisor additionally passes `loadScale`, `minSpeed`, `maxSpeed`, `e2TermIp`, `indicationPeriodicity`, `enableTraces`, and `reducedPmValues`. It uses C++20 against the compatible live ns-3/FlexRIC tree. The source must initialize its E2 agents and, where needed, wait for the `ric.ready` file before proceeding with traffic/control. Configure the minimum expected E2 node count using `--e2-nodes N` (default five); the checker requires distinct node identities and xApp discovery, not just repeated setup messages.

### Measurement output

All paths below are relative to the simulation working directory (`raw/`). The required application CSV header is:

```csv
window_start_s,window_end_s,ue_imsi,traffic_profile,direction,rx_bytes,app_goodput_mbps,x_m,y_m,speed_mps,is_warmup
```

Emit one row per UE per closed 100 ms window and flush the complete batch. `rx_bytes` measures data received by the application in that window; goodput is `rx_bytes * 8 / window_seconds / 1e6`. Mark warmup rather than deleting it. UE identifiers must agree across application, radio, and control traces; current matched runners use UEs numbered 1 through `ueCount`.

The radio adapter expects:

| File | Contract |
|---|---|
| `MmWaveSinrTime.txt` | Whitespace-separated simulation time, UE IMSI, cell ID, SINR in dB. |
| `CellIdStats.txt` | Time, UE IMSI, recorded path cell ID, RNTI. |
| `RxPacketTrace.txt` | Compatible ns-3 PHY trace layout. The parsers use DL time at index 1, cell at 7, bytes at 10, MCS at 11, RV at 12, SINR at 13, corruption at 14, and TBLER at 15. |
| `DlPdcpStats.txt`, `DlRlcStats.txt` | Compatible bearer interval traces; present header-only files are valid when no records exist. |

Field positions above are zero-based. See [datasets/build_csv.py](../datasets/build_csv.py) and [ai/stream.py](../ai/stream.py) for the exact parsers. [Synthetic telemetry fixtures](../tests/fixtures/telemetry.py) exercise the data contract but are not a real network scenario.

### Active control

To support `--applyAiControl=true`, implement the CSV-to-RRC bridge in the supplied C++ source:

| File | CSV header |
|---|---|
| `control_state.csv` | `decision_time_s,ue_imsi,nr_cell_id,rrc_state,control_required` |
| `control_dispatch.csv` | `sim_time_s,request_id,ue_imsi,from_cell,target_cell,status` |
| `control_events.csv` | `sim_time_s,request_id,ue_imsi,event,from_cell,target_cell,observed_cell` |

The source publishes and flushes actual state at the decision boundary. For required windows it waits for `control/step-N.csv`, where `N=round(decision_time_s*10)`. Python publishes the file atomically with header `decision_time_s,ue_imsi,action,target_cell` and one decision per UE. Actions are `hold`, `observe`, or `recommend_handover`.

Validate decision time, UE identity, duplicates, and targets before applying a recommendation. Record submissions separately from later `confirmed_target_connected`, `timeout`, or `unconfirmed_at_end` outcomes. A callback invocation is not a confirmation. Match the control settings between clean and attacked runs; avoid a competing automatic handover policy for the same UE. See [checks/check_control.py](../checks/check_control.py) for accepted evidence and [docs/EVALUATION.md](../docs/EVALUATION.md) for timing and outcome rules.

Missing traces or invalid evidence cause the AI pipeline to fail. Keep using `run_scenario` when the supplied program only supports standalone simulation.

## Matched suites and campaigns

A suite captures its selected source in `scenario.cc` and stores `scenario_sha256`. Every condition receives that snapshot; native conditions must also match the recorded executable hash. A campaign captures the source once and verifies the snapshot before each job and on resume. Editing the original file does not change an existing plan. Editing the captured file is rejected even with `--allow-code-change`.

Legacy campaigns without an external scenario snapshot cannot be resumed through the new runner. Existing measurements remain available for analysis; start a new campaign with an explicit source for new collection. Historical results from the removed bundled scenario do not validate a newly supplied one.
