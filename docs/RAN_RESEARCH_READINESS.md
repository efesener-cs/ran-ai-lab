# RAN track readiness and implementation gate

The project has separate IP, RF and RAN tracks; one cannot substitute for another.
The current IP/RF development campaigns are valid within their stated synthetic
scope, not evidence that a new RAN closed-loop dataset has been collected.

## Observed dependencies and candidate source

Read-only host/container inspection found:

- Native SDK: `/home/tarnished/Projects/ns-o-ran-ns3-mmwave` (ns-3.38).
- Live candidate SDK: `/home/tarnished/Projects/ns-O-RAN-flexric/mmwave-LENA-oran`
  (ns-3.42, mmWave/LTE and O-RAN libraries).
- FlexRIC KPM v3 plugin under `flexric-duranta/build/src/sm/kpm_sm/kpm_sm_v03.00/`.
- E2Sim under `ns-O-RAN-flexric/e2sim-kpmv3/e2sim/build/`.
- `scenario-zero-with_parallel_loging.cc` in the live SDK's scratch directory
  enables E2/KPM, but includes a project-relative custom header and does not
  establish the current self-contained source/application/radio/control contract.

Library presence is not ABI compatibility or an accepted scenario. The legacy
campaign lacks the required scenario snapshot and reported a missing E2 KPM input
adapter. Its historical outcomes must not be relabeled as a current-track run.
Current `run_scenario` success is expressly not RIC/AI acceptance.

## Required next implementation

Supply and snapshot an explicit self-contained RAN scenario satisfying
`scenario/README.md` and the current application/radio/CSV-to-RRC trace contract.
Use class-independent traffic/mobility/channel/context streams and held-out
scenario/UE-mobility groups. Include legitimate demand changes, mobility effects,
radio variation and missing/delayed telemetry controls before model-input attacks.
Measure raw windows, model recommendations, executable commands, dispatch,
confirmation and subsequent application outcomes separately. Establish clean
native acceptance before live RIC and attack/control comparisons. Model inputs
exclude UE/device/address IDs, scenario IDs, schedules and intervention-only data.

A seeded topology that merely starts an E2 client is insufficient. Host-native
private SDK use must preserve original dependencies; do not silently generate,
patch or fall back to an unreviewed bundled network scenario.

## Container/storage compatibility

`results` and `exports` now point to `/mnt/onetb/ran-ai-lab`. Host-native execution
uses these paths successfully. The existing `ran-lab` container binds Projects
under `/work` but does not bind `/mnt/onetb`; therefore `/work/ran-ai-lab/results`
is currently a broken container-side symlink. Container execution requires an
explicit additional data-volume bind and environment-compatible SDK paths.
No container was recreated/restarted, and no shared SDK was rebuilt during this
inspection. Do not treat a host-built SDK as portable across different glibc/ABI
versions without validation. Until that gate passes, the new development work
runs on the host, not in the old container.
