# Dependency provenance

External trees are not included in this repository. These are the locally
inspected revisions; a commit identifier does not capture local changes,
compiler flags, generated headers or prebuilt library contents.

| Component | Source | Inspected revision | Local use |
|---|---|---|---|
| ns-O-RAN ns-3 mmWave | https://github.com/wineslab/ns-o-ran-ns3-mmwave | `208e553148755161dc4466b30654d75c6e58832b` in local fork https://github.com/efesener-cs/ns-o-ran-ns3-mmwave | Native ns-3.38 build, scenario-zero source |
| mmwave-LENA-oran | https://github.com/MinaYonan123/mmwave-LENA-oran | `3b4c4f10d46129ba2e8ca382374459ba27051fdb` | Container ns-3.42, KPM v3 integration |
| FlexRIC | https://gitlab.eurecom.fr/mosaic5g/flexric.git | `46af1074d3580eed515fb84a88099c099e15b6e4` | Near-RT RIC and monitoring xApp |

The native builder expects a built sibling `ns-o-ran-ns3-mmwave` tree.
The live runner discovers compatible trees in an existing container and accepts
explicit `--flexric` / `--ns3` paths. A stock Ubuntu image alone is insufficient.
Matching E2AP v1 and KPM v3 plus locally installed e2sim headers/libraries are
required. Follow each upstream build's own dependency and license instructions;
this project does not install or vendor those dependencies automatically.

The live runner selects an available matching GCC/G++ pair and excludes GCC 11
for this FlexRIC tree. It builds FlexRIC in run-local directories and relinks
against existing ns-3 libraries; it does not rebuild the full radio stack.
Native and live backends use different ns-3 versions and must not be compared
as interchangeable performance environments.

Scenario changes: mixed traffic, per-UE application counters, seeded schedules,
windowed trace export, control-state observations and a file-to-RRC bridge.
KPM overrides: measurement matrix shape, owned names/IMSI and safe decoding.
The KPM-only SQLite wrapper omits unused NR RRC payload logging and fails
explicitly if that payload is requested. E2 RC actuation is not implemented.

NumPy is used for local model fitting/tests; matplotlib produces analysis
plots. Container inference uses Python's standard library. Trained weights,
measurements, execution reports, generated SQL imports and dependency binaries
are local artifacts excluded from publication. `tests/fixtures/model.json`
is synthetic test input, not a trained-model artifact.
