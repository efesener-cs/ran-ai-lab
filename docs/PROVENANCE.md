# Dependency provenance

External trees are not included in this repository. These are the locally
inspected revisions; a commit identifier does not capture local changes,
compiler flags, generated headers or prebuilt library contents.

The new [container workflow](CONTAINERS.md) builds dependencies from pinned
commits in `Dockerfile`, including native e2sim
`951b3e9e99b47260f1525d2a95fa4b2f8065530e` and live e2sim-kpmv3
`732d64703bb7f4ba585c434a133cf4cf23972298`. Live ns-3 submodules are checked out
at the parent commit's recorded revisions. It does not incorporate local
changes from the previously prepared host/container trees. Build and simulation
acceptance of these images remains pending an isolated integration run.

| Component | Source | Inspected revision | Local use |
|---|---|---|---|
| ns-O-RAN ns-3 mmWave | https://github.com/wineslab/ns-o-ran-ns3-mmwave | `208e553148755161dc4466b30654d75c6e58832b` in local fork https://github.com/efesener-cs/ns-o-ran-ns3-mmwave | Native ns-3.38 dependency build |
| mmwave-LENA-oran | https://github.com/MinaYonan123/mmwave-LENA-oran | `3b4c4f10d46129ba2e8ca382374459ba27051fdb` | Container ns-3.42, KPM v3 integration |
| FlexRIC | https://gitlab.eurecom.fr/mosaic5g/flexric.git | `46af1074d3580eed515fb84a88099c099e15b6e4` | Near-RT RIC and monitoring xApp |

The native builder expects a built sibling `ns-o-ran-ns3-mmwave` tree.
The live runner discovers compatible trees in an existing container and accepts
explicit `--flexric` / `--ns3` paths. A stock Ubuntu image alone is insufficient.
Matching E2AP v1 and KPM v3 plus locally installed e2sim headers/libraries are
required. Follow each upstream build's own dependency and license instructions;
the legacy entry points do not install or vendor those dependencies automatically.
The Dockerfile provides the separate automatic installation path.

The live runner selects an available matching GCC/G++ pair and excludes GCC 11
for this FlexRIC tree. It builds FlexRIC in run-local directories and relinks
against existing ns-3 libraries; it does not rebuild the full radio stack.
Native and live backends use different ns-3 versions and must not be compared
as interchangeable performance environments.

The earlier bundled scenario and its Python generation/extension scripts have been removed. New runs require an explicitly supplied self-contained C++ source; its bytes are copied unchanged and hashed. Topology, traffic, application counters, trace output, and any RRC bridge are now the source author's responsibility. Historical results still refer to the earlier scenario. The native cache tracks source bytes, compiler/dependency paths and library size/mtime signatures; binary hashes are recorded separately. These cache signatures do not constitute a hermetic dependency snapshot.
KPM overrides: measurement matrix shape, owned names/IMSI and safe decoding.
The KPM-only SQLite wrapper omits unused NR RRC payload logging and fails
explicitly if that payload is requested. E2 RC actuation is not implemented.

NumPy is used for local model fitting/tests; matplotlib produces analysis
plots. Container inference uses Python's standard library. Trained weights,
measurements, execution reports, generated SQL imports and dependency binaries
are local artifacts excluded from publication. `tests/fixtures/model.json`
is synthetic test input, not a trained-model artifact.
