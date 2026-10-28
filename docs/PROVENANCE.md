# Dependency provenance

External trees are not included in this repository. These are the locally
inspected revisions; a commit identifier does not capture local changes,
compiler flags, generated headers or prebuilt library contents.

The main branch expects dependencies built on the host. Optional image/launcher
recipes are preserved on `feat/docker-support`; they are not installed or invoked
by main. The revisions below describe previously inspected source trees, not
proof that every new scenario builds or runs against them.

| Component | Source | Inspected revision | Local use |
|---|---|---|---|
| ns-O-RAN ns-3 mmWave | https://github.com/wineslab/ns-o-ran-ns3-mmwave | `208e553148755161dc4466b30654d75c6e58832b` in local fork https://github.com/efesener-cs/ns-o-ran-ns3-mmwave | Native ns-3.38 dependency build |
| mmwave-LENA-oran | https://github.com/MinaYonan123/mmwave-LENA-oran | `3b4c4f10d46129ba2e8ca382374459ba27051fdb` | Live ns-3.42, KPM v3 integration |
| FlexRIC | https://gitlab.eurecom.fr/mosaic5g/flexric.git | `46af1074d3580eed515fb84a88099c099e15b6e4` | Near-RT RIC and monitoring xApp |

The native builder expects a built sibling `ns-o-ran-ns3-mmwave` tree.
The live runner discovers compatible trees on the host and accepts
explicit `--flexric` / `--ns3` paths. The required SDKs and built libraries must already be installed.
Matching E2AP v1 and KPM v3 plus locally installed e2sim headers/libraries are
required. Follow each upstream build's own dependency and license instructions;
the legacy entry points do not install or vendor those dependencies automatically.
Docker installation recipes, if needed, belong to the optional feature branch.

The live runner selects an available matching GCC/G++ pair and excludes GCC 11
for this FlexRIC tree. It builds FlexRIC in run-local directories and relinks
against existing ns-3 libraries; it does not rebuild the full radio stack.
Native and live backends use different ns-3 versions and must not be compared
as interchangeable performance environments.

The earlier bundled scenario and its Python generation/extension scripts have been removed. New runs require an explicitly supplied self-contained C++ source; its bytes are copied unchanged and hashed. Topology, traffic, application counters, trace output, and any RRC bridge are now the source author's responsibility. Historical results still refer to the earlier scenario. The native cache tracks source bytes, compiler/dependency paths and library size/mtime signatures; binary hashes are recorded separately. These cache signatures do not constitute a hermetic dependency snapshot.
KPM overrides: measurement matrix shape, owned names/IMSI and safe decoding.
The KPM-only SQLite wrapper omits unused NR RRC payload logging and fails
explicitly if that payload is requested. E2 RC actuation is not implemented.

NumPy is used for local model fitting/tests. Runtime inference uses Python's standard library. Main exports CSV and has no matplotlib/EDA or PostgreSQL layer. Trained weights,
measurements, execution reports, dependency binaries
are local artifacts excluded from publication. `tests/fixtures/model.json`
is synthetic test input, not a trained-model artifact.
