# Synthetic test input

`model.json` contains hand-written parameters for deterministic unit tests.
It was not trained on network measurements and is not an experimental result
or a model intended for simulation evaluation. Production/pilot models must
be trained locally and remain under the ignored `ai/artifacts/` directory.

`telemetry.py` generates small deterministic raw traces and runs the maintained
exporter to test streaming/CSV parity, future-data isolation, and incremental
shadow execution. It needs no saved campaign or live simulator.

`kpm_sender_layout.cc` is a hand-authored source-shape fixture for the KPM sender
patch. The mapping test compiles the patched merge fragment against minimal
structs to check scalar ordering and missing compound values without an external
ns-3 source checkout. It does not establish compatibility with every upstream revision.

`external_scenario.cc` prints received arguments, and `native_library.cc` provides
a minimal shared library for compiler tests. These are small standalone test
programs, not network topologies, AI-ready ns-3 scenarios, or experiment evidence.
