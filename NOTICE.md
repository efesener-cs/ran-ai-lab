# Source attribution and license scope

Earlier revisions contained a C++ scenario derived from
`ns-o-ran-ns3-mmwave/scratch/scenario-zero.cc`, with the original GPL version 2
header and author attributions (Andrea Lacava and Michele Polese). That bundled
scenario and its generation scripts have been removed. New scenarios are supplied
by the caller and retain their own source attribution and license. The upstream
GPL text remains in `LICENSES/GPL-2.0.txt` for dependency/historical attribution.

FlexRIC is a separate external dependency. The inspected source tree's main
license is Collaborative Standards Software License v1.0, reproduced for
reference in `LICENSES/CSSL-1.0.txt`. Its own NOTICE identifies file-specific
MIT and CC-BY exceptions. This repository does not vendor FlexRIC, its plugins,
SQLite sources or compiled libraries. `labcore/portable_build.py` and `labcore/kpm_fixes.py`
create build wrappers/overrides from locally supplied sources at runtime;
this does not change the licenses of those source/generated components.

Dependency versions and source locations are listed in
`docs/PROVENANCE.md`. No repository-wide license has been assigned to newly
authored Python, SQL or documentation files. The texts included here describe
upstream components; they do not relicense the whole repository. A repository-
wide license requires the rights holder's explicit choice before a licensed
release is advertised. No MIT/Apache license is implied by GitHub publication.
