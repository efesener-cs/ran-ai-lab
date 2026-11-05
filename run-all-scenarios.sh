#!/usr/bin/env bash
# One entry point; all orchestration lives in simulation/, not in shell strings.
set -euo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 "$project/lab.py" run_all_scenarios "$@"
