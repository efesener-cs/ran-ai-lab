#!/usr/bin/env bash
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
run_dir="$lab_dir/results/offline-$(date +%Y%m%d-%H%M%S)"
duration="${1:-3}"
mkdir -p "$run_dir/raw"
cd "$run_dir/raw"
"$lab_dir/ran-ai-offline" --liveRic=false --simTime="$duration" --ueCount=12 \
  --warmup=1 --RngSeed=7 --RngRun=1 > simulation.log 2>&1
python3 "$lab_dir/export_dataset.py" "$run_dir" --duration "$duration"
