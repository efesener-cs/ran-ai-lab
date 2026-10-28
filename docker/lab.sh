#!/usr/bin/env bash
# Run Python tools in a dependency image; an external scenario can be mounted read-only.
set -euo pipefail
if [ "$#" -lt 2 ]; then
    echo 'Usage: bash docker/lab.sh native|live OUTPUT_DIRECTORY [python arguments...]' >&2
    exit 2
fi
backend=$1
case "$backend" in native|live) ;; *) echo 'Expected native or live' >&2; exit 2 ;; esac
storage=$2
shift 2
mkdir -p "$storage"
storage=$(cd "$storage" && pwd -P)
project=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
case "$storage" in /|"$project"|"$project/results")
    echo 'Choose a dedicated output subdirectory.' >&2; exit 2 ;;
esac
scenario_mount=()
if [ -n "${RAN_AI_SCENARIO:-}" ]; then
    if [ ! -f "$RAN_AI_SCENARIO" ]; then
        echo 'RAN_AI_SCENARIO must point to an existing C++ file.' >&2; exit 2
    fi
    scenario_source=$(realpath -- "$RAN_AI_SCENARIO")
    scenario_mount=(--mount "type=bind,src=$scenario_source,dst=/opt/ran-ai-input/scenario.cc,readonly")
fi
mkdir -p "$storage/results" "$storage/models" "$storage/exports"
image=${RAN_AI_IMAGE:-ran-ai-lab:$backend}
image_id=$(docker image inspect --format '{{.Id}}' "$image")
docker run --rm --init \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp --env "RAN_AI_IMAGE_ID=$image_id" \
    --mount "type=bind,src=$storage/results,dst=/opt/ran-ai-lab/results" \
    --mount "type=bind,src=$storage/models,dst=/opt/ran-ai-lab/ai/artifacts" \
    --mount "type=bind,src=$storage/exports,dst=/opt/ran-ai-lab/exports" \
    "${scenario_mount[@]}" \
    "$image_id" "$@"
