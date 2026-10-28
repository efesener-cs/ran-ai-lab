#!/usr/bin/env bash
# Host dependency: Docker only. All Python, training and simulation run inside.
set -euo pipefail
if [ "$#" -lt 2 ]; then
    echo 'Usage: bash docker/lab.sh native|live OUTPUT_DIRECTORY [python arguments...]' >&2
    exit 2
fi
backend=$1
case "$backend" in native|live) ;; *) echo 'Expected native or live' >&2; exit 2 ;; esac
storage=$2
shift 2
case "$storage" in
    *campaign-20261025-231925-201987*)
        echo 'Choose a separate directory for new container outputs.' >&2; exit 2 ;;
esac
mkdir -p "$storage"
storage=$(cd "$storage" && pwd -P)
project=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# Never accidentally attach the protected experiment or its parent results tree.
case "$storage" in
    *campaign-20261025-231925-201987*|/|"$project"|"$project/results")
        echo 'Choose a separate directory for new container outputs.' >&2; exit 2 ;;
esac
mkdir -p "$storage/results" "$storage/models" "$storage/exports"
image=${RAN_AI_IMAGE:-ran-ai-lab:$backend}
image_id=$(docker image inspect --format '{{.Id}}' "$image")
docker run --rm --init \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp --env "RAN_AI_IMAGE_ID=$image_id" \
    --mount "type=bind,src=$storage/results,dst=/opt/ran-ai-lab/results" \
    --mount "type=bind,src=$storage/models,dst=/opt/ran-ai-lab/ai/artifacts" \
    --mount "type=bind,src=$storage/exports,dst=/opt/ran-ai-lab/exports" \
    "$image_id" "$@"
