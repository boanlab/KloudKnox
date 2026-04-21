#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

set -euo pipefail

TAG="${TAG:-v0.1.0}"
IMAGE="boanlab/e2e-workloads"

cd "$(dirname "$0")"

# remove old images for this repo
docker images "${IMAGE}" --format '{{.ID}}' | xargs -r -I {} docker rmi -f {} 2>/dev/null || true

# build
docker build --tag "${IMAGE}:${TAG}" --tag "${IMAGE}:latest" .

# push (skip by setting NO_PUSH=1)
if [[ "${NO_PUSH:-0}" != "1" ]]; then
    docker push "${IMAGE}:${TAG}"
    docker push "${IMAGE}:latest"
fi
