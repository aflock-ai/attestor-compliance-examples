#!/bin/bash
# Reproduce the docker attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
docker buildx build --metadata-file metadata.json --load -t cilock-validation:latest .
cilock run --step docker-build \
  --signer-file-key-path key.pem --outfile docker.json --workingdir . \
  --attestations docker \
  -- bash -c "docker buildx build --metadata-file metadata.json --load -t cilock-validation:latest . && cat metadata.json"
