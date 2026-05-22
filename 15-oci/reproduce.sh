#!/bin/bash
# Reproduce the oci attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
docker pull alpine:3.20 && docker save alpine:3.20 -o alpine-3.20.tar
cilock run --step oci-save \
  --signer-file-key-path key.pem --outfile oci.json --workingdir . \
  --attestations oci \
  -- bash -c "docker save alpine:3.20 -o alpine-3.20.tar"
