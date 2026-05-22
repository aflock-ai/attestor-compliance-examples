#!/bin/bash
# Reproduce the system-packages attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
cilock run --step host-packages \
  --signer-file-key-path key.pem --outfile system-packages.json --workingdir . \
  --attestations system-packages \
  -- echo "captured host packages"
