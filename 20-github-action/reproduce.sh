#!/bin/bash
# Reproduce the github-action attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
# Same workflow as #19, --attestations includes both github and github-action
cilock run --step github-actions-validation \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run"
