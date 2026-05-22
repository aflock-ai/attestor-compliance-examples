#!/bin/bash
# Reproduce the github attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
# In .github/workflows/cilock-ci-attestors.yml on a runner with id-token: write
cilock run --step github-actions-validation \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run id $GITHUB_RUN_ID"
