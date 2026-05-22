#!/bin/bash
# Reproduce the prowler attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
AWS_PROFILE=testifysec-demo prowler aws --services iam -M json -o output -F prowler-iam-real
cp output/prowler-iam-real.json prowler.json
cilock run --step prowler-real \
  --signer-file-key-path key.pem --outfile prowler-real.json --workingdir . \
  --attestations prowler,environment \
  -- bash -c "cp prowler.json prowler-out.json"
