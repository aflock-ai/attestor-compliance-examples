#!/bin/bash
# Reproduce the AWS KMS-signed envelope captured in this directory.
# Requires: cilock-all (built with --with .../signers/kms/aws), AWS credentials with
# kms:Sign on the key, and the alias set up via setup.sh.
set -euo pipefail
AWS_REGION=us-east-1 cilock run \
  --platform-url "" \
  --step kms-demo \
  --signer-kms-ref awskms:///alias/cilock-validation-signer \
  --outfile attestation.json \
  --workingdir . \
  --attestations environment,git \
  -- bash -c "echo 'AWS KMS signed payload' > kms-output.txt"
