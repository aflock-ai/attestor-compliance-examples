#!/bin/bash
# Reproduce the aws attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
cilock run --step ec2-identity \
  --signer-file-key-path key.pem --outfile aws-iid.json --workingdir . \
  --attestations aws \
  --attestor-aws-region-cert /opt/cilock/aws-us-east-1.pem \
  -- echo "captured EC2 instance identity"
