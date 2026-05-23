#!/usr/bin/env bash
# Reproduce the prowler attestor against real AWS infrastructure.
#
# Prerequisites:
#   - cilock built with the `prowler` attestor (built from presets/all or
#     by adding `_ "github.com/aflock-ai/rookery/plugins/attestors/prowler"`
#     to cilock/cmd/cilock/main.go and running `go build`)
#   - prowler installed (`brew install prowler` or `pipx install prowler`)
#   - AWS credentials in the environment (e.g. AWS_PROFILE set; for SSO
#     run `aws sso login --profile <profile>` first)
#   - openssl
#   - jq (for the inline verification step)
#
# Usage:
#   AWS_PROFILE=<profile> AWS_REGION=us-east-1 ./reproduce.sh
set -euo pipefail

: "${AWS_PROFILE:?AWS_PROFILE must be set (e.g. AWS_PROFILE=testifysec-demo)}"
: "${AWS_REGION:=us-east-1}"

# Confirm we can talk to STS before we burn time on a Prowler scan.
aws sts get-caller-identity >/dev/null

# Fresh ed25519 key for signing this run.
openssl genpkey -algorithm ed25519 -out key.pem

mkdir -p output

cilock run --step prowler-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations prowler,environment,git \
  --enable-archivista=false \
  -- prowler aws --services iam -M json -o output -F prowler-iam -z

# Inline verification: all 6 predicate types must be present.
echo "Predicate types:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'

echo "command-run argv:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("command-run/v0.1")) | .attestation.cmd'

echo "prowler summary:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("prowler/v0.1")) | .attestation.summary | {totalChecks, passCount, failCount, bySeverity}'
