#!/usr/bin/env bash
# Reproduce the validated CodeQL + cilock capture.
#
# Prereqs:
#   - cilock v0.3 on PATH (or set CILOCK env var)
#   - codeql CLI on PATH (https://github.com/github/codeql-cli-binaries/releases)
#   - ed25519 signing key at ./key.pem (generate with: openssl genpkey -algorithm ed25519 -out key.pem)
#   - python-queries pack downloaded: codeql pack download codeql/python-queries
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"

[ -f key.pem ] || openssl genpkey -algorithm ed25519 -out key.pem

# Step 1: build CodeQL database (one-shot, ~5s for the tiny fixture)
codeql database create codeql-db \
  --language=python \
  --source-root=src \
  --overwrite

# Step 2: cilock-wrapped analyze — captures the SARIF as a v0.3 product
$CILOCK run --step codeql-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- codeql database analyze codeql-db \
       --format=sarif-latest \
       --output=codeql.sarif \
       codeql/python-queries:codeql-suites/python-security-and-quality.qls

# Validate
echo
echo "Predicate types in envelope:"
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'

echo
echo "command-run argv:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'

echo
echo "SARIF finding count: $(jq '.runs[0].results | length' codeql.sarif)"
