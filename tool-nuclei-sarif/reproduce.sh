#!/usr/bin/env bash
# Reproduce the Nuclei + sarif attestor flow end-to-end against Google's
# Public Firing Range (a deliberately-vulnerable XSS/header testbed).
#
# Prerequisites:
#   - cilock built with the `sarif` attestor (in presets/all). Verify with:
#       cilock attestors list | grep sarif
#   - nuclei installed:
#       brew install nuclei      # macOS
#       # or: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   - openssl
#   - jq (for the inline verification step)
#   - This directory should be (or be inside) a git repo so the `git`
#     attestor can record HEAD. `git init` here works if you're running
#     standalone.
#
# Usage:
#   ./reproduce.sh
set -euo pipefail

# Polite-citizen guardrail: do NOT scan a site you don't own. The Public
# Firing Range and testphp.vulnweb.com are deliberately-vulnerable targets
# published for scanner validation. Override TARGET only if you control
# the destination.
TARGET="${TARGET:-https://public-firing-range.appspot.com/}"

# First-run template bootstrap (cached after the first call).
nuclei -update-templates >/dev/null 2>&1 || true

# Fresh ed25519 key for signing this run.
openssl genpkey -algorithm ed25519 -out key.pem

# Make sure we're in a git repo so the `git` attestor has HEAD to record.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git init -q
  git -c user.email=ci@example.com -c user.name=ci commit --allow-empty -q -m init
fi

# Run nuclei under cilock — DIRECT invocation, no bash/cp wrapper.
# Template subset and rate limits keep the scan deterministic + polite.
cilock run --step nuclei-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- nuclei \
       -u "${TARGET}" \
       -t http/exposures/ -t http/technologies/ -t http/misconfiguration/ \
       -sarif-export nuclei.sarif \
       -rl 20 -c 25 -no-color -stats -timeout 8 -retries 1

# Inline verification: all 6 predicate types must be present.
echo
echo "Predicate types:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'

echo
echo "command-run argv (must be literal nuclei, no bash/cp):"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

echo
echo "sarif summary (parsed by the sarif attestor):"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {tool:         .report.runs[0].tool.driver.name,
           findings:     ([.report.runs[].results[]] | length),
           reportFile:   .reportFileName}'
