#!/bin/bash
# Template verify-recipe.sh — copy into <NN>-<attestor>/policy/ and fill in
# the TODO markers per attestor.
#
# What this script does:
# 1. SIGN the human-readable policy.json with a test private key, producing
#    policy-signed.json. (In production: replace this step with the release
#    authority's offline signing flow.)
# 2. VERIFY the captured attestation envelope against the signed policy.
#    Exit code 0 = policy satisfied. Non-zero = denied (deploy gate would
#    block a real release).
#
# The full validation step (signing + verifying) is required for every
# example — running cilock + getting an envelope without proving the
# envelope satisfies a policy is half the story.

set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VALIDATION_DIR="$EXAMPLE_DIR/../_validation"
WORK="$VALIDATION_DIR/work"
KEY_PEM="$VALIDATION_DIR/key.pem"
KEY_PUB="$VALIDATION_DIR/key.pub"

# TODO: replace with the attestation envelope produced by your cilock run.
ENVELOPE="$WORK/TODO-fill-in-envelope.json"

# TODO: replace with the subject digest the policy is gating over.
# Easiest source: tree:products digest from the product attestor's
# subjects. Extract with:
#   jq -r '.payload | @base64d | fromjson |
#     .subject[] | select(.name | endswith("tree:products")) |
#     "sha256:" + .digest.sha256' < "$ENVELOPE"
TREE_SUBJECT_SHA="sha256:TODO-fill-in"

# Step A: sign the policy.
cilock sign \
  -k "$KEY_PEM" \
  -f "$EXAMPLE_DIR/policy/policy.json" \
  -o "$EXAMPLE_DIR/policy/policy-signed.json"

# Step B: verify.
cilock verify \
  -p "$EXAMPLE_DIR/policy/policy-signed.json" \
  -k "$KEY_PUB" \
  -a "$ENVELOPE" \
  -s "$TREE_SUBJECT_SHA"
