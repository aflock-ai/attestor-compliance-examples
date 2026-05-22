#!/bin/bash
# Multi-step verify recipe for the prowler example.
#
# What this proves:
# 1. The attestation envelope was signed by the trusted key (publickeys map).
# 2. The envelope contains ALL the attestation types the policy requires
#    (environment + material + command-run + product + prowler).
# 3. The two regopolicies pass:
#    - git-from-known-repo: ANY git-context check (decoded in
#      decoded-rego-git-from-known-repo.txt).
#    - prowler-findings-gate: totalChecks > 0 AND critical fail <= 2
#      (decoded in decoded-rego-prowler-gate.txt).
# 4. The artifact subject digest (passed via --subjects) is a subject
#    in the envelope — this is the back-ref that links the verify
#    decision to the artifact the scan was about.
#
# Exit code 0 → policy satisfied → deploy/release would be allowed.
# Exit code != 0 → policy denied → deploy gate would block.

set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VALIDATION_DIR="$EXAMPLE_DIR/../_validation"
WORK="$VALIDATION_DIR/work"
KEY_PEM="$VALIDATION_DIR/key.pem"
KEY_PUB="$VALIDATION_DIR/key.pub"

# Step A: SIGN the human-readable policy with the test private key.
# In production the policy is signed by a release authority offline; here
# we use the same ephemeral key we used to sign attestations, for
# reproducibility.
cilock sign \
  -k "$KEY_PEM" \
  -f "$EXAMPLE_DIR/policy/policy.json" \
  -o "$EXAMPLE_DIR/policy/policy-signed.json"

# Step B: VERIFY the prowler envelope against the signed policy.
# --subjects is the artifact subject digest the policy is evaluating; cilock
# walks the attestation graph from this digest backward, finding every
# collection whose subject set contains this digest, then runs the policy
# against those collections.
#
# The digest below is the tree:products SHA from the captured envelope
# (the prowler-out.json product). Recompute it for your own envelope with:
#   jq -r '.payload | @base64d | fromjson |
#     .subject[] | select(.name | endswith("tree:products")) |
#     "sha256:" + .digest.sha256' < attestation.json
TREE_SUBJECT_SHA="sha256:3fab27637caf6c60197f7b0590b64aa0cf4ff806d41ed66d450f2305b886536f"

cilock verify \
  -p "$EXAMPLE_DIR/policy/policy-signed.json" \
  -k "$KEY_PUB" \
  -a "$WORK/prowler-real.json" \
  -s "$TREE_SUBJECT_SHA"
