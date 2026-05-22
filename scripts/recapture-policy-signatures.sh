#!/usr/bin/env bash
# Recapture every example's policy-signed.json by re-running `cilock sign`
# against the (already-bumped-to-v0.3) policy.json.
#
# Run this after merging the v0.3-cutover PR(s). The committed
# policy-signed.json snapshots were deleted in that PR because they no
# longer matched the unsigned source. This script regenerates them.
#
# Prerequisites:
#   - cilock binary on PATH (v0.3+, i.e. built from rookery main after #136)
#   - $REPO_ROOT/_validation/key.pem exists (the maintainer's signing key)
#
# Behaviour:
#   - For every directory matching the patterns below that has a policy.json,
#     run `cilock sign -k <key> -f <policy.json> -o <policy-signed.json>`.
#   - Skip examples whose policy.json is absent (some examples are docs-only).
#   - Fail loud on any sign error so a missing/broken cilock binary surfaces
#     immediately rather than producing a partial recapture.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VAL_DIR="$REPO_ROOT/_validation"
KEY_PEM="$VAL_DIR/key.pem"

if ! command -v cilock >/dev/null 2>&1; then
  echo "error: cilock not found on PATH" >&2
  echo "       build it from rookery main (post #136) and put it on PATH:" >&2
  echo "         go build -o /usr/local/bin/cilock ./cilock/cmd/cilock" >&2
  exit 2
fi

if [ ! -f "$KEY_PEM" ]; then
  echo "error: signing key not found at $KEY_PEM" >&2
  echo "       this is a maintainer-side regeneration script; the key is" >&2
  echo "       intentionally gitignored. Place your key.pem there to proceed." >&2
  exit 2
fi

# Sanity-check cilock version: must support v0.3 product/material.
# We check by asking cilock to list attestors and grepping for the v0.3
# predicate URIs the bumped policies reference.
# Capture into a variable so the pipefail-vs-SIGPIPE interaction with
# `grep -q` doesn't false-positive on a successful match.
ATTESTORS_OUT="$(cilock attestors list 2>&1)"
if ! grep -qF "attestations/product/v0.3" <<<"$ATTESTORS_OUT"; then
  echo "error: cilock binary does not appear to support product/v0.3" >&2
  echo "       run 'cilock attestors list' and confirm product is registered at v0.3." >&2
  echo "       you likely have an older binary; build from rookery main." >&2
  exit 2
fi

cd "$REPO_ROOT"

# All directories that historically had a policy-signed.json. We rediscover
# by globbing for policy.json under known locations.
declare -a POLICY_DIRS=(
  "28-prowler/policy"
  "43-trivy-attack-detection"
  "signer-examples/aws-kms"
  "tool-checkov-sarif/policy"
  "tool-gosec-sarif/policy"
  "tool-govulncheck-sarif/policy"
  "tool-grype-sarif/policy"
  "tool-hadolint-sarif/policy"
  "tool-kubescape-sarif/policy"
  "tool-osv-scanner-sarif/policy"
  "tool-semgrep-sarif/policy"
  "tool-syft-sbom/policy"
  "multi-step-attestationsFrom/policy"
)

signed=0
skipped=0
errored=0
for d in "${POLICY_DIRS[@]}"; do
  policy="$REPO_ROOT/$d/policy.json"
  signed_out="$REPO_ROOT/$d/policy-signed.json"
  if [ ! -f "$policy" ]; then
    echo "skip:   $d (no policy.json)"
    skipped=$((skipped+1))
    continue
  fi
  if cilock sign -k "$KEY_PEM" -f "$policy" -o "$signed_out" >/dev/null 2>&1; then
    echo "signed: $d/policy-signed.json"
    signed=$((signed+1))
  else
    echo "error:  $d (cilock sign failed)" >&2
    errored=$((errored+1))
  fi
done

echo
echo "summary: $signed signed, $skipped skipped, $errored errored"
[ "$errored" -eq 0 ]
