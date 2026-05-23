#!/usr/bin/env bash
# Capture a Linkerd service-mesh state snapshot under cilock.
#
# Produces a signed v0.3 attestation whose linkerd-check/v0.1 predicate
# carries both:
#   - `linkerd check -o json` results (control plane + extensions)
#   - `linkerd viz edges -o json` results (service graph + mTLS booleans)
#
# Prereqs:
#   - linkerd CLI on PATH + kubeconfig pointed at a cluster with Linkerd
#     installed (this example was validated against dropbox-clone-dev with
#     the emojivoto demo deployed in the `emojivoto` namespace).
#   - cilock built with the linkerd-check attestor: rookery PR up.
#     (Available today via rookery-builder --preset all.)
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"
CLUSTER="${LINKERD_CLUSTER_NAME:-$(kubectl config current-context)}"

[ -f key.pem ] || openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null

echo "[*] capturing linkerd state for cluster: $CLUSTER"
LINKERD_CLUSTER_NAME="$CLUSTER" $CILOCK run --step linkerd-mesh-check \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations linkerd-check,environment,git \
  --enable-archivista=false \
  -- sh -c 'linkerd check -o json > linkerd-check.json; linkerd viz edges deploy -A -o json > linkerd-edges.json'

echo
echo "=== Predicate types ==="
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'

echo
echo "=== Linkerd predicate summary ==="
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/linkerd-check/v0.1") | .attestation | {
      cluster_name,
      check: .check_summary | {pass, warn, error, overall_success, categories: (.categories|length)},
      edges: .edges_summary
    }'
