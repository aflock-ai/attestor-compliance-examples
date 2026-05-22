#!/bin/bash
# Reproduce the k8smanifest attestor against real Kubernetes manifests.
# See README.md for the full scenario.
#
# Two flows:
#   1. Static manifest capture (no cluster required) — always runs.
#   2. Live cluster capture (requires kubeconfig)    — runs when KUBECONFIG
#      is set and the named deployment exists.
#
# Invoke from this directory with the signer key materialized at
#   ../_validation/key.pem
# (openssl genpkey -algorithm ed25519 -out ../_validation/key.pem)

set -euo pipefail

KEY="${KEY:-../_validation/key.pem}"

###############################################################################
# Flow 1 — Static manifest capture
###############################################################################
cilock run --step k8smanifest-static \
  --signer-file-key-path "$KEY" \
  --outfile attestation-static.json \
  --attestations k8smanifest,environment,git \
  --enable-archivista=false \
  -- sh -c 'cat deployment.source.yaml > deployment.yaml'

echo "static attestor set:"
jq -r '.payload' attestation-static.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'

###############################################################################
# Flow 2 — Live cluster capture
###############################################################################
# Override DEPLOYMENT and NAMESPACE to retarget. Defaults match the
# validated run on dropbox-clone-dev EKS.
DEPLOYMENT="${DEPLOYMENT:-dropbox-clone-api}"
NAMESPACE="${NAMESPACE:-dropbox-clone}"

if kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1; then
  cilock run --step k8smanifest-live \
    --signer-file-key-path "$KEY" \
    --outfile attestation-live.json \
    --attestations k8smanifest,environment,git \
    --enable-archivista=false \
    -- sh -c "kubectl get deployment $DEPLOYMENT -n $NAMESPACE -o yaml > deployment-live.yaml"

  echo "live attestor set:"
  jq -r '.payload' attestation-live.json | base64 -d \
    | jq '.predicate.attestations | map(.type)'
else
  echo "skipping live flow: deployment $NAMESPACE/$DEPLOYMENT not reachable" >&2
fi
