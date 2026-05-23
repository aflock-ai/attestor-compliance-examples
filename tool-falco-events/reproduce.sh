#!/usr/bin/env bash
# Reproduce the validated cilock + Falco capture against a live K8s cluster.
#
# Prereqs:
#   - cilock built with the falco attestor: `rookery-builder --preset all`
#     (or the canonical binary once rookery#146 lands)
#   - kubeconfig pointed at a cluster you control
#   - helm installed
#   - ed25519 signing key at ./key.pem (generate: openssl genpkey -algorithm ed25519 -out key.pem)
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"
NAMESPACE="${NAMESPACE:-falco-cilock-validate}"
CLUSTER="${FALCO_CLUSTER_NAME:-$(kubectl config current-context)}"

[ -f key.pem ] || openssl genpkey -algorithm ed25519 -out key.pem

# 1. Install Falco with JSON output enabled
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update >/dev/null
kubectl create namespace "$NAMESPACE" 2>/dev/null || true
helm install falco falcosecurity/falco -n "$NAMESPACE" \
  --set tty=true \
  --set json_output=true \
  --set json_include_output_property=true \
  --set falco.json_output=true \
  --set falco.json_include_output_property=true \
  --set driver.kind=modern-bpf \
  --wait --timeout 5m

# 2. Trigger a deterministic Falco rule firing
kubectl run cilock-falco-trigger --rm -i --restart=Never \
  --image=alpine:3.20 -n "$NAMESPACE" \
  --command -- sh -c 'cat /etc/shadow > /dev/null'

sleep 3  # let Falco emit + flush

# 3. Capture events under cilock
FALCO_CLUSTER_NAME="$CLUSTER" $CILOCK run --step falco-capture \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations falco,environment,git \
  --enable-archivista=false \
  -- sh -c "kubectl logs daemonset/falco -n $NAMESPACE --tail=500 \
            | grep '\"rule\"' > falco-events.jsonl"

# 4. Validate
echo
echo "=== Predicate types ==="
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'

echo
echo "=== Falco predicate body ==="
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/falco/v0.1") | .attestation | {total:.summary.total_events, priorities:.summary.priorities, rules:.summary.rule_hits}'

# 5. Clean up cluster resources
helm uninstall falco -n "$NAMESPACE"
kubectl delete namespace "$NAMESPACE" --wait=false
