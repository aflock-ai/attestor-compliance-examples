#!/usr/bin/env bash
# Reproduce the kube-bench attestor against a real EKS cluster.
# See README.md for the full scenario and why this requires a live cluster.
#
# Requires:
#   - AWS credentials for the testifysec-demo profile (or substitute your own)
#   - kubectl, jq, openssl, cilock on PATH
set -euo pipefail

NAMESPACE="${NAMESPACE:-kube-bench-cilock-demo}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# 1. Cluster access (skip if already configured)
if ! kubectl get nodes >/dev/null 2>&1; then
  aws sso login --profile testifysec-demo
  aws eks update-kubeconfig --name dropbox-clone-dev --region us-east-1 --profile testifysec-demo
fi
kubectl get nodes

# 2. Provision kube-bench Job in an isolated namespace
kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"
kubectl apply -f "${HERE}/job-eks.yaml"

# 3. Generate an ed25519 signing key if one doesn't already exist
mkdir -p "${HERE}/_validation"
[ -f "${HERE}/_validation/key.pem" ] || openssl genpkey -algorithm ed25519 -out "${HERE}/_validation/key.pem"

# 4. Run cilock — waits for the Job, captures kube-bench JSON report, signs everything
cd "${HERE}"
cilock run --step kube-bench-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile kube-bench-attestation.json \
  --attestations environment,git \
  --enable-archivista=false \
  -- sh -c "kubectl wait --for=condition=complete job/kube-bench -n ${NAMESPACE} --timeout=300s \
            && kubectl logs -n ${NAMESPACE} job/kube-bench --tail=-1 > kube-bench-report.json \
            && echo PASS_TOTAL=\$(jq .Totals.total_pass kube-bench-report.json) \
                    FAIL_TOTAL=\$(jq .Totals.total_fail kube-bench-report.json) \
                    WARN_TOTAL=\$(jq .Totals.total_warn kube-bench-report.json) \
                    INFO_TOTAL=\$(jq .Totals.total_info kube-bench-report.json)"

# 5. Surface the predicate types and totals for quick eyeballing
echo "--- predicate types ---"
jq -r '.payload' kube-bench-attestation.json | base64 -d \
  | jq -r '.predicate.attestations[].type'
echo "--- kube-bench totals ---"
jq '.Totals' kube-bench-report.json

# 6. Cleanup — do not leave the Job lingering
kubectl delete -f "${HERE}/job-eks.yaml"
kubectl delete namespace "${NAMESPACE}"
