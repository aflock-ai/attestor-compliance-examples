# 13 — `k8smanifest` (build)

**Status:** validated  
**Real-data source:** local (static) + EKS cluster `dropbox-clone-dev` (live)

Real Kubernetes Deployment YAML captured + subjected on
`apiVersion+kind+name+namespace`. Two flows are demonstrated:

1. **Static manifest capture** — a Deployment YAML committed to the repo (or
   rendered by `kustomize build` / `helm template`) is materialized as a
   cilock product. Useful in CI environments with no cluster access.
2. **Live cluster capture** — `kubectl get deployment ... -o yaml` is wrapped
   by cilock so the running cluster's authoritative manifest is attested.
   `command-run` records the kubectl argv, `product` captures the written
   manifest as a Merkle leaf, and `k8smanifest` parses + subjects it.

Both produce a v0.3 DSSE envelope whose `k8smanifest/v0.2` attestation
includes the parsed object and a subject of the form
`k8smanifest:<file>:<kind>:<name>` keyed on the SHA-256 of the recorded
document.

## Static manifest capture

Source `deployment.source.yaml` is checked in (or generated upstream).
cilock runs a command that writes `deployment.yaml` as a product; the
k8smanifest attestor parses the product.

```bash
cilock run --step k8smanifest-static \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation-static.json \
  --attestations k8smanifest,environment,git \
  --enable-archivista=false \
  -- sh -c 'cat deployment.source.yaml > deployment.yaml'
```

The `sh -c` is the same justification as `govulncheck` / pip-install:
the producing command is a single shell pipeline whose stdout has to
land in a file the product attestor can hash. cilock still records the
full argv in command-run.

Validate locally:

```bash
jq -r '.payload' attestation-static.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'
```

Expected:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/k8smanifest/v0.2"
]
```

## Live cluster capture (requires kubeconfig)

`kubectl get deployment` streams the cluster's authoritative manifest to
stdout. cilock wraps the kubectl invocation so the resulting
`deployment-live.yaml` becomes a product and the k8smanifest attestor
parses it.

Prerequisites: a valid `KUBECONFIG` and a Deployment to target. The
validated run used the existing `dropbox-clone-api` Deployment in
namespace `dropbox-clone` on the `dropbox-clone-dev` EKS cluster:

```bash
aws eks update-kubeconfig --name dropbox-clone-dev --region us-east-1 \
  --profile testifysec-demo
kubectl get deployments --all-namespaces   # pick a target
```

Run cilock around `kubectl get`:

```bash
cilock run --step k8smanifest-live \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation-live.json \
  --attestations k8smanifest,environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl get deployment dropbox-clone-api -n dropbox-clone -o yaml > deployment-live.yaml'
```

Validate locally:

```bash
jq -r '.payload' attestation-live.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'
```

Expected (identical attestor set to the static flow):

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/k8smanifest/v0.2"
]
```

The k8smanifest predicate also captures cluster identity for live runs:

```bash
jq -r '.payload' attestation-live.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/k8smanifest/v0.2")
        | .attestation.clusterinfo'
```

```json
{
  "server": "https://<eks-endpoint>.gr7.us-east-1.eks.amazonaws.com",
  "nodes": null
}
```

And the recorded document carries kind/name/namespace plus the full
spec, hashed into the subject:

```bash
jq -r '.payload' attestation-live.json | base64 -d \
  | jq '.subject[] | select(.name | startswith("https://aflock.ai/attestations/k8smanifest"))'
```

## Choosing a target Deployment

The validated example targeted `dropbox-clone/dropbox-clone-api`, a
pre-existing workload — nothing was created or destroyed. If your
cluster has no Deployments, create a throwaway one and clean up
afterwards:

```bash
kubectl create namespace cilock-demo
kubectl create deployment cilock-demo-nginx --image=nginx:1.27 -n cilock-demo
# ...run the live cilock invocation against cilock-demo/cilock-demo-nginx...
kubectl delete deployment cilock-demo-nginx -n cilock-demo
kubectl delete namespace cilock-demo
```

## Reproduce

See [`reproduce.sh`](./reproduce.sh) for the exact validated invocations
(both static and live flows).
