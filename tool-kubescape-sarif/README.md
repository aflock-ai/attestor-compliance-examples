# `Kubescape` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Kubescape` ([kubescape](https://github.com/kubescape/kubescape), a
Kubernetes security scanner from ARMO) using rookery's `sarif` attestor.

## Validated invocation

```bash
cilock run --step kubescape-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- kubescape scan framework nsa --format sarif --output kubescape.sarif manifests/
```

`manifests/` contains a small sample Deployment + Service in this directory
that intentionally trips a handful of NSA-framework controls so the SARIF
output has real findings to attest over.

## Why this shape

`kubescape scan framework` writes SARIF directly when given
`--format sarif --output FILE` — no shell glue required.

That lets `cilock` invoke the tool **as its direct child process**:

- `command-run/v0.1` records the real `argv`
  (`["kubescape", "scan", "framework", "nsa", "--format", "sarif", "--output", "kubescape.sarif", "manifests/"]`),
  not `bash -c "cp ..."`.
- The `tracing` spy (when enabled) traces the actual `kubescape` syscalls.
- `product/v0.3` hashes the SARIF file kubescape itself produced — not a copy
  laundered through `cp`.
- `sarif/v0.1` parses that same file and surfaces findings for rego policy
  to gate on.

The old `bash -c "cp …"` pattern broke all four properties: the cmd argv was
`cp`, tracing saw `cp`, and the product was a freshly-stat'd duplicate
unrelated to the scan run.

## Validate it locally

```bash
# from the repo root
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

cd tool-kubescape-sarif

# Run cilock with kubescape as its direct child (no shell, no cp).
cilock run --step kubescape-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- kubescape scan framework nsa --format sarif --output kubescape.sarif manifests/

# Confirm all predicate types are present.
cat attestation.json | jq -r '.payload' | base64 -d \
  | jq '.predicate.attestations[].type'
# https://aflock.ai/attestations/environment/v0.1
# https://aflock.ai/attestations/git/v0.1
# https://aflock.ai/attestations/material/v0.3
# https://aflock.ai/attestations/command-run/v0.1
# https://aflock.ai/attestations/product/v0.3
# https://aflock.ai/attestations/sarif/v0.1

# Confirm command-run captured the real kubescape argv (not bash -c / cp).
cat attestation.json | jq -r '.payload' | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

# Count SARIF findings the rego gate would see.
cat attestation.json | jq -r '.payload' | base64 -d \
  | jq '[.predicate.attestations[]
         | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
         | .attestation.report.runs[0].results[]] | length'
```

Against the bundled `manifests/deployment.yaml` this produces **5 SARIF
findings** under the NSA framework (e.g. `C-0013` non-root containers,
`C-0016` allow privilege escalation, `C-0017` immutable container filesystem,
`C-0030` ingress/egress, `C-0055` linux hardening) — all reported without
`level=error`, so the bundled rego policy
(`policy/decoded-rego-sarif-findings-gate.txt`) passes.

## Cluster snapshot scan

The flow above scans local YAML files. If you want kubescape findings against
a **running cluster's actual workloads** — real `SecurityContext`,
`serviceAccountName`, RBAC bindings as they exist in the API server — and you
need **SARIF** out the other end, you need a snapshot-then-scan flow.

```bash
cilock run --step kubescape-cluster-snapshot-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl get all,networkpolicies,roles,rolebindings,serviceaccounts -A -o yaml > cluster-snapshot.yaml && kubescape scan framework nsa --format sarif --output kubescape-cluster.sarif cluster-snapshot.yaml'
```

This is **snapshot-of-cluster-state then scan**, not a true live-API-server
scan — read the next section for the upstream reason.

### Why this is a snapshot, not a true live scan

Upstream kubescape refuses to emit SARIF when scanning the live cluster
context. From `core/pkg/resultshandling/results.go` in the kubescape source,
`ContextCluster` is excluded from the SARIF-emitting contexts — SARIF is only
produced for **local files**. Run `kubescape scan framework nsa --format
sarif` against the live cluster and you get JSON (or an error), not SARIF.

This flow works around that:

1. `kubectl get …` dumps the real cluster state to `cluster-snapshot.yaml`.
   The dump captures live `SecurityContext`, `serviceAccountName`, RBAC,
   NetworkPolicies, etc. — the data is real-cluster, not synthetic.
2. kubescape then scans the YAML dump (local-file context) → SARIF.
3. The `command-run/v0.1` attestor records the **entire `sh -c` argv** —
   both the kubectl dump command and the kubescape invocation — so the
   provenance of the SARIF is auditable end-to-end.

If your downstream policy can consume **JSON** instead of SARIF, you can
drop the snapshot entirely and run `kubescape scan framework nsa --format
json` directly against the live cluster — kubescape supports that mode. The
snapshot exists purely because of the SARIF/context restriction upstream.

### Why `sh -c` here (and not direct exec)

Same justification as the `govulncheck` and `kube-bench` examples in this
repo: `kubectl get … -o yaml` streams to stdout, kubescape needs a **file**
as its input argument, and there is no single-binary form of "stream-and-
then-scan". The shell pipe (`>` + `&&`) is the integration glue.

`command-run/v0.1` records the literal argv `["sh", "-c", "kubectl get … >
cluster-snapshot.yaml && kubescape scan …"]`, so the recipe is still fully
captured — just one level of indirection.

### Validate it locally

```bash
# from the repo root — kubeconfig must already point at the target cluster.
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

cd tool-kubescape-sarif

cilock run --step kubescape-cluster-snapshot-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl get all,networkpolicies,roles,rolebindings,serviceaccounts -A -o yaml > cluster-snapshot.yaml && kubescape scan framework nsa --format sarif --output kubescape-cluster.sarif cluster-snapshot.yaml'

# Confirm the predicate carries SARIF + the rest.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/material/v0.1
#   https://aflock.ai/attestations/product/v0.1
#   https://aflock.ai/attestations/sarif/v0.1
#   https://aflock.ai/attestations/git/v0.1
```

The kubectl dump can be sizeable (this example produced ~140 KB against a
small dev cluster); kubescape parses multi-document YAML fine.

### What gets read from the cluster

All reads are read-only via `kubectl get`; nothing is mutated:

- `all` — Pods, Services, Deployments, ReplicaSets, StatefulSets,
  DaemonSets, Jobs, CronJobs (whatever `kubectl get all` resolves to in
  your cluster, across all namespaces with `-A`)
- `networkpolicies`
- `roles`
- `rolebindings`
- `serviceaccounts`

Add more resource types as your framework demands (e.g. `clusterroles`,
`clusterrolebindings`, `ingresses`) — kubescape will pick up anything it
recognises from the snapshot.

## Validated against

- kubescape `v4.0.8` (Homebrew, `kubescape version`)
- cilock `dev` (`cilock version`)
- Static-flow target: `manifests/deployment.yaml` (sample nginx Deployment + Service) — **5 SARIF findings** under `nsa`
- Snapshot-flow target: live EKS dev cluster (`kubectl get all,networkpolicies,roles,rolebindings,serviceaccounts -A`) — **55 SARIF findings** under `nsa` on a ~140 KB snapshot
- Framework: `nsa` (`kubescape scan framework nsa`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
- kubescape upstream SARIF/context restriction:
  [`kubescape/core/pkg/resultshandling/results.go`](https://github.com/kubescape/kubescape/blob/master/core/pkg/resultshandling/results.go)
  (search for `ContextCluster`)
