# 18 — `kube-bench` (live cluster)

**Status:** validated end-to-end against `dropbox-clone-dev` (EKS, `us-east-1`)
**Real-data source:** live EKS cluster (kube-bench Job on a node)

[CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) scan via
[`aquasecurity/kube-bench`](https://github.com/aquasecurity/kube-bench) run as a Job
on a real worker node, with the captured report signed and digested by `cilock`.

## Why a live cluster

kube-bench is meaningless against static manifests. The checks read kubelet
configuration off the node filesystem (`/var/lib/kubelet/config.yaml`,
`/etc/kubernetes/...`, systemd units), inspect process arguments via `hostPID`,
and emit `pass`/`fail`/`warn` counts derived from that runtime state. Running it
against a directory of YAML produces a report full of "file not found", which
is the antipattern this example previously fell into.

This example provisions the upstream EKS Job manifest (pinned to kube-bench
`v0.15.5`, image `docker.io/aquasec/kube-bench:v0.15.5`) into a dedicated
`kube-bench-cilock-demo` namespace, waits for it to complete, then captures the
JSON report from pod logs under a `cilock run` so the resulting DSSE envelope
binds the report digest to the command and environment that produced it.

## Predicate types in the envelope

```
https://aflock.ai/attestations/environment/v0.1
https://aflock.ai/attestations/git/v0.1
https://aflock.ai/attestations/material/v0.3
https://aflock.ai/attestations/command-run/v0.1
https://aflock.ai/attestations/product/v0.3
https://aflock.ai/attestations/kube-bench/v0.1
```

The **native `kube-bench` attestor** ([rookery PR #148](https://github.com/aflock-ai/rookery/pull/148) landed it in canonical `cilock`) parses kube-bench's `{Controls, Totals}` JSON into a structured predicate with `summary.total_pass / total_fail / total_warn` plus enumerated `failed_checks[]` and `warned_checks[]`. Rego policies can gate directly on those fields without re-parsing the report:

```rego
deny[msg] {
  input.summary.total_fail > 0
  msg := sprintf("kube-bench reports %d CIS failures: %v",
                 [input.summary.total_fail, [c | c := input.summary.failed_checks[_].id]])
}
```

Earlier versions of this example relied only on `product/v0.3` to bind the report file. That still works as a generic integrity primitive, but loses the structured-gating story — release-gate Rego had to walk the raw kube-bench JSON itself.

## Real result captured from `dropbox-clone-dev`

```
PASS_TOTAL=12 FAIL_TOTAL=1 WARN_TOTAL=33 INFO_TOTAL=0
```

Per-control rollup (from `_validation/kube-bench-sample.json`):

| id  | text                                | pass | fail | warn |
| --- | ----------------------------------- | ---- | ---- | ---- |
| 2   | Control Plane Configuration         | 0    | 0    | 1    |
| 3   | Worker Node Security Configuration  | 12   | 1    | 0    |
| 4   | Policies                            | 0    | 0    | 20   |
| 5   | Managed Services                    | 0    | 0    | 12   |

The single FAIL on control 3 is real EKS posture for the demo cluster, not a
synthetic example. A real release gate would add a Rego policy that fails on
`Totals.total_fail > 0` (see `28-prowler/` for the pattern).

## Cluster prerequisites

This example talks to a live EKS cluster. To reproduce:

```bash
aws sso login --profile testifysec-demo            # if not already valid
aws eks update-kubeconfig --name dropbox-clone-dev --region us-east-1 --profile testifysec-demo
kubectl get nodes                                  # must list at least one Ready node
```

The kube-bench Job needs `hostPID` and `hostPath` mounts on the node. The
upstream `job-eks.yaml` manifest pins those exactly. If a tighter
PodSecurityAdmission profile blocks the Job, **do not relax cluster security**
to make the example work — choose a less-restricted namespace or run against a
different cluster.

## Reproduce

See [`reproduce.sh`](./reproduce.sh) for the exact validated invocation. The
short version:

```bash
# 1. Deploy kube-bench Job (pinned to upstream SHA 13c5a2bed634b4f324ad54ba2942f4a77fc802e0 + image v0.15.5)
kubectl create namespace kube-bench-cilock-demo
kubectl apply -f job-eks.yaml

# 2. Generate signing key
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 3. Run cilock — waits for Job, captures logs, signs everything
cilock run --step kube-bench-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile kube-bench-attestation.json \
  --attestations environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl wait --for=condition=complete job/kube-bench -n kube-bench-cilock-demo --timeout=300s \
            && kubectl logs -n kube-bench-cilock-demo job/kube-bench --tail=-1 > kube-bench-report.json'

# 4. Cleanup
kubectl delete -f job-eks.yaml
kubectl delete namespace kube-bench-cilock-demo
```

## Why the `sh -c` wrapper is OK here

`sh -c '...'` is normally a smell — it hides the real argv from the
`command-run` attestor. We accept it in this example for the same reason
`govulncheck` and similar tools accept it: `kubectl logs` writes to stdout, and
the **only** way to land that stream in a file is to redirect inside a shell.
The redirect is part of the work being attested, not an attempt to hide it.
The full `sh -c` string is recorded verbatim by the `command-run` attestor —
inspect it with:

```bash
jq -r '.payload' kube-bench-attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type | endswith("command-run/v0.1")) | .attestation.cmd'
```

## Validate it locally

After running `reproduce.sh`:

```bash
# 1. Confirm the five expected predicate types are present
jq -r '.payload' kube-bench-attestation.json | base64 -d \
  | jq -r '.predicate.attestations[].type'
# Expected:
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/git/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/product/v0.3

# 2. Confirm the kube-bench totals
jq '.Totals' kube-bench-report.json

# 3. Confirm the merkle root binds at least one product file
jq -r '.payload' kube-bench-attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type | endswith("product/v0.3")) | .attestation'
```

A canonical captured report lives at
[`_validation/kube-bench-sample.json`](./_validation/kube-bench-sample.json)
for comparison.

## Files

- [`job-eks.yaml`](./job-eks.yaml) — adapted from
  [`aquasecurity/kube-bench@13c5a2b`](https://github.com/aquasecurity/kube-bench/blob/13c5a2bed634b4f324ad54ba2942f4a77fc802e0/job-eks.yaml).
  Local changes: pinned image tag, scoped to `kube-bench-cilock-demo`
  namespace, appended `--json` to the kube-bench argv.
- [`reproduce.sh`](./reproduce.sh) — exact validated invocation.
- [`_validation/kube-bench-sample.json`](./_validation/kube-bench-sample.json)
  — kube-bench report from a real run, kept for diffing.
