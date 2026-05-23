# `Falco` via the native `falco` attestor

Real-infra validation example for the rookery `falco` native attestor ([rookery PR for #139](https://github.com/aflock-ai/rookery/issues/139)). Captures a window of Falco runtime-security events from a live Kubernetes cluster under cilock, producing a signed v0.3 attestation whose `falco/v0.1` predicate carries the per-event records and aggregate priority/rule counts.

## What's in this dir

| File | Content |
|---|---|
| `raw/falco-events.jsonl` | The Falco line-delimited JSON event capture (real events from the `dropbox-clone-dev` EKS cluster — "Read sensitive file untrusted" rule firing twice when a test pod did `cat /etc/shadow`) |
| `raw/attestation.json` | The signed DSSE envelope wrapping the capture step. Predicate types: `command-run/v0.1`, `environment/v0.1`, `git/v0.1`, `material/v0.3`, `product/v0.3`, `falco/v0.1` |
| `reproduce.sh` | The full recipe — install Falco via Helm, trigger events, capture under cilock, verify |

## Validated invocation

```bash
# Pre-reqs: Falco installed in the cluster, kubeconfig pointed at it.
# This wrapper writes Falco's line-delimited JSON events to a file via
# `kubectl logs` and lets cilock pick it up as a product. The `sh -c` is
# necessary because kubectl writes to stdout; command-run records the
# real argv including the kubectl invocation.

FALCO_CLUSTER_NAME=dropbox-clone-dev cilock run --step falco-capture \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations falco,environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl logs daemonset/falco -n falco-system --tail=500 \
            | grep "\"rule\"" > falco-events.jsonl'
```

## Validated predicate body

The `falco/v0.1` predicate carries:

```json
{
  "total": 2,
  "priorities": { "warning": 2 },
  "rules": [
    {
      "rule": "Read sensitive file untrusted",
      "count": 2,
      "highest_priority": "Warning"
    }
  ],
  "cluster": "dropbox-clone-dev"
}
```

(Plus the full per-event records and the source file's product digest.)

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, tags, dirty status |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working tree before the capture |
| `https://aflock.ai/attestations/command-run/v0.1` | the literal `sh -c 'kubectl logs … > falco-events.jsonl'` argv |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `falco-events.jsonl` as a real product file |
| `https://aflock.ai/attestations/falco/v0.1` | parsed events + per-rule aggregation + priority counts + cluster name |

## Validated against

- Falco chart `falcosecurity/falco` (modern-bpf driver) in namespace `falco-cilock-validate` on `dropbox-clone-dev` EKS cluster
- cilock built from `feat/kube-bench-attestor` branch (falco attestor not yet in canonical main; available via `rookery-builder --preset all`)
- Trigger pod: `kubectl run cilock-falco-trigger --image=alpine:3.20 -- sh -c 'cat /etc/shadow'` — fires the "Read sensitive file untrusted" rule deterministically

## Reproduce

```bash
./reproduce.sh
```

Cleans up the Helm install + trigger pods after capture.
