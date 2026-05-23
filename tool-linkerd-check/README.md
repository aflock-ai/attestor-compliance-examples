# `Linkerd` via the native `linkerd-check` attestor

Real-infra validation example for the rookery `linkerd-check` native attestor. Captures Linkerd service-mesh state (control-plane health + service graph + per-edge mTLS booleans) under cilock and ships every envelope + every JSON output as committed evidence. The included Rego policy **denies** a deploy if any meshed edge is non-mTLS — the canonical "no unmeshed traffic in production" gate.

## What `linkerd-check` captures

- `linkerd check -o json` results: per-category validation across 10 areas (kubernetes-api, linkerd-existence, linkerd-config, linkerd-identity, linkerd-webhooks-and-apisvc-tls, linkerd-identity-data-plane, linkerd-version, linkerd-control-plane-proxy, linkerd-control-plane-version, linkerd-viz).
- `linkerd viz edges deploy -A -o json` results: meshed service graph with `client_id` / `server_id` peer identities and `no_tls_reason` per src→dst pair. An edge with both IDs present + empty `no_tls_reason` is mTLS-secured; everything else is insecure.
- Optional `LINKERD_CLUSTER_NAME` env var stamps the envelope so cross-cluster Rego policies can branch on which cluster the snapshot is from.

## What's in this dir

| File | Content |
|---|---|
| `raw/linkerd-check.json` | Real `linkerd check -o json` output from the dropbox-clone-dev EKS cluster. 9 categories, 54 total checks, 4 warnings (version-channel mismatches on stable-2.14.10), 0 errors. |
| `raw/linkerd-edges.json` | Real `linkerd viz edges deploy -A -o json` from the same cluster — 15 edges across `emojivoto`, `linkerd`, and `linkerd-viz` namespaces, **all mTLS-secured**. |
| `raw/attestation.json` | Signed DSSE envelope wrapping the capture step. Predicates: command-run/v0.1, environment/v0.1, material/v0.3, product/v0.3, linkerd-check/v0.1. |
| `raw/linkerd-edges-with-bypass.json` | The same edges file with one extra insecure edge synthesised (`no_tls_reason: "client proxy not connected to control plane"`) for the negative-test case. |
| `raw/attestation-bypass.json` | Signed envelope wrapping the synthesised-bypass edges file — 16 edges, 1 insecure. |
| `policy/policy.json` | Multi-step policy: requires all five predicates, gates on the `linkerd-mtls-required` Rego. |
| `policy/policy-signed.json` | The policy after `cilock sign`. |
| `policy/cilock.pub` | Public key the policy trusts. |
| `policy/decoded-rego-linkerd-mtls.txt` | Human-readable Rego source (decoded from policy.json). Five deny rules; the headline is "any insecure edge → block". |
| `policy/verify-recipe.sh` | Runs positive + negative verify end-to-end. |
| `policy/expected-verify-output.txt` | Captured PASS + DENY output. |
| `reproduce.sh` | The capture recipe — run `linkerd check -o json` + `linkerd viz edges -o json` under cilock. |

## Validated invocation

```bash
# Pre-reqs: linkerd CLI + kubeconfig pointed at a cluster with Linkerd
# control plane installed. Viz extension required for the edges capture.

LINKERD_CLUSTER_NAME=<your-cluster> cilock run --step linkerd-mesh-check \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations linkerd-check,environment,git \
  --enable-archivista=false \
  -- sh -c 'linkerd check -o json > linkerd-check.json; \
            linkerd viz edges deploy -A -o json > linkerd-edges.json'
```

The single `sh -c` wrapper writes both JSON files into the working directory in one shot. cilock's product attestor hashes both, the linkerd-check attestor parses both, and the resulting envelope carries the full snapshot under a single `command-run/v0.1` argv record. This is the same pattern as the [falco example](../tool-falco-events): redirect a structured CLI output to a file the product attestor can hash, then a postproduct attestor parses it.

## The mTLS-required policy (the value cilock adds)

The Rego in `policy/decoded-rego-linkerd-mtls.txt` enforces five conditions:

1. The check report has at least one category — refuses to gate on an empty capture.
2. No error-level checks (warnings allowed, errors block).
3. The edges report is present — refuses to gate on check alone.
4. **Zero insecure edges.** This is the headline contract — if anything in the mesh is unmeshed or has broken trust, the gate fires.
5. The edges report has at least one edge — refuses to silently pass on an empty edges capture (would mask an unmeshed cluster).

Without this policy, you have a signed envelope but no enforcement. With this policy, the deploy step is gated on real service-mesh integrity.

## End-to-end results

```
=== POSITIVE: 15/15 edges mTLS-secured ===
level=info msg="Verification succeeded"
level=info msg="Step: linkerd-mesh-check"
[PASS] policy accepted the all-mTLS envelope

=== NEGATIVE: 1 insecure edge (out of 16) — expect deny ===
[PASS] policy correctly denied the bypass envelope (cilock rc=1)
      reports 1 insecure (non-mTLS) edge(s) of 16 total — refusing to deploy through unmeshed traffic
```

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working tree before the capture |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `sh -c 'linkerd check ...; linkerd viz edges ...'` argv |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `linkerd-check.json` + `linkerd-edges.json` |
| `https://aflock.ai/attestations/linkerd-check/v0.1` | parsed reports with per-category pass/warn/error counts, edges summary with secured/insecure counts, cluster name |

## Validated against

- **Cluster:** [dropbox-clone-dev](https://github.com/testifysec/dropbox-clone) EKS in us-east-1, profile `testifysec-demo`
- **Linkerd:** stable-2.14.10 (control plane + viz extension, modern-bpf driver)
- **Workload:** [emojivoto](https://github.com/BuoyantIO/emojivoto) with `linkerd.io/inject=enabled` on the namespace — produces real traffic across web → emoji, web → voting, vote-bot → web; the viz extension's prometheus + tap also generate metrics edges, all auto-meshed.
- **cilock:** built from `feat/linkerd-check-attestor` branch.

## Reproduce

```bash
LINKERD_CLUSTER_NAME=<your-cluster> ./reproduce.sh
./policy/verify-recipe.sh   # runs positive + negative verify
```
