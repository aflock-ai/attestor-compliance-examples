# `attestationsFrom` — cross-step policy example

**Status:** scaffolded (policy compiles; envelope capture pending v0.3 cilock release)

This example demonstrates the `attestationsFrom` field on a policy step — the cilock primitive for writing Rego rules that read attestations collected by an *earlier* step in the same policy evaluation.

## What problem `attestationsFrom` solves

A single-step Rego block can only see attestations bound to its own step. That means a SARIF clean-bill-of-health check can't, by itself, also assert that the scanner ran against the artifact the producer is shipping — those two facts live in different steps' attestation collections.

Before `attestationsFrom`, you had two unattractive options:

1. **Collapse everything into one step.** Lose the multi-functionary trust model (each step can pin a different signer) and lose the temporal ordering (build is necessarily earlier than scan).
2. **Drop the cross-step check entirely.** Trust that whoever assembled the verify-time envelope set didn't swap a clean SARIF for a real artifact's findings.

`attestationsFrom: ["build", "scan"]` on a `release` step surfaces the build's and scan's attestations under `input.steps.build.<predicate-type>` and `input.steps.scan.<predicate-type>` when the release step's Rego evaluates. The release gate can then enforce the binding the other two options miss.

## The three-step contract this example demonstrates

| Step | Emits | Functionary pinned to |
|---|---|---|
| `build` | `material/v0.3` + `command-run/v0.1` + `product/v0.3` | the build pipeline's signer |
| `scan` | `material/v0.3` + `command-run/v0.1` + `sarif/v0.1` + `inclusion-proof/v0.1` | the scanner pipeline's signer |
| `release` | `policyverify/v0.1` (with `attestationsFrom: ["build", "scan"]`) | the release gate's signer |

The `release` step's Rego policy enforces two cross-step invariants:

1. **The scan ran against the artifact the build produced.** The scan step must include an inclusion-proof attestation whose `treeRoot` equals the build step's product Merkle root (`input.steps.build["...product/v0.3"].merkleRoot`). Without this, an attacker could attach a clean scan of a totally different artifact to the release.

2. **The scan found zero error-severity SARIF findings.** A straight Rego rule over `input.steps.scan["...sarif/v0.1"]`, expressible only because `attestationsFrom` lifted that predicate into the release step's `input.steps`.

See `policy/policy.json` for the full policy and `policy/decoded-rego.txt` for the plain-text Rego module that's base64-embedded into the policy.

## Other patterns `attestationsFrom` enables

The general shape is: **a later step asserting an invariant over an earlier step's attestation contents.** Concrete patterns from the field:

- **"Same commit across build and scan."** The release step pulls both the build's `git` attestation and the scan's `git` attestation via `attestationsFrom`, asserts `input.steps.build["...git/v0.1"].commithash == input.steps.scan["...git/v0.1"].commithash`. Blocks the "scan an older clean tree, deploy newer dirty tree" attack.

- **"VSA from a prior policy says pass."** A downstream stage (e.g. promote-to-prod) pulls a VSA emitted by an earlier policy verification step via `attestationsFrom: ["sandbox-gate"]`, asserts `input.steps["sandbox-gate"]["...policyverify/v0.1"].verificationResult == "PASSED"`. Chains policies temporally — you can require the sandbox gate passed before allowing the prod promotion.

- **"Provenance of the SBOM."** Two-step pipeline: a `gen-sbom` step that emits the SBOM, and a `scan-sbom` step that runs grype against it. The scan step's release gate uses `attestationsFrom: ["gen-sbom"]` to assert the SBOM digest grype scanned matches the SBOM the producer published — closes the "we scanned a clean SBOM but published a dirty one" attack.

- **"Diff between two scans."** A `release` step pulls both an `attack-simulation` step's findings and a `clean-build` step's findings via `attestationsFrom: ["attack-simulation", "clean-build"]`. Asserts the symmetric difference is non-empty (the simulator actually detected the planted issue) AND that the clean-build set contains zero of the attack-simulation findings (the same patterns aren't legitimately present in a real build). Useful for validating that a detection ruleset is calibrated correctly — exactly the kind of check `43-trivy-attack-detection/` could grow into.

- **"Workflow OIDC binding."** A `release` step asserts that the build's `github` attestation's `pipelineurl` claim matches a hardcoded production-workflow URL. Without `attestationsFrom`, the release step's Rego can't read the build's github predicate. With it, you can pin "release only runs after build-prod.yml" cryptographically.

## What this example does NOT do

It does not yet ship a captured envelope set. Producing one requires:

1. A cilock binary built from rookery `main` after [rookery#136](https://github.com/aflock-ai/rookery/pull/136) merges (the v0.3 cutover).
2. A real three-stage build/scan/release pipeline that emits the five attestation types in the contract above.
3. The producer running `cilock prove --tree-sidecar <build>.product.tree.json --file <artifact>` to emit the inclusion-proof attestation the release step depends on.

That capture is filed as a follow-up. Until then, this example documents the contract and the policy JSON; running `cilock verify` against it requires the captured envelopes.

## Reproduce (sketch — pending real capture)

```bash
# 1. Build step
cilock run --step build \
  --signer-file-key-path key.pem --outfile build.attestation.json \
  -- make dist/cilock

# 2. Scan step. Scanner reads dist/cilock as a material; emits SARIF; cilock
#    prove emits the inclusion-proof attestation binding the scan to build's
#    product tree root.
cilock run --step scan \
  --signer-file-key-path key.pem --outfile scan.attestation.json \
  --attestations sarif \
  -- trivy fs --format sarif -o scan.sarif dist/cilock

cilock prove \
  --tree-sidecar build.attestation.product.tree.json \
  --file dist/cilock \
  --signer-file-key-path key.pem \
  --outfile scan.inclusion-proof.json

# 3. Verify release gate
cilock sign -k key.pem -f policy/policy.json -o policy/policy-signed.json
cilock verify \
  -p policy/policy-signed.json \
  -k key.pub \
  -a build.attestation.json,scan.attestation.json,scan.inclusion-proof.json \
  -s sha256:<dist-cilock-digest>
```

## See also

- [`_policy-templates/backref-subjects.md`](../_policy-templates/backref-subjects.md) — the subject-graph mental model `attestationsFrom` extends
- [`_policy-templates/policy-shape.md`](../_policy-templates/policy-shape.md) — the policy.json field reference
- [`43-trivy-attack-detection/`](../43-trivy-attack-detection) — a two-step policy that could use `attestationsFrom` to compare its two scans against each other
- [Issue #135 on rookery](https://github.com/aflock-ai/rookery/issues/135) — the v0.3 design that makes inclusion-proof attestations the cross-step binding primitive
