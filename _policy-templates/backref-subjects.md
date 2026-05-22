# Back-ref subjects — how attestors layer

The whole point of `cilock verify` running across multiple attestations is **subject digest overlap**. Each attestor emits subjects (named, hashed identifiers) for its predicate. When two attestors emit the SAME subject digest, they share that identity — and the policy can enforce that linkage.

This is the multi-step contract: not just "I have N attestations signed by N functionaries," but "the N attestations agree on the artifact / commit / workflow they're describing, via overlapping subject digests."

## The subjects each common attestor emits

Captured from real envelopes in this repo. Use this as a reference when designing multi-step policies.

### `git` attestor

| Subject name | Identifies | Hashed value |
|---|---|---|
| `commithash:<sha>` | the HEAD commit SHA | sha of the SHA string |
| `parenthash:<sha>` | the parent commit SHA | sha of the SHA string |
| `authoremail:<email>` | author identity | sha of the email |
| `committeremail:<email>` | committer identity | sha of the email |
| `refnameshort:<branch>` | branch name | sha of the branch name |
| `remote:<url>` | the repo URL | sha of the URL |

Real example (from `19-github/`):
```
git/v0.1/commithash:4873ae5a76c4a2985a221ad98f10c... → sha=4873ae5a76c4a2985a...
git/v0.1/remote:https://github.com/aflock-ai/...    → sha=53dabb75ba3bea9f...
```

### `github` attestor

| Subject name | Identifies |
|---|---|
| `pipelineurl:<url>` | the workflow run URL (https://github.com/<org>/<repo>/actions/runs/<id>) |
| `projecturl:<url>` | the repo URL |

Crucially: `github.projecturl` hashes to the **same value** as `git.remote` when both reference the same repo URL. That's the multi-step anchor.

### `material` and `product` attestors

| Subject name | Identifies |
|---|---|
| `https://aflock.ai/attestations/material/v0.3/tree:materials` | the RFC 6962 Merkle root over the file-tree state **before** the wrapped command (`H(0x00 \|\| sha256(path \|\| 0x00 \|\| file-digest))` leaves, sorted lex by path) |
| `https://aflock.ai/attestations/product/v0.3/tree:products` | the RFC 6962 Merkle root over the file-tree state **after** the wrapped command |
| `file:<path>` (via `inclusion-proof` attestation) | a specific file's identity, emitted on-demand by `cilock prove` against the producer's tree sidecar; the inclusion-proof predicate carries `leafPath` + `fileDigest` + `auditPath` so the verifier reconstructs the leaf hash and confirms inclusion against the signed tree root |

The `tree:products` digest is the canonical artifact identity — passing it to `cilock verify --subjects sha256:<digest>` walks every collection that recorded that artifact. To verify a *specific* file inside the tree, the producer must additionally have emitted an inclusion-proof attestation for that file via `cilock prove --tree-sidecar <outfile>.product.tree.json --file <path>`. See [verify a specific file](https://cilock.aflock.ai/guides/verify-a-specific-file) in the docs site for the full verifier flow.

> **v0.1 / v0.2 status.** v0.1 product and material envelopes pre-dating the cutover are still readable via the verify-only `LegacyDecoder` in `plugins/attestors/{product,material}/legacy.go`. v0.2 product envelopes are **not** decoded — that URI resolves to `V02Unsupported`, whose every method returns `ErrV02Unsupported`. v0.2 envelopes must be re-issued under v0.3 before they will verify against any current cilock build.

### `prowler` attestor

| Subject name | Identifies |
|---|---|
| `aws:account:<id>` | the scanned AWS account |
| `aws:arn:<arn>` | each unique failed-check ResourceArn |
| `aws:service:<name>` | each unique failed-check ServiceName |

### `oci` / `docker` attestors

Both expose the image digest. They overlap when the same image is captured by both (one via `docker save`, the other via `docker buildx --metadata-file`).

### Tool-via-sarif (`sarif`, `sbom`, `secretscan`)

The pass-through attestors expose:
- `tree:products` (the SARIF/SBOM file digest)
- The product attestor adds `file:<sarif-name>` with the sarif bytes' digest

## Common layering patterns

### Pattern 1: "scan ran against the commit we're shipping"

Policy goal: a tool scan must be against the same commit that built the artifact, not some random older commit.

Layering:
```
build:
  git attestor → commithash:abc123 (subject)
  product attestor → tree:products:<hash> (subject)

scan:
  git attestor → commithash:abc123 (subject — same)
  sarif attestor (wrapping trivy) → tree:products:<sarif-hash>
```

Enforcement: `cilock verify -s sha256:<hash of abc123>` finds both collections; policy requires both to share `commithash`.

### Pattern 2: "release came from this workflow"

Policy goal: the github OIDC identity must match the release workflow we trust.

Layering:
```
github attestor → 
  pipelineurl:https://github.com/<org>/<repo>/actions/runs/<id>
  + jwt.claims:
    - workflow_ref = .github/workflows/release.yml@refs/heads/main
    - repository = <org>/<repo>
    - runner_environment = github-hosted
```

Enforcement: Rego on the github attestation's `jwt.claims.workflow_ref`, `repository`, `runner_environment`.

### Pattern 3: "the SBOM I'm shipping is the SBOM the scanner used"

Layering:
```
build step:
  syft (sbom attestor) → tree:products:<sbom-hash>

scan step:
  material attestor → tree:materials includes <sbom-hash>
  grype (sarif passthrough) → findings against that SBOM
```

Enforcement: pass `-s sha256:<sbom-hash>`. Verify finds both syft's collection (where it's a product) and grype's collection (where it's a material). Policy checks both pass.

### Pattern 4: "all the scans the policy gates on ran on the same artifact"

Multi-tool layering:
```
trivy step  → product tree:T
syft step   → product tree:S
grype step  → material tree:S, product tree:G  (grype consumed syft's SBOM)
secretscan → material tree:M, product tree:Sec
```

Policy can require: `trivy.product.tree == grype.material.tree == syft.product.tree` (all scanners consumed the same artifact).

## Cross-step rules via `attestationsFrom`

Subject-digest overlap is what makes the verifier *find* the right collections. But the **rule** that enforces an overlap is something a single step's Rego block can't express — because a Rego block on step B can only see step B's own attestations. To assert "step B's findings reference step A's artifact," the policy engine must surface step A's attestations into step B's Rego context.

That's what `attestationsFrom` does. Adding `"attestationsFrom": ["A"]` to step B's policy entry causes the policy engine to lift step A's verified attestations under `input.steps.A.<predicate-type>` when step B's Rego evaluates. The Rego module on step B can then reference both steps' data:

```rego
# step B's Rego, with attestationsFrom: ["A"]
deny[msg] {
    a_root := input.steps.A["https://aflock.ai/attestations/product/v0.3"].merkleRoot
    b_root := input.steps.B["https://aflock.ai/attestations/material/v0.3"].merkleRoot
    a_root != b_root
    msg := "step B's materials don't include step A's product"
}
```

See [`multi-step-attestationsFrom/`](../multi-step-attestationsFrom/) for a full worked example with a three-step build → scan → release policy. The release step's Rego asserts (a) the scan ran against the artifact the build produced (via an inclusion-proof attestation's `treeRoot` matching the build's product Merkle root), and (b) the scan's SARIF findings are clean — both invariants expressible only because `attestationsFrom: ["build", "scan"]` is on the release step.

## Why this matters

A naïve verify is "have a signed attestation from a trusted signer." That stops crude attacks. Subject-digest layering blocks the more interesting attacks:

- A scanner output from a DIFFERENT artifact ("we scanned alpine:3.20, deployed alpine:3.19") — caught when the artifact digests don't overlap.
- A scanner output from a DIFFERENT commit ("we scanned main yesterday, releasing today's main") — caught when commithash subjects diverge.
- A SBOM from a DIFFERENT image ("I'll attach a clean SBOM and ship the dirty image") — caught when the SBOM's tree digest doesn't appear as a subject in the image's collection.

Subject digests are the cryptographic glue. The policy is the contract. `attestationsFrom` is how the contract is written.
