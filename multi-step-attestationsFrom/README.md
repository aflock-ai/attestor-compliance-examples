# `attestationsFrom` — real worked pipeline using the v0.3 BackRef graph + inclusion-proof

**Status:** validated end-to-end against cilock dev. The verify in
[`policy/expected-verify-output.txt`](./policy/expected-verify-output.txt) is
copied verbatim from a successful run of [`verify-recipe.sh`](./verify-recipe.sh)
on this branch.

This is the first end-to-end demonstration of the cilock v0.3 BackRef graph
spine. A four-step pipeline (build → scan-syft → scan-trivy → release) is
recorded by four separate `cilock run` invocations; a per-file inclusion-proof
emitted via `cilock prove` cryptographically pins the scanned binary to the
build's product Merkle root; and the release step's Rego asserts the
cross-step invariants over the lifted predicates.

> See the cilock-docs explanations of the underlying primitives:
>
> - [Concepts → The Spine of the Graph](https://cilock.aflock.ai/concepts/the-spine-of-the-graph)
> - [Guides → Verify a Specific File](https://cilock.aflock.ai/guides/verify-a-specific-file)

## Tree

```
multi-step-attestationsFrom/
├── README.md                          # this file
├── build/
│   ├── go.mod                         # one real dependency (google/uuid) so the
│   ├── go.sum                         #   SBOM has a non-trivial component count
│   └── main.go                        # tiny real Go program the build step compiles
├── policy/
│   ├── policy.json                    # the four-step policy with attestationsFrom + externalAttestations
│   ├── rego/
│   │   └── release-gate.rego          # plaintext copy of the Rego module
│   │                                  #   (verify-recipe.sh base64-embeds this at run-time)
│   └── expected-verify-output.txt     # captured cilock verify stdout from a passing run
└── verify-recipe.sh                   # full reproduce script — generates keypair,
                                       # runs all four cilock steps, prove, and verify
```

## The four-step contract

| Step          | Wraps                                                                     | Emits                                                                                                                |
| ------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `build`       | `go build -trimpath -o hello main.go`                                     | `material/v0.3`, `command-run/v0.1`, `product/v0.3` (and a sidecar tree JSON for `cilock prove`)                     |
| `scan-syft`   | `syft hello -o cyclonedx-json=hello.cdx.json`                             | `material/v0.3`, `command-run/v0.1`, `product/v0.3`, `https://cyclonedx.org/bom` (CycloneDX SBOM embedded predicate) |
| `scan-trivy`  | `trivy fs --quiet --format sarif --output hello.sarif.json hello`         | `material/v0.3`, `command-run/v0.1`, `product/v0.3`, `sarif/v0.1`                                                    |
| `release`     | `echo 'release gate evaluated' > release.log` (no-op; provides the gate)  | `material/v0.3`, `command-run/v0.1`, `product/v0.3` — and verify-time `policyverify/v0.1` from the embedded Rego     |

Out-of-band of any step, `cilock prove --tree-sidecar build.attestation.product.tree.json --file hello` emits a bare-predicate DSSE envelope of type `https://aflock.ai/attestations/inclusion-proof/v0.1` whose `treeRoot == build.product.merkleRoot` and whose `file:hello` subject matches the binary's content digest.

## How the v0.3 BackRef spine lines up

Each step's `cilock run` is invoked from a clean directory so the
`material/v0.3` and `product/v0.3` Merkle roots are deterministic. The
following equalities hold by construction (verified by inspection of the
`*.tree.json` sidecars in a fresh run):

```
build.product/v0.3.tree:products          == build's product Merkle root R
scan-syft.material/v0.3.tree:materials    == R     (scan-syft consumed build's output as material)
scan-trivy.material/v0.3.tree:materials   == R     (scan-trivy consumed build's output as material)
inclusion-proof.treeRoot                  == R     (cilock prove builds against build's product tree sidecar)
```

That single shared root is the BackRef graph spine. When `cilock verify -f
build/hello` seeds the search with the binary's content digest, the BackRef
expansion walks the shared root across collections and discovers every step's
envelope without any explicit subject configuration beyond the explicit
`--subjects artifact=sha256:<bin>` injection on the scan and release steps
(which lets `-f` work as the single seed point).

## The release-step Rego

The release step declares:

```jsonc
"release": {
  "attestationsFrom": ["build", "scan-syft", "scan-trivy"],
  "externalFrom":     ["inclusionProof"],
  "attestations": [{
    "type": "https://aflock.ai/attestations/command-run/v0.1",
    "regopolicies": [{"name": "release-gate", "module": "<base64 of policy/rego/release-gate.rego>"}]
  }]
}
```

`attestationsFrom` lifts each named step's predicates into
`input.steps.<step>.<predicateType>`. `externalFrom` lifts the inclusion-proof
envelope (which is a bare-predicate DSSE, not a Collection — see
`attestation/policy/step.go`) into `input.external.inclusionProof`.

The full Rego is in [`policy/rego/release-gate.rego`](./policy/rego/release-gate.rego);
the predicates it consumes:

- `input.steps.build["https://aflock.ai/attestations/product/v0.3"]` — for `merkleRoot`
- `input.steps["scan-syft"]["https://cyclonedx.org/bom"]` — for `components`
- `input.steps["scan-trivy"]["https://aflock.ai/attestations/sarif/v0.1"]` — for `report.runs[_].results[_].level`
- `input.external.inclusionProof` — for `treeRoot`

And the three checks it enforces:

1. **Cross-step artifact identity binding.** `inclusion_proof.treeRoot == build_product.merkleRoot`. Without this check, an attacker who swapped the artifact between build and scan would still pass the gate.
2. **SBOM is non-empty.** `count(scan_sbom.components) >= 1`.
3. **No SARIF error-level findings.** `scan_sarif.report.runs[_].results[_].level != "error"`.

## Reproduce

The recipe is fully scripted in [`verify-recipe.sh`](./verify-recipe.sh) — it
generates a fresh Ed25519 keypair, runs build/scan-syft/scan-trivy/prove/release,
renders policy.json with the fresh keyid substituted, signs it, and runs
`cilock verify`.

```bash
# From the example directory:
./verify-recipe.sh --cilock=/path/to/cilock

# Or with cilock on PATH:
./verify-recipe.sh
```

Required tools: `cilock`, `go`, `syft`, `trivy`, `openssl`, `jq`, `base64`. On
macOS: `brew install syft trivy jq`.

Expected stdout for the final `cilock verify` invocation is committed at
[`policy/expected-verify-output.txt`](./policy/expected-verify-output.txt). The
only field that varies between runs is the kid suffix in the dsse-verify
trace, which the committed reference masks as `kid=<ephemeral>`.

## What this example does NOT do

- It does not sign with a Fulcio cert or use OIDC functionaries. Each step's
  functionary is a publickey constraint against a single Ed25519 keypair.
  Production policies should pin per-step Fulcio cert constraints to match
  each workflow's OIDC identity.
- It does not exercise `artifactsFrom` (the v0.3 artifact-flow primitive that
  asserts step N's materials match step N-1's products at the file level —
  complementary to the BackRef spine asserted here).
- The release step's `cilock run -- echo ...` is a no-op cheap placeholder. A
  real release pipeline would publish artifacts (push image, upload archive,
  cut a GitHub release) inside that step so the publish action itself is
  attested.

## See also

- [`_policy-templates/backref-subjects.md`](../_policy-templates/backref-subjects.md)
  — the subject-graph mental model this example builds on.
- [`09-sbom/`](../09-sbom) — single-step SBOM example.
- [`36-sarif/`](../36-sarif) — single-step SARIF example.
- [`tool-syft-sbom/`](../tool-syft-sbom), [`tool-trivy-sarif/`](../tool-trivy-sarif)
  — tool-integration examples this one composes.
- [cilock-docs: spine of the graph](https://cilock.aflock.ai/concepts/the-spine-of-the-graph)
- [cilock-docs: verify a specific file](https://cilock.aflock.ai/guides/verify-a-specific-file)
