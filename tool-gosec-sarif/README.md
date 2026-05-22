# `gosec` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of [`gosec`](https://github.com/securego/gosec) using rookery's `sarif`
attestor.

## Validated invocation

Run from inside [`fixtures/`](./fixtures) (a tiny Go package containing
deliberate insecure patterns so gosec emits a real, non-empty SARIF report).

```bash
cilock run --step gosec-scan \
  --signer-file-key-path ../../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- gosec -no-fail -fmt=sarif -out=gosec.sarif ./...
```

## Why this shape

- **cilock invokes `gosec` directly** as the child process. The
  `command-run` attestor records the real argv (`gosec -no-fail -fmt=sarif
  -out=gosec.sarif ./...`), exit code, stdout, and stderr. A spy or
  reviewer reading the envelope sees exactly what ran.
- **No `bash -c "cp ..."` shim.** The previous shape made cilock attest
  `cp`, hiding the actual tool from `command-run` and breaking the product
  chain. With the direct invocation, `gosec.sarif` is created by gosec in
  the working directory and picked up by the `product` attestor on the
  same run — no copy, no rename, no shell wrapper.
- **`-no-fail` keeps gosec exit code at 0** when findings are present.
  Without it, gosec exits non-zero and cilock aborts the run before the
  envelope is signed. Findings are still recorded in the SARIF and
  enforced by the Rego gate in [`policy/policy.json`](./policy/policy.json),
  so policy verification (not the tool's exit code) is what fails the
  build.

## Validate it locally

```bash
# 1. Sign a fresh attestation (from this directory)
cd fixtures
cilock run --step gosec-scan \
  --signer-file-key-path ../../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- gosec -no-fail -fmt=sarif -out=gosec.sarif ./...

# 2. Inspect the predicate attestation types
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/sarif/v0.1"
]
```

The `fixtures/` package is designed to trip three gosec rules
(`G404` insecure RNG, `G401` weak hash, `G501` blocklisted import) so the
SARIF report contains real findings the Rego gate in
[`policy/policy.json`](./policy/policy.json) can evaluate.

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-gosec-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
