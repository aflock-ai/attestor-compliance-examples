# `Trivy` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Trivy` ([trivy](https://github.com/aquasecurity/trivy)) using rookery's
`sarif` attestor.

## Validated invocation

`cilock` invokes `trivy` **directly** as the wrapped command. There is no
`bash -c "cp ..."` shim — the real tool is what cilock executes, traces, and
records.

```bash
cilock run --step trivy-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- trivy fs --scanners vuln --format sarif --output trivy.sarif .
```

## Why this shape

- **Direct invocation.** `cilock run -- trivy fs ...` means the
  `command-run/v0.1` attestor records the real `argv` (`["trivy", "fs",
  "--scanners", "vuln", ...]`) and the real exit code. The spy/ptrace layer
  traces `trivy`'s syscalls — not `bash`'s, not `cp`'s.
- **Product set captures the SARIF.** Because `trivy.sarif` is written into
  the working directory during the run, the always-on `product/v0.3` attestor
  picks it up as a Merkle-leaf product. The file's content hash is bound to
  this step's attestation collection.
- **`sarif` attestor parses the output.** The `sarif` attestor (postproduct)
  reads `*.sarif` products and emits a structured
  `https://aflock.ai/attestations/sarif/v0.1` predicate alongside the raw
  product hash, so downstream policies can reason about findings without
  re-parsing.
- **`environment` + `git` for provenance.** Bind the scan to the host
  environment and the exact git commit it ran against.

If `trivy` finds nothing, the SARIF is still emitted (with an empty
`results` array) and the `sarif/v0.1` predicate is still produced — the
collection shape doesn't depend on findings being non-empty.

## Validate it locally

```bash
# 1. Generate an ephemeral signing key.
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 2. Run the example.
cd tool-trivy-sarif
cilock run --step trivy-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- trivy fs --scanners vuln --format sarif --output trivy.sarif .

# 3. Confirm the expected predicate types are present.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/product/v0.3
#   https://aflock.ai/attestations/sarif/v0.1
#   https://aflock.ai/attestations/git/v0.1
```

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
