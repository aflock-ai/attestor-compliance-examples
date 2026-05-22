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

## Validated against

- kubescape `v4.0.8` (Homebrew, `kubescape version`)
- cilock `dev` (`cilock version`)
- Target: `manifests/deployment.yaml` (sample nginx Deployment + Service)
- Framework: `nsa` (`kubescape scan framework nsa`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
