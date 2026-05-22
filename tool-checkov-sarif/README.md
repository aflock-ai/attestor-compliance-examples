# `Checkov` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output of
[Checkov](https://github.com/bridgecrewio/checkov) (an IaC misconfiguration
scanner from Bridgecrew / Prisma Cloud) using rookery's `sarif` attestor.

## Validated invocation

`cilock` invokes Checkov **directly**, with no `bash -c "cp ..."` wrapper. This
matters: when cilock runs the real tool, `command-run` captures the real argv,
the `product/v0.3` Merkle tree captures the SARIF file Checkov actually wrote,
and the `sarif` attestor digests that same file. Everything chains.

```bash
cilock run --step checkov-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- checkov -d fixtures -s -o sarif --output-file-path .
```

A few Checkov-specific notes baked into that command:

- `-d fixtures` — point Checkov at the IaC directory. This example commits a
  small intentionally-insecure Terraform fixture under `fixtures/` so the SARIF
  always contains real findings.
- `-s` (soft-fail) — Checkov exits non-zero when it finds misconfigurations.
  Soft-fail makes it exit 0 so `command-run` records a clean execution; the
  findings are still present in the SARIF and in the `sarif` attestor.
- `--output-file-path .` — Checkov treats this as a *directory* and writes
  `results_sarif.sarif` into it. The `product` and `sarif` attestors discover
  that file in cwd and digest it.

## Why this shape

| Antipattern (old)                                      | This example                                       |
| ------------------------------------------------------ | -------------------------------------------------- |
| `cilock run ... -- bash -c "cp output.sarif x.sarif"`  | `cilock run ... -- checkov ... --output-file-path .` |
| `command-run` records `bash -c "cp ..."` — useless     | `command-run` records the real Checkov argv         |
| Product attestor digests the `cp` destination          | Product attestor digests Checkov's actual output    |
| Tool execution happens outside the attestation         | Tool runs inside cilock; spy can trace its syscalls |

With the corrected shape, all of these chain together:

1. `command-run/v0.1` — real `checkov ...` argv + exit code.
2. `material/v0.3` — Merkle tree of inputs (the Terraform fixture).
3. `product/v0.3` — Merkle tree of outputs (`results_sarif.sarif`).
4. `sarif/v0.1` — parsed SARIF report + `reportDigestSet.sha256` that matches
   the leaf in the product tree.

## Validate it locally

```bash
# Generate a signing key (one-time).
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

cd tool-checkov-sarif

# Run cilock + Checkov against the committed fixture.
cilock run --step checkov-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- checkov -d fixtures -s -o sarif --output-file-path .

# Confirm the predicate carries the expected attestor types.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/product/v0.3
#   https://aflock.ai/attestations/sarif/v0.1
#   https://aflock.ai/attestations/git/v0.1

# Confirm Checkov's real argv ended up in command-run.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'

# Confirm the SARIF report and its findings landed in the sarif attestor.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {reportFileName, digest: .reportDigestSet.sha256,
           findingCount: (.report.runs[0].results | length)}'
```

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
