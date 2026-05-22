# Grype via the `sarif` attestor

Tool-integration example showing how to capture and attest a [Grype](https://github.com/anchore/grype) SARIF scan under cilock — without the `cp` antipattern. cilock invokes grype directly so the captured envelope's `command-run/v0.1` records the real argv, the `product/v0.3` Merkle root binds the SARIF as a real product, and the `sarif` attestor parses the file out of that product.

## Validated invocation

```bash
# Prereqs: grype on PATH and an ed25519 key at ../_validation/key.pem
cilock run --step grype-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- grype dir:. -o sarif=grype.sarif
```

The same shape works against a container image — substitute `grype alpine:3.20 -o sarif=grype.sarif` for the `--`-args. Local-dir target is documented as the default because it doesn't depend on registry network access.

## Why this shape

| Antipattern (old) | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "cp …grype-output… grype-product.sarif"` | `cilock run ... -- grype dir:. -o sarif=grype.sarif` |
| `command-run.cmd` records `["bash","-c","cp …"]` — cilock is "running" cp | `command-run.cmd` records the literal grype argv |
| Product is a copy-of-a-copy; spy/ptrace can't trace grype's syscalls because cilock isn't its parent | Product is grype's real output; spy traces grype directly |
| sarif attestor parses a file that's a copy of one grype produced elsewhere | sarif attestor parses the file grype just produced inside the wrapped step |

## Validate it locally

```bash
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

Confirm `command-run.cmd` is the literal grype argv (proof the antipattern is gone):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["grype","dir:.","-o","sarif=grype.sarif"]
```

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
