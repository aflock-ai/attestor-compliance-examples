# Syft via the `sbom` attestor

Tool-integration example showing how to capture and attest a [Syft](https://github.com/anchore/syft) SBOM under cilock — without the `cp` antipattern. cilock invokes syft directly so the captured envelope's `command-run/v0.1` records the real argv, the `product/v0.3` Merkle root binds the CycloneDX JSON as a real product, and the `sbom` attestor parses the SBOM out of that product file.

## Validated invocation

```bash
# Prereqs: syft on PATH and an ed25519 key at ../_validation/key.pem
cilock run --step syft-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sbom,environment,git \
  --enable-archivista=false \
  -- syft dir:. -o cyclonedx-json=syft.cdx.json
```

The same shape works against a container image — substitute `syft alpine:3.20 -o cyclonedx-json=syft.cdx.json` for the `--`-args. Local-dir target is documented as the default because it doesn't depend on registry network access.

## Why this shape

| Antipattern (old) | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "cp …syft-output… syft-product.json"` | `cilock run ... -- syft dir:. -o cyclonedx-json=syft.cdx.json` |
| `command-run.cmd` records `["bash","-c","cp …"]` — cilock is "running" cp | `command-run.cmd` records the literal syft argv |
| Product is a copy-of-a-copy; the spy/ptrace can't trace syft's syscalls because cilock isn't its parent | Product is syft's real output; the spy traces syft directly |
| sbom attestor parses a file that's a copy of one syft produced elsewhere | sbom attestor parses the file syft just produced inside the wrapped step |

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
  "https://cyclonedx.org/bom"
]
```

The sbom attestor emits the SBOM's native predicate type (`https://cyclonedx.org/bom` for CycloneDX, `https://spdx.dev/Document/v2.3` for SPDX) rather than wrapping it under an aflock URI — that's intentional so downstream policy engines and SBOM consumers can match on the standard URI directly.

Confirm `command-run.cmd` is the literal syft argv (proof the antipattern is gone):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["syft","dir:.","-o","cyclonedx-json=syft.cdx.json"]
```

## See also

- [`sbom` attestor docs](https://cilock.aflock.ai/attestors/sbom)
- [Tools index](https://cilock.aflock.ai/tools)
