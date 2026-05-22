# `Syft` via the `sbom` attestor

This is a **tool integration example** — it shows how to attest the output
of `Syft` ([syft](https://github.com/anchore/syft)) using rookery's `sbom` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
syft alpine:3.20 -o cyclonedx-json=alpine.cdx.json

# Step 2: wrap with cilock to sign the output
cilock run --step syft-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sbom,environment \
  -- bash -c "cp $(echo 'syft alpine:3.20 -o cyclonedx-json=alpine.cdx.json' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) syft-product.json"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-syft-sbom.json`)

## See also

- [`sbom` attestor docs](https://cilock.aflock.ai/attestors/sbom)
- [Tools index](https://cilock.aflock.ai/tools)
