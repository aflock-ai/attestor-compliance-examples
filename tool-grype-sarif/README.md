# `Grype` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Grype` ([grype](https://github.com/anchore/grype)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
grype alpine:3.20 -o sarif --file grype.sarif

# Step 2: wrap with cilock to sign the output
cilock run --step grype-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'grype alpine:3.20 -o sarif --file grype.sarif' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) grype-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-grype-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
