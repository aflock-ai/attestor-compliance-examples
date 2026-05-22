# `Trivy` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Trivy` ([trivy](https://github.com/aquasecurity/trivy)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
trivy fs --format sarif --output trivy.sarif --severity HIGH,CRITICAL .

# Step 2: wrap with cilock to sign the output
cilock run --step trivy-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'trivy fs --format sarif --output trivy.sarif --severity HIGH,CRITICAL .' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) trivy-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-trivy-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
