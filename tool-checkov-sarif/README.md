# `Checkov` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Checkov` ([checkov](https://github.com/bridgecrewio/checkov)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
checkov -d . --output sarif --output-file-path checkov-output

# Step 2: wrap with cilock to sign the output
cilock run --step checkov-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'checkov -d . --output sarif --output-file-path checkov-output' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) checkov-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-checkov-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
