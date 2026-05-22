# `Kubescape` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Kubescape` ([kubescape](https://github.com/kubescape/kubescape)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
kubescape scan deploy.yaml --format sarif --output kubescape.sarif

# Step 2: wrap with cilock to sign the output
cilock run --step kubescape-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'kubescape scan deploy.yaml --format sarif --output kubescape.sarif' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) kubescape-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-kubescape-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
