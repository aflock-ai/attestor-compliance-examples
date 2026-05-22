# `Hadolint` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Hadolint` ([hadolint](https://github.com/hadolint/hadolint)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
hadolint -f sarif Dockerfile > hadolint.sarif

# Step 2: wrap with cilock to sign the output
cilock run --step hadolint-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'hadolint -f sarif Dockerfile > hadolint.sarif' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) hadolint-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-hadolint-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
