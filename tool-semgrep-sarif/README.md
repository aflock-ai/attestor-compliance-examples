# `Semgrep` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Semgrep` ([semgrep](https://github.com/semgrep/semgrep)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
semgrep scan --config=auto --sarif --output semgrep.sarif --error-only .

# Step 2: wrap with cilock to sign the output
cilock run --step semgrep-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'semgrep scan --config=auto --sarif --output semgrep.sarif --error-only .' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) semgrep-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-semgrep-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
