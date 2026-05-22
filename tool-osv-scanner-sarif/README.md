# `OSV-Scanner` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `OSV-Scanner` ([osv-scanner](https://github.com/google/osv-scanner)) using rookery's `sarif` attestor.

## Validated invocation

```bash
# Step 1: run the tool against a real target
osv-scanner --format sarif --output osv.sarif .

# Step 2: wrap with cilock to sign the output
cilock run --step osv-scanner-scan \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations sarif,environment \
  -- bash -c "cp $(echo 'osv-scanner --format sarif --output osv.sarif .' | grep -oE '[^ ]+\.sarif|[^ ]+\.json' | head -1) osv-scanner-product.sarif"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-osv-scanner-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
