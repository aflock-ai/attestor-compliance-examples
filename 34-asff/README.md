# 34 — `asff` ⚠️ blocked

## Why this isn't validated against real data

SecurityHub not subscribed in testifysec-demo (subscribing has cost). The asff attestor consumes the JSON output of `aws securityhub get-findings`.

## Recipe (when unblocked)

```bash
# In an account with SecurityHub subscribed:
aws securityhub get-findings --max-results 100 --output json > asff-findings.json

cilock run --step asff-ingest \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations asff \
  -- bash -c "cp asff-findings.json asff-product.json"
```
