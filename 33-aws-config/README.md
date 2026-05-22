# 33 — `aws-config` ⚠️ blocked

## Why this isn't validated against real data

No AWS Config recorder configured in testifysec-demo or archivista-sandbox. Enabling Config has cost (per-resource recording fee) and footprint side-effects (S3 bucket for delivery channel, IAM role, recorder + delivery channel). Not enabling for this validation.

## Recipe (when unblocked)

```bash
# In an account with AWS Config + a Config rule configured:
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited \
  --output json > aws-config-eval.json

cilock run --step aws-config-eval \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations aws-config \
  -- bash -c "cp aws-config-eval.json aws-config-product.json"
```
