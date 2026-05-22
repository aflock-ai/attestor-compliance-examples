# 42 — `vsa` ⚠️ doc-only

## Why this isn't validated against real data

Verification Summary Attestation. Same flow as policyverify (#41); the vsa attestor is a different output shape for the same verify-time SLSA VSA emission.

## Recipe (when unblocked)

```bash
# Same verify flow as #41:
cilock verify \
  --policy <policy.json> \
  --policy-key <policy.pub> \
  --attestations <prior-attestation>.json \
  --policy-summary-output vsa.json
```
