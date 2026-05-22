# 41 — `policyverify` ⚠️ doc-only

## Why this isn't validated against real data

policyverify is a VERIFY-time attestor — it doesn't run during `cilock run`, it runs during `cilock verify`. The example shows verifying a prior attestation against a policy and emitting a SLSA Verification Summary.

## Recipe (when unblocked)

```bash
# After running cilock run (e.g., from #28-prowler):
cilock verify \
  --policy prowler-policy-signed.json \
  --policy-key prowler-policy.pub \
  --attestations prowler-real.json \
  --policy-summary-output policyverify-vsa.json

# The policyverify attestor emits a SLSA Verification Summary v1 envelope
# at policyverify-vsa.json signed by the cilock verifier's key.
```
