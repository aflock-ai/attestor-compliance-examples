# 35 — `nessus` ⚠️ doc-only

## Why this isn't validated against real data

Nessus is commercial. Nessus Essentials has a free tier (up to 16 IPs, personal/learning use) but registering for a public-repo example is a TOS gray area.

## Recipe (when unblocked)

```bash
# After downloading + activating Nessus Pro or Essentials:
nessuscli scan-launch --target=<host> --policy=<scan-policy>
# Export results:
nessuscli scan-export --uuid=<scan-uuid> --format=nessus > scan.nessus

cilock run --step nessus-ingest \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations nessus \
  -- bash -c "cp scan.nessus scan-product.nessus"
```
