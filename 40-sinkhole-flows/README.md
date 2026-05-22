# 40 — `sinkhole-flows` ⚠️ doc-only

## Why this isn't validated against real data

The attestor hard-codes the flows path to `/flows/out.jsonl` and the scan-id env var to `PIPW_SCAN_ID`. This makes it specific to the pip-witness sinkhole deployment shape: a mitmproxy sidecar in a Docker network captures every outbound HTTPS flow from a `pip install` and bind-mounts `/flows/out.jsonl` into the scan container.

This isn't a generic attestor — it's tightly coupled to the pip-witness defense surface. The validated example requires the full sinkhole-flows + pip-witness setup.

## Recipe (when unblocked)

```bash
# Full pip-witness setup required. See:
# https://github.com/aflock-ai/pip-witness (sinkhole network + scan container)

# Inside the scan container (with /flows/out.jsonl bind-mounted in):
PIPW_SCAN_ID=<uuid> \
PIPW_PACKAGE_NAME=<package> \
PIPW_PACKAGE_VERSION=<version> \
cilock run --step pip-witness-scan \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations sinkhole-flows,environment \
  -- pip install --quiet $PIPW_PACKAGE_NAME==$PIPW_PACKAGE_VERSION
```
