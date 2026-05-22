# 32 — `structured-data` ⚠️ blocked

## Why this isn't validated against real data

The package exposes `WithSubjectQuery`, `WithDataType`, `WithSubjectPrefix`, `WithEmbedData`, `WithDataFile` as Go functions, but the `init()` only registers the attestor without `registry.StringConfigOption(...)` calls. This means there are no `--attestor-structured-data-*` CLI flags — the attestor is library-only.

Filed as a rookery bug. The fix is small: wire each `With*` to a registry option in `init()`.

## Recipe (when unblocked)

```bash
# After the fix lands, this should work:
cilock run --step structured-data-recipe \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations structured-data \
  --attestor-structured-data-data-file prowler.json \
  --attestor-structured-data-subject-query '$[?@.Status=="FAIL"].CheckID' \
  --attestor-structured-data-data-type "https://aflock.ai/data/prowler-failed-checks/v0.1" \
  --attestor-structured-data-subject-prefix "prowler:check:" \
  -- echo "indexed prowler failed checks"

# Until then, use the structured-data attestor programmatically via Go imports:
# import structureddata "github.com/aflock-ai/rookery/plugins/attestors/structured-data"
```
