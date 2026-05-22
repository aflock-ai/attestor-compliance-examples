# `hadolint` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `hadolint` ([hadolint](https://github.com/hadolint/hadolint), a Dockerfile
linter) using rookery's `sarif` attestor.

## Validated invocation

```bash
cilock run --step hadolint-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- sh -c 'hadolint --no-fail --format sarif Dockerfile > hadolint.sarif'
```

`cilock` invokes `hadolint` directly through `sh -c`. The full argv
(`["sh","-c","hadolint --no-fail --format sarif Dockerfile > hadolint.sarif"]`)
is recorded by the `command-run` attestor, the tracer/spy sees the real
`hadolint` process, and the `product` attestor digests the real
`hadolint.sarif` output file. The `sarif` attestor then parses that file
and folds the findings into the attestation.

`--no-fail` keeps `hadolint`'s exit code at 0 when findings are present;
without it `command-run` records `exitcode != 0` and the run terminates
before any post-product attestors fire. The findings themselves are still
preserved in the SARIF predicate either way.

## Why this shape (not `bash -c "cp ..."`)

`hadolint` writes SARIF to **stdout** only — even the latest release
(2.14.0) has no `-o/--output` file flag. The minimal `sh -c` wrapper exists
solely to redirect stdout to a file the `product` attestor can hash. We do
**not** wrap with `cp` after the fact: that anti-pattern makes `cilock` think
it ran `cp`, the spy can't trace `hadolint`, and `command-run` records the
wrong argv. Here `cilock` is genuinely the parent of `hadolint`.

## Target

The directory ships a minimal `Dockerfile` with intentional findings so the
example produces deterministic SARIF output:

- `DL3007` — `FROM alpine:latest` (unpinned tag)
- `DL3018` — `RUN apk add curl` (unpinned package)
- `DL3019` — `apk add` without `--no-cache`
- `DL3002` — final `USER root`

## Validate it locally

```bash
# from repo root, after generating _validation/key.pem
cd tool-hadolint-sarif
cilock run --step hadolint-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- sh -c 'hadolint --no-fail --format sarif Dockerfile > hadolint.sarif'

# decode the DSSE payload and list predicate types
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[].type'

# inspect the recorded command-run argv (should be the real hadolint invocation)
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

# count SARIF findings parsed by the sarif attestor
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation.report.runs[0].results | length'
```

Expected predicate types:

```
"https://aflock.ai/attestations/environment/v0.1"
"https://aflock.ai/attestations/git/v0.1"
"https://aflock.ai/attestations/material/v0.3"
"https://aflock.ai/attestations/command-run/v0.1"
"https://aflock.ai/attestations/product/v0.3"
"https://aflock.ai/attestations/sarif/v0.1"
```

Expected finding count: **4** (DL3007, DL3019, DL3018, DL3002).

## Validated against

- `hadolint` 2.14.0 (latest release as of 2026-05)
- `cilock` v0.3

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
