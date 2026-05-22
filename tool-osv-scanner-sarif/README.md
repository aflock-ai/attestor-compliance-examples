# `OSV-Scanner` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `OSV-Scanner` ([osv-scanner](https://github.com/google/osv-scanner)) using
rookery's `sarif` attestor.

## Validated invocation

`cilock` invokes `osv-scanner` directly. There is no `bash -c` wrapper and no
post-hoc `cp` — the scanner writes its SARIF report straight to disk, and
every cilock attestor (`command-run`, `material`, `product`, `sarif`) observes
the real process tree and the real output file.

```bash
# osv-scanner v2+ uses --output-file (older versions used --output).
cilock run --step tool-osv-scanner \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- osv-scanner --format sarif --output-file osv.sarif fixtures/
```

The `fixtures/` directory contains a minimal `go.mod` + `go.sum` so the
example is self-contained; point `osv-scanner` at any directory with
supported lockfiles (`go.sum`, `package-lock.json`, `Pipfile.lock`,
`Cargo.lock`, `pom.xml`, etc.) and the same shape works.

## Why this shape

The earlier version of this README wrapped the invocation in
`bash -c "cp …"`. That breaks the attestation chain in three places:

- **`command-run`** records `["bash","-c","cp …"]` instead of the real
  scanner argv. A verifier inspecting the attestation has no evidence that
  `osv-scanner` ever ran.
- **`product`** captures whatever file `cp` produced, not the file the
  scanner emitted. The merkle root no longer binds to the tool's output.
- **`sarif`** parses a copy that the build script wrote — a malicious or
  buggy wrapper could substitute arbitrary SARIF and the chain wouldn't
  notice.

Running `osv-scanner` as cilock's direct subcommand keeps argv, exit code,
working directory, and product hashes bound to the actual scanner
invocation. That's the whole point of `command-run`.

## Validate it locally

```bash
# 1. Generate a signing key (ed25519).
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 2. From this directory, run the cilock command above.
cd tool-osv-scanner-sarif

# 3. Confirm all six predicate types are present.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[].type'
# https://aflock.ai/attestations/environment/v0.1
# https://aflock.ai/attestations/git/v0.1
# https://aflock.ai/attestations/material/v0.3
# https://aflock.ai/attestations/command-run/v0.1
# https://aflock.ai/attestations/product/v0.3
# https://aflock.ai/attestations/sarif/v0.1

# 4. Confirm command-run captured the real osv-scanner argv.
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[]
         | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        ][0].attestation.cmd'
# [ "osv-scanner", "--format", "sarif", "--output-file", "osv.sarif", "fixtures/" ]

# 5. Confirm the sarif attestor parsed the report.
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[]
         | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        ][0].attestation
       | {reportFileName, findings: [.report.runs[].results[]] | length}'
# { "reportFileName": "osv.sarif", "findings": <N> }
```

## Validated against

- `osv-scanner` v2.3.8 (`osv-scalibr` v0.4.5) on macOS arm64
- `cilock` v0.3 (dev), DSSE envelope, ed25519 signer
- Fixture: `fixtures/go.sum` (testify v1.8.0 dependency tree); produced 40
  SARIF results across `stretchr/testify`, `davecgh/go-spew`,
  `pmezard/go-difflib`, and `gopkg.in/yaml.v3`.

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
