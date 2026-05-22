# `Semgrep` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `Semgrep` ([semgrep](https://github.com/semgrep/semgrep)) using rookery's `sarif` attestor.

## Validated invocation

```bash
cilock run --step semgrep-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- semgrep --config p/security-audit --sarif --output semgrep.sarif fixture/
```

`--config p/security-audit` uses the bundled Semgrep Registry ruleset (no
account or API key required). For the broader auto-selected ruleset, use
`--config auto` instead — that path requires network access to the Semgrep
Registry but does not require auth.

A small Python fixture under `fixture/` (intentional MD5 / `shell=True`
patterns) is committed so the example produces a non-empty SARIF report
out of the box.

## Why this shape

`cilock run -- <tool> <args>` invokes the tool **directly**. The previous
revision of this example wrapped the invocation in
`bash -c "cp ..."`, which meant:

- `command-run` recorded `bash` (and its `-c` string), **not** the actual
  semgrep argv — so consumers couldn't see which ruleset ran.
- The spy / ptrace-based attestors traced `cp`, not `semgrep`, so material
  → product causality was wrong.
- The `sarif` attestor still had to scrape a file that `cilock` did not
  see produced inside the traced process tree.

With the corrected shape:

- `command-run` records `["semgrep", "--config", "p/security-audit", "--sarif", "--output", "semgrep.sarif", "fixture/"]` verbatim.
- `product` captures `semgrep.sarif` as a real output of the traced
  process (recorded in the v0.3 Merkle tree under
  `product/v0.3/tree:products`).
- `sarif` parses that same file and surfaces structured findings the
  policy's rego gate can evaluate.

## Validate it locally

```bash
# 1. Key + workspace
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 2. Install semgrep (one of):
brew install semgrep          # macOS
pipx install semgrep          # any platform with pipx

# 3. Run from this directory
cd tool-semgrep-sarif
PATH=/path/to/cilock-dir:$PATH cilock run --step semgrep-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- semgrep --config p/security-audit --sarif --output semgrep.sarif fixture/

# 4. Confirm all six predicates are present
jq -r '.payload' attestation.json | base64 -d \
  | jq -r '.predicate.attestations[].type'
# https://aflock.ai/attestations/environment/v0.1
# https://aflock.ai/attestations/git/v0.1
# https://aflock.ai/attestations/material/v0.3
# https://aflock.ai/attestations/command-run/v0.1
# https://aflock.ai/attestations/product/v0.3
# https://aflock.ai/attestations/sarif/v0.1

# 5. Confirm command-run captured real semgrep argv (not bash -c)
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

# 6. Inspect sarif findings count + tool driver
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {tool: .report.runs[0].tool.driver.name,
           findings: ([.report.runs[].results[]] | length),
           report_file: .reportFileName}'
```

## Validated against

- cilock dev (v0.3 line)
- Semgrep OSS 1.157.0
- Ruleset: `p/security-audit` (Semgrep Registry, no auth)
- Result: 1 finding on the bundled `fixture/vuln.py`

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
