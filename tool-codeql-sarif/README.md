# `CodeQL` via the `sarif` attestor

Tool-integration example: capture a [GitHub CodeQL](https://codeql.github.com/) scan under cilock so the SARIF report becomes a signed v0.3 attestation parsed by the rookery `sarif` attestor.

CodeQL is a two-step flow — first build a CodeQL **database** from the source tree, then **analyze** it against a query suite. Only the analyze step produces structured findings, so that's the step we wrap with cilock. The database creation is a build artifact you can either pre-build outside cilock or wrap as its own discrete step.

## Validated invocation

```bash
# Step 1 (outside cilock): build the CodeQL database for the language.
codeql database create codeql-db \
  --language=python \
  --source-root=src

# Step 2 (wrapped): cilock invokes codeql analyze directly. The SARIF is
# captured as a v0.3 product Merkle leaf; the sarif attestor parses it.
cilock run --step codeql-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- codeql database analyze codeql-db \
       --format=sarif-latest \
       --output=codeql.sarif \
       codeql/python-queries:codeql-suites/python-security-and-quality.qls
```

Notes:
- The query-pack reference `codeql/python-queries:codeql-suites/python-security-and-quality.qls` covers both security and code-quality queries. The narrower `python-code-scanning.qls` is the GitHub-default; switch the suite to match what your GitHub Advanced Security configuration runs.
- For other languages, swap `python-queries` for `go-queries`, `javascript-queries`, `java-queries`, `cpp-queries`, `csharp-queries`, `ruby-queries`, or `swift-queries`.
- `codeql database analyze` exits 0 even when findings are present, so no `-no-fail` shim is needed.

## What gets captured

The captured envelope's `.predicate.attestations[].type` list:

```json
[
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/sarif/v0.1"
]
```

`command-run.cmd` records the literal codeql argv (no `bash`, no `cp`):

```json
[
  "codeql", "database", "analyze", "codeql-db",
  "--format=sarif-latest", "--output=codeql.sarif",
  "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
]
```

## Raw envelope + SARIF (real data)

This directory contains the captured artifacts from a real cilock + codeql run against the fixture in `src/vulnerable.py`:

- `raw/attestation.json` — the full signed DSSE envelope (279 KB). Inspect with `jq -r '.payload' raw/attestation.json | base64 -d | jq`.
- `raw/codeql.sarif` — the SARIF document CodeQL wrote (134 KB), 6 findings:
  - `py/code-injection` (CWE-94: untrusted input → `eval()`)
  - `py/sql-injection` (CWE-89: string-concat SQL on HTTP query)
  - `py/xml-bomb` (CWE-611: XXE via `ET.fromstring(request.data)`)
  - `py/command-line-injection` (CWE-78: HTTP query → `subprocess.check_output(..., shell=True)`)
  - `py/unused-import` × 2 (quality)

## Fixture

`src/vulnerable.py` is a deliberately bad Flask app with one route per CWE. Inspect it; do NOT deploy it.

## Reproduce

```bash
# Prereqs: cilock v0.3 on PATH, codeql CLI on PATH (https://github.com/github/codeql-cli-binaries/releases),
# an ed25519 signing key at key.pem, and the python-queries pack downloaded:
codeql pack download codeql/python-queries

# Build the database, then run cilock-wrapped analyze:
codeql database create codeql-db --language=python --source-root=src --overwrite
cilock run --step codeql-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- codeql database analyze codeql-db \
       --format=sarif-latest \
       --output=codeql.sarif \
       codeql/python-queries:codeql-suites/python-security-and-quality.qls

# Verify:
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
jq '.runs[0].results | length' codeql.sarif    # expected: 6 against this fixture
```

## Validated against

- CodeQL CLI 2.25.5 (macOS arm64)
- CodeQL python-queries 1.8.3
- cilock v0.3 (rookery main post-#136)
- Fixture: 1-file Flask app, 6 findings, 0 errors (CodeQL warnings/notes; severity gating is policy-side)

## See also

- [cilock-docs: tools/codeql](https://cilock.aflock.ai/tools/codeql) — the user-facing doc
- [`sarif` attestor](https://cilock.aflock.ai/attestors/sarif) — the underlying ingestion path
- [GitHub CodeQL CLI manual](https://docs.github.com/en/code-security/codeql-cli)
- [`github/codeql-cli-binaries` releases](https://github.com/github/codeql-cli-binaries/releases) — where to download codeql
