# `govulncheck` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of `govulncheck` ([govulncheck](https://github.com/golang/vuln)) using rookery's `sarif` attestor.

> **Note:** govulncheck also has its own dedicated cilock attestor
> (`govulncheck`, predicate type `https://aflock.ai/attestations/govulncheck/v0.1`).
> This example is intentionally the **SARIF-output** flow — useful when you
> want a unified `sarif/v0.1` predicate across many scanners.

## Validated invocation

cilock invokes `govulncheck` directly so the `command-run` attestor records the
real argv, `command-run`'s ptrace spy can trace the scanner, and the `product`
attestor captures the real SARIF file.

`govulncheck` only writes its report to **stdout** (no `-o`/`--output` flag
exists as of govulncheck v1.3.0 — see `govulncheck -h`). To redirect that
stdout into a file we use a **minimal `sh -c` wrapper**. This is **not** the
`cp` antipattern: the shell is solely doing the stdout redirect that govulncheck
itself cannot do. `command-run` therefore records
`sh -c 'govulncheck -format sarif ./... > govulncheck.sarif'`, which is the
real invocation; the spy traces govulncheck under sh; and `product` captures
the redirected file.

```bash
# (Optional) install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest

cilock run --step govulncheck-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- sh -c 'govulncheck -format sarif ./... > govulncheck.sarif'
```

Run this from the directory of the Go module you want to scan (the one with
`go.mod`). A minimal fixture module lives under `fixture/` in this example.

## Validate it locally

After running the invocation above:

```bash
# All six predicate types should be present (note: sarif/v0.1, NOT govulncheck/v0.1)
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'
# [
#   "https://aflock.ai/attestations/command-run/v0.1",
#   "https://aflock.ai/attestations/environment/v0.1",
#   "https://aflock.ai/attestations/git/v0.1",
#   "https://aflock.ai/attestations/material/v0.3",
#   "https://aflock.ai/attestations/product/v0.3",
#   "https://aflock.ai/attestations/sarif/v0.1"
# ]

# command-run records the REAL argv (sh -c wrapping govulncheck, not cp):
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("command-run/v0.1")) | .attestation.cmd'
# [
#   "sh",
#   "-c",
#   "govulncheck -format sarif ./... > govulncheck.sarif"
# ]

# sarif attestor parsed the real govulncheck SARIF:
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("sarif/v0.1")) | .attestation.report.runs[0].tool.driver.name'
# "govulncheck"
```

## Validated against

(Filled in by VM tools batch — see `/tmp/vm-results/tool-govulncheck-sarif.json`)

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Tools index](https://cilock.aflock.ai/tools)
