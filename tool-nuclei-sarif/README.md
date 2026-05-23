# `nuclei` via the `sarif` attestor

This is a **tool integration example** — it shows how to attest the output
of [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei)
using rookery's `sarif` attestor (predicate type
`https://aflock.ai/attestations/sarif/v0.1`).

Nuclei is the fastest-growing template-based scanner — a community-maintained
library of ~13,000 YAML templates covering CVEs, default credentials,
exposed dashboards, security-header misconfigurations, tech fingerprints,
and DAST checks. Cilock doesn't replace Nuclei; it wraps the same
`nuclei -sarif-export <file>` invocation you already use and turns the
SARIF report into a **signed v0.3 in-toto attestation** with `command-run`,
`material`, `product`, and parsed `sarif` predicates.

No new attestor is required — Nuclei emits SARIF natively via
`-sarif-export <file>`, and the existing `sarif` attestor handles it.

## Validated invocation

cilock invokes `nuclei` directly so the `command-run` attestor records the
real argv, the ptrace spy can trace the scanner's syscalls, and the
`product` attestor captures the actual SARIF file written by nuclei (not a
`cp` of one written outside cilock's view).

Nuclei exits with code `0` when findings are present, so no soft-fail flag
is needed. Rate-limiting (`-rl 20`) and per-host concurrency (`-c 25`) keep
us polite against shared testbeds; `-timeout 8 -retries 1` keeps the scan
deterministic.

```bash
cilock run --step nuclei-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- nuclei \
       -u https://public-firing-range.appspot.com/ \
       -t http/exposures/ -t http/technologies/ -t http/misconfiguration/ \
       -sarif-export nuclei.sarif \
       -rl 20 -c 25 -no-color -stats -timeout 8 -retries 1
```

Run `nuclei -update-templates` once before the first scan so the template
library is on disk (~13,000 templates) and the scan is reproducible.

## What we ran against

This directory's [`raw/attestation.json`](./raw/attestation.json) and
[`raw/nuclei.sarif`](./raw/nuclei.sarif) are the **actual signed envelope
and Nuclei report** produced by running the command above against Google's
[Public Firing Range](https://public-firing-range.appspot.com/) — a
deliberately-vulnerable XSS / DOM-clobbering / header-misconfiguration
testbed published by Google's security team. The scan loaded 2,521
templates and completed in ~4m27s.

| | |
| --- | --- |
| Nuclei version | v3.8.0 |
| Templates loaded | 2,521 (subset: `http/exposures/`, `http/technologies/`, `http/misconfiguration/`) |
| Target | `https://public-firing-range.appspot.com/` |
| Findings | 14 (all info-severity: `http-missing-security-headers` matches) |
| Scan duration | 4m 27s |
| Envelope size | 34,776 bytes |
| SARIF size | 14,423 bytes |

The 14 findings all match the `http-missing-security-headers` template
family — the firing range deliberately omits CSP, HSTS, X-Frame-Options,
referrer-policy, COEP/COOP/CORP, etc. so any DAST run against it produces
a stable, non-empty SARIF report.

## Why this shape

`cilock run -- nuclei -u <target> -sarif-export nuclei.sarif` invokes
nuclei directly. The antipattern would be wrapping in `bash -c "cp ..."`,
which breaks three properties at once:

- `command-run/v0.1.cmd` would record `bash -c '<string>'` instead of the
  literal `nuclei` argv. A reviewer reading the envelope couldn't tell
  which templates / rate limits / target the scan ran against.
- The ptrace spy would trace `cp`, not `nuclei` — so material→product
  causality is wrong; the spy never observes nuclei reading its template
  files or writing the SARIF.
- `product/v0.3` would capture a copy of a file written *outside* cilock's
  view. The digest in `product` would equal the source SARIF, but cilock
  never observed it being produced.

With the direct invocation:
- `command-run` records `["nuclei","-u","https://...","-t","http/exposures/",..."-sarif-export","nuclei.sarif",...]` verbatim.
- The spy traces nuclei's syscalls (HTTP requests, template reads, the SARIF write).
- `product` captures the SARIF file nuclei actually wrote in CWD.
- `sarif` parses that same file — its digest matches what `product` recorded.

## Validate it locally

After running the invocation above (the captured artifacts in
[`raw/`](./raw) reproduce identically):

```bash
# 1. All six predicate types should be present
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

# 2. command-run records the REAL nuclei argv (no bash, no cp)
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'
# ["nuclei","-u","https://public-firing-range.appspot.com/","-t","http/exposures/",
#  "-t","http/technologies/","-t","http/misconfiguration/","-sarif-export","nuclei.sarif",
#  "-rl","20","-c","25","-no-color","-stats","-timeout","8","-retries","1"]

# 3. sarif attestor parsed the real findings
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {tool: .report.runs[0].tool.driver.name,
           findings: ([.report.runs[].results[]] | length),
           reportFileName}'
# { "tool": "Nuclei", "findings": 14, "reportFileName": "nuclei.sarif" }
```

## Reproduce

See [`reproduce.sh`](./reproduce.sh). One-liner:

```bash
./reproduce.sh
```

## See also

- [`sarif` attestor docs](https://cilock.aflock.ai/attestors/sarif)
- [Nuclei tool page](https://cilock.aflock.ai/tools/nuclei)
- [Tools index](https://cilock.aflock.ai/tools)
- [Nuclei upstream](https://github.com/projectdiscovery/nuclei)
- [Google Public Firing Range](https://public-firing-range.appspot.com/) — the validated target
