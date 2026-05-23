# `testssl.sh` via the `sarif` attestor

Real-infra validation example for [testssl.sh](https://testssl.sh) — the de-facto open-source TLS connection scanner. Captures four scans against four real targets under cilock and ships every envelope + every JSON output as committed evidence.

## What `testssl.sh` checks

- Protocol negotiation (flags SSLv2/3 and TLS 1.0/1.1 as deprecated)
- Full cipher matrix per protocol version
- Forward secrecy (PFS) ciphers
- Server defaults (preferred cipher order, session ticket TTL, OCSP stapling, HSTS)
- Certificate chain (issuer, key size, signature algorithm, expiry, CT log inclusion)
- Every TLS-stack vulnerability with a name: Heartbleed, ROBOT, BEAST, CRIME, POODLE, Lucky13, Logjam, FREAK, DROWN, Ticketbleed
- **FIPS 140-2/140-3** compliance via `--fips` mode — flags non-approved ciphers, hash algorithms, key sizes

## Permissions to scan

testssl.sh probes live services on the wire. Scan only targets you own or have written authorization to scan:

| Target type | OK to scan? | Notes |
|---|---|---|
| Your own public infrastructure | Yes | Mark as authorized in your runbook |
| Your own private/internal services | Yes | Requires network access — VPN, bastion host, or in-cluster pod |
| Cloud-provider managed services on your account | Usually yes | AWS [explicitly allows penetration testing](https://aws.amazon.com/security/penetration-testing/) of your own resources without prior approval; the same applies to TLS scanning. GCP and Azure have similar policies. |
| Third-party services | **No unless authorized in writing** | Cloud-provider ToS often forbid scanning their managed services without consent; subject to the [Computer Fraud and Abuse Act](https://www.law.cornell.edu/uscode/text/18/1030) and equivalent laws elsewhere |
| Deliberately-vulnerable public testbeds | Yes | [badssl.com](https://badssl.com/), [testssl.sh own site](https://testssl.sh/), [public-firing-range.appspot.com](https://public-firing-range.appspot.com/) — designed to be scanned |

## Validated invocation

```bash
# Pre-reqs: testssl.sh on PATH, ed25519 key at key.pem
cilock run --step testssl-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- testssl.sh --jsonfile-pretty testssl.json --quiet <target-host>
```

`testssl.sh` accepts a hostname, `host:port`, or IP. For FIPS-targeted scans add `--fips`:

```bash
cilock run --step testssl-fips-scan ... \
  -- testssl.sh --fips --jsonfile-pretty testssl-fips.json --quiet <target>
```

`testssl.sh` exits 0 on a clean scan even when severity findings are present — no soft-fail flag needed. (Exit ≥1 indicates a connection problem, not findings.)

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, dirty status |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over working tree |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `testssl.sh …` argv + exit code |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `testssl.json` |
| `https://aflock.ai/attestations/sarif/v0.1` | parsed testssl JSON exposed as SARIF-shaped findings |

## Four real scans committed in `raw/`

| Target | Scope | JSON size | Notable findings |
|---|---|---|---|
| `cilock.aflock.ai` | cilock docs site (Cloudflare Pages) | 71 KB | TLS 1.2 + 1.3 only; SSLv2/3 + TLS 1.0/1.1 not offered; SNI handled; modern cipher suite |
| `aflock.ai` | project marketing site (Cloudflare) | 72 KB | Same posture as cilock.aflock.ai (shared Cloudflare front) |
| `platform.testifysec.com` | TestifySec platform production | 56 KB | TLS posture for a production multi-tenant SaaS |
| `a910d5b6f605c4390953f889459fc5da-996636974.us-east-1.elb.amazonaws.com` (testifysec-demo Classic ELB) | dropbox-clone ALB | 1.2 KB | **NO TLS** on :443 — ELB only listens on port 80. `command-run/v0.1` records exit 246 (testssl connection failure); the cilock envelope still captures + signs this finding. |

The fourth one is a deliberate teaching example: a public-facing service with no TLS is a real-world finding that cilock's evidence chain catches. A release-gate policy could deny on `command-run.exitcode != 0` for the testssl step (or, with [rookery#141](https://github.com/aflock-ai/rookery/pull/144), use `--ignore-command-exit-code` and gate via Rego on whatever connection-failure structure testssl reports).

## Validate it locally

After running the invocation above against your own target:

```bash
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Expected output (when the scan completes):

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/sarif/v0.1"
]
```

Pull FIPS-relevant findings out of the captured testssl JSON:

```bash
jq '[.scanResult[0].protocols[], .scanResult[0].ciphers[], .scanResult[0].fs[]] | map(select(.severity != "OK" and .severity != "INFO"))' testssl.json
```

## Reproduce

```bash
./reproduce.sh https://your-target.example.com
```

Defaults to `cilock.aflock.ai` if no target is given.
