# `OWASP ZAP` via the `sarif` attestor

Tool-integration example: capture an [OWASP ZAP](https://www.zaproxy.org/) DAST scan under cilock so the SARIF report becomes a signed v0.3 attestation parsed by the rookery `sarif` attestor.

ZAP is the most popular open-source DAST scanner — it proxies traffic to a running web application, runs passive and active scan rules against every request/response, and flags OWASP Top 10 issues (CSP misconfigurations, info disclosure, injection, etc.). ZAP doesn't have a one-flag SARIF switch like Trivy or Semgrep do; the canonical way to emit SARIF is via ZAP's **automation framework** plan that ends in a `report` job with `template: sarif-json` (the SARIF template ships with the `reports` add-on, included in the `zaproxy/zap-stable` Docker image).

## Validated invocation

cilock invokes the `docker` CLI **directly** as the wrapped command. There is no `bash -c "cp ..."` shim — the real `docker run ...` argv is what cilock executes, traces, and records. ZAP writes `zap.sarif.json` into the bind-mounted working directory, so `product/v0.3` hashes the file the scan actually wrote.

```bash
cilock run --step zap-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- docker run --rm --network host \
       -v "$(pwd):/zap/wrk/:rw" \
       zaproxy/zap-stable \
       zap.sh -cmd -autorun /zap/wrk/zap-plan.yaml
```

The companion `zap-plan.yaml` describes a baseline (passive-only) scan against `http://localhost:3000`:

```yaml
env:
  contexts:
    - name: target
      urls:
        - http://localhost:3000
  parameters:
    failOnError: false
jobs:
  - type: passiveScan-config
    parameters: { maxAlertsPerRule: 10, scanOnlyInScope: true }
  - type: spider
    parameters: { context: target, url: http://localhost:3000, maxDuration: 1 }
  - type: passiveScan-wait
    parameters: { maxDuration: 2 }
  - type: report
    parameters:
      template: sarif-json
      reportDir: /zap/wrk
      reportFile: zap.sarif        # ZAP appends `.json` → zap.sarif.json
      reportTitle: ZAP Baseline against Juice Shop
```

Notes:
- ZAP's `report` job appends `.json` to `reportFile` when the SARIF template is selected, so the on-disk artifact is `zap.sarif.json`.
- `failOnError: false` keeps the automation plan's exit code 0 even when findings are present. With it true, ZAP exits non-zero and cilock's `command-run/v0.1.exitcode` is non-zero; downstream policy can branch either way.
- `--network host` lets the container reach a target running on the host's `localhost`. On macOS Docker Desktop this still resolves correctly because the network namespace tunnels through the Docker VM.

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

`command-run.cmd` records the literal docker argv (no `bash`, no `cp`):

```json
[
  "docker", "run", "--rm", "--network", "host",
  "-v", "/tmp/ex-zap/tool-zap-sarif:/zap/wrk/:rw",
  "zaproxy/zap-stable",
  "zap.sh", "-cmd", "-autorun", "/zap/wrk/zap-plan.yaml"
]
```

## Raw envelope + SARIF (real data)

This directory contains the captured artifacts from a real cilock + ZAP run against an OWASP Juice Shop instance on `http://localhost:3000`:

- `raw/attestation.json` — the full signed DSSE envelope (~224 KB). Inspect with `jq -r '.payload' raw/attestation.json | base64 -d | jq`.
- `raw/zap.sarif.json` — the SARIF document ZAP wrote (~188 KB), **19 findings** in 4 distinct rules:
  - `10038` Content Security Policy (CSP) Header Not Set — warning × 5
  - `10096` Timestamp Disclosure (Unix epoch) — note × 5
  - `10098` Cross-Domain Misconfiguration — warning × 4
  - `10109` Modern Web Application — none (informational) × 5

## Why this shape

- **Direct invocation.** `cilock run -- docker run ...` means the `command-run/v0.1` attestor records the real `argv` (`["docker","run",...]`) and the real exit code. The spy/ptrace layer traces `docker`'s syscalls — not `bash`'s, not `cp`'s. The ZAP work happens inside a container the `docker` CLI owns; from cilock's perspective the wrapped binary is `docker` itself, the same binary the user types in their terminal.
- **Bind-mounted product capture.** `-v $(pwd):/zap/wrk/:rw` mounts the working directory into the container at the path ZAP's `reportDir` points at. When ZAP writes `/zap/wrk/zap.sarif.json` inside the container, that file lands at `$(pwd)/zap.sarif.json` on the host — the same directory cilock scans for products. `product/v0.3` picks it up as a Merkle-leaf product.
- **`sarif` attestor parses the output.** ZAP's `sarif-json` report template produces a SARIF 2.1.0 document. The sarif attestor (postproduct) accepts any product whose detected MIME is `application/json` and whose bytes are valid JSON, embeds the report verbatim into a `sarif/v0.1` predicate, and records the file's digest.
- **`environment` + `git` for provenance.** Bind the scan to the host environment and the exact git commit the example repo was checked out at.

## Reproduce

```bash
# Prereqs:
#   - cilock v0.3 on PATH
#   - docker installed and running (Docker Desktop on macOS, dockerd on Linux)
#   - an ed25519 signing key at key.pem (generate with: openssl genpkey -algorithm ed25519 -out key.pem)
#   - the zaproxy/zap-stable image pulled (docker pull zaproxy/zap-stable)
#   - a target running on localhost:3000. The reproduce script starts Juice Shop:
#       docker run --rm -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

./reproduce.sh
```

The script:
1. Starts (or reuses) a Juice Shop container on `localhost:3000`.
2. Generates `key.pem` if missing.
3. Invokes `cilock run ... -- docker run ... zap.sh -cmd -autorun zap-plan.yaml`.
4. Prints the predicate types, the captured argv, and the SARIF finding count.
5. Stops the Juice Shop container.

## Validated against

- ZAP 2.17.0 (via the `zaproxy/zap-stable` Docker image)
- Docker 28.4.0 (Desktop on macOS arm64)
- OWASP Juice Shop (`bkimminich/juice-shop:latest`) on `http://localhost:3000`
- cilock v0.3 (rookery main post-#117)
- Scan duration: ~32 seconds (spider 18s + passive-scan + report generation)
- Findings: 19 alerts in 4 distinct rules (CSP, timestamp disclosure, cross-domain misconfig, modern-web-app)

## See also

- [cilock-docs: tools/zap](https://cilock.aflock.ai/tools/zap) — the user-facing doc
- [`sarif` attestor](https://cilock.aflock.ai/attestors/sarif) — the underlying ingestion path
- [OWASP ZAP project](https://www.zaproxy.org/) — upstream
- [`zaproxy/zap-stable` on Docker Hub](https://hub.docker.com/r/zaproxy/zap-stable) — the container used here
- [ZAP automation framework docs](https://www.zaproxy.org/docs/automate/automation-framework/) — for plan-yaml extensions (active scan, auth, etc.)
