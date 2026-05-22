# Rookery Candidate Attestors — Matrix + Issue Drafts

Date: 2026-05-22
Scope: tools that fit `cilock`/rookery's attestor model (machine-readable JSON/SARIF
output, stable schema, supply-chain or posture signal) and don't yet have a native
rookery attestor.

Existing rookery attestors (42, at `plugins/attestors/`): `asff`, `aws-codebuild`,
`aws-config`, `aws-iid`, `commandrun`, `configuration`, `docker`, `docker-bench`,
`environment`, `gcp-iit`, `git`, `github`, `githubaction`, `githubwebhook`,
`gitlab`, `inspec`, `jenkins`, `jwt`, `k8smanifest`, `kube-bench`, `link`,
`lockfiles`, `material`, `maven`, `nessus`, `oci`, `omnitrail`, `oscap`,
`pip-install`, `policyverify`, `product`, `prowler`, `sarif`, `sbom`,
`secretscan`, `sinkhole-flows`, `slsa`, `steampipe`, `structured-data`,
`system-packages`, `vex`, `vsa`.

Two critical existing attestors set the boundary for "is this already covered?":

- **sarif** (`plugins/attestors/sarif/sarif.go`) — generic byte-preserving SARIF
  2.1.0 ingest. Any tool with stable `--format sarif` is **supported-via-existing**.
- **sbom** (`plugins/attestors/sbom/sbom.go`) — CycloneDX/SPDX ingest. Tool that
  produces standard SBOM is supported.
- **secretscan** — generic secret-scan ingest (TBD which schema it ingests; treat
  as overlapping for raw secret scanners).
- **structured-data** — generic structured ingestion.

---

## Matrix

### SAST / source code

| Tool | URL | License | JSON/SARIF flag | Maturity | Predicate it would produce | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **semgrep** | https://github.com/semgrep/semgrep | LGPL-2.1 (CLI) / commercial cloud | `--json` (schema: `semgrep-interfaces/semgrep_output_v1.jsonschema`), `--sarif` | 10k+ stars, very active, ~7 yr | Per-rule findings: rule id, path+range, severity, fix suggestion, metadata (CWE/OWASP). Stable v1 JSON. | SARIF supported via `sarif`. But native preserves Semgrep-specific fields (`metavars`, `dataflow_trace`, rule metadata) lost in SARIF transform. | **proposed-new-attestor** (native richer than SARIF) |
| **gosec** | https://github.com/securego/gosec | Apache-2.0 | `-fmt=json` or `-fmt=sarif` | ~8k stars, ~8 yr, active | Go SAST findings (rule id, file:line, severity, CWE). | SARIF flag works → covered by `sarif`. JSON has Go-specific call/issue fields not in SARIF. | **supported-via-existing** (SARIF), optional native for richer JSON |
| **bandit** | https://github.com/PyCQA/bandit | Apache-2.0 | `-f json` / `-f sarif` | ~6.7k stars, ~10 yr, active | Python SAST findings: test id, severity, confidence, CWE, file:line. | SARIF supported. | **supported-via-existing** |
| **govulncheck** | https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck | BSD-3 (golang.org/x/vuln) | `-format json` (v1.0.0 stable streaming JSON), `-format sarif` | Go team, official, stable v1 | Per-module vuln findings tied to actual reachable call traces — a *call-graph-aware* vuln signal stronger than generic SCA. | SARIF works → `sarif` covers it. But the *reachable trace* data is govulncheck-unique and gets lost in SARIF. Compliance and audit value is high. | **proposed-new-attestor** |
| **bearer** | https://github.com/Bearer/bearer | Elastic License v2 (free) | `--report security --format json`, `--report dataflow --format json` | ~7k stars, ~4 yr | PII/PHI/PD data-type inventory + risk findings + components/dependencies. Useful for GDPR/HIPAA controls. | Not directly. SARIF mode exists but loses data-flow report. | **proposed-new-attestor** |

### SCA / vulnerability scan

| Tool | URL | License | JSON/SARIF flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **trivy** | https://github.com/aquasecurity/trivy | Apache-2.0 | `--format json` (`SchemaVersion: 2`, stable), `--format sarif`, `--format cyclonedx`, `--format spdx-json`, `--format cosign-vuln` | 25k+ stars, very active, ~7 yr — the de-facto OSS scanner | Vuln findings, secrets, misconfig (IaC), license, k8s — multi-mode. | SARIF supported → `sarif`. SBOM modes → `sbom`. cosign-vuln predicate → potential native predicate. But trivy's native JSON is the canonical input for many downstream tools and includes results-per-target, rich CVSS, layer attribution, and `cosign-vuln` predicate format directly. | **proposed-new-attestor** (native trivy is high-value and richer than SARIF/SBOM views) |
| **grype** | https://github.com/anchore/grype | Apache-2.0 | `-o json`, `-o sarif`, `-o cyclonedx-json` (vex), `-o table` | ~10k stars, very active | Vuln findings against SBOM or image. Pairs natively with syft SBOMs. | SARIF supported. But grype JSON has unique `relatedVulnerabilities` and `matchDetails` (CPE/PURL match path) crucial for VEX generation. | **proposed-new-attestor** |
| **osv-scanner** | https://github.com/google/osv-scanner | Apache-2.0 | `--format json` (OSV schema), `--format sarif`, `--format cyclonedx-1-5` | 10k+ stars, Google-backed, ~3 yr, V2 in 2026 | OSV.dev-format findings (OpenSSF OSV schema). Authoritative for ecosystem vuln data. | SARIF works. But OSV schema is the canonical OpenSSF vuln format — preserving it natively is more useful than SARIF transform. | **proposed-new-attestor** |
| **snyk** | https://github.com/snyk/cli | Apache-2.0 CLI / commercial backend | `--json`, `--sarif` | Mature, requires auth token. | Vuln, license, IaC findings. | SARIF works. Native JSON better preserves Snyk's `dependencyChain`/`upgradePath` advice. Licensing/auth complications. | **supported-via-existing** (SARIF) — skip native unless customer demand |
| **cosign-vuln** | https://github.com/sigstore/cosign/blob/main/specs/COSIGN_VULN_ATTESTATION_SPEC.md | Apache-2.0 | Output of `trivy/grype --format cosign-vuln` | Spec-defined predicate type | This *is* a predicate already (`https://cosign.sigstore.dev/attestation/vuln/v1`). | A trivy/grype native attestor could opt to emit the cosign-vuln predicate directly — duplicates one downstream representation. | **subsumed by trivy/grype native attestors** (not a separate attestor) |

### SBOM generation

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **syft** | https://github.com/anchore/syft | Apache-2.0 | `-o json` (syft native), `-o cyclonedx-json`, `-o spdx-json` | 8.4k stars, active, ~5 yr | SBOM (component graph). Anchore's open SBOM tool. | The CycloneDX/SPDX outputs → existing `sbom` attestor. Native syft JSON adds source/relationship richness not in CycloneDX. | **supported-via-existing** (`sbom` ingests cyclonedx-json + spdx-json) — only propose a native `syft` attestor if syft-specific metadata (relationships, file digests) is needed for downstream use |

### Secret scanning

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **gitleaks** | https://github.com/gitleaks/gitleaks | MIT | `--report-format json` / `sarif` / `junit` / `csv` | 26k stars, active | Detected secrets (rule, file, commit, redacted match). | Existing `secretscan` attestor may already cover this (verify ingest schema). SARIF works. | **supported-via-existing** (sarif + secretscan) — confirm `secretscan` ingest covers gitleaks JSON |
| **trufflehog** | https://github.com/trufflesecurity/trufflehog | AGPL-3.0 | `--json` | 25.7k stars, active | Detected + verified-live secrets (deeper signal than gitleaks — actually attempts auth). | Native JSON not SARIF. `secretscan` may or may not ingest it. The `verified=true` flag is a uniquely valuable supply-chain signal. | **proposed-new-attestor** (if `secretscan` doesn't already cover trufflehog) |

### Container / image

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **hadolint** | https://github.com/hadolint/hadolint | GPL-3.0 (binary), MIT (rules) | `--format json`, `--format sarif`, `--format checkstyle`, `--format codeclimate` | 10k+ stars, very active, ~9 yr | Dockerfile lint findings (DL/SC rule codes, line, severity). Covers CIS Docker best practices. | SARIF → `sarif`. But Dockerfile linting is a discrete enough phase that a native attestor lets policy gate "Dockerfile clean before image build". | **proposed-new-attestor** |
| **dive** | https://github.com/wagoodman/dive | MIT | `--json <path>` and `--ci` mode | ~46k stars, mature, ~7 yr | Layer-by-layer image inefficiency: `sizeBytes`, `inefficientBytes`, `efficiencyScore`, wasted-files list. | Not SARIF. No existing coverage. Image-bloat policy gate is real. | **proposed-new-attestor** |
| **grype (container scan)** | (see SCA) | | | | | Covered above. | **see SCA row** |

### IaC

| Tool | URL | License | JSON/SARIF flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **checkov** | https://github.com/bridgecrewio/checkov | Apache-2.0 | `--output json`, `--output sarif`, `--output cyclonedx` | 7k+ stars, Bridgecrew/Prisma, very active | IaC findings across Terraform/CFN/K8s/Dockerfile/Helm/Ansible — extremely broad. | SARIF works → `sarif`. JSON has policy-pack/check-id detail and remediation links. | **proposed-new-attestor** (high-value; Checkov is the most-used OSS IaC scanner; native preserves check IDs for compliance mapping) |
| **tfsec** | https://github.com/aquasecurity/tfsec | MIT | `--format json` / `sarif` | **DEPRECATED — merged into Trivy as `trivy config`** | (same as trivy config) | Covered by proposed trivy native attestor. Don't build separately. | **not-supportable / deprecated** |
| **terrascan** | https://github.com/tenable/terrascan | Apache-2.0 | `-o json` / `sarif` | **ARCHIVED Nov 2025 (read-only)** | n/a | Don't build. | **not-supportable / archived** |
| **kics** | https://github.com/Checkmarx/kics | Apache-2.0 | `--report-formats json,sarif,html,...` | 2.5k stars, Checkmarx-backed, active | IaC findings across Terraform/K8s/Docker/Helm/Ansible/CloudFormation/OpenAPI. Strong query coverage. | SARIF works. | **proposed-new-attestor** (alternative to checkov; preserves KICS-specific query metadata) |

### Kubernetes policy / posture

| Tool | URL | License | JSON/SARIF flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **kubescape** | https://github.com/kubescape/kubescape | Apache-2.0 | `--format json` (v2 schema), `--format sarif`, `--format junit` | 11k stars, CNCF Sandbox, very active | Framework-based posture (NSA, MITRE, ArmoBest, CIS) findings against live cluster or YAML. | SARIF works. Native JSON has `frameworks[].controls[]` mapping crucial for compliance attestations (NSA/CISA, MITRE ATT&CK). | **proposed-new-attestor** |
| **kube-linter** | https://github.com/stackrox/kube-linter | Apache-2.0 | `--format json` / `sarif` / `plain` | ~3.2k stars, StackRox/RedHat, active | YAML/Helm best-practice lint (security context, resource limits, image tags). Adjacent to `k8smanifest` and `kube-bench`. | SARIF works. | **supported-via-existing** (SARIF) — optional native |
| **polaris** | https://github.com/FairwindsOps/polaris | Apache-2.0 | `--format json` / `yaml` / `score` | ~3.3k stars, Fairwinds, active | YAML and live-cluster best-practice findings with category scoring. | Not SARIF natively (depending on version). Score field is unique. | **proposed-new-attestor** |
| **opa-conftest** | https://github.com/open-policy-agent/conftest | Apache-2.0 | `--output json` / `tap` / `junit` / `github` | ~2.9k stars, CNCF, active | Rego policy results vs config (k8s YAML, Terraform JSON, Dockerfile, …). | The output is generic policy-as-code result. Adjacent to `policyverify` but conftest is *external* policy eval, not VSA. | **proposed-new-attestor** |

### Cloud posture

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **scoutsuite** | https://github.com/nccgroup/ScoutSuite | GPL-2.0 | Emits `scoutsuite-results-<provider>-<account>.js` (JSON inside JS wrapper); also pure JSON in newer versions | NCC Group, ~8 yr, active | Multi-cloud (AWS/Azure/GCP/AlibabaCloud/OCI) findings. Strong Azure/GCP coverage that `prowler` and `steampipe` lack. | Not directly. | **proposed-new-attestor** |
| **cloudsploit** | https://github.com/aquasecurity/cloudsploit | GPL-3.0 | `--console=none --json=out.json` | Aqua, active | AWS/Azure/GCP/Oracle/GitHub plugin checks. | Not directly. Overlaps `prowler` heavily; lower priority. | **proposed-new-attestor** (low priority) |
| **cloudquery** | https://github.com/cloudquery/cloudquery | MPL-2.0 / commercial plugins | n/a — writes to Postgres/etc, not a one-shot JSON report | Big project, but architecture is sync-to-DB not point-in-time scan output | Not a single attestation-shaped artifact. The DB *contents* would be the predicate, which is unbounded. | **not-supportable** (wrong shape for attestor model — emits ETL'd DB rows, not a finite report) |

### Runtime / hardening

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **lynis** | https://github.com/CISOfy/lynis | GPL-3.0 | OSS version writes `/var/log/lynis-report.dat` (key=value, **not JSON**). Enterprise has JSON. Third-party converter (`lynis-report-converter`) exists. | 13k+ stars, very mature | Host hardening findings (CIS-style). | Lacks stable upstream JSON → too brittle. | **not-supportable** (OSS lacks stable structured output; would have to parse `.dat` file) |
| **wazuh** | https://github.com/wazuh/wazuh | GPL-2.0 | Server-side platform, emits alerts via Elasticsearch/Indexer. Not a one-shot CLI report. | Big platform | Continuous alerts, not point-in-time. | Wrong shape. | **not-supportable** (continuous-monitoring system, not attestor-shaped) |
| **chef-inspec** | https://github.com/inspec/inspec | Apache-2.0 / commercial Chef | Already covered. | | | Covered by existing `inspec` attestor. | **already covered** |

### Build / CI provenance

| Tool | URL | License | JSON flag | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **goreleaser** | https://goreleaser.com | MIT (OSS) / Pro | Emits `dist/artifacts.json` and `dist/metadata.json` + SLSA attestation (via slsa-github-generator) | Very active, de-facto Go release tool | Per-release artifact manifest with digests and metadata. | Existing `slsa` attestor covers the provenance side. `artifacts.json` is not currently ingested. | **proposed-new-attestor** (small, capture `artifacts.json` + `metadata.json` for goreleaser build provenance independent of GitHub-only slsa-github-generator) |
| **bazel BES** | https://bazel.build/remote/bep | Apache-2.0 | Build Event Protocol → gRPC stream / `--build_event_json_file=out.json` | Bazel-native | Per-target build events (targets, actions, test results, outputs+digests). Authoritative build-graph attestation. | Not covered. Huge but valuable. | **proposed-new-attestor** (large effort; high enterprise value for hermetic Bazel shops) |
| **ko** | https://github.com/ko-build/ko | Apache-2.0 | `--platform`, emits OCI image with embedded SBOM by default; `ko publish` returns image digest | Active, ~6k stars | Image build provenance (Go binary → OCI + SBOM). | The output image is captured by `oci` attestor; SBOM by `sbom`. | **supported-via-existing** |
| **buildpacks (BOM)** | https://buildpacks.io | Apache-2.0 | `pack build ... --report-output-file <path>` (JSON report), `pack sbom download` (CycloneDX) | CNCF | Build report + buildpack BOM. | SBOM covered. The `report.toml`/`report.json` has Buildpacks-specific buildpack-stack provenance. | **proposed-new-attestor** (medium) |

### Test results

| Tool | URL | License | Format | Maturity | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|---|
| **JUnit XML** | de-facto standard | n/a | XML | Universal | Test results suite/case/status/time. The format has ~10 dialects, no canonical schema, but is universal. | Not covered. | **proposed-new-attestor** (small — bytes-preserving like `sarif`; predicate is the XML embedded) |
| **CTRF** | https://ctrf.io | MIT | JSON (well-defined schema) | New (2024) but growing | Modern test result format covering JS/Python/Java/Go reporters. | Not covered. | **proposed-new-attestor** (small; cleanest schema for test attestation) |
| **allure** | https://github.com/allure-framework | Apache-2.0 | Allure-native JSON per-test (`*-result.json`) + attachments — many files, not one report | 4k stars (allure2) | Rich test results. | Multi-file; harder to attest. Use JUnit/CTRF instead. | **supported-via-existing** (allure can also emit junit) — skip native |
| **pytest-json-report** | https://github.com/numirias/pytest-json-report | MIT | `--json-report --json-report-file=report.json` | ~800 stars, stable | pytest results in single JSON file. | Subsumed by CTRF or JUnit. | **supported-via-existing** |

### Sigstore-adjacent

| Tool | URL | License | Output | Predicate | Covered? | Verdict |
|---|---|---|---|---|---|---|
| **cosign verify / verify-attestation** | https://github.com/sigstore/cosign | Apache-2.0 | Prints verified in-toto Statements as JSON to stdout. | Verification result + the verified statement. | Overlap with existing `vsa` and `policyverify`. | **supported-via-existing** — the verified statement *is* an in-toto attestation that flows through the rookery chain naturally |
| **slsa-verifier** | https://github.com/slsa-framework/slsa-verifier | Apache-2.0 | Prints `PASSED:` / `FAILED:` text, with `--print-provenance` emits verified SLSA provenance JSON. | Verification result + verified SLSA provenance. | Same as cosign verify — verified provenance feeds existing `slsa` attestor; result line is text not JSON. | **proposed-new-attestor** (small — wraps slsa-verifier exit + provenance into a deterministic VSA-shaped predicate) |
| **in-toto-verify** | https://github.com/in-toto/in-toto | Apache-2.0 | Python CLI, exits 0/non-0, no structured JSON output by default | Verification pass/fail of in-toto layout. | Same shape as VSA. | **supported-via-existing** — the existing `vsa` attestor already models this |

### Misc / mentioned in brief

| Tool | Verdict |
|---|---|
| **steampipe** | already covered (existing `steampipe` attestor) |
| **chef-compliance** / chef-inspec | already covered (`inspec`) |
| **pip-audit** | possible **proposed-new-attestor** — JSON output of vulnerable pip deps; partially overlaps with `pip-install` + `lockfiles`; low priority |
| **npm audit** / **yarn audit** | `--json` outputs are not strictly stable across versions; partial overlap with `lockfiles`; **proposed-new-attestor** (low priority) |
| **terraform plan** show -json | not yet covered. **proposed-new-attestor** (preserves intent-to-change for IaC supply chain) |

---

## Issue Drafts

Each issue is ready to file at https://github.com/aflock-ai/rookery/issues.
Predicate types follow the pattern `https://aflock.ai/attestations/<name>/v0.1`.
Module paths follow the pattern `github.com/aflock-ai/rookery/plugins/attestors/<name>`.

---

### Issue 1 — Trivy native attestor

**Title:** `feat(attestors): add native Trivy attestor for vuln/misconfig/secret scans`

**Body:**

Trivy (Aqua Security, Apache-2.0, 25k+ stars) is the de-facto open-source
multi-mode scanner: image vulns, IaC misconfig (absorbed tfsec in 2024),
secrets, license, and Kubernetes. While Trivy emits SARIF (already supported
via the `sarif` attestor) and SBOM (covered by `sbom`), the native JSON output
(`--format json`, `SchemaVersion: 2`) carries per-target results, layer
attribution, CVSS vectors, fix versions, and the `cosign-vuln` predicate
format that downstream tooling expects.

Compliance/attack-model coverage: CVE/KEV gating, SLSA L3 vulnerability
attestation, FedRAMP RA-5 (vulnerability scanning), CIS Benchmarks via
`trivy config`. Replaces the now-deprecated `tfsec` and archived `terrascan`.

- Schema: https://github.com/aquasecurity/trivy/discussions/7552 (Schema v2,
  discussed for documentation in 2026)
- CLI: `trivy image --format json --output trivy.json ubuntu:24.04`
- Also supports: `trivy config`, `trivy fs`, `trivy k8s`, `trivy repo` —
  attestor should accept any of them via a single ingest pipeline.
- Predicate type: `https://aflock.ai/attestations/trivy/v0.1`
- Attestor name: `trivy`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/trivy`
- Effort: **medium** (multi-target JSON with rich nested schema; preserve
  `Results[].Vulnerabilities[]` + `Results[].Misconfigurations[]` + `Results[].Secrets[]`
  as `json.RawMessage` to be byte-stable like `sarif`)

---

### Issue 2 — Grype native attestor

**Title:** `feat(attestors): add native Grype attestor for vulnerability match results`

**Body:**

Grype (Anchore, Apache-2.0, ~10k stars) is the canonical companion to Syft
SBOMs. It produces match results with `matchDetails` (the CPE/PURL/version-range
explanation for why a vuln applies to a specific package) — data that's lost
when converted to SARIF. This explanation is critical for generating VEX
statements and for `not-affected` justification in supply-chain policy.

Compliance/attack-model coverage: NIST SSDF PS.1.1 (vulnerability scanning),
EU CRA conformity, openVEX statement input.

- Schema: https://github.com/anchore/grype/tree/main/grype/presenter/json
- CLI: `grype docker.io/library/alpine:3.20 -o json > grype.json`
- Predicate type: `https://aflock.ai/attestations/grype/v0.1`
- Attestor name: `grype`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/grype`
- Effort: **small** (single, well-structured JSON document; passthrough)

---

### Issue 3 — OSV-Scanner native attestor

**Title:** `feat(attestors): add OSV-Scanner attestor (OpenSSF OSV-schema findings)`

**Body:**

OSV-Scanner (Google, Apache-2.0, 10.3k stars, V2 in 2026) emits findings
in the canonical OpenSSF OSV schema (https://ossf.github.io/osv-schema/),
the same schema used by osv.dev. Preserving the native format lets downstream
policy reuse OSV ecosystem identifiers without lossy SARIF translation.

Compliance/attack-model coverage: SLSA L2/L3 vulnerability gating, OpenSSF
Scorecard alignment, dependency-confusion detection.

- Schema: https://google.github.io/osv-scanner/output/ — references
  https://ossf.github.io/osv-schema/
- CLI: `osv-scanner --format json --output osv.json -r .`
- Predicate type: `https://aflock.ai/attestations/osv-scanner/v0.1`
- Attestor name: `osv-scanner`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/osvscanner`
- Effort: **small**

---

### Issue 4 — Semgrep native attestor

**Title:** `feat(attestors): add native Semgrep attestor (SAST findings with metavars + dataflow)`

**Body:**

Semgrep (LGPL-2.1, 10k+ stars, ~7 yr) is one of the most adopted OSS SAST
tools. The native JSON output (schema in
`semgrep/semgrep-interfaces/semgrep_output_v1.jsonschema`) preserves
`metavars`, `dataflow_trace`, `rule_metadata.cwe`, `rule_metadata.owasp`,
and matching explanations that get flattened in the SARIF conversion.

Compliance/attack-model coverage: OWASP Top 10, CWE mapping, MITRE ATT&CK
(via custom rules), PCI-DSS 6.2/6.3 source-code scanning.

- Schema: https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema
- CLI: `semgrep --config auto --json --json-output semgrep.json`
- Predicate type: `https://aflock.ai/attestations/semgrep/v0.1`
- Attestor name: `semgrep`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/semgrep`
- Effort: **small** (single JSON doc; passthrough with summary roll-up)

---

### Issue 5 — Checkov native attestor

**Title:** `feat(attestors): add Checkov attestor for IaC misconfig findings`

**Body:**

Checkov (Bridgecrew/Prisma Cloud, Apache-2.0, 7k+ stars) is the most-deployed
OSS IaC scanner — covering Terraform, CloudFormation, Kubernetes,
Dockerfile, Helm, ARM, Serverless, Ansible, OpenAPI, and Bicep. The native
JSON preserves Checkov check IDs (e.g. `CKV_AWS_20`), guideline URLs, and
the per-resource `failed_checks` / `passed_checks` ratio used for posture
trending.

Compliance/attack-model coverage: CIS AWS/Azure/GCP, NIST 800-53, PCI-DSS,
HIPAA, SOC2 — checkov has explicit framework mappings per check.

- Docs: https://www.checkov.io/8.Outputs/JSON.html
- CLI: `checkov -d . --output json --output-file-path console,checkov.json`
- Predicate type: `https://aflock.ai/attestations/checkov/v0.1`
- Attestor name: `checkov`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/checkov`
- Effort: **medium** (large JSON tree with per-check-type sections; preserve raw)

---

### Issue 6 — Kubescape native attestor

**Title:** `feat(attestors): add Kubescape attestor for K8s framework posture (NSA, MITRE, CIS)`

**Body:**

Kubescape (CNCF Sandbox, Apache-2.0, 11k stars) scans Kubernetes manifests,
Helm charts, and live clusters against named frameworks (NSA/CISA, MITRE
ATT&CK for Kubernetes, ArmoBest, CIS, AllControls). The v2 JSON format
preserves the `frameworks[].controls[]` mapping that's mandatory for any
compliance attestation linking a finding back to a control identifier —
this data is lost in the SARIF transform.

Compliance/attack-model coverage: NSA/CISA Kubernetes Hardening Guide,
MITRE ATT&CK for Containers, CIS Kubernetes Benchmark (complements existing
`kube-bench` for cluster-state vs `kube-bench` for node-state).

- Schema: https://hub.armosec.io/docs/examples
- CLI: `kubescape scan framework nsa --format json --format-version v2 --output ks.json`
- Predicate type: `https://aflock.ai/attestations/kubescape/v0.1`
- Attestor name: `kubescape`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/kubescape`
- Effort: **small-medium**

---

### Issue 7 — govulncheck native attestor

**Title:** `feat(attestors): add govulncheck attestor (Go call-graph-aware vuln scan)`

**Body:**

govulncheck (Go team, BSD-3) is the only Go vulnerability scanner that
distinguishes "vulnerable code is imported" from "vulnerable code is
actually reachable from your call graph". The v1.0.0 streaming JSON output
preserves the reachable-trace data that is the key differentiator vs
generic SCA tools — and that data is destroyed in the SARIF conversion.

For Go-heavy projects (Judge, rookery itself, witness, archivista), this
is the single most useful Go-supply-chain attestor.

Compliance/attack-model coverage: Reachability-based vulnerability
prioritization (reduces false positives for SLSA L3 / SSDF gating), Go-module
proxy supply-chain incident response.

- Schema: https://pkg.go.dev/golang.org/x/vuln/internal/govulncheck (protocol v1.0.0)
- CLI: `govulncheck -format json -mode source ./... > vulns.json`
- Predicate type: `https://aflock.ai/attestations/govulncheck/v0.1`
- Attestor name: `govulncheck`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/govulncheck`
- Effort: **small** (streaming JSON; reconstitute Message list into a single
  predicate doc; keep the call traces verbatim)

---

### Issue 8 — Hadolint native attestor

**Title:** `feat(attestors): add Hadolint attestor for Dockerfile linting`

**Body:**

Hadolint (GPL-3.0 binary / MIT rules, 10k+ stars, ~9 yr) parses Dockerfiles
into an AST and checks them against rule codes prefixed `DL` (hadolint) and
`SC` (ShellCheck, for inline `RUN` shell). A native attestor on the linter
result lets policy gate "Dockerfile clean (no SEVERITY>=error rule fired)
before image build" — currently policy would have to reverse-engineer
hadolint's findings from a SARIF blob.

Compliance/attack-model coverage: CIS Docker Benchmark rule mapping,
prevention of unsafe `ADD`, missing `USER` directive, `latest` tag pinning.

- Docs: https://github.com/hadolint/hadolint
- CLI: `hadolint --format json Dockerfile > hadolint.json`
- Predicate type: `https://aflock.ai/attestations/hadolint/v0.1`
- Attestor name: `hadolint`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/hadolint`
- Effort: **small** (flat array of findings)

---

### Issue 9 — Bearer native attestor

**Title:** `feat(attestors): add Bearer attestor for PII/data-flow security findings`

**Body:**

Bearer CLI (Elastic License v2 — free tier, ~7k stars) is unique among SAST
tools in that it identifies 120+ sensitive data types (PII, PHI, PD) and
tracks them through code components, internal data stores, cloud data
stores, and third-party APIs. This is a *privacy* attestation, not just a
security one — it covers compliance frameworks that no other rookery
attestor speaks to.

Compliance/attack-model coverage: GDPR Art. 30 (records of processing),
HIPAA §164.308 (data-flow analysis), CCPA inventory, ISO 27701.

- Schema: https://docs.bearer.com/guides/dataflow/
- CLI: `bearer scan . --report dataflow --format json --output bearer.json`
  and `bearer scan . --report security --format json --output bearer-sec.json`
- Predicate type: `https://aflock.ai/attestations/bearer/v0.1`
- Attestor name: `bearer`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/bearer`
- Effort: **medium** (separate `security` vs `dataflow` reports;
  attestor should support both modes or split into two predicates)

---

### Issue 10 — JUnit / CTRF test-results attestor

**Title:** `feat(attestors): add test-results attestor (JUnit XML + CTRF JSON)`

**Body:**

Test-suite results are missing from rookery's attestation surface — a
critical gap for any SLSA L3+ pipeline that wants to prove "tests ran and
passed before this artifact was released". JUnit XML is the universal
de-facto format (every major test framework emits it). CTRF
(https://ctrf.io, MIT, 2024+) is a modern JSON alternative with a
well-defined schema. A single attestor should ingest both.

Compliance/attack-model coverage: SLSA L3 build process verification
(tests-ran-and-passed gate), SOC2 CC8.1 change management evidence.

- JUnit XML — no canonical schema; preserve verbatim as in `sarif`
- CTRF — https://ctrf.io/docs/schema/overview
- CLI examples: `pytest --junitxml=results.xml`, `go test -json ./... | gotestsum --junitfile=results.xml`
- Predicate type: `https://aflock.ai/attestations/test-results/v0.1`
- Attestor name: `test-results`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/testresults`
- Effort: **small** (byte-preserving ingest like `sarif`; emit summary
  pass/fail/skipped counts in predicate top-level for rego policies to gate on)

---

### Issue 11 — Conftest attestor

**Title:** `feat(attestors): add OPA/Conftest attestor for policy-eval results vs configs`

**Body:**

Conftest (CNCF, Apache-2.0, ~2.9k stars) evaluates Rego policies against
arbitrary structured config files (Kubernetes YAML, Terraform JSON,
Dockerfile, Helm). This is conceptually adjacent to rookery's
`policyverify`/VSA flow but applied to *config* not *attestations*. Capturing
conftest results as their own attestor closes the loop: policy result on
config → witness chain → policy result on policy result.

Compliance/attack-model coverage: GitOps policy enforcement evidence,
ArgoCD/Flux supply-chain policy gates.

- Docs: https://www.conftest.dev/
- CLI: `conftest test --output json deployment.yaml > conftest.json`
- Predicate type: `https://aflock.ai/attestations/conftest/v0.1`
- Attestor name: `conftest`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/conftest`
- Effort: **small**

---

### Issue 12 — Dive attestor

**Title:** `feat(attestors): add Dive attestor for container image inefficiency metrics`

**Body:**

Dive (MIT, 46k stars) reports layer-by-layer image inefficiency:
`sizeBytes`, `inefficientBytes`, `efficiencyScore` (0..1), and a list of
files duplicated/deleted across layers. While not a security tool per se,
image bloat is a supply-chain risk (larger attack surface, more transitive
deps). A rookery attestor lets policy gate "image efficiency >= 0.9 before
release" — a control absent from every other attestor.

Compliance/attack-model coverage: Image-size SLO enforcement, dead-code
leakage detection (sensitive files in deleted layers).

- Docs: https://github.com/wagoodman/dive
- CLI: `CI=true dive --json out.json my-image:latest`
- Predicate type: `https://aflock.ai/attestations/dive/v0.1`
- Attestor name: `dive`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/dive`
- Effort: **small**

---

### Issue 13 — KICS attestor (alternative IaC scanner)

**Title:** `feat(attestors): add KICS attestor for IaC misconfig findings (Checkmarx)`

**Body:**

KICS (Checkmarx, Apache-2.0, 2.5k stars) is the alternative OSS IaC scanner
to Checkov. It covers Terraform, K8s, Docker, Helm, Ansible, CloudFormation,
and OpenAPI with a different rule set (some queries unique to KICS, some
to Checkov — many orgs run both). The native JSON output keeps KICS query
IDs and severity classifications.

Compliance/attack-model coverage: same as Checkov (CIS, NIST 800-53, PCI,
HIPAA) — complement, not replacement.

- Docs: https://docs.kics.io/latest/results/
- CLI: `kics scan -p ./infra --report-formats json --output-path ./out`
- Predicate type: `https://aflock.ai/attestations/kics/v0.1`
- Attestor name: `kics`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/kics`
- Effort: **small**

---

### Issue 14 — ScoutSuite attestor

**Title:** `feat(attestors): add ScoutSuite attestor for multi-cloud security audit`

**Body:**

ScoutSuite (NCC Group, GPL-2.0) is the most mature OSS multi-cloud audit
tool, with strong Azure/GCP/Alibaba coverage that the rookery `prowler`
attestor lacks (Prowler is AWS-primary). ScoutSuite emits a single JSON
report indexed by service with per-finding `flagged_items` (resource
identifiers).

Compliance/attack-model coverage: Multi-cloud CIS Foundations (AWS/Azure/GCP),
multi-cloud incident-response control attestation.

- Docs: https://github.com/nccgroup/ScoutSuite
- CLI: `scout aws --report-dir ./scoutsuite-report --no-browser` →
  produces `scoutsuite-results-<provider>-<account>.js` (newer versions
  also emit pure JSON via `--result-format json`)
- Predicate type: `https://aflock.ai/attestations/scoutsuite/v0.1`
- Attestor name: `scoutsuite`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/scoutsuite`
- Effort: **medium** (handle the JS-wrapper-around-JSON quirk, or require
  pure JSON output mode)

---

### Issue 15 — slsa-verifier verified-result attestor

**Title:** `feat(attestors): add slsa-verifier attestor (VSA-shaped wrapper around verify-artifact result)`

**Body:**

slsa-verifier (slsa-framework, Apache-2.0) verifies SLSA provenance from
GitHub-hosted builders. The CLI exits 0/non-0 with text output, plus the
verified provenance via `--print-provenance`. A rookery attestor wraps the
exit code + the verified provenance into a deterministic VSA-shaped
predicate, so downstream rego policies can gate on "slsa-verifier said
PASSED for artifact X built by trusted-builder Y at SHA Z" without parsing
free-form stderr.

Compliance/attack-model coverage: SLSA L3+ artifact verification, downstream
consumer evidence.

- Docs: https://github.com/slsa-framework/slsa-verifier
- CLI: `slsa-verifier verify-artifact artifact.tgz --provenance-path prov.intoto.jsonl --source-uri github.com/foo/bar --print-provenance > result.json` (combined with exit code)
- Predicate type: `https://aflock.ai/attestations/slsa-verifier/v0.1`
- Attestor name: `slsa-verifier`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/slsaverifier`
- Effort: **small** (run as wrapped commandrun-like; capture exit, stdout,
  re-emit as VSA predicate)

---

### Issue 16 — TruffleHog attestor (if not covered by `secretscan`)

**Title:** `feat(attestors): add TruffleHog attestor (verified-live secret findings)`

**Body:**

Prerequisite: confirm whether the existing `secretscan` attestor already
ingests TruffleHog `--json` output. If yes, close this issue.

TruffleHog (AGPL-3.0, 25.7k stars) differentiates from gitleaks by
*verifying* discovered credentials against the live API — a `verified: true`
finding is a P0 incident, not a P3 lint. This signal is uniquely valuable
in supply-chain attestation.

Compliance/attack-model coverage: PCI-DSS 6.3.1 (no live secrets in code),
incident response evidence.

- CLI: `trufflehog filesystem . --json > th.json`
- Predicate type: `https://aflock.ai/attestations/trufflehog/v0.1`
- Attestor name: `trufflehog`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/trufflehog`
- Effort: **small**

---

### Issue 17 — Polaris (k8s) attestor

**Title:** `feat(attestors): add Polaris attestor for Kubernetes best-practice scoring`

**Body:**

Polaris (Fairwinds, Apache-2.0, ~3.3k stars) emits a `--format score` and
a JSON report that uniquely include a *score* (0-100) per check category
(`security`, `efficiency`, `reliability`). The score makes Polaris ideal
for trending/gating ("repo cannot regress below 85"), which is awkward to
encode against findings-only outputs.

Compliance/attack-model coverage: Internal platform engineering SLOs,
k8s security maturity tracking.

- Docs: https://github.com/FairwindsOps/polaris
- CLI: `polaris audit --audit-path ./k8s --format json > polaris.json`
- Predicate type: `https://aflock.ai/attestations/polaris/v0.1`
- Attestor name: `polaris`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/polaris`
- Effort: **small**

---

### Issue 18 — Buildpacks BOM/report attestor

**Title:** `feat(attestors): add Cloud Native Buildpacks build-report attestor`

**Body:**

CNCF Buildpacks emit a `report.toml` (or `--report-output-file` JSON) per
build with the buildpack stack identifiers, buildpack versions used, run
image digest, and SBOM references. Captures buildpack-specific provenance
that's adjacent to but distinct from generic SLSA.

Compliance/attack-model coverage: Heroku/Paketo/Google Cloud Buildpacks
build provenance, run-image SBOM linkage.

- Docs: https://buildpacks.io/docs/reference/spec/platform-api/
- CLI: `pack build my-app --builder paketobuildpacks/builder:base --report-output-file report.json`
- Predicate type: `https://aflock.ai/attestations/buildpacks/v0.1`
- Attestor name: `buildpacks`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/buildpacks`
- Effort: **medium**

---

### Issue 19 — goreleaser artifacts/metadata attestor

**Title:** `feat(attestors): add goreleaser attestor (artifacts.json + metadata.json ingest)`

**Body:**

goreleaser (MIT, OSS) is the de-facto Go release tool. Each release writes
`dist/artifacts.json` and `dist/metadata.json` enumerating every artifact
emitted with its digest, OS/arch, signing status, and SBOM/provenance
references. The existing `slsa` attestor covers the SLSA provenance side
(via `slsa-github-generator`); this attestor covers the release-manifest
side independent of the SLSA workflow (useful for non-GH builds).

Compliance/attack-model coverage: Release-artifact inventory, multi-target
binary supply-chain attestation.

- Docs: https://goreleaser.com/customization/metadata/
- CLI: `goreleaser release --snapshot --clean` →
  `dist/artifacts.json` + `dist/metadata.json`
- Predicate type: `https://aflock.ai/attestations/goreleaser/v0.1`
- Attestor name: `goreleaser`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/goreleaser`
- Effort: **small**

---

### Issue 20 — Bazel BES build-event attestor (stretch)

**Title:** `feat(attestors): add Bazel Build Event Protocol attestor`

**Body:**

Bazel emits the canonical hermetic-build event stream via
`--build_event_json_file=path` (or BES gRPC). The stream describes every
target built, every action executed, every test run, and every output
artifact with content-addressed digests — the closest thing to a perfect
build-provenance attestation that exists. Filing this as a stretch
proposal: large effort, big payoff for Bazel-heavy orgs.

Compliance/attack-model coverage: SLSA L4 hermetic build evidence,
reproducible-build attestation, dependency-graph audit.

- Docs: https://bazel.build/remote/bep
- CLI: `bazel build //... --build_event_json_file=bep.json`
- Predicate type: `https://aflock.ai/attestations/bazel-bep/v0.1`
- Attestor name: `bazel-bep`
- Module path: `github.com/aflock-ai/rookery/plugins/attestors/bazelbep`
- Effort: **large** (streaming JSON, many event types, must roll up into
  summary predicate while keeping a digest of the raw stream)

---

## Top-10 ranked by impact / effort

Ranking criteria: (a) frequency-of-use in TestifySec/Judge customer pipelines,
(b) breadth of compliance-framework coverage, (c) ratio of unique signal to
attestor effort, (d) whether competitors/peers already attest this tool, (e)
deprecation/maturity risk.

1. **Trivy** (#1, Issue 1) — Single most-used OSS scanner; covers vuln + IaC
   + secrets + license + k8s in one tool. Subsumes deprecated tfsec/terrascan.
   The native attestor unlocks many policies at once.
2. **govulncheck** (#7) — Best-in-class for Go; call-graph reachability is
   unique and high-value for rookery itself (Go monorepo). Easy win because
   the schema is small and stable.
3. **Test-results (JUnit + CTRF)** (#10) — Glaring omission from rookery
   today. Every CI pipeline produces test results; SLSA L3 essentially
   requires attesting them. Tiny effort.
4. **Semgrep** (#4) — Most adopted OSS SAST; native preserves rule metadata
   and dataflow info that SARIF erases.
5. **Checkov** (#5) — Most-deployed OSS IaC scanner with explicit compliance
   framework mappings; replaces deprecated tfsec.
6. **OSV-Scanner** (#3) — Google-backed, canonical OSV schema, OpenSSF
   alignment. Will be the OpenSSF reference scanner.
7. **Kubescape** (#6) — CNCF Sandbox, named-framework posture (NSA, MITRE),
   ideal companion to existing `kube-bench` and `k8smanifest`. The framework
   mapping is the killer feature.
8. **Grype** (#2) — Natural pair with `sbom`. `matchDetails` powers VEX flow.
9. **Hadolint** (#8) — Small effort, ubiquitous in Docker pipelines, CIS
   Docker Benchmark coverage at Dockerfile level (complements `docker-bench`
   at host level).
10. **Conftest** (#11) — Closes the policy-on-config loop next to the
    existing policy-on-attestation flow (`policyverify`). Small effort,
    high architectural symmetry.

Honorable mentions (file after the top-10):
- **Bearer** — unique privacy/PII coverage, but Elastic License v2 may add
  friction for some downstream redistributors. Worth doing, slightly later.
- **slsa-verifier wrapper** — small but only useful when SLSA-shaped
  inputs are flowing; not a daily-use predicate.
- **Dive** — niche but cheap.
- **TruffleHog** — verify whether `secretscan` already ingests it first.
- **Polaris** — score-based, useful, but kube-bench + kubescape already
  cover much of the territory.
- **KICS** — only after Checkov is in place; redundant rule set.
- **ScoutSuite** — only matters if/when multi-cloud (Azure/GCP) demand
  shows up; Prowler covers AWS already.

## Verdicts at a glance

| Verdict | Count | Tools |
|---|---|---|
| supported-via-existing | 8 | gosec, bandit, snyk, syft (via sbom), gitleaks (via secretscan/sarif), ko, in-toto-verify (via vsa), kube-linter (via sarif), allure (via junit), pytest-json-report |
| proposed-new-attestor | 17 | trivy, grype, osv-scanner, semgrep, checkov, kubescape, govulncheck, hadolint, bearer, test-results (junit+ctrf), conftest, dive, kics, scoutsuite, slsa-verifier wrapper, trufflehog, polaris, buildpacks, goreleaser, bazel-bep |
| not-supportable | 4 | cloudquery (wrong shape — DB sync, not report), lynis (OSS lacks stable structured output), wazuh (continuous platform, not point-in-time), tfsec/terrascan (deprecated/archived) |
