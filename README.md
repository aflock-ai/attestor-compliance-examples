# Attestor Compliance Examples

Real-data, end-to-end validation examples for every attestor in
[`aflock-ai/rookery`](https://github.com/aflock-ai/rookery), plus tool
integration recipes and a multi-step policy framework. Every example is
**validated through the full cycle**: run → sign → verify with a real
policy. No synthetic fixtures unless the attestor's data source
requires it (commercial scanner license, hard-coded sidecar bind-mount,
etc.).

## What you get per example

```
<NN>-<attestor>/
├── README.md                     # what cilock adds + when to use it
├── reproduce.sh                  # the validated cilock run invocation
└── policy/
    ├── policy.json               # multi-step verify policy (human-readable)
    ├── policy-signed.json        # DSSE-signed via test key
    ├── decoded-rego-*.txt        # plain-text Rego (LLM/reviewer friendly)
    ├── verify-recipe.sh          # the validated cilock verify invocation
    └── expected-verify-output.txt # captured PASS or DEMO-of-deny output
```

A PASS proves the multi-step contract holds. A documented DENY in
`DEMO-NOTES.md` proves the gate caught a real finding — that's the value
cilock adds over running the scanner standalone.

## Multi-step policy framework

The policy/ directory in each example asserts a contract across multiple
attestation types: not just "have a signed envelope," but "the envelope
contains env + material + command-run + product + tool attestations, all
signed by the same trusted functionary, and the tool's findings pass
Rego policies that gate on actual scan content."

The shared infrastructure lives at [`_policy-templates/`](./_policy-templates/):

- [`policy-shape.md`](./_policy-templates/policy-shape.md) — annotated walk-through of policy.json fields
- [`backref-subjects.md`](./_policy-templates/backref-subjects.md) — how attestors layer via shared subject digests (the cross-attestation graph)
- [`rego-snippets/`](./_policy-templates/rego-snippets/) — drop-in Rego policies for common gates
- [`verify-recipe-template.sh`](./_policy-templates/verify-recipe-template.sh) — sign + verify flow template

[`28-prowler/policy/`](./28-prowler/policy/) is the canonical exemplar.

## Status

**26/42 attestors validated against real infrastructure**, 5 pending VM
batch completion, 6 blocked on external constraints, 5 verify-time or
doc-only by design. See per-attestor READMEs for the exact scenario.

**10 tool integrations** layered on top: Trivy, Syft, Grype, Semgrep, gosec,
Hadolint, Checkov, Kubescape, OSV-Scanner, govulncheck. 5 fully validated
(grype/syft/osv-scanner PASS; gosec/hadolint correctly DENY on real
findings — the gate working). Remaining 5 in the VM batch backlog.

Plus [`43-trivy-attack-detection/`](./43-trivy-attack-detection/) — the
full reproduction + 3-layer detection of the March 2026 trivy-action
tag-rewrite supply-chain attack, consolidated from the standalone
`cilock-trivy-detection-test` repo.

Plus [`multi-step-attestationsFrom/`](./multi-step-attestationsFrom/) —
a build → scan → release-gate policy demonstrating the `attestationsFrom`
cross-step contract. The release step's Rego pulls attestations from both
earlier steps via `attestationsFrom: ["build", "scan"]` and enforces
invariants that no single-step Rego block could express (the scanner ran
against the artifact we're shipping, AND the scan was clean).

## Attestor coverage

| # | Attestor | Category | Status | Real-data source | Example |
|---|---|---|---|---|---|
| 1 | `command-run` | core | validated | local | [01-command-run/](./01-command-run/) |
| 2 | `product` | core | validated | local | [02-product/](./02-product/) |
| 3 | `material` | core | validated | local | [03-material/](./03-material/) |
| 4 | `environment` | core | validated | local | [04-environment/](./04-environment/) |
| 5 | `git` | core | validated | local | [05-git/](./05-git/) |
| 6 | `configuration` | core | validated | local | [06-configuration/](./06-configuration/) |
| 7 | `lockfiles` | build | validated | local | [07-lockfiles/](./07-lockfiles/) |
| 8 | `link` | build | validated | local | [08-link/](./08-link/) |
| 9 | `sbom` | build | validated | local | [09-sbom/](./09-sbom/) |
| 10 | `maven` | build | validated | local | [10-maven/](./10-maven/) |
| 11 | `pip-install` | build | validated | mac-pypi | [11-pip-install/](./11-pip-install/) |
| 12 | `omnitrail` | build | validated | local | [12-omnitrail/](./12-omnitrail/) |
| 13 | `k8smanifest` | build | validated | local | [13-k8smanifest/](./13-k8smanifest/) |
| 14 | `system-packages` | build | validated | vm-amzn2023 | [14-system-packages/](./14-system-packages/) |
| 15 | `oci` | container | validated | vm | [15-oci/](./15-oci/) |
| 16 | `docker` | container | pending | vm-buildx | [16-docker/](./16-docker/) |
| 17 | `docker-bench` | container | pending | vm | [17-docker-bench/](./17-docker-bench/) |
| 18 | `kube-bench` | container | pending | vm-eks | [18-kube-bench/](./18-kube-bench/) |
| 19 | `github` | ci | validated | gh-actions | [19-github/](./19-github/) |
| 20 | `github-action` | ci | validated | gh-actions | [20-github-action/](./20-github-action/) |
| 21 | `githubwebhook` | ci | blocked | webhook-scope | [21-githubwebhook/](./21-githubwebhook/) |
| 22 | `gitlab` | ci | doc-only | no-gitlab | [22-gitlab/](./22-gitlab/) |
| 23 | `jenkins` | ci | validated | local-env | [23-jenkins/](./23-jenkins/) |
| 24 | `aws-codebuild` | ci | validated | vm-env | [24-aws-codebuild/](./24-aws-codebuild/) |
| 25 | `aws` | cloud | validated | vm-ec2 | [25-aws/](./25-aws/) |
| 26 | `gcp-iit` | cloud | blocked | gcloud-pending | [26-gcp-iit/](./26-gcp-iit/) |
| 27 | `jwt` | cloud | blocked | gcloud-pending | [27-jwt/](./27-jwt/) |
| 28 | `prowler` | compliance | validated | mac-real-aws | [28-prowler/](./28-prowler/) |
| 29 | `oscap` | compliance | validated | vm-ssg | [29-oscap/](./29-oscap/) |
| 30 | `inspec` | compliance | pending | vm | [30-inspec/](./30-inspec/) |
| 31 | `steampipe` | compliance | pending | vm | [31-steampipe/](./31-steampipe/) |
| 32 | `structured-data` | compliance | blocked | cli-gap | [32-structured-data/](./32-structured-data/) |
| 33 | `aws-config` | compliance | blocked | no-recorder | [33-aws-config/](./33-aws-config/) |
| 34 | `asff` | compliance | blocked | no-securityhub | [34-asff/](./34-asff/) |
| 35 | `nessus` | compliance | doc-only | commercial | [35-nessus/](./35-nessus/) |
| 36 | `sarif` | output | validated | local | [36-sarif/](./36-sarif/) |
| 37 | `vex` | output | validated | local | [37-vex/](./37-vex/) |
| 38 | `slsa` | output | validated | local | [38-slsa/](./38-slsa/) |
| 39 | `secretscan` | output | validated | local | [39-secretscan/](./39-secretscan/) |
| 40 | `sinkhole-flows` | specialty | doc-only | sidecar | [40-sinkhole-flows/](./40-sinkhole-flows/) |
| 41 | `policyverify` | verify | doc-only | verify-time | [41-policyverify/](./41-policyverify/) |
| 42 | `vsa` | verify | doc-only | verify-time | [42-vsa/](./42-vsa/) |

## Supported tools (via existing attestors)

In addition to per-attestor examples, this repo includes **tool integration examples** — validated end-to-end recipes for popular OSS tools that flow through rookery's `sarif`, `sbom`, or `secretscan` attestors today. No new attestor code required; the tool's existing structured output is captured byte-identically.

| Tool | Category | Attestor | Example |
|---|---|---|---|
| [Linkerd](https://linkerd.io) | service mesh (CNCF graduated) | `linkerd-check` (native) | [tool-linkerd-check/](./tool-linkerd-check/) |
| [Trivy](https://github.com/aquasecurity/trivy) | container/IaC/secret scan | `sarif` (native attestor in dev — [#89](https://github.com/aflock-ai/rookery/issues/89)) | [tool-trivy-sarif/](./tool-trivy-sarif/) |
| [Syft](https://github.com/anchore/syft) | SBOM generation | `sbom` | [tool-syft-sbom/](./tool-syft-sbom/) |
| [Grype](https://github.com/anchore/grype) | vuln scan vs SBOM/image | `sarif` (native in dev — [#90](https://github.com/aflock-ai/rookery/issues/90)) | [tool-grype-sarif/](./tool-grype-sarif/) |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST | `sarif` (native in dev — [#92](https://github.com/aflock-ai/rookery/issues/92)) | [tool-semgrep-sarif/](./tool-semgrep-sarif/) |
| [gosec](https://github.com/securego/gosec) | Go SAST | `sarif` | [tool-gosec-sarif/](./tool-gosec-sarif/) |
| [Hadolint](https://github.com/hadolint/hadolint) | Dockerfile lint | `sarif` (native in dev — [#96](https://github.com/aflock-ai/rookery/issues/96)) | [tool-hadolint-sarif/](./tool-hadolint-sarif/) |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC misconfig | `sarif` (native in dev — [#93](https://github.com/aflock-ai/rookery/issues/93)) | [tool-checkov-sarif/](./tool-checkov-sarif/) |
| [Kubescape](https://github.com/kubescape/kubescape) | K8s framework posture | `sarif` (native in dev — [#94](https://github.com/aflock-ai/rookery/issues/94)) | [tool-kubescape-sarif/](./tool-kubescape-sarif/) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | OSV-schema vuln scan | `sarif` (native in dev — [#91](https://github.com/aflock-ai/rookery/issues/91)) | [tool-osv-scanner-sarif/](./tool-osv-scanner-sarif/) |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Go reachable-vuln scan | `sarif` (native in dev — [#95](https://github.com/aflock-ai/rookery/issues/95)) | [tool-govulncheck-sarif/](./tool-govulncheck-sarif/) |

See also [`CANDIDATE-ATTESTORS.md`](./CANDIDATE-ATTESTORS.md) for the full matrix of 35 tools researched as potential additions (17 proposed-new, 8 supported-via-existing, 4 not-supportable).

## Status legend

- **validated**: cilock run against real infrastructure produced a real predicate captured in this repo
- **pending**: VM batch in progress; will be promoted to validated when complete
- **blocked**: validation requires external infra we don't currently have (AWS Config recorder, SecurityHub subscription, commercial license, GitLab CI runner, etc.) — recipe is documented for when the infra exists
- **doc-only**: verify-time attestor or special deployment (sinkhole sidecar) where the canonical example isn't a `cilock run` invocation

## How each example was validated

- Local Mac: validation harness at `_validation/work/` (gitignored) + kitchen-sink cilock-all built with `rookery-builder --preset all --with ...`
- VM: t3.small Amazon Linux 2023 EC2 instance in testifysec-demo (`i-0a112150767ab72cf`), Docker + Go + cilock-all built from source
- GitHub Actions: `.github/workflows/cilock-ci-attestors.yml` in this repo, run on real GitHub-hosted runners
- Real testifysec-demo AWS account (898769392027) for cloud-bound attestors (prowler, aws-iid, aws-codebuild)
- Real `dropbox-clone-dev` EKS cluster (us-east-1) for kube-bench

## Bugs filed during validation

Validation exposed real bugs in rookery. Tracked separately; PR-ready patches in `_validation/patches/`:

1. `aws-iid`: setter rejects empty default value — attestor cannot be instantiated without `--attestor-aws-region-cert` even though built-in certs exist for us-east-1 (`plugins/attestors/aws-iid/aws-iid.go:registry.StringConfigOption`)
2. `system-packages`: Amazon Linux 2023 detected as Debian — `/etc/os-release` ID is "amzn" but the attestor case matches only "amazon" (`plugins/attestors/system-packages/system-packages.go`)
3. `structured-data`: package exposes `WithSubjectQuery` etc. as Go funcs but never registers them with the CLI flag system — no `--attestor-structured-data-*` flags exist
4. `builder/cmd/builder/main.go`: `--preset all` is missing 14 attestors (aws-config, asff, configuration, docker-bench, github-action, inspec, kube-bench, nessus, oscap, pip-install, prowler, sinkhole-flows, steampipe, structured-data)

## License

Apache 2.0. Real-data captures are from accounts we own (testifysec-demo, aflock-ai org repos, `dropbox-clone-dev` EKS cluster) and contain no third-party secrets.
