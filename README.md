# Attestor Compliance Examples

Real-data, end-to-end validation examples for every attestor in
[`aflock-ai/rookery`](https://github.com/aflock-ai/rookery). Each example
captures the **exact command + real predicate output** from running
cilock against actual infrastructure — no synthetic fixtures unless
the attestor's data source requires it (commercial scanner license,
hard-coded sidecar bind-mount, etc.).

**Status:** **26/42 validated against real infrastructure**, 5 pending VM
batch completion, 6 blocked on external constraints, 5 verify-time or
doc-only by design. See per-attestor READMEs for the exact scenario.

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
