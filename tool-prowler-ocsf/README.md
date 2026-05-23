# `prowler` (multi-cloud CSPM)

This is a **tool integration example** — it shows how to attest the output
of [Prowler](https://github.com/prowler-cloud/prowler) using rookery's
native `prowler` attestor (predicate type
`https://aflock.ai/attestations/prowler/v0.1`).

> This directory is the **canonical going-forward example** for the
> `prowler` attestor. It supersedes [`28-prowler/`](../28-prowler), which
> demonstrated the older `bash -c "cp …"` shape. Prefer this directory for
> new policy work; `28-prowler/` is left in place for the multi-step
> verify-recipe reference.

Prowler is the most popular open-source multi-cloud security posture
(CSPM) scanner. It audits AWS / GCP / Azure / Kubernetes / Microsoft 365
against CIS, NIST 800-53, ISO 27001, HIPAA, GDPR, PCI-DSS and ~20 other
compliance frameworks. Prowler's own `-M json` writes a native JSON
report (in Prowler 4+ the recommended formats are `json-ocsf` and
`json-asff`; the rookery `prowler` attestor accepts all three).

## Validated invocation

cilock invokes `prowler` directly so the `command-run` attestor records
the real argv, the ptrace spy can trace the scanner's syscalls, and the
`product` attestor captures the actual report file written by prowler
(not a `cp` of one written outside cilock's view).

Prowler exits non-zero (exit code 3) when failures are found. To keep
`command-run/v0.1.exitcode == 0` and avoid the runner aborting the
postproduct stage, we pass `-z` / `--ignore-exit-code-3`. The findings
themselves are still recorded in the parsed `prowler/v0.1` predicate — the
flag affects only the process exit code, not the report contents.

```bash
# Install prowler (one of):
#   brew install prowler
#   pipx install prowler

cilock run --step prowler-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations prowler,environment,git \
  --enable-archivista=false \
  -- prowler aws --services iam -M json -o output -F prowler-iam -z
```

`AWS_PROFILE` (or any other AWS credential source `boto3` understands) is
read from the surrounding shell. For an SSO-backed profile, run
`aws sso login --profile <profile>` first.

## What we ran against

This directory's `raw/attestation.json` and `raw/prowler-iam.json` are
the **actual signed envelope and Prowler report** produced by running
the command above against AWS account `898769392027` (testifysec-demo).
The scan completed 36 IAM checks in ~11 seconds.

| Result | Count |
| --- | --- |
| Total checks executed | 93 |
| `PASS` | 74 |
| `FAIL` | 19 |
| `FAIL` by severity (critical / high / medium / low) | 2 / 9 / 7 / 1 |

The `raw/prowler-iam.json` file in this directory has `AWSReservedSSO_*`
and `AWSSSO_*` directory IDs replaced with `REDACTED` placeholders.
`raw/attestation.json` is the original signed envelope and is not
modified (resigning it would defeat the point of committing a real
validation artifact).

## Validate it locally

After running the invocation above:

```bash
# All six predicate types should be present
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'
# [
#   "https://aflock.ai/attestations/command-run/v0.1",
#   "https://aflock.ai/attestations/environment/v0.1",
#   "https://aflock.ai/attestations/git/v0.1",
#   "https://aflock.ai/attestations/material/v0.3",
#   "https://aflock.ai/attestations/product/v0.3",
#   "https://aflock.ai/attestations/prowler/v0.1"
# ]

# command-run records the REAL argv (literal prowler, not bash/cp):
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("command-run/v0.1")) | .attestation.cmd'
# ["prowler","aws","--services","iam","-M","json","-o","output","-F","prowler-iam","-z"]

# prowler attestor parsed the real findings:
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("prowler/v0.1")) | .attestation.summary | {totalChecks, passCount, failCount, bySeverity}'
# {
#   "totalChecks": 93,
#   "passCount": 74,
#   "failCount": 19,
#   "bySeverity": { "critical": {"pass":5,"fail":2}, "high": {"pass":55,"fail":9}, ... }
# }
```

## See also

- [`prowler` attestor docs](https://cilock.aflock.ai/attestors/prowler)
- [Tools index](https://cilock.aflock.ai/tools)
- [`28-prowler/`](../28-prowler) — older example, same attestor, includes a
  multi-step verify-recipe policy
- [Prowler upstream](https://github.com/prowler-cloud/prowler)
