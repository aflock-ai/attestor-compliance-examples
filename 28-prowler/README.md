# 28 — `prowler` ✅ validated end-to-end (run + verify)

Real Prowler v3 scan of testifysec-demo IAM service. 89 IAM checks executed against the live AWS account (898769392027) in us-east-1, signed by cilock into a DSSE envelope, then **verified against a multi-step policy** that gates on real findings.

## What cilock adds to a prowler scan

Running `prowler aws` on its own writes a JSON file. After cilock + the policy in `policy/`:

1. **Signed evidence.** The findings are inside a DSSE envelope signed by the run's key (here a local test key; in production a Fulcio CI identity).
2. **Multi-step contract.** The policy requires 5 attestation types (environment + material + command-run + product + prowler) — drop any one and verify fails.
3. **Real-data gate.** A Rego policy denies the deploy if `totalChecks == 0` (catches silent scan failures) or if more than 2 critical IAM findings exist.
4. **Reproducible from the recipe.** `policy/verify-recipe.sh` is the validated invocation — exit code 0 means deploy/release would be allowed, non-zero means blocked.

## Predicate excerpt

```json
{
  "summary": {
    "accountId": "898769392027",
    "provider": "aws",
    "totalChecks": 89,
    "passCount": 71,
    "failCount": 18,
    "bySeverity": {
      "critical": { "pass": 5, "fail": 2 },
      "high":     { "pass": 52, "fail": 8 },
      "medium":   { "pass": 13, "fail": 7 },
      "low":      { "pass": 1, "fail": 1 }
    },
    "failedChecks": [
      {
        "checkId": "iam_aws_attached_policy_no_administrative_privileges",
        "checkTitle": "Ensure IAM AWS-Managed policies that allow full \"*:*\" administrative privileges are not attached",
        "severity": "high",
        "serviceName": "iam",
        "region": "us-east-1",
        "resourceId": "AdministratorAccess",
        "resourceArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "statusExtended": "AWS policy AdministratorAccess is attached and allows '*:*' administrative privileges."
      }
    ]
  }
}
```

## Step 1 — run prowler + sign with cilock

```bash
AWS_PROFILE=testifysec-demo prowler aws --services iam -M json -o output -F prowler-iam-real
cp output/prowler-iam-real.json prowler.json

cilock run --step prowler-real \
  --signer-file-key-path key.pem --outfile prowler-real.json --workingdir . \
  --attestations prowler,environment \
  -- bash -c "cp prowler.json prowler-out.json"
```

## Step 2 — verify against the multi-step policy

See [`policy/`](./policy/) for the full structure:

- [`policy/policy.json`](./policy/policy.json) — human-readable policy with `_comment` fields explaining every step (intended for LLMs/humans to read inline without base64 decoding)
- [`policy/decoded-rego-prowler-gate.txt`](./policy/decoded-rego-prowler-gate.txt) — the `prowler-findings-gate` Rego in plain text
- [`policy/decoded-rego-git-from-known-repo.txt`](./policy/decoded-rego-git-from-known-repo.txt) — the `git-from-known-repo` Rego in plain text
- [`policy/policy-signed.json`](./policy/policy-signed.json) — same policy signed (DSSE) by the test key
- [`policy/verify-recipe.sh`](./policy/verify-recipe.sh) — the validated `cilock verify` invocation
- [`policy/expected-verify-output.txt`](./policy/expected-verify-output.txt) — actual captured verify output (PASS)

Verified output (real, captured from a live run against the prowler envelope):

```
level=info msg="policy signature verified"
level=info msg="Verification succeeded"
level=info msg="Evidence:"
level=info msg="Step: prowler-real"
```

Exit code 0 → policy passed → in a release pipeline, cilock verify here would unblock the next stage.

## What we found in the real scan

- `iam_aws_attached_policy_no_administrative_privileges` (high) — AWS-managed AdministratorAccess policy is attached
- `iam_password_policy_expires_passwords_within_90_days_or_less` (medium) — no password policy configured
- `iam_password_policy_lowercase`, `iam_password_policy_minimum_length_14`, etc.

Severity rollup: Critical 2, High 8, Medium 7, Low 1. These are the live posture of testifysec-demo as of the scan run; they reflect real cleanup work for that demo account.

## Modifying for production

Two changes for non-demo use:

1. Replace `publickeys` in `policy.json` with a Fulcio cert constraint matching your CI workflow identity:

```json
"roots": {
  "sigstore-fulcio": {
    "certConstraint": { "commonName": "https://fulcio.sigstore.dev" }
  }
},
"functionaries": [{
  "type": "root",
  "certConstraint": {
    "extensions": {
      "buildConfigURI": "https://github.com/<org>/<repo>/.github/workflows/<workflow>.yml",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  }
}]
```

2. Tighten the Rego: `input.summary.bySeverity.critical.fail > 0` (zero critical findings allowed) instead of `> 2`.
