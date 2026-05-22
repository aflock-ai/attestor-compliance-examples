# 28 — `prowler` ✅ validated against real infrastructure

Real Prowler v3 scan of testifysec-demo IAM service. 89 IAM checks executed against the live AWS account (898769392027) in us-east-1.

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
      "critical": {
        "pass": 5,
        "fail": 2
      },
      "high": {
        "pass": 52,
        "fail": 8
      },
      "low": {
        "pass": 1,
        "fail": 1
      },
      "medium": {
        "pass": 13,
        "fail": 7
      }
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
      },
      {
        "checkId": "iam_password_policy_expires_passwords_within_90_days_or_less",
        "checkTitle": "Ensure IAM password policy expires passwords within 90 days or less",
        "severity": "medium",
        "serviceName": "iam",
        "region": "us-east-1",
        "resourceId": "898769392027",
        "resourceArn": "arn:aws:iam::898769392027:root",
        "statusExtended": "Password policy cannot be found."
      },
      {
        "checkId": "iam_password_policy_lowercase",
        "checkTitle": "Ensure IAM password policy require at least one lowercase letter",
        "severity": "medium",
        "serviceName": "iam",
        "region": "us-east-1",
        "resourceId": "898769392027",
        "resourceArn": "arn:aws:iam::898769392027:root",
        "statusExtended": "Password policy canno
... (truncated)
```

## What we found

Real failed checks include:
- `iam_aws_attached_policy_no_administrative_privileges` (high) — `AdministratorAccess` AWS-managed policy is attached
- `iam_password_policy_expires_passwords_within_90_days_or_less` (medium) — no password policy configured
- `iam_password_policy_lowercase`, `iam_password_policy_minimum_length_14`, etc.

Severity rollup: Critical 2, High 8, Medium 7, Low 1. These are the live posture of testifysec-demo as of the scan run; they reflect real cleanup work for that account.

## Reproduce

```bash
AWS_PROFILE=testifysec-demo prowler aws --services iam -M json -o output -F prowler-iam-real
cp output/prowler-iam-real.json prowler.json
cilock run --step prowler-real \
  --signer-file-key-path key.pem --outfile prowler-real.json --workingdir . \
  --attestations prowler,environment \
  -- bash -c "cp prowler.json prowler-out.json"
```
