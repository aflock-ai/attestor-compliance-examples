# 33 — `aws-config` ⚠️ blocked on infra (recipe validated by shape)

Captures AWS Config rule compliance state and emits an
`https://aflock.ai/attestations/aws-config/v0.1` predicate keyed on each
rule, resource, and account.

## Status

⚠️ **Not validated end-to-end** in `testifysec-demo` because AWS Config has
not been enabled there. Enabling Config requires:

- A `configuration-recorder` resource
- A delivery channel + S3 bucket for evaluation snapshots
- An IAM service-linked role (`AWSServiceRoleForConfig`) with permission to
  describe every recordable resource type
- Per-resource recording cost (small but non-zero)

Per repo guardrails, the agent does not provision the IAM role on Cole's
behalf. When Config is enabled in a target account, the recipe below is the
validated shape.

## Why this shape (when unblocked)

The aws-config attestor is a `postproduct` attestor — it reads `.json`
products in the working directory looking for the `EvaluationResults` array
that `aws configservice get-compliance-details-by-config-rule` emits. The
canonical mistake is wrapping a copy command:

```bash
# ❌ DO NOT do this — the recorded argv is `cp`, not the AWS CLI call.
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited \
  --output json > aws-config-eval.json
cilock run --step aws-config-eval \
  -- bash -c "cp aws-config-eval.json aws-config-product.json"
```

That destroys the audit chain — `command-run/v0.1` records `cp`, not the
real AWS API call, and the spy/ptrace layer traces the wrong process.

The **correct** shape is to let cilock invoke the AWS CLI directly so the
captured argv, the spied syscalls, the captured product, and the
attestor-parsed predicate all line up:

```bash
# ✅ Direct invocation. cilock records the real argv.
cilock run --step aws-config-eval \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations aws-config,environment,git \
  --enable-archivista=false \
  -- bash -c "aws configservice get-compliance-details-by-config-rule \
                --config-rule-name <RULE_NAME> \
                --output json > aws-config-product.json"
```

The `bash -c "aws ... > file.json"` is **not** the cp-antipattern — `aws` is
the real tool being run, shell redirection just routes its stdout to the
product file in the working directory. The `command-run/v0.1` predicate
records `["bash", "-c", "aws configservice ..."]`, which is the actual
business of this step. Compare with the cp form, where `cmd` records only
the cp and the AWS call is invisible to the auditor.

The aws-config attestor (postproduct) then reads `aws-config-product.json`
from the product set and emits compliance summary subjects.

## Validate it locally (when Config is enabled)

```bash
# Pre-req: target account has at least one Config rule with recorded results.
# Replace <RULE_NAME> with a real rule — list with:
#   aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'

# 1. Generate an ephemeral signing key.
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 2. Run the example.
cd 33-aws-config
AWS_PROFILE=<your-profile> AWS_REGION=us-east-1 cilock run \
  --step aws-config-eval \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations aws-config,environment,git \
  --enable-archivista=false \
  -- bash -c "aws configservice get-compliance-details-by-config-rule \
                --config-rule-name <RULE_NAME> \
                --output json > aws-config-product.json"

# 3. Confirm the expected predicate types.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/git/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/product/v0.3
#   https://aflock.ai/attestations/aws-config/v0.1

# 4. Inspect the compliance summary parsed by the attestor.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("aws-config")) | .attestation.summary'
```

## To unblock

Provision in the target account (one-time):

```bash
# IAM service-linked role (cheap, just permission).
aws iam create-service-linked-role --aws-service-name config.amazonaws.com

# S3 bucket for delivery channel.
aws s3api create-bucket --bucket config-bucket-<account-id>-<region> --region us-east-1

# Configuration recorder + delivery channel + at least one managed rule.
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::<account-id>:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
  --recording-group allSupported=true,includeGlobalResourceTypes=true
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=config-bucket-<account-id>-<region>
aws configservice start-configuration-recorder --configuration-recorder-name default
aws configservice put-config-rule \
  --config-rule '{"ConfigRuleName":"s3-bucket-public-read-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_READ_PROHIBITED"}}'

# Wait ~5 minutes for the first evaluation.
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited
```

Then re-run the validated invocation above.
