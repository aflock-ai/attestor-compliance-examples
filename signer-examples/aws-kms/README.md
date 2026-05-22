# AWS KMS signer

Production-ready signer for enterprises on AWS. The key material never leaves AWS KMS; cilock makes a `Sign` API call for each envelope. IAM controls who can sign; CloudTrail records every sign call.

| | |
|---|---|
| Signer ref | `--signer-kms-ref awskms:///<key-id-or-alias>` |
| Required IAM | `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on the key |
| Key spec | RSA_2048, RSA_3072, RSA_4096, or ECC_NIST_P256/P384 |
| Cost | ~$1/month per key + $0.03 per 10k Sign calls |

## What cilock adds over raw KMS signing

You can already `aws kms sign` to produce a signature over any blob. What cilock adds:

1. **The in-toto Statement** (subject + materials + products + tool predicates) is what gets signed. KMS just signs whatever bytes you give it.
2. **Policy enforcement at verify time** binds the IAM identity that signed the envelope to a Rego-gated production contract.
3. **Subject-digest graph** links the KMS-signed envelope to the artifact, the commit, the workflow that produced it.

## One-time setup

```bash
# Create the key
aws kms create-key \
  --description "cilock-production-signer" \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --profile <your-profile> \
  --region us-east-1

# Create an alias (recommended for stable refs)
aws kms create-alias \
  --alias-name alias/cilock-production-signer \
  --target-key-id <key-id-from-above> \
  --profile <your-profile> \
  --region us-east-1

# Grant IAM permission to whatever role/user will sign
aws kms create-grant \
  --key-id <key-id> \
  --grantee-principal arn:aws:iam::<account-id>:role/<your-ci-role> \
  --operations Sign GetPublicKey DescribeKey \
  --profile <your-profile> \
  --region us-east-1
```

In `setup.sh` you'll find the exact commands run for the validation in this repo. Re-running them is a no-op (idempotent on existing key+alias).

## Validated invocation

`cilock run` calls AWS KMS `Sign` **directly** for the envelope signature — there is no `aws kms sign` shim, and the wrapped command is the real workload (here, a placeholder `echo`). The captured envelope is byte-for-byte what AWS signed.

```bash
AWS_REGION=us-east-1 \
cilock run \
  --signer-kms-ref awskms:///alias/cilock-validation-signer \
  --step kms-demo \
  --outfile attestation.json \
  --attestations environment,git \
  --enable-archivista=false \
  --platform-url "" \
  -- bash -c "echo 'AWS KMS signed payload' > kms-output.txt"
```

Or use the key-id form (stable across alias renames):

```bash
AWS_REGION=us-east-1 \
cilock run \
  --signer-kms-ref awskms:///<key-id> \
  --step kms-demo \
  --outfile attestation.json \
  --attestations environment,git \
  --enable-archivista=false \
  -- echo "signed by AWS KMS"
```

## Why this shape

- **Direct KMS API call from the signer.** cilock's KMS signer streams the in-toto Statement bytes into `KMS:Sign` over the AWS SDK — no shelling out to `aws kms sign`, no intermediate file. The signature lands directly in the DSSE envelope.
- **CloudTrail records the Sign call.** Every envelope signature corresponds to a `KMS Sign` event in CloudTrail, callable by IAM identity, source IP, and the request's `RequestId`. That's the production audit trail.
- **`product/v0.3` captures the wrapped command's output.** Here it's `kms-output.txt`; in real use it would be your binary, image manifest, or SBOM. The product hash is bound to the envelope.
- **`environment` + `git` for build provenance.** Same provenance you'd expect from any cilock step.

## Validate it locally

```bash
# 1. One-time setup (idempotent).
bash setup.sh

# 2. Generate the envelope.
bash reproduce-run.sh

# 3. Confirm signature came from the KMS key.
jq '.signatures[0].keyid' attestation.json
# expected: "awskms:///alias/cilock-validation-signer"

# 4. Confirm the expected predicate types are present.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/git/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/product/v0.3

# 5. Cross-check the CloudTrail entry for the Sign call.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Sign \
  --profile <your-profile> --region us-east-1 \
  --max-results 5 \
  --query 'Events[].{Time:EventTime,User:Username,Source:SourceIPAddress}'
```

## Policy functionary

For verifying envelopes signed by AWS KMS, the functionary uses `type: publickey` with the KMS key's public PEM. Fetch the public PEM once via `aws kms get-public-key`:

```bash
aws kms get-public-key \
  --key-id <key-id> \
  --query 'PublicKey' --output text \
  --profile <your-profile> --region us-east-1 | base64 -d > kms-pubkey.der

openssl rsa -inform DER -pubin -in kms-pubkey.der -outform PEM > kms-pubkey.pem
```

Then in `policy.json`:

```json
"publickeys": {
  "<sha256 of kms-pubkey.pem>": {
    "_comment": "AWS KMS key alias/cilock-production-signer (RSA_2048). The keyid is sha256 of the PEM bytes returned by GetPublicKey. Sign access is gated by IAM grant.",
    "keyid": "<sha256 of kms-pubkey.pem>",
    "key": "<base64 of kms-pubkey.pem>"
  }
}
```

See `policy.json` in this directory for the validated example.

## See also

- [`fulcio-keyless/`](../fulcio-keyless/) — keyless alternative for CI workflows
- [AWS KMS docs](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#key-spec-sign)
- [Cosign + AWS KMS](https://docs.sigstore.dev/cosign/key_management/aws_kms/) — the parallel pattern in the sigstore world
