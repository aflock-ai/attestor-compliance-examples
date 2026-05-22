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
  --grantee-principal arn:aws:iam::<account>:role/<your-ci-role> \
  --operations Sign GetPublicKey DescribeKey \
  --profile <your-profile> \
  --region us-east-1
```

In `setup.sh` you'll find the exact commands run for the validation in this repo. Re-running them is a no-op (idempotent on existing key+alias).

## Run

```bash
AWS_REGION=us-east-1 \
cilock run \
  --signer-kms-ref awskms:///<key-id-or-alias> \
  --step my-step \
  --outfile attestation.json \
  --attestations environment,git \
  -- echo "signed by AWS KMS"
```

Or use the alias form:

```bash
AWS_REGION=us-east-1 \
cilock run \
  --signer-kms-ref awskms:///alias/cilock-production-signer \
  --step my-step \
  --outfile attestation.json \
  --attestations environment,git \
  -- echo "signed by AWS KMS via alias"
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
