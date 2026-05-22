# 25 — `aws` (EC2 Instance Identity) ✅ validated against real infrastructure

Captures the AWS EC2 Instance Identity Document (IID) from the metadata
service (IMDSv2) and verifies its signature against AWS's regional public
certificate. Emits an `https://aflock.ai/attestations/aws/v0.1` predicate
with the instance ID, AMI, region, AZ, account, and the raw RSA signature
so downstream verifiers can re-prove cryptographic identity offline.

## Validated invocation

`cilock` invokes the workload command **directly** (here, `aws sts
get-caller-identity` to capture the runtime IAM principal). The `aws`
attestor is a `prematerial` attestor — it independently calls IMDSv2 from
inside cilock's process during the prematerial pass; it does not shell out.

```bash
PATH=/usr/local/bin:$PATH cilock run \
  --step ec2-identity \
  --signer-file-key-path key.pem \
  --outfile aws-iid.json \
  --workingdir . \
  --enable-archivista=false \
  --attestations aws,environment \
  -- bash -c "aws sts get-caller-identity --output json > caller.json"
```

This must run **on an EC2 instance** (IMDS is not reachable from anywhere
else). The validated capture in this directory ran on
`i-0ea5d83b4b068de40` (t3.large, us-east-1a) in `testifysec-demo` via SSM
Run Command.

## Why this shape

- **The aws attestor reads IMDSv2 directly from cilock's process.** It uses
  the AWS SDK to fetch `http://169.254.169.254/latest/dynamic/instance-identity/document`
  with a session token. The captured `rawiid` + `rawsig` are the exact
  bytes AWS signed.
- **`PATH=/usr/local/bin:$PATH`** is set on the wrapped command because
  Amazon Linux 2023's default `aws` CLI is broken (vendored botocore can't
  find urllib3). Using AWS CLI v2 from `/usr/local/bin` avoids that.
- **Wrapped command is the real `aws sts get-caller-identity`.** That tells
  the auditor the IAM principal that ran the step (here, the EC2 instance
  role `cilock-validation-ssm`). `command-run/v0.1` records the real argv,
  not a `cp` shim.
- **Why not just `echo`?** The original validation used `echo "captured
  EC2 instance identity"` as a placeholder. The current shape pairs the
  EC2 IID (machine identity, AWS-signed) with the STS caller identity (IAM
  principal identity, IMDS-rotated session creds) for a complete identity
  capture. The two facts are linked: same instance, same role, same step.
- **No `git` attestor** in the attestation list because EC2 working dirs
  aren't repos. Add it back when running from inside a checked-out repo
  (e.g., a CodeBuild source dir — see `24-aws-codebuild/`).

## Predicate excerpt

```json
{
  "instanceId": "i-0ea5d83b4b068de40",
  "region": "us-east-1",
  "availabilityZone": "us-east-1a",
  "accountId": "898769392027",
  "instanceType": "t3.large",
  "imageId": "ami-02b2c1b57c5105166",
  "pendingTime": "2026-05-22T14:44:52Z",
  "rawiid": "{ ... full JSON exactly as IMDS served it ... }",
  "rawsig": "<base64 RSA signature over rawiid bytes>",
  "publickey": "<PEM of the regional AWS IID signing cert>"
}
```

The `rawiid` + `rawsig` + `publickey` triple is independently verifiable —
a verifier with only `attestation.json` can confirm AWS signed those exact
bytes, no IMDS round-trip needed at verify time.

## Validate it locally (on an EC2 instance)

Pre-req: an EC2 instance in the target account with an IAM instance
profile granting `sts:GetCallerIdentity` (any role does, since the call
returns the role's own identity). The `aws` (IID) attestor itself needs no
IAM permissions — it just reads IMDS.

```bash
# 1. SSH or SSM into the instance.
aws ssm start-session --target <instance-id> --profile <your-profile> --region us-east-1

# 2. Install AWS CLI v2 if the OS only has v1 (Amazon Linux 2023's default
#    awscli is broken in some AMIs).
curl -sLO https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
unzip -qo awscli-exe-linux-x86_64.zip && sudo ./aws/install --update

# 3. Ephemeral signing key.
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 4. Run.
PATH=/usr/local/bin:$PATH cilock run \
  --step ec2-identity \
  --signer-file-key-path _validation/key.pem \
  --outfile aws-iid.json \
  --enable-archivista=false \
  --attestations aws,environment \
  -- bash -c "aws sts get-caller-identity --output json > caller.json"

# 5. Confirm the expected predicate types.
jq -r '.payload' aws-iid.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/aws/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/product/v0.3

# 6. Inspect the IID predicate.
jq -r '.payload' aws-iid.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("aws/v0.1")) | .attestation | {instanceId, region, accountId, availabilityZone, instanceType, imageId, pendingTime}'

# 7. Confirm the wrapped argv was the real AWS call.
jq -r '.payload' aws-iid.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("command-run")) | .attestation.cmd'
# expected: ["bash", "-c", "aws sts get-caller-identity --output json > caller.json"]

# 8. Independently verify the IID signature (no cilock needed).
jq -r '.payload' aws-iid.json | base64 -d \
  | jq -r '.predicate.attestations[] | select(.type|contains("aws/v0.1")) | .attestation.rawiid' > rawiid.txt
jq -r '.payload' aws-iid.json | base64 -d \
  | jq -r '.predicate.attestations[] | select(.type|contains("aws/v0.1")) | .attestation.rawsig' \
  | base64 -d > rawsig.bin
jq -r '.payload' aws-iid.json | base64 -d \
  | jq -r '.predicate.attestations[] | select(.type|contains("aws/v0.1")) | .attestation.publickey' > pubkey.pem
openssl dgst -sha256 -verify pubkey.pem -signature rawsig.bin rawiid.txt
# expected: Verified OK
```

## See also

- [AWS Instance Identity Document docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html)
- [`24-aws-codebuild/`](../24-aws-codebuild/) — sister attestor for CodeBuild env vars
