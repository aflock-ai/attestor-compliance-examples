# 34 — `asff` ✅ validated against real Security Hub

Captures AWS Security Hub ASFF (AWS Security Finding Format) JSON and emits
a structured `https://aflock.ai/attestations/asff/v0.1` predicate keyed on
the AWS account, each resource ARN, and each CRITICAL/HIGH finding ARN.

## Validated invocation

`cilock` invokes the AWS CLI **directly** as the wrapped command — the
`bash -c` shell is only used to redirect `aws`'s stdout into a product
file. There is no `cp` shim; the `command-run/v0.1` attestor records the
real argv, the spy traces the real `aws` process, and the `asff`
postproduct attestor parses the captured output.

```bash
AWS_PROFILE=<your-profile> AWS_REGION=us-east-1 cilock run \
  --step asff-ingest \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations asff,environment,git \
  --enable-archivista=false \
  -- bash -c "aws securityhub get-findings --max-results 50 --output json > asff-product.json"
```

## Why this shape

- **Direct invocation.** `cilock run -- bash -c "aws securityhub
  get-findings ... > asff-product.json"` means the `command-run/v0.1`
  predicate records `["bash", "-c", "aws securityhub get-findings ..."]`.
  The wrapped tool is `aws`, not `cp` — the audit chain points at the real
  AWS API call. (Why `bash -c`? Shell redirection routes `aws`'s stdout to
  the product file. The alternative is `aws ... --output json` to a flag
  the AWS CLI doesn't support for file output, so `>` is the standard way.)
- **Product set captures the ASFF JSON.** `asff-product.json` is written
  into the working directory during the run; the always-on `product/v0.3`
  attestor picks it up as a Merkle-leaf product and hashes its content.
- **`asff` attestor parses the output.** The `asff` attestor (postproduct)
  validates the JSON is real ASFF (every record has `Id`, `Severity.Label`,
  `Compliance.Status`), then emits the structured summary alongside the raw
  product hash. Downstream policies can reason about severity / compliance
  status without re-parsing.
- **Subjects for graph linking.** The attestor emits subjects for the AWS
  account ID (`aws:account:<id>`), every resource ARN referenced in failed
  findings (`aws:arn:<arn>`), and every CRITICAL/HIGH finding ARN
  (`aws:finding:<arn>`). Archivista uses these to cross-link this
  attestation with other AWS attestations (prowler, aws-config, etc.) that
  touch the same resources.

If `get-findings` returns zero findings, the asff attestor's
`validateASFF` rejects the empty array and the attestor fails — by design,
since this attestor's job is to attest to *actual* findings. If you need to
attest "no findings exist", that's a separate predicate (use the raw
`product/v0.3` hash of the empty JSON instead).

## Validate it locally

```bash
# Pre-req: Security Hub enabled in the target account with at least one
# finding present. To validate without waiting for the standards to
# generate findings, push a synthetic one via BatchImportFindings:
#
#   aws securityhub batch-import-findings \
#     --cli-input-json file://cilock-demo-finding.json \
#     --profile <your-profile> --region us-east-1

# 1. Generate an ephemeral signing key.
mkdir -p _validation
openssl genpkey -algorithm ed25519 -out _validation/key.pem

# 2. Run the example.
cd 34-asff
AWS_PROFILE=<your-profile> AWS_REGION=us-east-1 cilock run \
  --step asff-ingest \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations asff,environment,git \
  --enable-archivista=false \
  -- bash -c "aws securityhub get-findings --max-results 50 --output json > asff-product.json"

# 3. Confirm the expected predicate types.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/git/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/product/v0.3
#   https://aflock.ai/attestations/asff/v0.1

# 4. Inspect the parsed summary.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("asff")) | .attestation.summary'

# 5. Confirm command-run captured the real argv.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("command-run")) | .attestation.cmd'
# expected: ["bash", "-c", "aws securityhub get-findings --max-results 50 ..."]
```

## To unblock (if Security Hub not yet subscribed)

```bash
# One-time per account+region. Subscribes to AWS Foundational Security
# Best Practices by default (no extra charge for the subscription itself;
# pay per finding ingestion only).
aws securityhub enable-security-hub --profile <your-profile> --region us-east-1
```
