#!/bin/bash
# One-time setup for the AWS KMS signer example. Idempotent on existing
# resources. Run once with: bash setup.sh
set -euo pipefail

KEY_DESC="cilock-validation-test-signer"
ALIAS="alias/cilock-validation-signer"
REGION="us-east-1"
PROFILE="${AWS_PROFILE:-testifysec-demo}"

# Create the signing key (RSA_2048, SIGN_VERIFY)
KEY_ID=$(aws kms list-aliases --profile "$PROFILE" --region "$REGION" \
  --query "Aliases[?AliasName=='$ALIAS'].TargetKeyId" --output text)
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = "None" ]; then
  KEY_ID=$(aws kms create-key \
    --description "$KEY_DESC" \
    --key-usage SIGN_VERIFY --key-spec RSA_2048 \
    --profile "$PROFILE" --region "$REGION" \
    --query "KeyMetadata.KeyId" --output text)
  aws kms create-alias --alias-name "$ALIAS" --target-key-id "$KEY_ID" \
    --profile "$PROFILE" --region "$REGION"
fi
echo "Key ID: $KEY_ID  (alias: $ALIAS)"

# Print the ARN used in policy.json's publickey keyid + sign URL
echo "Sign URL: awskms:///$ALIAS"
echo "Or: awskms:///$KEY_ID"

# Fetch + persist the public PEM (used in policy.json's publickey.key field)
aws kms get-public-key --key-id "$KEY_ID" \
  --profile "$PROFILE" --region "$REGION" \
  --query 'PublicKey' --output text | base64 -d > kms-pubkey.der
openssl rsa -inform DER -pubin -in kms-pubkey.der -outform PEM > kms-pubkey.pem
rm -f kms-pubkey.der
echo "Public key written: kms-pubkey.pem"
