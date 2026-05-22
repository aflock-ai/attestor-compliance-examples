# Signer + KMS examples

Every cilock attestation envelope is signed. The **signer** is the part of cilock that holds (or fetches) the key material and produces the DSSE signature. By default cilock supports many signers — file, debug, Fulcio (keyless via OIDC), AWS KMS, GCP KMS, Azure KMS, Vault, Vault Transit, SPIFFE.

This directory holds **validated, end-to-end examples** for each signer we have access to:

| Signer | Provider | Validated? | Cost | Best for |
|---|---|---|---|---|
| [`fulcio-keyless`](./fulcio-keyless/) | Sigstore Fulcio | ✅ via real GH Actions OIDC | Free | Public-cloud CI (GH, GL, GCP), no key management |
| [`aws-kms`](./aws-kms/) | AWS KMS | ✅ via testifysec-demo | ~$1/mo per key | Enterprise on AWS — IAM-gated keys |
| [`vault-transit`](./vault-transit/) | HashiCorp Vault | ✅ via dev-mode Vault | Open-source | Enterprise self-hosted, k8s-native |

Each example dir has:

```
<signer-name>/
├── README.md                      # what cilock + this signer adds
├── setup.sh                       # the validated one-time setup (create key, grant IAM, etc.)
├── reproduce-run.sh               # the validated cilock run invocation
├── policy.json                    # functionary block matching this signer
├── policy-signed.json             # DSSE-signed via the example key
├── verify-recipe.sh               # the validated cilock verify
└── expected-verify-output.txt     # captured PASS output
```

## Why diverse signers matter

The `file` signer used in most examples in this repo is for demo only. Production never uses a long-lived RSA key on disk. The signer choice is what binds your attestations to a verifiable identity:

- **Fulcio keyless** → identity is the CI workflow's OIDC token (`repository`, `workflow_ref`, `sha`). The signature cert lasts ~10 minutes; verification walks the Sigstore transparency log.
- **AWS KMS** → identity is the IAM role with `kms:Sign` on the key. Audit trails through CloudTrail.
- **Vault Transit** → identity is the Vault policy that allowed access to the key. Audit trails through Vault audit log.

Different signers fit different threat models. Picking the right one is part of the cilock contract.

## What doesn't have an example here (yet)

- **GCP KMS** — needs an active GCP project. Recipe form only until we have one.
- **Azure KMS** — same.
- **SPIFFE** — needs a SPIRE server. Self-host story.

Until those land, the patterns from `aws-kms` and `vault-transit` carry over directly — same CLI flag shape (`--signer-kms-ref`), same functionary block shape, just different cert constraints.
