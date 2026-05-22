# cilock-action Detection Validation: Trivy Supply Chain Attack

**Can cilock-action's secretscan attestor detect the TeamPCP credential stealer that compromised trivy-action in March 2026?**

**Yes.** 4 findings detected. [See the attestation output](attestation-with-findings.json)

## What This Repo Proves

On March 19, 2026, attackers force-pushed malicious code to 75 version tags on `aquasecurity/trivy-action`. The payload harvested CI/CD secrets and exfiltrated them via HTTPS POST. This repo reproduces the attack techniques and proves cilock catches them.

## Findings

| # | Rule | What was detected | Depth |
|---|------|------------------|-------|
| 1 | `github-pat` | GitHub PAT in command stdout | 0 |
| 2 | `private-key` | RSA private key in command stdout | 0 |
| 3 | `github-pat` | Same PAT found in base64-decoded Python stealer output | 1 (recursive) |
| 4 | `private-key` | Private key in command-run JSON | 0 |

## How to Reproduce

```bash
# Build cilock
go build -o cilock ./cmd/cilock/  # from judge/subtrees/rookery/cilock

# Generate test key
openssl ecparam -genkey -name prime256v1 -noout -out test-key.pem

# Run with secretscan
cilock run --step trivy-scan-test --attestations secretscan \
  --signer-file-key-path test-key.pem --enable-archivista=false \
  --outfile attestation.json -- bash entrypoint.sh
```

## The Detection Window

The attacker encrypts the final exfiltration bundle with AES-256 + RSA-4096. But plaintext credentials pass through stdout *before* encryption. That window is where cilock catches them.

## Blog Post

[testifysec.com/blog/cilock-action-supply-chain-attacks](https://testifysec.com/blog/cilock-action-supply-chain-attacks)
