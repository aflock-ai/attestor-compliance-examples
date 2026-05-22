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

## The two-step policy (`policy.json`)

The committed policy splits the detection into two steps and uses
`attestationsFrom` to cross-check them:

| Step | Purpose | Expected outcome |
|---|---|---|
| `attack-simulation` | Plant credential-stealer behaviour; secretscan must detect it | Findings present |
| `clean-build` | A real build using the same toolchain; secretscan must be clean | Zero findings |

The `clean-build` step lists `attestationsFrom: ["attack-simulation"]` so its
Rego rules see the simulation step's secretscan output under
`input.steps["attack-simulation"]["…/secretscan/v0.1"]`. The Rego asserts
**three** invariants:

1. **Direct clean-bill on `clean-build`.** Same as the original single-step
   gate — if clean-build's secretscan turns up any finding, deny with the
   ruleId and location.

2. **Calibration: `attack-simulation` MUST find secrets.** If the simulation
   passes with zero findings, the detection ruleset has silently regressed.
   The example no longer demonstrates what it claims to demonstrate, and the
   gate fails loudly so the regression is caught the moment it lands. This
   invariant is only expressible because `attestationsFrom` lifts the
   simulation's findings into the clean-build step's Rego input.

3. **Set-disjointness: `clean-build` MUST NOT contain any pattern from
   `attack-simulation`.** Catches a regression in the opposite direction —
   a real build accidentally leaking the same patterns the planted attack
   used. Vacuously satisfied if Rule 1 passes (clean-build is empty), but
   the explicit check documents the intent and produces a sharper deny
   message if Rule 1 ever weakens.

See `decoded-rego-clean-build-no-secrets-and-disjoint-from-simulation.txt`
for the plain-text Rego module that's base64-embedded in the policy.

For the general pattern see
[`../multi-step-attestationsFrom/`](../multi-step-attestationsFrom/) and the
"Cross-step rules via attestationsFrom" section of
[`../_policy-templates/backref-subjects.md`](../_policy-templates/backref-subjects.md).

## Blog Post

[testifysec.com/blog/cilock-action-supply-chain-attacks](https://testifysec.com/blog/cilock-action-supply-chain-attacks)
