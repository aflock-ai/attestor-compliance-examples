# Attestor Compliance Examples

Working examples for cilock's **builder-opt-in attestors** — the compliance
scanners that aren't in the default cilock binary but are one
`rookery-builder --with` flag away.

Each example is **tested end-to-end in CI**. A passing badge means the
recipe works against the current rookery main.

| Example | Attestor | Compliance angle | CI |
|---|---|---|---|
| [`01-prowler-aws/`](./01-prowler-aws/) | `prowler` | NIST 800-53 AC-2 / SC-7 (cloud posture) | [![ci](https://github.com/aflock-ai/attestor-compliance-examples/actions/workflows/ci.yml/badge.svg)](https://github.com/aflock-ai/attestor-compliance-examples/actions/workflows/ci.yml) |
| [`02-kube-bench-cis/`](./02-kube-bench-cis/) | `kube-bench` | CIS Kubernetes Benchmark, NIST CM-6 | (above) |
| [`03-oscap-stig/`](./03-oscap-stig/) | `oscap` | DoD STIG, NIST SI-2 / CM-6 | (above) |
| [`04-inspec-cis/`](./04-inspec-cis/) | `inspec` | CIS host benchmarks | (above) |
| [`05-aws-config/`](./05-aws-config/) | `aws-config` | AWS continuous compliance | (above) |
| [`06-asff-securityhub/`](./06-asff-securityhub/) | `asff` | AWS Security Hub findings | (above) |
| [`07-structured-data/`](./07-structured-data/) | `structured-data` | Custom JSON evidence (FedRAMP 20x KSI) | (above) |
| [`08-steampipe/`](./08-steampipe/) | `steampipe` | Multi-cloud SQL-driven compliance | (above) |

## The pattern, every example

```
01-prowler-aws/
├── README.md          # Compliance control + walkthrough
├── fixture/           # Sample scanner output (committed; not regenerated each run)
│   └── prowler.json
├── manifest.yaml      # rookery-builder manifest for this example's plugin set
├── policy.json        # cilock verify policy (gates on the scanner's results)
├── policy-signed.json # Same policy, signed by a test keypair (regenerated in CI)
└── .github/workflows/verify.yml   # End-to-end CI: build cilock, attest, verify, assert
```

The fixture is a recorded sample of the scanner's real output, so the
example doesn't depend on having the scanner installed in CI. In a real
pipeline you'd swap the fixture for a live scanner invocation.

## Why builder-opt-in?

These attestors ship as separate Go modules in
[`rookery/plugins/attestors/`](https://github.com/aflock-ai/rookery/tree/main/plugins/attestors)
but are **not** blank-imported in the default `cilock` binary. They
typically have heavyweight transitive dependencies (AWS SDKs, scanner
parsers, etc.) that would bloat the default binary 5×–10×.

To use one:

```bash
go install github.com/aflock-ai/rookery/builder/cmd/builder@latest
rookery-builder \
  --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/attestors/prowler \
  --output ./cilock
```

The output is a real cilock binary with the prowler attestor compiled
in alongside everything in the `cicd` preset.

See the cilock docs:
[Build a custom cilock](https://cilock.aflock.ai/guides/build-a-custom-cilock).

## License

Apache 2.0. Each example's fixture data is fictional / public-sample
and carries no real-world security signal.
