# `scubagoggles` (Google Workspace config)

A **tool integration example** showing how to attest a Google Workspace
tenant's configuration with CISA [ScubaGoggles](https://github.com/cisagov/ScubaGoggles)
under cilock, using rookery's native `scubagoggles` attestor (predicate type
`https://aflock.ai/attestations/scubagoggles/v0.1`), then gate it with our own
Rego policy.

## Facts, not a verdict

This example's defining choice: the attestor signs the **raw provider
configuration** ScubaGoggles collects — not ScubaGoggles' own Pass/Fail
results. ScubaGoggles bundles OPA to run CISA's baselines; cilock ignores that
verdict and captures only the configuration (the `Raw` section of
`ScubaResults*.json`, which is byte-for-byte what ScubaGoggles feeds to OPA).
The compliance decision lives in **your** policy.

| Antipattern | Correct shape (this example) |
|---|---|
| Attest ScubaGoggles' `Results` (per-control Pass/Fail) | Attest the `Raw` provider config — the actual settings |
| Verdict baked into the evidence | Evidence is reusable ground truth; your policy decides |
| Rego sees pre-decided results | Rego sees `input.predicate.config` = the real settings |

## Validated invocation

```bash
cilock run --step gws-assessment \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations scubagoggles,environment \
  --enable-archivista=false \
  -- scubagoggles gws -b commoncontrols -c credentials.json -o ./out --quiet
```

ScubaGoggles is a Python package (`pip install scubagoggles`), needs OPA
(`scubagoggles getopa`), and authenticates to Google with an OAuth client
(`-c credentials.json`, one-time super-admin browser sign-in; token cached for
headless reruns) or a domain-wide-delegation service account
(`--subjectemail`). cilock **records** the output; it does not authenticate for
you, and all scopes are read-only. See [`reproduce.sh`](./reproduce.sh).

## What gets captured

`scubagoggles,environment` (plus the always-on `product`/`material`) yields:

- `command-run/v0.1` — the literal `scubagoggles` argv and exit code.
- `material/v0.3`, `product/v0.3` — Merkle hashes of inputs and the
  `ScubaResults*.json` written.
- `scubagoggles/v0.1` — the raw GWS provider config (`policies`,
  `super_admins`, `domains`, OU layout, …). Subjects:
  `googleworkspace:tenant:<customerId>`, `:domain:<domain>`, `:orgunit:<path>`.
- `environment/v0.1` — host facts.

## The policy

The `policy/` directory holds TestifySec-authored, deny-based rego that reads
`input.predicate.config` directly. It is **our** rego — CISA's baselines read
`input.policies` and emit a `tests` set, which doesn't fit the policyverify
`deny[]` contract, so we re-expressed the control intent (informed by CISA's
SCuBA baselines, CC0-1.0). Three baselines are covered:

| File | GWS baseline | Checks |
|---|---|---|
| `gws_commoncontrols.rego` | Common Controls | phishing-resistant MFA (1.1), 12h session cap (4.1), 2–8 super-admins (6.2), 2SV enforcement |
| `gws_gmail.rego` | Gmail | DMARC enforcing (not `p=none`), SPF + DKIM published, anomalous-attachment protection |
| `gws_drive.rego` | Drive & Docs | external sharing not unrestricted, no web publishing |

**NIST 800-171 coverage.** These baselines were chosen to give a CUI assessment
the evidence it needs across the families that map to Google Workspace config:
Access Control (3.1 — least privilege, session, CUI sharing), Identification &
Authentication (3.5 — MFA, password policy), and System & Communications
Protection (3.13 — email authenticity/anti-spoofing). The precise
GWS-control → 800-171-requirement mapping is the platform's job; this policy
only checks GWS controls and references their GWS ids.

Unit tests: `opa test policy/` (15 cases).

## Full cycle: create → verify

[`reproduce.sh`](./reproduce.sh) runs the whole loop through cilock: it
**creates** the attestation (`cilock run`), builds a witness policy that trusts
the run's signer and embeds the rego, **signs** it (`cilock sign`), and
**verifies** the attestation against it (`cilock verify -s sha256:<domain>`).
`policyverify` evaluates our rego inside the signature-verified envelope, so the
verdict is bound to trusted evidence.

A non-compliant tenant **denies** — the gate blocks, e.g.:

```
collection rejected: gws-assessment … rego policy evaluation failed …: policy was denied due to:
  … allows non-phishing-resistant 2SV factor "NO_TELEPHONY" … (GWS.COMMONCONTROLS.1.1),
  … web-session duration 72000s exceeds the 12h/43200s maximum (GWS.COMMONCONTROLS.4.1),
  super-admin count 1 is below the required minimum of 2 (GWS.COMMONCONTROLS.6.2)
```

A compliant tenant verifies clean (exit 0) and the gate allows.

## Try it without a tenant

`raw/sample-provider-input.json` is **synthetic** (no real tenant — see the
privacy note below) and deliberately non-compliant, so you can see the policy
fire offline:

```bash
opa eval -d policy/gws_commoncontrols.rego -i raw/sample-provider-input.json \
  'data.gws_commoncontrols.deny' --format pretty
```

Expected: three denials — non-phishing-resistant 2SV factor, a 20h session, and
a single super-admin.

## Privacy

Unlike the cloud-scanner examples, a real run here captures a tenant's live
security configuration (admin accounts, OU layout, DNS/auth policy). **No real
tenant data is committed** to this public repo — `raw/` holds only synthetic
example.org data. Keep your own `attestation.json` out of version control.
