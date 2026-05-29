# Slack workspace posture (Steampipe + NIST 800-171 gate)

A **recipe** showing how to attest a Slack workspace's security posture with
[Steampipe](https://steampipe.io)'s `slack` plugin under cilock, using rookery's
native `steampipe` attestor (predicate type
`https://aflock.ai/attestations/steampipe/v0.1`), then gate it with our own Rego
policy mapped to NIST SP 800-171.

It is the SaaS-posture sibling of [`tool-scubagoggles-gws`](../../tool-scubagoggles-gws):
where that example attests Google Workspace config, this one attests Slack —
treating the workspace as if it carries (or may carry) CUI.

## Facts, not a verdict

The `steampipe` attestor signs the **raw query rows** — members and their 2FA /
admin / guest flags, channels and their external-sharing flags. It does not
decide pass/fail. The compliance decision lives in **your** Rego policy
(`policy/slack_posture.rego`), evaluated by `policyverify` inside the
signature-verified collection.

## In the collection, not a sidecar

The steampipe attestation rides **inside the run's collection** (the default), so
a witness policy step can require `steampipe/v0.1` and gate its rows directly —
the same shape as every other in-collection attestor. Emitting it as a
standalone sidecar envelope is the exception, opt-in with
`--attestor-steampipe-export`.

## Validated invocation

```bash
cilock run --step slack-posture \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations steampipe,environment \
  --enable-archivista=false \
  -- bash collect.sh
```

`collect.sh` runs the query pack (`queries/slack_users.sql`,
`queries/slack_channels.sql`) via `steampipe query --output json`, one JSON
product per query. Steampipe authenticates from its own connection config
(`~/.steampipe/config/slack.spc`) — no token in argv or env. See
[`reproduce.sh`](./reproduce.sh) for the full create → sign → verify cycle.

### Prerequisites

```bash
steampipe plugin install slack
# ~/.steampipe/config/slack.spc:
#   connection "slack" { plugin = "slack"  token = "xoxp-..." }
```

A read-only **user** token with `users:read`, `channels:read`, `groups:read` is
enough for **member** posture. **Channel** posture needs `im:read` + `mpim:read`
too, because steampipe's `slack_conversation` table lists *all* conversation
types (including DMs) — a least-privilege posture token usually omits the DM
scopes, so `collect.sh` captures channels best-effort and skips them (without
failing the run) when the scopes aren't granted.

## What gets captured

`steampipe,environment` (plus the always-on `product`/`material`) yields a
collection with:

- `command-run/v0.1` — the literal `bash collect.sh` argv and exit code.
- `material/v0.3`, `product/v0.3` — Merkle trees of inputs and the captured
  `out/*.json` query results. The product tree is the verify anchor.
- `steampipe/v0.1` — the raw Slack rows (`input.predicate.results[].rows.rows[]`).
- `environment/v0.1` — host facts.

## The policy

`policy/slack_posture.rego` is TestifySec-authored, deny-based rego that reads
the captured rows. It is **our** rego, written against the steampipe predicate
and the policyverify `deny[]` contract.

| Control | NIST 800-171 (Rev.2) | Check |
|---|---|---|
| Multifactor authentication | 3.5.3 (IA-2) | every active member has 2FA enabled |
| Limit access to authorized users | 3.1.1 / 3.1.2 (AC-3) | no external/guest accounts |
| Least privilege | 3.1.5 (AC-6) | ≤25% of members hold admin/owner (tunable) |
| Control CUI flow / protect boundary | 3.1.3 / 3.13.1 (AC-21 / SC-7) | no externally-shared (Slack Connect) channels |

The precise control→requirement mapping is the platform's job; this policy
checks Slack facts and cites the requirements it is informed by. Unit tests:
`opa test policy/` (10 cases).

## Full cycle: create → verify

[`reproduce.sh`](./reproduce.sh) runs the whole loop through cilock: **creates**
the attestation (`cilock run`), builds a witness policy that trusts the run's
signer and embeds the rego, **signs** it (`cilock sign`), and **verifies** the
collection against it (`cilock verify`), anchoring on the captured product
file's digest (cilock bridges it to the `tree:products` root and finds the
`slack-posture` collection).

A non-compliant workspace **denies** — the gate blocks. The deny reasons look
like this (illustrative — counts and IDs depend on your workspace):

```
collection rejected: slack-posture … rego policy evaluation failed … policy was denied due to:
  N of M active members have two-factor authentication DISABLED (NIST 800-171 3.5.3 / IA-2): [...],
  K of M members hold workspace admin/owner privilege (>25%); apply least privilege (NIST 800-171 3.1.5 / AC-6): [...],
  guest account "U…" has workspace access; external/guest users must not reach a CUI boundary (NIST 800-171 3.1.1/3.1.2 / AC-3)
```

A compliant workspace verifies clean (exit 0) and the gate allows.

## Try it without a workspace

`raw/sample-steampipe-input.json` is **synthetic** and deliberately
non-compliant, so you can see the policy fire offline:

```bash
opa eval -d policy/slack_posture.rego -i raw/sample-steampipe-input.json \
  'data.slack_posture.deny' --format pretty
```

Expected: denials for missing 2FA, a guest account, excessive admins, and an
externally-shared channel.

## Privacy

A real run captures your workspace's member/channel posture (user IDs, 2FA /
admin / guest flags, channel sharing flags — **no** message content, file
contents, emails, or real names). **No real workspace data is committed** to this
repo — `raw/` holds only synthetic `example.org`-style data. Keep your own
`attestation.json` out of version control.
