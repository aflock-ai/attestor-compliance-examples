# `policy.json` shape

Cilock policies are JSON documents that describe a **multi-step contract**: which attestations must be present, which functionaries are allowed to sign them, and which Rego policies gate on the attestation contents. `cilock verify` walks the attestation graph (linked by subject digests) and either accepts or denies based on these rules.

This file documents every field, with annotations a reviewer (or an LLM ingesting the repo) can read inline.

## Top-level structure

```jsonc
{
  "_comment": "Free-text description of what this policy gates.",
  "expires": "2027-12-31T23:59:59Z",   // ISO-8601. cilock verify refuses to evaluate past this.
  "name": "my-policy-v1",              // Free identifier. Convention: snake-case + version suffix.

  "roots": { },                         // x509 trust roots for Fulcio-signed envelopes
  "publickeys": { },                    // raw public keys for non-keyless signers (testing)

  "steps": {                            // each step = one named stage of the pipeline
    "<step-name>": {
      "name": "<step-name>",
      "attestations": [ ... ],          // required predicate types + Rego per type
      "functionaries": [ ... ]          // who is allowed to sign this step
    }
  }
}
```

## `publickeys` block

```jsonc
"publickeys": {
  "<keyid>": {                          // sha256 of the public-key PEM bytes
    "keyid": "<keyid>",
    "key": "<base64 PEM>"               // base64-encoded PEM block
  }
}
```

Use this for local testing. For production prefer Fulcio (`roots`) so signers don't have to manage long-lived keys.

## `roots` block — Fulcio

```jsonc
"roots": {
  "sigstore-fulcio": {
    "certConstraint": {
      "commonName": "https://fulcio.sigstore.dev"
    }
  }
}
```

Then constrain functionaries by the OIDC identity baked into the Fulcio cert:

```jsonc
"functionaries": [{
  "type": "root",
  "certConstraint": {
    "extensions": {
      "buildConfigURI": "https://github.com/<org>/<repo>/.github/workflows/<workflow>.yml",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  }
}]
```

This pins the signer to a specific workflow in a specific repo, OIDC-issued.

## `steps[].attestations`

```jsonc
"attestations": [
  {
    "type": "https://aflock.ai/attestations/prowler/v0.1",   // predicate type URL
    "regopolicies": [
      {
        "name": "no-critical-iam-findings",
        "module": "<base64 of plain-text Rego module>"
      }
    ]
  }
]
```

For every attestation type in this list, cilock verify requires the envelope's predicate to include that type. The Rego module receives the predicate as `input` (e.g. `input.summary.bySeverity.critical.fail` for the prowler attestor's summary shape).

If a Rego module's `deny[msg]` rule fires for any value, the policy denies. Multiple deny rules accumulate — the error message lists them all.

## `steps[].functionaries`

Two shapes:

**Public key:**
```jsonc
{ "type": "publickey", "publickeyid": "<keyid>" }
```

**Fulcio cert constraint:**
```jsonc
{
  "type": "root",
  "certConstraint": {
    "commonName": "https://fulcio.sigstore.dev",
    "extensions": {
      "buildConfigURI": "...",   // pinned workflow path
      "issuer": "..."            // pinned OIDC issuer
    }
  }
}
```

The envelope's signature(s) must satisfy at least one functionary entry per step.

## Multi-step policies

When a pipeline has multiple stages (build → scan → release), define a step per stage. Cilock verify automatically walks subjects across collections — if step A's product subject digest appears as a subject in step B's collection, the steps are linked.

Example:

```jsonc
"steps": {
  "build": {
    "attestations": [
      { "type": "https://aflock.ai/attestations/git/v0.1", "regopolicies": [...] },
      { "type": "https://aflock.ai/attestations/github/v0.1", "regopolicies": [...] },
      { "type": "https://aflock.ai/attestations/product/v0.2", "regopolicies": [] }
    ],
    "functionaries": [...]
  },
  "scan": {
    "attestations": [
      { "type": "https://aflock.ai/attestations/prowler/v0.1", "regopolicies": [...] },
      { "type": "https://aflock.ai/attestations/product/v0.2", "regopolicies": [] }
    ],
    "functionaries": [...]
  }
}
```

The link between `build` and `scan` is implicit: both collections list the same product digest as a subject (the build's product = the scan's target). Verify walks both collections and checks all step rules pass before returning success.

## Signing the policy

Once authored, sign with the same `cilock sign` machinery as any other DSSE envelope:

```bash
cilock sign -k policy-signer.pem -f policy.json -o policy-signed.json
```

The signed copy is what `cilock verify --policy` consumes. Verifier needs `--publickey` (or `--policy-ca-roots` for Fulcio) to validate the policy signature itself.

## Running verify

```bash
cilock verify \
  --policy policy-signed.json \
  --publickey policy-signer.pub \
  --attestations envelope-1.json [--attestations envelope-2.json ...] \
  --subjects sha256:<subject-digest-to-link-attestations>
```

`--subjects` is the digest verify walks backward from. Each attestation has subjects; cilock finds every collection containing the digest and runs the policy against all of them. Pass the digest of the build's product to make verify gate over the whole graph.
