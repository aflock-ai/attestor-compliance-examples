# cilock verifies a cosign-signed DSSE attestation

End-to-end proof that cilock can ingest a [cosign](https://github.com/sigstore/cosign)-signed in-toto DSSE envelope as **first-class policy evidence** via `Policy.externalAttestations`. No code change in cilock — the wire format is already shared.

## What this validates

| Claim | Validated by |
|---|---|
| cosign and cilock both produce the same DSSE wire format | The same `cilock verify` call ingests both files without conversion |
| cilock can require a cosign attestation as part of a policy | `externalAttestations.slsa-provenance-from-cosign.required = true` |
| cilock cryptographically verifies the cosign signature using the embedded public key | NEGATIVE-2: a tampered signature is rejected |
| cilock enforces the predicate-type contract in policy | NEGATIVE-1: absent cosign attestation produces `not found` |

The point isn't that cosign and cilock are interchangeable — they're at different abstraction levels (see [`docs/ecosystem/cosign.md`](https://cilock.aflock.ai/ecosystem/cosign)). The point is that an organisation running cosign for artifact signing today can layer cilock policy on top of those exact same envelopes without re-signing.

## What's in this dir

| File | Content |
|---|---|
| `hello.go` + `predicate.json` | Source artifact and the SLSA Provenance v0.2 predicate body cosign attests |
| `policy.json` | The cilock policy: one `build` step (signed by cilock key) + one `externalAttestations` entry pointing at a `slsa.dev/provenance/v0.2` predicate signed by cosign key |
| `raw/cilock-attestation.json` | Real cilock-signed collection envelope from a `go build` run |
| `raw/cosign-dsse.json` | Real cosign-signed DSSE envelope (`cosign attest-blob`, classic-format) over the same `hello` artifact |
| `raw/policy-signed.json` | The policy after `cilock sign` |
| `raw/cilock.pub`, `raw/cosign.pub` | The two public keys the policy trusts |
| `reproduce.sh` | Full recipe — generate keys, build artifact, produce both envelopes, sign policy, run 1 positive + 2 negative `cilock verify` checks |

## The policy shape

```json
{
  "publickeys": {
    "<cilock-keyid>": { "key": "..." },
    "<cosign-keyid>": { "key": "..." }
  },
  "steps": {
    "build": {
      "functionaries": [{ "publickeyid": "<cilock-keyid>" }],
      "attestations": [
        { "type": "https://aflock.ai/attestations/material/v0.3" },
        { "type": "https://aflock.ai/attestations/product/v0.3" },
        ...
      ]
    }
  },
  "externalAttestations": {
    "slsa-provenance-from-cosign": {
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "required": true,
      "functionaries": [{ "publickeyid": "<cosign-keyid>" }]
    }
  }
}
```

The `build` step expects a cilock collection envelope. The `slsa-provenance-from-cosign` external expects a bare-predicate DSSE envelope with `predicateType=https://slsa.dev/provenance/v0.2` signed by the cosign key. Both go through DSSE signature verification; the external also runs through any attached Rego or AI policies (see [policy_external_test.go](https://github.com/aflock-ai/rookery/blob/main/attestation/policy/policy_external_test.go) for the test matrix).

## How cosign produces the envelope

```bash
cosign attest-blob \
  --key cosign.key \
  --predicate predicate.json \
  --type slsaprovenance \
  --new-bundle-format=false \
  --use-signing-config=false \
  --tlog-upload=false \
  --yes \
  hello > cosign-dsse.json
```

Three flags worth noting:
- `--new-bundle-format=false` — cosign v3 defaults to the bundle format; we want the classic DSSE envelope cilock can ingest directly. Both forms wrap the same in-toto Statement.
- `--tlog-upload=false` — keeps the demo offline. In a real pipeline you'd want the Rekor entry; verifying that the cosign envelope is in Rekor is a separate decision from verifying the cosign signature, and is the kind of check you'd put in a Rego policy on this external attestation.
- The cosign-emitted file is `payloadType=application/vnd.in-toto+json` with a single in-toto Statement payload. That's the wire format cilock policy already speaks.

## How cilock verifies

```bash
cilock verify \
  -p policy-signed.json \
  -k cilock-pub.pem \
  -a cilock-attestation.json \
  -a cosign-dsse.json \
  -f hello \
  -s "sha256:<materials-root>" \
  -s "sha256:<products-root>" \
  --enable-archivista=false
```

The `-a cosign-dsse.json` is the cosign envelope, passed alongside the cilock collection. The Merkle subjects are necessary because cilock collections subject their envelope to the materials / products Merkle roots, not the artifact file hash — `reproduce.sh` extracts them from the cilock envelope before calling verify.

## Reproduce

```bash
# Tested with cilock built from rookery main (v0.3 material/product) and cosign v3.0.2.
CILOCK=/path/to/cilock ./reproduce.sh
```

Output ends with `[*] all three checks behaved as expected. evidence in <tmpdir>`. The temp dir contains all generated envelopes and verify logs so you can inspect them with `jq`.

## What this is NOT

- **Not** an in-bundle Rekor proof. You can layer that on top with a Rego policy on the external — cilock gives you the verified envelope; what you check against it is a policy decision.
- **Not** a claim that cosign and cilock have feature parity. Cosign signs blobs and OCI artifacts; cilock signs pipeline steps and produces structured per-attestor evidence. The interop is on the **wire format**: both sides emit + consume the same DSSE-wrapped in-toto Statements. See [`docs/ecosystem/cosign.md`](https://cilock.aflock.ai/ecosystem/cosign) for the abstraction-level breakdown.
