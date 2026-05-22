# 11 — `pip-install` ✅ validated against real infrastructure

Real `pip install httpx` against PyPI on a Python 3.14 venv. The pip-install attestor reads `pip list --format=json`, walks site-packages for suspicious patterns, and queries PyPI's PEP 740 integrity API for every installed package.

## Predicate excerpt

```json
{
  "pipVersion": "pip 26.1.1 from /private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages/pip (python 3.14)",
  "pythonVersion": "Python 3.14.5",
  "packages": [
    {
      "name": "anyio",
      "version": "4.13.0",
      "location": "/private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages",
      "requires": [
        "idna"
      ],
      "requiredBy": [
        "httpx"
      ]
    },
    {
      "name": "certifi",
      "version": "2026.5.20",
      "location": "/private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages",
      "requiredBy": [
        "httpcore",
        "httpx",
        "requests"
      ],
      "homePage": "https://github.com/certifi/python-certifi",
      "author": "Kenneth Reitz",
      "license": "MPL-2.0"
    },
    {
      "name": "charset-normalizer",
      "version": "3.4.7",
      "location": "/private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages",
      "requiredBy": [
        "requests"
      ],
      "license": "MIT"
    },
    {
      "name": "h11",
      "version": "0.16.0",
      "location": "/private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages",
      "requiredBy": [
        "httpcore"
      ],
      "homePage": "https://github.com/python-hyper/h11",
      "author": "Nathaniel J. Smith",
      "license": "MIT"
    },
    {
      "name": "httpcore",
      "version": "1.0.9",
      "location": "/private/tmp/attestor-compliance-examples/_validation/work/.venv/lib/python3.14/site-packages",
      "requires": [
        "certifi",
        "h11"
      ],
      "requiredBy": [
        "httpx"
      ],
      "homePage": "https://www.encode.io/httpcore
... (truncated)
```

## What we found

9 of the 10 installed packages had valid PEP 740 attestations on PyPI, all from GitHub-issued Sigstore certificates. Each attestation links back to a real workflow URL (e.g. https://github.com/agronholm/anyio/.github/workflows/publish.yml).

## Reproduce

```bash
source .venv/bin/activate && cilock run --step pip-install-real \
  --signer-file-key-path key.pem --outfile pip.json --workingdir . \
  --attestations pip-install,environment \
  -- bash -c "pip install --quiet httpx && pip list --format=json > pip-list.json"
```
