# 15 — `oci` ✅ validated against real infrastructure

Real `docker save alpine:3.20` OCI tarball captured by the oci attestor. The attestor reads the tar, parses `manifest.json` for repo tags + layer digests, computes the image-id digest, and emits a structured predicate.

## Predicate excerpt

```json
{
  "tardigest": {
    "sha256": "e10b8d2928f8bb4e55e50bac3876631bf819f5d6286294979ead449ea7a0ed32"
  },
  "manifest": [
    {
      "Config": "blobs/sha256/bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731",
      "RepoTags": [
        "alpine:3.20"
      ],
      "Layers": [
        "blobs/sha256/08bc4e534116aa76b16015484b82eac51f9a593416feae9296c8a2d4bb7aa4a2"
      ]
    }
  ],
  "imagetags": [
    "alpine:3.20"
  ],
  "diffids": [
    {
      "sha256": "08bc4e534116aa76b16015484b82eac51f9a593416feae9296c8a2d4bb7aa4a2"
    }
  ],
  "imageid": {
    "sha256": "bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731"
  },
  "manifestraw": "W3siQ29uZmlnIjoiYmxvYnMvc2hhMjU2L2JmODUyN2ViNTRjMzY4MGU3MjhkNWI0YjM4M2E4YmE3MzBkNzJkYWU3MjM2ZmJjOGRmZjk3ZWQ2YjIyNGE3MzEiLCJSZXBvVGFncyI6WyJhbHBpbmU6My4yMCJdLCJMYXllcnMiOlsiYmxvYnMvc2hhMjU2LzA4YmM0ZTUzNDExNmFhNzZiMTYwMTU0ODRiODJlYWM1MWY5YTU5MzQxNmZlYWU5Mjk2YzhhMmQ0YmI3YWE0YTIiXSwiTGF5ZXJTb3VyY2VzIjp7InNoYTI1NjowOGJjNGU1MzQxMTZhYTc2YjE2MDE1NDg0YjgyZWFjNTFmOWE1OTM0MTZmZWFlOTI5NmM4YTJkNGJiN2FhNGEyIjp7Im1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5vY2kuaW1hZ2UubGF5ZXIudjEudGFyIiwic2l6ZSI6ODA5MjE2MCwiZGlnZXN0Ijoic2hhMjU2OjA4YmM0ZTUzNDExNmFhNzZiMTYwMTU0ODRiODJlYWM1MWY5YTU5MzQxNmZlYWU5Mjk2YzhhMmQ0YmI3YWE0YTIifX19XQo=",
  "manifestdigest": {
    "sha256": "3ee760636780b5ac089f0384ed338a96df2c6f51979d43a904f2194883029eec"
  }
}
```

## What we found

Captured real alpine:3.20 manifest with layer diff-ids matching what `docker inspect` reports. Tar SHA, manifest SHA, and image-id digests all match independent verification.

## Reproduce

```bash
docker pull alpine:3.20 && docker save alpine:3.20 -o alpine-3.20.tar
cilock run --step oci-save \
  --signer-file-key-path key.pem --outfile oci.json --workingdir . \
  --attestations oci \
  -- bash -c "docker save alpine:3.20 -o alpine-3.20.tar"
```
