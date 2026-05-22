# 16 — `docker` ✅ validated against real infrastructure

Real `docker buildx build` against a tiny Dockerfile. The `--metadata-file metadata.json` flag writes a BuildKit JSON file that the docker attestor consumes as a product, extracting the image digest.

## Predicate excerpt

```json
{
  "products": {
    "1c1ee1a28c9bd4e1ebced0e39aa203309442f3bb1736c76ff6b807f60f4a54fd": {
      "materials": {},
      "imagereferences": [
        ""
      ],
      "imagedigest": {
        "sha256": "1c1ee1a28c9bd4e1ebced0e39aa203309442f3bb1736c76ff6b807f60f4a54fd"
      }
    }
  }
}
```

## What we found

Real built image digest sha256:1c1ee1a28c9bd4e1ebced0e39aa203309442f3bb1736c76ff6b807f60f4a54fd. Real BuildKit metadata-file consumed.

## Reproduce

```bash
docker buildx build --metadata-file metadata.json --load -t cilock-validation:latest .
cilock run --step docker-build \
  --signer-file-key-path key.pem --outfile docker.json --workingdir . \
  --attestations docker \
  -- bash -c "docker buildx build --metadata-file metadata.json --load -t cilock-validation:latest . && cat metadata.json"
```
