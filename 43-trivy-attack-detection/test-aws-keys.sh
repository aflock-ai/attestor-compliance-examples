#!/bin/bash
# Test realistic AWS key patterns
# Keys generated at runtime to avoid GitHub push protection
# cilock secretscan catches these in command stdout

FAKE_KEY_ID="AKIA$(openssl rand -hex 8 | tr '[:lower:]' '[:upper:]')"
FAKE_SECRET="$(openssl rand -base64 30)"
FAKE_GH_TOKEN="ghp_$(openssl rand -hex 18)"

echo "Harvested from /proc/1234/environ:"
echo "AWS_ACCESS_KEY_ID=$FAKE_KEY_ID"
echo "AWS_SECRET_ACCESS_KEY=$FAKE_SECRET"
echo "GITHUB_TOKEN=$FAKE_GH_TOKEN"
echo "DATABASE_URL=postgresql://admin:$(openssl rand -base64 12)@db.internal:5432/prod"
