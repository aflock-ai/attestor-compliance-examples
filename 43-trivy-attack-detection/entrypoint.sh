#!/bin/bash
# Simulated malicious entrypoint.sh mimicking the TeamPCP/Trivy attack
# This is a SAFE REPRODUCTION for testing cilock secretscan detection.
# No actual exfiltration occurs. All credentials are fake test values.

_COLLECT_PIDS="$$"

# --- STAGE 1: Credential Harvesting (simulated) ---
# Simulated harvested credentials using patterns gitleaks detects
# These are NOT real credentials — they are synthetic test values
# that match credential regex patterns

# Simulated GitHub PAT (matches github pat regex)
echo "Collected: ghp_R4nd0mT0k3nV4lu3Th4tL00ksR34lEnough1"

# Simulated AWS access key (matches AKIA pattern but not the allowlisted example)
echo "AWS_ACCESS_KEY_ID=AKIAT3ST0NLYF4K3K3YX"
echo "AWS_SECRET_ACCESS_KEY=t3stSecr3tK3y/N0tR34l/JustF0rSc4nn3rT3st1ng"

# Simulated private key in stdout
cat << 'KEYEOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNVRfRDhkPhTtKHFxPOIAIkRFSTiy6AlJBrqFr5X87LrGSsB93G3oT7VzMHTsefH
VaFmkOlgOd2dBHQGnKY9lHR2b8VYQ1dN7sTbOil3GJzq4N5cePayVJFMk9J5PsFG
WRiVt0JY4sDPOkvKxHIFfc/RdKPULkqkhJRz4YMShFj0tFjLcnPBMCSPkTJnR8WJ
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2y==
-----END RSA PRIVATE KEY-----
KEYEOF

# --- STAGE 2: Base64-encoded Python credential stealer ---
ENCODED_PAYLOAD=$(echo '#!/usr/bin/env python3
## TeamPCP Cloud stealer v2.1
import os, json, base64

# Read runner process memory for secrets
def harvest():
    token = "ghp_R4nd0mT0k3nV4lu3Th4tL00ksR34lEnough1"
    aws_key = "AKIAT3ST0NLYF4K3K3YX"
    aws_secret = "t3stSecr3tK3y/N0tR34l/JustF0rSc4nn3rT3st1ng"
    return json.dumps({"secrets": [token, aws_key, aws_secret]})

if __name__ == "__main__":
    data = harvest()
    # Double-encode to evade scanners
    encoded = base64.b64encode(data.encode()).decode()
    print(f"COLLECTED: {encoded}")
' | base64)

echo "Running encoded payload..."
echo "$ENCODED_PAYLOAD" | base64 -d | python3 - 2>/dev/null || true

# --- STAGE 3: Exfiltration target ---
EXFIL_URL=$(echo "aHR0cHM6Ly9zY2FuLmFxdWFzZWN1cnRpeS5vcmc=" | base64 -d)
echo "C2: $EXFIL_URL"

# --- LEGITIMATE SCAN ---
echo "Running trivy scan..."
echo "Scan complete."
