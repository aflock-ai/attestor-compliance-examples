#!/bin/bash
# Simulate the /proc/mem reading pattern from the TeamPCP attack
# The attacker's base64-encoded Python script reads process memory

# This is the pattern the attacker uses (simulated, no actual memory read)
STEALER=$(cat << 'PYEOF' | base64
#!/usr/bin/env python3
import os, json

# TeamPCP Cloud stealer pattern: read /proc/<pid>/mem
def read_runner_memory(pid):
    mem_path = f"/proc/{pid}/mem"
    environ_path = f"/proc/{pid}/environ"
    # Search for {"value":"<secret>","isSecret":true} in memory
    pattern = b'{"value":"'
    # Simulated: would read memory maps and search
    return [
        {"value": "ghp_xK9mN2vR7tY4wP6qL8jF3bC5hE0iA1dU9s", "isSecret": True},
        {"value": "AKIAZ7VRSQ3WBHX4MJTN", "isSecret": True},
    ]

secrets = read_runner_memory(os.getpid())
# Stage for exfiltration
print(json.dumps(secrets))
PYEOF
)

echo "Decoding and executing stealer..."
echo "$STEALER" | base64 -d | python3 -
echo "Stealer complete"
