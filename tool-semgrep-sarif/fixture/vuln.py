"""Fixture with intentional findings for semgrep to detect.

This file exists only so the tool example produces a non-empty SARIF report.
Do not use any of these patterns in real code.
"""

import hashlib
import os
import subprocess


def insecure_hash(data: bytes) -> str:
    # semgrep: python.lang.security.audit.md5-used-as-password.md5-used-as-password
    return hashlib.md5(data).hexdigest()


def shell_injection(user_input: str) -> None:
    # semgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
    subprocess.Popen("echo " + user_input, shell=True)


def os_system_tainted(cmd: str) -> None:
    # semgrep: python.lang.security.audit.dangerous-system-call.dangerous-system-call
    os.system("ls " + cmd)
