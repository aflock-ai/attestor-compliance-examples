"""Intentionally vulnerable Python — multi-CWE for CodeQL demo."""
import subprocess
import os
import sys
import xml.etree.ElementTree as ET
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

@app.route("/exec")
def web_exec():
    # CWE-78: untrusted HTTP arg → shell command
    cmd = request.args.get("cmd", "")
    return subprocess.check_output(cmd, shell=True)

@app.route("/lookup")
def lookup():
    # CWE-89: SQL injection via untrusted HTTP arg
    import sqlite3
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()

@app.route("/parse")
def parse_xml():
    # CWE-611: XXE via ET.fromstring on attacker-controlled body
    return ET.fromstring(request.data).tag

@app.route("/render")
def render():
    # CWE-94: code injection via eval on untrusted input
    return str(eval(request.args.get("expr", "0")))

def weak_hash(pw):
    # CWE-327: MD5 for password hashing
    return hashlib.md5(pw.encode()).hexdigest()

def deserialize(payload):
    # CWE-502: untrusted pickle
    return pickle.loads(payload)

if __name__ == "__main__":
    app.run()
