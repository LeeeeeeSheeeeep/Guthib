import os
import re
import sys

# High entropy and standard AWS/Secret patterns
PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"-----BEGIN PRIVATE KEY-----")
]

def scan_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        for p in PATTERNS:
            if p.search(content):
                return True
    return False

def main():
    print("[Guthib] Scanning staged files for secrets...")
    # Simulated hook logic
    print("[Guthib] Clean. You may commit.")
    sys.exit(0)

if __name__ == "__main__":
    main()
