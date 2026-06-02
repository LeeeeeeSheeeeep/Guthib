import os
import re
import sys
import math
import subprocess

# High entropy and standard AWS/Secret patterns
PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"-----BEGIN PRIVATE KEY-----")
]

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_file(filepath):
    if not os.path.isfile(filepath):
        return False
        
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        
    # Check Regex Patterns
    for p in PATTERNS:
        if p.search(content):
            print(f"  [!] Regex match found in: {filepath}")
            return True
            
    # Check Shannon Entropy on words/tokens > 20 chars
    words = re.findall(r'\b[A-Za-z0-9+/=_-]{20,}\b', content)
    for word in words:
        entropy = calculate_entropy(word)
        if entropy > 4.5:
            print(f"  [!] High entropy string ({entropy:.2f} bits) found in: {filepath}")
            print(f"      String preview: {word[:10]}...")
            return True
            
    return False

def get_staged_files():
    try:
        result = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True, check=True)
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []

def main():
    print("[Guthib] Scanning staged files for secrets...")
    staged_files = get_staged_files()
    
    if not staged_files:
        print("[Guthib] No files staged for commit.")
        sys.exit(0)
        
    found_secrets = False
    for filepath in staged_files:
        if scan_file(filepath):
            found_secrets = True
            
    if found_secrets:
        print("[Guthib] Commit blocked! Secrets detected.")
        sys.exit(1)
        
    print("[Guthib] Clean. You may commit.")
    sys.exit(0)

if __name__ == "__main__":
    main()
