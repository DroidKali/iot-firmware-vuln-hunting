#!/usr/bin/env python3
"""Synthetic status CGI for bench sample B-007 (hardened)."""
import json
import subprocess

ALLOWED = {"uptime": ["uptime"], "date": ["date", "+%Y-%m-%d"]}

def main():
    action = "uptime"
    argv = ALLOWED.get(action)
    if argv is None:
        print("Content-Type: application/json")
        print()
        print(json.dumps({"error": "unsupported action"}))
        return 1
    out = subprocess.run(argv, shell=False, check=False,
                         capture_output=True, text=True, timeout=5)
    print("Content-Type: application/json")
    print()
    print(json.dumps({"action": action, "out": out.stdout.strip()}))
    return 0

if __name__ == "__main__":
    main()
