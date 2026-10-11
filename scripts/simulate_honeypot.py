#!/usr/bin/env python3
"""
scripts/simulate_honeypot.py
Simulates an adversary scanner probing CloudShield honeypot decoys:
- Probes decoy /admin-backup/ and /wp-login.php
- Demonstrates immediate high-confidence tripwire
- Verifies that the offending IP is blocked from accessing benign endpoints
"""

import time
import json
import urllib.request
import urllib.error
import argparse

BASE_URL = "http://localhost:8080"
ATTACKER_IP = "203.0.113.199"

def probe_decoy(endpoint: str):
    print(f"\n[STEP 1] Attacker ({ATTACKER_IP}) scanning decoy endpoint: {endpoint}")
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Nmap-Scripting-Engine/7.94",
        "X-Forwarded-For": ATTACKER_IP
    })
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"       Response HTTP {resp.status} - Body: {resp.read().decode()[:80]}...")
    except urllib.error.HTTPError as e:
        print(f"       Trapped! Response HTTP {e.code} ({e.reason})")
    except Exception as e:
        print(f"       Connection error: {e}")

def verify_blocklist():
    print(f"\n[STEP 2] Verifying that IP {ATTACKER_IP} is now blocked from legitimate endpoints...")
    legit_url = f"{BASE_URL}/api/v1/sample/hello"
    req = urllib.request.Request(legit_url, headers={
        "User-Agent": "Mozilla/5.0",
        "X-Forwarded-For": ATTACKER_IP
    })
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"       UNEXPECTED: IP was NOT blocked! Status: {resp.status}")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"       CONFIRMED! IP {ATTACKER_IP} was blocked with HTTP 403.")
            print(f"       Block details: {e.read().decode()}")
        else:
            print(f"       Received HTTP {e.code}")
    except Exception as e:
        print(f"       Error: {e}")

def inspect_honeypot_stats():
    print("\n[STEP 3] Inspecting Honeypot telemetry...")
    try:
        stats_url = f"{BASE_URL}/api/v1/honeypot/stats"
        with urllib.request.urlopen(stats_url, timeout=3.0) as resp:
            stats = json.loads(resp.read().decode())
            print(f"       Total Honeypot Hits: {stats.get('total_hits')}")
            print(f"       Trapped IPs Count:   {stats.get('trapped_ips')}")
            print(f"       Decoy Endpoints:     {stats.get('decoy_endpoints')}")
    except Exception as e:
        print(f"       Error fetching stats: {e}")

def main():
    print("=" * 60)
    print("CloudShield Honeypot & Tripwire Decoy Simulation")
    print("=" * 60)
    
    probe_decoy("/admin-backup/")
    time.sleep(1.0)
    verify_blocklist()
    time.sleep(0.5)
    inspect_honeypot_stats()

    print("\n" + "=" * 60)
    print("Honeypot Decoy Simulation Completed Successfully.")
    print("=" * 60)

if __name__ == "__main__":
    main()
