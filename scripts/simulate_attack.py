#!/usr/bin/env python3
"""
scripts/simulate_attack.py
Simulates a safe, controlled HTTP Flood DDoS attack against local CloudShield:
- Concentrated targeting on a single URL (/api/v1/sample/hello)
- High concurrency using a thread pool
- Intended to trigger Tier 1 rate-limiting and Tier 2 IP mitigation
"""

import time
import urllib.request
import urllib.error
import argparse
from concurrent.futures import ThreadPoolExecutor

TARGET_URL = "http://localhost:8080/api/v1/sample/hello"

def send_attack_request(client_id: int):
    # Spoof attack headers to simulate external adversary
    headers = {
        "User-Agent": "FloodBot/3.0 (CloudShield-Lab-Simulation)",
        "X-Forwarded-For": f"198.51.100.{10 + (client_id % 3)}",  # Concentrated attacker IPs
        "Accept": "*/*"
    }
    req = urllib.request.Request(TARGET_URL, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def run_simulation(duration_seconds: int = 10, concurrency: int = 25):
    print("=" * 60)
    print(f"CloudShield Safe HTTP Flood DDoS Simulation")
    print(f"Target:      {TARGET_URL}")
    print(f"Concurrency: {concurrency} threads | Duration: {duration_seconds}s")
    print("=" * 60)

    start_time = time.time()
    status_counts = {}
    total_sent = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        while time.time() - start_time < duration_seconds:
            futures = [executor.submit(send_attack_request, i) for i in range(concurrency)]
            for f in futures:
                code = f.result()
                status_counts[code] = status_counts.get(code, 0) + 1
                total_sent += 1
            time.sleep(0.05)

    duration = time.time() - start_time
    rps = total_sent / duration if duration > 0 else 0

    print("-" * 60)
    print("Attack Simulation Complete:")
    print(f"Total Requests: {total_sent} in {duration:.2f}s ({rps:.1f} req/s)")
    print("Response Status Breakdown:")
    for code, count in sorted(status_counts.items()):
        status_name = "Passed (200)" if code == 200 else ("Blocked (403)" if code == 403 else f"Status {code}")
        pct = (count / total_sent) * 100.0
        print(f"  [{code}] {status_name}: {count} ({pct:.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate HTTP flood against CloudShield")
    parser.add_argument("--duration", type=int, default=8, help="Attack duration in seconds")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrent attack threads")
    args = parser.parse_args()

    run_simulation(duration_seconds=args.duration, concurrency=args.concurrency)
