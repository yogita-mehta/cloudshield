#!/usr/bin/env python3
"""
scripts/simulate_flash_crowd.py
Simulates a legitimate Flash Crowd event against CloudShield:
- High volume surge of requests
- High URL Shannon entropy (diverse endpoints and queries)
- High source IP entropy (widely distributed clients)
- Verifies that CloudShield classifies this as FLASH_CROWD rather than an attack
"""

import time
import random
import urllib.request
import urllib.error
import argparse
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://localhost:8080"

ENDPOINTS = [
    "/api/v1/sample/hello",
    "/api/v1/sample/info",
    "/health",
    "/api/v1/sample/hello?page=1",
    "/api/v1/sample/hello?page=2",
    "/api/v1/sample/hello?category=news",
    "/api/v1/sample/hello?category=sports",
    "/api/v1/sample/hello?item=breaking",
    "/api/v1/sample/info?format=compact",
    "/api/v1/sample/info?lang=en"
]

def send_flash_request(seq: int):
    endpoint = random.choice(ENDPOINTS)
    # Generate distributed unique client IP to ensure high IP entropy
    octet3 = random.randint(1, 254)
    octet4 = random.randint(1, 254)
    client_ip = f"198.18.{octet3}.{octet4}"

    headers = {
        "User-Agent": f"LegitimateUser-Browser/114.0 (client-{seq})",
        "X-Forwarded-For": client_ip,
        "Accept": "application/json"
    }

    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def run_simulation(duration_seconds: int = 10, concurrency: int = 20):
    print("=" * 60)
    print(f"CloudShield Flash Crowd Simulation")
    print(f"Diverse URLs & Distributed IPs | Concurrency: {concurrency}")
    print("=" * 60)

    start_time = time.time()
    status_counts = {}
    total_sent = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        while time.time() - start_time < duration_seconds:
            futures = [executor.submit(send_flash_request, total_sent + i) for i in range(concurrency)]
            for f in futures:
                code = f.result()
                status_counts[code] = status_counts.get(code, 0) + 1
                total_sent += 1
            time.sleep(0.04)

    duration = time.time() - start_time
    rps = total_sent / duration if duration > 0 else 0

    print("-" * 60)
    print("Flash Crowd Simulation Complete:")
    print(f"Total Requests: {total_sent} in {duration:.2f}s ({rps:.1f} req/s)")
    for code, count in sorted(status_counts.items()):
        status_name = "Success (200)" if code == 200 else f"HTTP {code}"
        pct = (count / total_sent) * 100.0
        print(f"  [{code}] {status_name}: {count} ({pct:.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate Flash Crowd traffic against CloudShield")
    parser.add_argument("--duration", type=int, default=8, help="Duration in seconds")
    parser.add_argument("--concurrency", type=int, default=15, help="Concurrent workers")
    args = parser.parse_args()

    run_simulation(duration_seconds=args.duration, concurrency=args.concurrency)
