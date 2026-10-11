#!/usr/bin/env python3
"""
scripts/simulate_normal.py
Simulates legitimate, diverse client traffic against CloudShield:
- Multiple endpoints (/api/v1/sample/hello, /api/v1/sample/info, /health)
- Diverse User-Agents and query parameters
- Moderate rate (5-15 req/s)
- Healthy Shannon entropy across IPs and URLs
"""

import time
import random
import urllib.request
import urllib.error
import argparse

TARGET_URL = "http://localhost:8080"

ENDPOINTS = [
    "/api/v1/sample/hello",
    "/api/v1/sample/info",
    "/health",
    "/api/v1/sample/hello?item=1",
    "/api/v1/sample/hello?item=2",
    "/api/v1/sample/hello?item=3",
    "/api/v1/sample/info?view=detailed"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "CloudShield-HealthProber/1.0"
]

def run_simulation(duration_seconds: int = 15, requests_per_sec: float = 10.0):
    print("=" * 60)
    print(f"CloudShield Normal Traffic Simulation")
    print(f"Duration: {duration_seconds}s | Target RPS: {requests_per_sec}")
    print("=" * 60)

    start_time = time.time()
    total_sent = 0
    success_count = 0
    error_count = 0

    interval = 1.0 / requests_per_sec

    while time.time() - start_time < duration_seconds:
        endpoint = random.choice(ENDPOINTS)
        ua = random.choice(USER_AGENTS)
        url = f"{TARGET_URL}{endpoint}"

        req = urllib.request.Request(url, headers={"User-Agent": ua})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
                if status == 200:
                    success_count += 1
                else:
                    error_count += 1
        except Exception:
            error_count += 1

        total_sent += 1
        elapsed = time.time() - t0
        sleep_time = max(0.0, interval - elapsed)
        time.sleep(sleep_time)

    duration = time.time() - start_time
    actual_rps = total_sent / duration if duration > 0 else 0
    success_rate = (success_count / total_sent * 100.0) if total_sent > 0 else 0

    print("-" * 60)
    print(f"Simulation Complete:")
    print(f"Total Requests Sent: {total_sent}")
    print(f"Success Rate:        {success_rate:.1f}% ({success_count}/{total_sent})")
    print(f"Errors / Blocks:     {error_count}")
    print(f"Achieved RPS:        {actual_rps:.1f} req/s")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate normal traffic for CloudShield")
    parser.add_argument("--duration", type=int, default=10, help="Simulation duration in seconds")
    parser.add_argument("--rps", type=float, default=10.0, help="Target requests per second")
    args = parser.parse_args()

    run_simulation(duration_seconds=args.duration, requests_per_sec=args.rps)
