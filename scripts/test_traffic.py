#!/usr/bin/env python3
"""
Simple Traffic Generator Script for CloudShield Phase 1
Generates benign requests to the Nginx proxy to demonstrate load balancing
and generate baseline metrics for Prometheus.
"""

import sys
import time
import urllib.request
import json

NGINX_URL = "http://localhost:8080/api/v1/sample/hello"

def send_traffic(count=20, delay=0.1):
    print(f"[*] Sending {count} sample requests to {NGINX_URL}...")
    distribution = {}

    for i in range(1, count + 1):
        try:
            req = urllib.request.Request(NGINX_URL, headers={"User-Agent": f"CloudShield-TestClient/{i}"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                node = data.get("served_by", "unknown")
                upstream = resp.headers.get("X-Served-By", "unknown")
                distribution[node] = distribution.get(node, 0) + 1
                print(f"Request #{i:02d}: Handled by {node} (Upstream: {upstream})")
        except Exception as e:
            print(f"Request #{i:02d}: FAILED ({e})")
        time.sleep(delay)

    print("\n--- Upstream Distribution Summary ---")
    for node, c in distribution.items():
        print(f"  {node}: {c} requests ({(c/count)*100:.1f}%)")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    send_traffic(count)
