import os
import time
import json
import logging
import httpx
from datetime import datetime
from collections import deque
from typing import Dict, Any, List

logger = logging.getLogger("cloudshield.monitoring")

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://172.28.0.20:9090")
LOGS_PATH = os.getenv("NGINX_LOG_PATH", "/app/data/logs/access.log")

# In-memory circular buffer for time-series chart history (last 60 data points)
_history_buffer: deque = deque(maxlen=60)

async def query_prometheus(query: str) -> float:
    """Executes an instant PromQL query against Prometheus."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": query})
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", {}).get("result", [])
                if results and "value" in results[0]:
                    return float(results[0]["value"][1])
    except Exception as e:
        logger.debug(f"Prometheus query failed for '{query}': {e}")
    return 0.0

from app.core.proxy import extract_client_ip

# Dashboard and internal monitoring endpoints excluded from traffic analytics
INTERNAL_POLLING_PREFIXES = (
    "/api/v1/monitoring/",
    "/api/v1/detection/",
    "/api/v1/mitigation/",
    "/api/v1/auth/me",
    "/api/v1/health",
    "/health",
    "/metrics",
    "/stub_status",
    "/nginx-health",
    "/favicon.ico",
)

def is_internal_polling_request(uri: str, method: str = "GET") -> bool:
    """
    Identifies automated dashboard / telemetry polling queries that should be
    excluded from Layer-7 traffic and entropy calculations to prevent self-poisoning.
    Never filters honeypot decoys, admin actions (POST), or application endpoints.
    """
    if not uri:
        return False
    clean_uri = uri.split("?")[0]

    # Exclude standard telemetry, health, and status query paths
    if any(clean_uri.startswith(prefix) for prefix in INTERNAL_POLLING_PREFIXES):
        return True

    # The React dashboard polls GET /api/v1/incidents/ every 10s
    if method.upper() == "GET" and clean_uri.rstrip("/").endswith("/api/v1/incidents"):
        return True

    return False

def read_recent_access_logs(seconds_window: int = 10, filter_internal: bool = True) -> List[Dict[str, Any]]:
    """
    Reads JSON access logs within the last N seconds.
    - Supports millisecond-precision timestamps ('msec') with fallback to ISO 'time_local'.
    - Filters internal dashboard polling queries when filter_internal=True to prevent self-poisoning.
    - Resolves authenticated client-IP using trusted reverse-proxy chain traversal.
    """
    entries = []
    if not os.path.exists(LOGS_PATH):
        return entries

    now = time.time()
    try:
        with open(LOGS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            # Read last 1500 lines for efficiency (covers bursts up to 150 req/s over 10s)
            lines = f.readlines()[-1500:]
            for line in lines:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    data = json.loads(line)

                    # 1. High-resolution timestamp parsing ('msec' with fallback to 'time_local')
                    ts = None
                    msec_raw = data.get("msec")
                    if msec_raw is not None:
                        try:
                            ts = float(msec_raw)
                        except (ValueError, TypeError):
                            ts = None

                    if ts is None:
                        time_iso = data.get("time_local")
                        if time_iso:
                            try:
                                ts = datetime.fromisoformat(time_iso.replace("Z", "+00:00")).timestamp()
                            except Exception:
                                ts = None

                    if ts is None:
                        continue

                    # Window check (allow up to 2.0s future clock drift for container time jitter)
                    if (now - ts) > seconds_window or (ts - now) > 2.0:
                        continue

                    data["timestamp"] = ts

                    # 2. Exclude internal telemetry polling requests if requested
                    uri = data.get("request_uri", "")
                    method = data.get("request_method", "GET")
                    if filter_internal and is_internal_polling_request(uri, method):
                        continue

                    # 3. Client-IP attribution via trusted proxy policy and simulation channel
                    peer_ip = data.get("remote_addr")
                    xff = data.get("x_forwarded_for")
                    sim_token = data.get("sim_token")
                    sim_ip = data.get("sim_ip")
                    client_ip = extract_client_ip(
                        peer_ip=peer_ip,
                        xff_header=xff,
                        sim_token=sim_token,
                        sim_ip=sim_ip
                    )
                    data["client_ip"] = client_ip
                    # Set remote_addr to resolved client IP to preserve backward compatibility
                    data["remote_addr"] = client_ip

                    entries.append(data)
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"Error reading access logs: {e}")
    return entries

async def get_current_metrics() -> Dict[str, Any]:
    """
    Computes real-time telemetry combining Prometheus exporters and Nginx logs:
    - requests_per_sec
    - cpu_utilization
    - active_connections
    - bandwidth_kbps
    - error_rate_5xx
    - latency_ms
    """
    now_str = datetime.utcnow().strftime("%H:%M:%S")

    # 1. Requests per second: try Prometheus nginx exporter first
    rps = await query_prometheus("sum(rate(nginx_http_requests_total[10s]))")
    active_conn = await query_prometheus("nginx_connections_active")
    
    # 2. CPU utilization: query node_exporter
    cpu = await query_prometheus("100 - (avg(rate(node_cpu_seconds_total{mode='idle'}[10s])) * 100)")
    if cpu <= 0.0:
        cpu = await query_prometheus("avg(rate(process_cpu_seconds_total[10s])) * 100")
        if cpu <= 0.0:
            cpu = 12.5  # Baseline normal idle CPU

    # Fallback / log enrichment if Prometheus rate is still warming up
    log_entries = read_recent_access_logs(seconds_window=10)
    log_count = len(log_entries)
    if log_count > 0:
        log_rps = log_count / 10.0
        # Select the more responsive measurement: log_rps avoids Prometheus scrape delay/warming lag during sudden bursts
        rps = max(rps, log_rps)
        
        # Calculate 5xx errors from logs
        errors_5xx = sum(1 for e in log_entries if int(e.get("status", 200)) >= 500)
        error_rate = (errors_5xx / log_count) * 100.0

        # Partition proxy-level rate-limiting drops from genuine upstream application errors
        upstream_5xx = sum(
            1 for e in log_entries
            if int(e.get("status", 200)) >= 500 and bool(e.get("upstream_addr")) and e.get("upstream_addr") != "-"
        )
        upstream_error_rate = (upstream_5xx / log_count) * 100.0
        proxy_rate_limited_count = sum(
            1 for e in log_entries
            if int(e.get("status", 200)) == 503 and (not bool(e.get("upstream_addr")) or e.get("upstream_addr") == "-")
        )
        proxy_rate_limited_rate = (proxy_rate_limited_count / log_count) * 100.0

        # Calculate average request latency
        durations = [float(e.get("request_time", 0.0)) for e in log_entries]
        avg_latency = (sum(durations) / len(durations)) * 1000.0 if durations else 15.0

        # Bandwidth
        total_bytes = sum(int(e.get("body_bytes_sent", 0)) for e in log_entries)
        bandwidth_kbps = (total_bytes * 8.0) / (10.0 * 1024.0)
    else:
        error_rate = 0.0
        upstream_error_rate = 0.0
        proxy_rate_limited_rate = 0.0
        avg_latency = 18.0
        bandwidth_kbps = max(rps * 1.2, 2.5)

    if active_conn <= 0.0:
        active_conn = max(1.0, round(rps * 0.4, 0))

    metrics_point = {
        "timestamp": now_str,
        "requests_per_sec": round(rps, 1),
        "cpu_utilization": round(min(cpu, 100.0), 1),
        "active_connections": int(active_conn),
        "bandwidth_kbps": round(bandwidth_kbps, 1),
        "error_rate_5xx": round(error_rate, 2),
        "upstream_error_rate_5xx": round(upstream_error_rate, 2),
        "proxy_rate_limited_rate_503": round(proxy_rate_limited_rate, 2),
        "latency_ms": round(avg_latency, 1)
    }

    _history_buffer.append(metrics_point)
    return metrics_point

def get_metrics_history() -> List[Dict[str, Any]]:
    """Returns stored time-series points for dashboard charts."""
    if not _history_buffer:
        # Prepopulate with a few initial baseline points
        now = int(time.time())
        return [
            {
                "timestamp": datetime.fromtimestamp(now - (5 * i)).strftime("%H:%M:%S"),
                "requests_per_sec": 1.0,
                "cpu_utilization": 12.0,
                "active_connections": 1,
                "bandwidth_kbps": 2.5,
                "error_rate_5xx": 0.0,
                "latency_ms": 15.0
            }
            for i in range(10, -1, -1)
        ]
    return list(_history_buffer)
