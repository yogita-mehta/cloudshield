#!/usr/bin/env python3
"""
scripts/benchmark_suite.py
CloudShield Repeatable Live Benchmark Suite

Executes live, safe local benchmarks against running CloudShield deployment:
1. Normal Traffic (Baseline benign web usage)
2. Concentrated Flood (High RPS on single URI from concentrated IPs)
3. Distributed Flood (High RPS on single URI from widely distributed IPs)
4. Low-Rate Flood (Sub-surge RPS on target URI testing sensitivity vs false negatives)
5. Honeypot Tripwire (Adversary scanning decoy endpoints triggering deterministic tripwire)
6. Flash Crowd (High RPS surge across diverse URIs from widely distributed IPs)
7. Ambiguous Traffic (Borderline rate near threshold with moderate diversity)

Features:
- Live observation: Real request timing, actual HTTP status codes, live detection status polling.
- Zero hardcoded results: Ground truth recorded separately from actual observed classifications.
- Strict safety limits: Concurrency <= 25, RPS <= 65, duration <= 12s per scenario.
- Independent probing: Measures legitimate client availability and p50/p95 latency.
- Supported reset pipeline: Unblocks IPs, resets tier, ages out the 10s log window between runs.
- Secret-safe: Dynamically loads SIMULATION_TOKEN without printing or writing to results.
- Outputs structured data to docs/BENCHMARK_RESULTS_LIVE.json.
"""

import os
import sys
import subprocess
import time
import json
import random
import argparse
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple, Callable

BASE_URL = os.getenv("TARGET_URL", "http://localhost:8080")
DEFAULT_RESULTS_NAME = "BENCHMARK_RESULTS_RUN2_CONTROLLED_RATE.json"
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", DEFAULT_RESULTS_NAME)

def load_simulation_token() -> Optional[str]:
    """Loads SIMULATION_TOKEN from environment or local .env without printing it."""
    token = os.getenv("SIMULATION_TOKEN")
    if token and token.strip():
        return token.strip()
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("SIMULATION_TOKEN="):
                        val = line.split("=", 1)[1].strip()
                        if val:
                            return val
        except Exception:
            pass
    return None

KNOWN_BACKENDS = ["172.28.0.11:8000", "172.28.0.12:8000"]
BACKEND_CONTAINERS: Dict[str, str] = {
    "172.28.0.11:8000": "cloudshield-backend-1",
    "172.28.0.12:8000": "cloudshield-backend-2",
}

def direct_backend_request(
    container_name: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    timeout: float = 3.0
) -> Optional[Dict[str, Any]]:
    """
    Directly invokes a FastAPI endpoint on a specific backend container via 'docker exec'.
    This communicates directly with the container's internal FastAPI server on 127.0.0.1:8000,
    bypassing Nginx load balancing and eliminating any routing ambiguity or round-robin assumptions.
    """
    if payload is not None:
        payload_json = json.dumps(payload)
        py_code = (
            f"import urllib.request, json\n"
            f"req = urllib.request.Request('http://127.0.0.1:8000{path}', "
            f"data={repr(payload_json)}.encode('utf-8'), "
            f"headers={{'Content-Type': 'application/json', 'Accept': 'application/json'}}, "
            f"method='{method}')\n"
            f"with urllib.request.urlopen(req, timeout={timeout}) as resp:\n"
            f"    print(resp.read().decode('utf-8'))\n"
        )
    else:
        py_code = (
            f"import urllib.request\n"
            f"req = urllib.request.Request('http://127.0.0.1:8000{path}', "
            f"headers={{'Accept': 'application/json'}}, "
            f"method='{method}')\n"
            f"with urllib.request.urlopen(req, timeout={timeout}) as resp:\n"
            f"    print(resp.read().decode('utf-8'))\n"
        )
    try:
        cmd = ["docker", "exec", container_name, "python", "-c", py_code]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3.0)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
    except Exception:
        pass
    return None

def http_get_json_node(url: str, timeout: float = 3.0) -> Tuple[Optional[Dict[str, Any]], str]:
    """Helper to perform HTTP GET and parse JSON, capturing X-Served-By upstream node."""
    req = urllib.request.Request(url, headers={"User-Agent": "CloudShield-Benchmark/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            node = resp.headers.get("X-Served-By", "unknown")
            return json.loads(resp.read().decode("utf-8")), node
    except Exception:
        return None, "unknown"

def http_post_json_node(url: str, payload: Dict[str, Any], timeout: float = 3.0) -> Tuple[Optional[Dict[str, Any]], str]:
    """Helper to perform HTTP POST with JSON body, capturing X-Served-By upstream node."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "CloudShield-Benchmark/1.0", "Accept": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            node = resp.headers.get("X-Served-By", "unknown")
            return json.loads(resp.read().decode("utf-8")), node
    except Exception:
        return None, "unknown"

def http_get_json(url: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Helper to perform HTTP GET and parse JSON."""
    data, _ = http_get_json_node(url, timeout=timeout)
    return data

def http_post_json(url: str, payload: Dict[str, Any], timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Helper to perform HTTP POST with JSON body."""
    data, _ = http_post_json_node(url, payload, timeout=timeout)
    return data

# ---------------------------------------------------------------------------
# State Reset & Cleanup Pipeline
# ---------------------------------------------------------------------------

def reset_system_state() -> Dict[str, Any]:
    """
    Resets CloudShield mitigation and detection state using supported API endpoints
    addressed independently to each backend container:
    1. Unblocks all currently blocked IPs via POST /api/v1/mitigation/unblock
       (Directly invoked on each backend container to clear in-memory and disk state)
    2. Resets mitigation tier to NONE via POST /api/v1/mitigation/tier
       (Directly invoked on each backend container)
    3. Waits for 11 seconds so the 10-second Nginx access log window ages out
    4. Triggers POST /api/v1/detection/evaluate and independently verifies baseline state
       on both backends (classification=NORMAL, active_tier=NONE, blocked_ip_count=0)
    5. Confirms Nginx reverse proxy health
    """
    print("[RESET] Initiating clean system state reset...")
    cleanup_log = []
    tiers_reset_nodes = []

    # 1. Wait for Nginx access log analysis window (10s) to age out first.
    # This prevents the 4.0s background detection loop from re-detecting honeypot or flood logs.
    print("[RESET] Waiting 11s for 10-second Nginx telemetry log window to age out...")
    time.sleep(11.0)

    # 2. Reset each backend container directly and independently AFTER log-drain completes
    for backend_addr, container_name in BACKEND_CONTAINERS.items():
        # Step 2a: Query mitigation status directly on this container
        mit_status = direct_backend_request(container_name, "GET", "/api/v1/mitigation/status")
        if mit_status and mit_status.get("blocked_ips"):
            for ip in mit_status["blocked_ips"]:
                unblock_res = direct_backend_request(
                    container_name, "POST", "/api/v1/mitigation/unblock",
                    {"ip": ip, "reason": "Benchmark scenario reset (post-drain)"}
                )
                if unblock_res and unblock_res.get("success"):
                    cleanup_log.append(f"Unblocked {ip} directly on {container_name} ({backend_addr})")
                else:
                    cleanup_log.append(f"Unblock for {ip} on {container_name} ({backend_addr}) reported: {unblock_res}")

        # Step 2b: Reset active tier to NONE directly on this container
        tier_res = direct_backend_request(
            container_name, "POST", "/api/v1/mitigation/tier",
            {"tier": "NONE", "reason": "Benchmark scenario reset (post-drain)"}
        )
        if tier_res and tier_res.get("active_tier") == "NONE":
            tiers_reset_nodes.append(backend_addr)
            cleanup_log.append(f"Tier reset to NONE confirmed directly on {container_name} ({backend_addr})")
        else:
            cleanup_log.append(f"Tier reset on {container_name} ({backend_addr}) reported: {tier_res}")

        # Step 2c: Trigger evaluation on this container to clear detector verdict
        direct_backend_request(container_name, "POST", "/api/v1/detection/evaluate", {})

    # 3. Independently verify baseline clean state across all backends
    def _verify_all_nodes():
        nodes_state = {}
        for b_addr, c_name in BACKEND_CONTAINERS.items():
            direct_backend_request(c_name, "POST", "/api/v1/detection/evaluate", {})
            d_stat = direct_backend_request(c_name, "GET", "/api/v1/detection/status")
            m_stat = direct_backend_request(c_name, "GET", "/api/v1/mitigation/status")
            if d_stat and m_stat:
                c = d_stat.get("classification", "UNKNOWN")
                t = m_stat.get("active_tier", d_stat.get("mitigation_tier", "UNKNOWN"))
                r = d_stat.get("requests_per_sec", 0.0)
                b_cnt = m_stat.get("blocked_ip_count", len(m_stat.get("blocked_ips", [])))
                b_ips = m_stat.get("blocked_ips", [])
                clean = (c == "NORMAL" and t == "NONE" and b_cnt == 0)
                nodes_state[b_addr] = {
                    "container": c_name,
                    "classification": c,
                    "mitigation_tier": t,
                    "requests_per_sec": r,
                    "blocked_ip_count": b_cnt,
                    "blocked_ips": b_ips,
                    "is_clean": clean
                }
            else:
                nodes_state[b_addr] = {
                    "container": c_name,
                    "classification": "UNREACHABLE",
                    "mitigation_tier": "UNKNOWN",
                    "requests_per_sec": 0.0,
                    "blocked_ip_count": -1,
                    "blocked_ips": [],
                    "is_clean": False
                }
        all_ok = all(b in nodes_state and nodes_state[b]["is_clean"] for b in KNOWN_BACKENDS)
        return all_ok, nodes_state

    all_verified, verified_nodes = _verify_all_nodes()
    # Retry once after 1.0s grace if any node is transiently not clean
    if not all_verified:
        time.sleep(1.0)
        for b_addr, c_name in BACKEND_CONTAINERS.items():
            m_stat = direct_backend_request(c_name, "GET", "/api/v1/mitigation/status")
            if m_stat and m_stat.get("blocked_ips"):
                for ip in m_stat["blocked_ips"]:
                    direct_backend_request(c_name, "POST", "/api/v1/mitigation/unblock", {"ip": ip, "reason": "Retry unblock"})
            direct_backend_request(c_name, "POST", "/api/v1/mitigation/tier", {"tier": "NONE", "reason": "Retry reset"})
            direct_backend_request(c_name, "POST", "/api/v1/detection/evaluate", {})
        all_verified, verified_nodes = _verify_all_nodes()

    if all_verified:
        print(f"[RESET] Baseline verified clean independently on all backends ({list(verified_nodes.keys())}): State=NORMAL | Tier=NONE | Blocked=0")
    else:
        print(f"[RESET WARNING] Reset verification incomplete or unconfirmed for backends: {verified_nodes}", file=sys.stderr)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reset_verified": all_verified,
        "actions": cleanup_log,
        "tier_reset_confirmed_nodes": tiers_reset_nodes,
        "backend_verifications": verified_nodes,
        "baseline_state": "NORMAL" if all_verified else "UNVERIFIED"
    }

# ---------------------------------------------------------------------------
# Legitimate Client Probe Worker
# ---------------------------------------------------------------------------

class LegitimateProbeClient:
    """Continuously probes the server during a scenario to measure availability & latency."""
    def __init__(self, target_url: str, interval: float = 1.0):
        self.target_url = f"{target_url}/api/v1/sample/hello"
        self.interval = interval
        self.stop_requested = False
        self.results: List[Tuple[float, int, float]] = []  # (timestamp, status, latency_ms)

    def run(self):
        while not self.stop_requested:
            t0 = time.perf_counter()
            status_code = 0
            req = urllib.request.Request(
                self.target_url,
                headers={
                    "User-Agent": "CloudShield-LegitProbe/1.0",
                    "Accept": "application/json"
                }
            )
            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    status_code = resp.status
            except urllib.error.HTTPError as e:
                status_code = e.code
            except Exception:
                status_code = 504
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self.results.append((time.time(), status_code, latency_ms))
            time.sleep(self.interval)

    def stop(self) -> Dict[str, Any]:
        self.stop_requested = True
        total = len(self.results)
        if total == 0:
            return {"probes_sent": 0, "probes_successful": 0, "availability_pct": 0.0, "mean_latency_ms": 0.0, "p50_latency_ms": 0.0, "p95_latency_ms": 0.0}

        successes = sum(1 for _, code, _ in self.results if code == 200)
        latencies = sorted(lat for _, _, lat in self.results)
        mean_lat = sum(latencies) / total
        p50 = latencies[int(total * 0.50)]
        p95 = latencies[min(int(total * 0.95), total - 1)]
        p99 = latencies[min(int(total * 0.99), total - 1)]
        avail = (successes / total) * 100.0

        return {
            "probes_sent": total,
            "probes_successful": successes,
            "availability_pct": round(avail, 2),
            "mean_latency_ms": round(mean_lat, 2),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2)
        }

# ---------------------------------------------------------------------------
# Continuous Detection Observer
# ---------------------------------------------------------------------------

class DetectionObserver:
    """Polls /api/v1/detection/status every 500ms to observe real detection state changes."""
    def __init__(self, target_url: str, interval: float = 0.5):
        self.status_url = f"{target_url}/api/v1/detection/status"
        self.interval = interval
        self.stop_requested = False
        self.observations: List[Dict[str, Any]] = []

    def run(self):
        while not self.stop_requested:
            t0 = time.time()
            data = http_get_json(self.status_url, timeout=2.0)
            if data:
                self.observations.append({
                    "poll_time": t0,
                    "classification": data.get("classification"),
                    "mitigation_tier": data.get("mitigation_tier"),
                    "requests_per_sec": data.get("requests_per_sec"),
                    "baseline_rps": data.get("baseline_rps"),
                    "url_entropy": data.get("url_entropy"),
                    "ip_entropy": data.get("ip_entropy"),
                    "top_ip_concentration_pct": data.get("top_ip_concentration_pct"),
                    "verdict_reason": data.get("verdict_reason")
                })
            time.sleep(self.interval)

    def stop(self) -> List[Dict[str, Any]]:
        self.stop_requested = True
        return self.observations

# ---------------------------------------------------------------------------
# Rate-Controlled Precision Scheduler
# ---------------------------------------------------------------------------

class RateControlledScheduler:
    """
    Precision rate-controlled scheduler using a monotonic clock and bounded worker pool.
    Guarantees that target_rps means total requests per second across all workers.

    Metrics & Architecture:
    - Immutable run-start timestamp (immutable_start) for uncorrupted duration accounting.
    - Separate schedule anchor for tracking inter-request intervals without drifting run-start.
    - Strictly bounded to duration: stops scheduling as soon as monotonic time reaches duration.
    - Bounded worker pool & queue: pauses dispatch if in-flight active futures reach max_queue.
    - Explicit exception-safe draining with strict timeout handling for uncompleted tasks.
    - Discloses both dispatch-window RPS and completion throughput.
    """
    def __init__(
        self,
        target_rps: float,
        duration: float,
        concurrency: int = 10,
        max_queue: Optional[int] = None,
        drain_timeout_sec: float = 3.0
    ):
        self.target_rps = max(0.1, float(target_rps))
        self.duration = float(duration)
        self.concurrency = max(1, int(concurrency))
        self.max_queue = max_queue or max(int(self.target_rps * 1.5), self.concurrency * 3, 16)
        self.drain_timeout_sec = max(0.05, float(drain_timeout_sec))

    def execute(self, task_fn: Callable[[], Any]) -> Tuple[List[Any], Dict[str, Any]]:
        interval = 1.0 / self.target_rps
        total_slots = int(self.duration * self.target_rps)

        results = []
        active_futures = set()

        # Immutable timestamps
        immutable_start = time.perf_counter()
        overall_start_iso = datetime.now(timezone.utc).isoformat()
        deadline = immutable_start + self.duration

        first_dispatch_time: Optional[float] = None
        last_dispatch_time: Optional[float] = None
        last_completion_time: Optional[float] = None

        submitted_requests = 0
        completed_requests = 0
        missed_slots = 0
        backpressure_waits = 0
        max_lateness_sec = 0.0
        worker_errors = 0
        worker_timeouts = 0
        unfinished_requests = 0
        drain_timed_out = False

        schedule_anchor = immutable_start

        executor = ThreadPoolExecutor(max_workers=self.concurrency)
        try:
            for slot_idx in range(total_slots):
                target_dispatch = schedule_anchor + (slot_idx * interval)
                now = time.perf_counter()

                # Bounded by duration: strictly cease scheduling if duration has expired
                if now >= deadline or target_dispatch >= deadline:
                    missed_slots += (total_slots - slot_idx)
                    break

                # Sleep if ahead of schedule
                delay = target_dispatch - now
                if delay > 0.0005:
                    time.sleep(min(delay, max(0.0, deadline - now)))
                    now = time.perf_counter()
                    if now >= deadline:
                        missed_slots += (total_slots - slot_idx)
                        break

                lateness = max(0.0, now - target_dispatch)
                if lateness > max_lateness_sec:
                    max_lateness_sec = lateness

                # If behind by more than 1 interval, do not burst-compensate; re-anchor schedule
                # Schedule anchor adjustment must never push any dispatch past deadline
                if lateness > interval:
                    schedule_anchor = now - (slot_idx * interval)

                # Collect already completed futures
                done = {f for f in active_futures if f.done()}
                for f in done:
                    try:
                        res = f.result()
                        results.append(res)
                        completed_requests += 1
                        last_completion_time = time.perf_counter()
                    except Exception:
                        worker_errors += 1
                        last_completion_time = time.perf_counter()
                active_futures.difference_update(done)

                # Queue bounding: if in-flight active futures reach max_queue, wait for capacity
                while len(active_futures) >= self.max_queue:
                    backpressure_waits += 1
                    if time.perf_counter() >= deadline:
                        break
                    remaining_time = max(0.001, deadline - time.perf_counter())
                    wait_timeout = max(0.001, min(interval * 0.5, remaining_time, 0.01))
                    finished, _ = concurrent.futures.wait(
                        active_futures,
                        timeout=wait_timeout,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for f in finished:
                        try:
                            res = f.result()
                            results.append(res)
                            completed_requests += 1
                            last_completion_time = time.perf_counter()
                        except Exception:
                            worker_errors += 1
                            last_completion_time = time.perf_counter()
                    active_futures.difference_update(finished)

                    if time.perf_counter() >= deadline:
                        break

                # Strict dispatch deadline: no task may be submitted at or after immutable deadline
                if time.perf_counter() >= deadline:
                    missed_slots += (total_slots - slot_idx)
                    break

                # Dispatch task
                f = executor.submit(task_fn)
                active_futures.add(f)
                dispatch_ts = time.perf_counter()
                if first_dispatch_time is None:
                    first_dispatch_time = dispatch_ts
                last_dispatch_time = dispatch_ts
                submitted_requests += 1

            # Draining phase with bounded timeout
            drain_deadline = time.perf_counter() + self.drain_timeout_sec
            cancelled_pending = 0
            running_at_shutdown = 0
            if active_futures:
                remaining_drain = max(0.001, drain_deadline - time.perf_counter())
                finished, unfinished = concurrent.futures.wait(
                    active_futures,
                    timeout=remaining_drain,
                    return_when=concurrent.futures.ALL_COMPLETED
                )
                for f in finished:
                    try:
                        res = f.result()
                        results.append(res)
                        completed_requests += 1
                        last_completion_time = time.perf_counter()
                    except Exception:
                        worker_errors += 1
                        last_completion_time = time.perf_counter()

                if unfinished:
                    drain_timed_out = True
                    worker_timeouts = len(unfinished)
                    unfinished_requests = len(unfinished)
                    for f in unfinished:
                        if f.cancel():
                            cancelled_pending += 1
                        else:
                            running_at_shutdown += 1
        finally:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

        completion_end = time.perf_counter()
        if last_completion_time is None:
            last_completion_time = completion_end

        # Duration calculations strictly from immutable timestamps
        total_completion_duration = max(0.0001, completion_end - immutable_start)

        if first_dispatch_time and last_dispatch_time and submitted_requests > 1:
            dispatch_duration = max(0.0001, last_dispatch_time - first_dispatch_time)
            # Dispatch window RPS covers the inter-arrival span of (submitted_requests - 1) intervals
            dispatch_window_rps = (submitted_requests - 1) / dispatch_duration
        elif submitted_requests == 1:
            dispatch_duration = interval
            dispatch_window_rps = 1.0 / interval
        else:
            dispatch_duration = 0.0
            dispatch_window_rps = 0.0

        # Throughput strictly based on genuinely completed tasks
        completed_request_throughput_rps = (
            completed_requests / total_completion_duration if total_completion_duration > 0 else 0.0
        )

        dispatch_deadline_respected = (last_dispatch_time is None) or (last_dispatch_time < deadline)
        is_workload_fully_delivered = (
            missed_slots == 0 and
            submitted_requests == total_slots and
            completed_requests == submitted_requests and
            worker_errors == 0 and
            worker_timeouts == 0 and
            unfinished_requests == 0 and
            backpressure_waits == 0
        )
        rate_limited_or_incomplete = not is_workload_fully_delivered

        stats = {
            "configured_target_rps": self.target_rps,
            "configured_duration_sec": self.duration,
            "concurrency": self.concurrency,
            "total_scheduling_slots": total_slots,
            "submitted_requests": submitted_requests,
            "completed_requests": completed_requests,
            "worker_errors": worker_errors,
            "worker_timeouts": worker_timeouts,
            "unfinished_requests": unfinished_requests,
            "cancelled_pending_requests": cancelled_pending,
            "running_at_shutdown_requests": running_at_shutdown,
            "missed_scheduling_slots": missed_slots,
            "backpressure_wait_events": backpressure_waits,
            "max_lateness_sec": round(max_lateness_sec, 4),
            "drain_timed_out": drain_timed_out,
            "drain_timeout_sec": self.drain_timeout_sec,
            "executor_shutdown_waited": False,
            "dispatch_deadline_respected": dispatch_deadline_respected,
            "workload_fully_delivered": is_workload_fully_delivered,
            "rate_limited_or_incomplete": rate_limited_or_incomplete,
            "timestamps": {
                "overall_start_iso": overall_start_iso,
                "first_dispatch_sec": round(first_dispatch_time - immutable_start, 4) if first_dispatch_time else None,
                "last_dispatch_sec": round(last_dispatch_time - immutable_start, 4) if last_dispatch_time else None,
                "last_completion_sec": round(last_completion_time - immutable_start, 4) if last_completion_time else None,
                "dispatch_duration_sec": round(dispatch_duration, 4),
                "total_completion_duration_sec": round(total_completion_duration, 4),
            },
            "dispatch_window_rps": round(dispatch_window_rps, 2),
            "completed_request_throughput_rps": round(completed_request_throughput_rps, 2),
            # Backward-compatible aliases:
            "target_rps": self.target_rps,
            "scheduled_requests": submitted_requests,
            "completion_throughput_rps": round(completed_request_throughput_rps, 2),
            "within_configured_duration": dispatch_deadline_respected,
            "is_rate_limited_or_incomplete": rate_limited_or_incomplete,
            "metric_definitions": {
                "total_scheduling_slots": "Number of temporal dispatch slots configured for the run: int(duration * target_rps).",
                "submitted_requests": "Number of tasks successfully submitted to the executor before the dispatch deadline.",
                "completed_requests": "Number of tasks whose futures genuinely finished. Includes successful responses and HTTP error status codes (403, 429, 503, 504). HTTP 503 is a completed HTTP request from Nginx or backend, NOT a worker error.",
                "worker_errors": "Tasks that were submitted to the executor but terminated with an unhandled Python exception in the worker thread.",
                "worker_timeouts": "Tasks that were submitted to the executor and were still active or pending when the drain deadline expired.",
                "unfinished_requests": "Tasks submitted to the executor remaining unfinished (running or pending) after the drain timeout.",
                "cancelled_pending_requests": "Submitted tasks that were successfully cancelled before starting execution in the worker thread.",
                "running_at_shutdown_requests": "Submitted tasks that were already executing on worker threads (cancelling could not abort them).",
                "missed_scheduling_slots": (
                    "Scheduling slots that were never submitted to the executor because the monotonic clock reached the scenario duration "
                    "deadline or queue backpressure prevented timely submission. These represent UNATTEMPTED workload slots, strictly distinguished "
                    "from submitted tasks that failed or timed out in worker threads."
                ),
                "workload_delivery_distinction": (
                    "A missed slot means the scheduler never attempted submission (e.g., dispatch loop ran out of time). "
                    "In contrast, worker_errors, worker_timeouts, and unfinished_requests represent requests that WERE dispatched into the thread pool "
                    "but failed to complete cleanly. HTTP-level error responses (e.g. 503 from Nginx or 403 from blocklists) are COMPLETED requests, "
                    "not worker errors or missed slots."
                ),
                "dispatch_window_rps": "Rate of task submission measured strictly within the active dispatch window: (submitted_requests - 1) / dispatch_duration_sec.",
                "completed_request_throughput_rps": "Genuinely completed tasks per second over the total run duration: completed_requests / total_completion_duration_sec. Excludes timeouts, errors, and synthetic records.",
                "dispatch_deadline_respected": "True if no task was submitted at or after immutable_start + duration.",
                "workload_fully_delivered": "True if all scheduled slots were submitted, completed without errors or timeouts, and no backpressure occurred.",
                "rate_limited_or_incomplete": "True if backpressure, missed slots, worker errors, timeouts, or incomplete submissions prevented full workload delivery.",
                "runtime_bounding_note": "Cancelling a future prevents queued pending tasks from starting, but cannot abort a worker thread that is already actively running. The drain timeout bounds the scheduler's wait time, not necessarily total Python process lifetime if threads remain running."
            }
        }
        return results, stats

# ---------------------------------------------------------------------------
# Scenario Execution Engine
# ---------------------------------------------------------------------------

def send_scenario_request(url: str, client_ip: str, sim_token: Optional[str], ua: str) -> int:
    """
    Sends a single HTTP request with optional simulation token and simulated IP.

    Status Code Documentation:
    - 200: Successful upstream HTTP response.
    - 403: Forbidden - Tier 2 in-memory/Nginx blocklist drop.
    - 429: Too Many Requests - Application rate-limit response.
    - 503: Service Unavailable - Nginx rate/connection limit rejection or upstream overload.
           Note: An HTTP 503 is a genuinely completed HTTP exchange from Nginx/upstream,
           NOT an unhandled worker error or exception.
    - 504: Gateway Timeout / socket timeout.
    """
    headers = {"User-Agent": ua, "Accept": "*/*"}
    if sim_token:
        headers["X-Simulation-Token"] = sim_token
        headers["X-Simulated-IP"] = client_ip
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 504

def compute_detection_latencies(
    observations: List[Dict[str, Any]],
    traffic_start_time: float,
    ground_truth: str
) -> Dict[str, Any]:
    """
    Computes fine-grained detection latency metrics from raw observer polling records.

    Metrics:
    - time_to_first_alert_sec: Elapsed seconds from traffic start until the system first
      transitions to ANY non-NORMAL state (e.g., SUSPICIOUS or ATTACK).
    - first_alert_classification: The verdict observed at time_to_first_alert_sec (e.g. SUSPICIOUS).
    - time_to_ground_truth_match_sec: Elapsed seconds from traffic start until the system
      first reaches the exact classification matching the scenario ground-truth label
      (e.g., ATTACK for flood scenarios, FLASH_CROWD for flash crowds).
      Returns None if the ground truth is NORMAL (baseline traffic has no anomaly transition)
      or if the ground-truth classification was never reached during the observation window.
      Never fabricates a ground-truth detection time if unreached.
    - time_to_detect_sec: Preserved backward-compatible alias identical to time_to_first_alert_sec.
    """
    time_to_first_alert: Optional[float] = None
    first_alert_class: Optional[str] = None
    time_to_gt_match: Optional[float] = None

    for obs in observations:
        classification = obs.get("classification")
        if not classification:
            continue
        poll_time = obs.get("poll_time", 0.0)
        elapsed = max(0.0, round(poll_time - traffic_start_time, 2))

        # First non-NORMAL alert
        if classification != "NORMAL" and time_to_first_alert is None:
            time_to_first_alert = elapsed
            first_alert_class = classification

        # First ground-truth match (only applicable when ground truth is not NORMAL)
        if ground_truth != "NORMAL" and classification == ground_truth and time_to_gt_match is None:
            time_to_gt_match = elapsed

    return {
        "time_to_first_alert_sec": time_to_first_alert,
        "first_alert_classification": first_alert_class,
        "time_to_ground_truth_match_sec": time_to_gt_match,
        # Backward-compatible alias:
        "time_to_detect_sec": time_to_first_alert
    }

def run_single_scenario(scenario: Dict[str, Any], sim_token: Optional[str]) -> Dict[str, Any]:
    """Runs a single live benchmark scenario with observer, probe monitoring, and rate-controlled scheduler."""
    name = scenario["name"]
    ground_truth = scenario["ground_truth"]
    duration = min(scenario.get("duration", 10), 12)  # Cap at 12s safety limit
    concurrency = min(scenario.get("concurrency", 15), 25)  # Cap at 25 workers
    target_rps = min(scenario.get("target_rps", 50), 65)  # Cap at 65 RPS

    print("\n" + "=" * 70)
    print(f"Executing: {name} (Ground Truth: {ground_truth})")
    print(f"Settings: Concurrency={concurrency} workers | Target={target_rps} RPS | Duration={duration}s")
    print("=" * 70)

    # 1. Reset state before running scenario
    reset_info = reset_system_state()
    if not reset_info.get("reset_verified"):
        unclean_details = reset_info.get("backend_verifications", {})
        err_msg = (
            f"Pre-scenario reset verification failed for '{name}'. "
            f"Refusing to execute scenario on unverified baseline: {unclean_details}"
        )
        print(f"\n[RESET FAIL-CLOSED] {err_msg}", file=sys.stderr)
        raise RuntimeError(err_msg)

    # 2. Start legitimate probe client & detection observer
    prober = LegitimateProbeClient(BASE_URL, interval=1.0)
    observer = DetectionObserver(BASE_URL, interval=0.5)

    with ThreadPoolExecutor(max_workers=4) as monitor_executor:
        probe_future = monitor_executor.submit(prober.run)
        observer_future = monitor_executor.submit(observer.run)

        # 3. Generate scenario traffic with RateControlledScheduler
        traffic_start_iso = datetime.now(timezone.utc).isoformat()
        traffic_start_time = time.time()

        endpoints = scenario["endpoints"]
        ip_pool = scenario["ip_pool"]
        ua_pool = scenario.get("user_agents", ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"])

        def scenario_request_task() -> int:
            ep = random.choice(endpoints)
            ip = random.choice(ip_pool)
            ua = random.choice(ua_pool)
            url = f"{BASE_URL}{ep}"
            return send_scenario_request(url, ip, sim_token, ua)

        scheduler = RateControlledScheduler(
            target_rps=target_rps,
            duration=duration,
            concurrency=concurrency
        )
        task_results, sched_stats = scheduler.execute(scenario_request_task)

        traffic_end_iso = datetime.now(timezone.utc).isoformat()
        dispatch_duration = sched_stats["timestamps"]["dispatch_duration_sec"]
        total_duration = sched_stats["timestamps"]["total_completion_duration_sec"]
        submitted_requests = sched_stats["submitted_requests"]
        completed_requests = sched_stats["completed_requests"]
        dispatch_rps = sched_stats["dispatch_window_rps"]
        completion_throughput = sched_stats["completed_request_throughput_rps"]

        status_counts: Dict[str, int] = {}
        for res in task_results:
            code = str(res)
            status_counts[code] = status_counts.get(code, 0) + 1

        # Stop monitoring threads
        probe_stats = prober.stop()
        observations = observer.stop()

    # 4. Gather Post-Scenario Mitigation Evidence
    post_mit_status = http_get_json(f"{BASE_URL}/api/v1/mitigation/status") or {}
    active_tier_observed = post_mit_status.get("active_tier", "NONE")
    blocked_ips_observed = post_mit_status.get("blocked_ips", [])
    aws_info = post_mit_status.get("aws_integration", {})
    tier3_mode = "AWS_LIVE" if (aws_info.get("is_configured") and aws_info.get("mode") == "AWS_LIVE") else "SIMULATED_LOCAL"

    # Evidence: was tier escalated, was IP added to blocklist, were malicious requests dropped?
    c_403 = status_counts.get("403", 0)
    c_429 = status_counts.get("429", 0)
    c_503 = status_counts.get("503", 0)
    other_errors = sum(count for code, count in status_counts.items() if code not in ("200", "403", "429", "503"))

    mitigation_evidence = {
        "active_mitigation_tier": active_tier_observed,
        "blocked_ips_count": len(blocked_ips_observed),
        "blocked_ips_list": blocked_ips_observed,
        "blocked_scenario_ips": [ip for ip in ip_pool if ip in blocked_ips_observed],
        "status_403_count": c_403,
        "status_429_count": c_429,
        "status_503_count": c_503,
        "status_other_error_count": other_errors,
        "tier_3_scaling_mode": tier3_mode,
        "tier_3_scaling_disclosure": (
            f"Tier 3 scaling status is '{tier3_mode}'. "
            + ("AWS Auto Scaling Group API calls confirmed live." if tier3_mode == "AWS_LIVE"
               else "SIMULATED_LOCAL: No AWS credentials configured; aws_manager operates in simulation mode. "
                    "No real cloud infrastructure scaling or container pool expansion occurs in the local Docker environment.")
        ),
        "status_code_interpretation": (
            "HTTP 403: Tier 2 in-memory/Nginx blocklist drops. "
            "HTTP 503: Nginx proxy rate/connection limit rejections. "
            "HTTP 429: Application rate-limit responses (if configured). "
            "Status codes alone are telemetry indicators and do NOT prove mitigation."
        ),
        "mitigation_verified_by_multi_signal": (
            (active_tier_observed in ("TIER_1", "TIER_2", "TIER_3", "TIER_4")) and
            (len([ip for ip in ip_pool if ip in blocked_ips_observed]) > 0 or active_tier_observed != "NONE") and
            (probe_stats.get("availability_pct", 0.0) >= 90.0)
        ),
        "legitimate_probes_available": probe_stats.get("availability_pct", 0.0) >= 90.0
    }

    # 5. Extract Observed Classification and Detection Latencies
    observed_classifications = [obs["classification"] for obs in observations if obs.get("classification")]
    final_observed_classification = observed_classifications[-1] if observed_classifications else "NORMAL"

    latency_metrics = compute_detection_latencies(observations, traffic_start_time, ground_truth)
    time_to_detect_sec = latency_metrics["time_to_detect_sec"]
    time_to_first_alert_sec = latency_metrics["time_to_first_alert_sec"]
    first_alert_classification = latency_metrics["first_alert_classification"]
    time_to_ground_truth_match_sec = latency_metrics["time_to_ground_truth_match_sec"]

    alert_ttd_str = f"{time_to_first_alert_sec}s ({first_alert_classification})" if time_to_first_alert_sec is not None else "N/A"
    gt_ttd_str = f"{time_to_ground_truth_match_sec}s" if time_to_ground_truth_match_sec is not None else "N/A"

    print(f"Results for {name}:")
    print(f"  Ground Truth:           {ground_truth}")
    print(f"  Observed Classification: {final_observed_classification}")
    print(f"  Dispatch Rate:          {dispatch_rps:.1f} req/s ({submitted_requests} submitted over {dispatch_duration:.2f}s)")
    print(f"  Completion Throughput:  {completion_throughput:.1f} req/s ({completed_requests} completed over {total_duration:.2f}s)")
    print(f"  HTTP Status Codes:      403={c_403}, 429={c_429}, 503={c_503}, other={other_errors}, 200={status_counts.get('200', 0)}")
    print(f"  Time to First Alert:    {alert_ttd_str}")
    print(f"  Time to GT Match:       {gt_ttd_str}")
    print(f"  Legacy TTD (alias):     {time_to_detect_sec if time_to_detect_sec is not None else 'N/A'}")
    print(f"  Probe Availability:     {probe_stats.get('availability_pct')}% (p50: {probe_stats.get('p50_latency_ms')}ms)")
    print(f"  Active Tier:            {active_tier_observed} ({tier3_mode}) (Blocked IPs: {len(blocked_ips_observed)})")
    print(f"  Workload Delivered:     {'YES' if sched_stats['workload_fully_delivered'] else 'NO (rate-limited/incomplete)'}")

    return {
        "scenario_name": name,
        "scenario_description": scenario["description"],
        "ground_truth_label": ground_truth,
        "observed_classification": final_observed_classification,
        "classification_matched": final_observed_classification == ground_truth,
        "traffic_start": traffic_start_iso,
        "traffic_end": traffic_end_iso,
        "scheduler_stats": sched_stats,
        "dispatch_duration_sec": dispatch_duration,
        "total_completion_duration_sec": total_duration,
        "total_scheduling_slots": sched_stats["total_scheduling_slots"],
        "submitted_requests": submitted_requests,
        "completed_requests": completed_requests,
        "worker_errors": sched_stats["worker_errors"],
        "worker_timeouts": sched_stats["worker_timeouts"],
        "unfinished_requests": sched_stats["unfinished_requests"],
        "missed_scheduling_slots": sched_stats["missed_scheduling_slots"],
        "dispatch_window_rps": dispatch_rps,
        "completed_request_throughput_rps": completion_throughput,
        "dispatch_deadline_respected": sched_stats["dispatch_deadline_respected"],
        "workload_fully_delivered": sched_stats["workload_fully_delivered"],
        "rate_limited_or_incomplete": sched_stats["rate_limited_or_incomplete"],
        # Backward-compatible aliases:
        "scheduled_requests": submitted_requests,
        "completion_throughput_rps": completion_throughput,
        "actual_duration_sec": round(total_duration, 2),
        "total_requests_sent": completed_requests,
        "achieved_rps": round(completion_throughput, 1),
        "http_status_distribution": status_counts,
        "time_to_detect_sec": time_to_detect_sec,
        "time_to_first_alert_sec": time_to_first_alert_sec,
        "first_alert_classification": first_alert_classification,
        "time_to_ground_truth_match_sec": time_to_ground_truth_match_sec,
        "legitimate_probes": probe_stats,
        "mitigation_evidence": mitigation_evidence,
        "detection_observations": observations,  # Complete raw polling observations preserved
        "pre_scenario_reset": reset_info
    }

# ---------------------------------------------------------------------------
# Metrics Computation: Binary & Multiclass
# ---------------------------------------------------------------------------

def compute_benchmark_metrics(scenario_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes binary and multiclass evaluation statistics from actual observed results."""
    # 1. Binary Evaluation: ATTACK vs NON-ATTACK (NORMAL, FLASH_CROWD, SUSPICIOUS)
    tp = 0  # Ground truth ATTACK, observed ATTACK
    fp = 0  # Ground truth NON-ATTACK, observed ATTACK
    tn = 0  # Ground truth NON-ATTACK, observed NON-ATTACK
    fn = 0  # Ground truth ATTACK, observed NON-ATTACK

    classes = ["NORMAL", "ATTACK", "FLASH_CROWD", "SUSPICIOUS"]
    multiclass_matrix: Dict[str, Dict[str, int]] = {gt: {obs: 0 for obs in classes} for gt in classes}

    correct_matches = 0
    total_scenarios = len(scenario_results)

    for r in scenario_results:
        gt = r["ground_truth_label"]
        obs = r["observed_classification"]

        if gt in multiclass_matrix and obs in multiclass_matrix[gt]:
            multiclass_matrix[gt][obs] += 1

        if gt == obs:
            correct_matches += 1

        is_gt_attack = (gt == "ATTACK")
        is_obs_attack = (obs == "ATTACK")

        if is_gt_attack and is_obs_attack:
            tp += 1
        elif not is_gt_attack and is_obs_attack:
            fp += 1
        elif not is_gt_attack and not is_obs_attack:
            tn += 1
        elif is_gt_attack and not is_obs_attack:
            fn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else None
    fnr = round(fn / (tp + fn), 4) if (tp + fn) > 0 else None
    accuracy = round(correct_matches / total_scenarios, 4) if total_scenarios > 0 else 0.0

    return {
        "binary_evaluation": {
            "metric_scope": "Scenario-level classification across the 7 benchmark scenarios (NOT request-level packet detection performance)",
            "definition": "Positive Class = ATTACK scenarios (Concentrated, Distributed, Low-Rate, Honeypot); Negative Class = Non-ATTACK scenarios (Normal, Flash Crowd, Ambiguous)",
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr
        },
        "multiclass_evaluation": {
            "metric_scope": "Scenario-level classification across the 7 benchmark scenarios",
            "classes": classes,
            "confusion_matrix": multiclass_matrix,
            "exact_match_accuracy": accuracy,
            "correct_matches": correct_matches,
            "total_scenarios": total_scenarios
        }
    }

# ---------------------------------------------------------------------------
# Main Benchmark Definition
# ---------------------------------------------------------------------------

SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "1_normal_traffic",
        "description": "Baseline legitimate web browsing across 7 endpoints with distributed client IPs",
        "ground_truth": "NORMAL",
        "endpoints": [
            "/api/v1/sample/hello",
            "/api/v1/sample/info",
            "/health",
            "/api/v1/sample/hello?item=1",
            "/api/v1/sample/hello?item=2",
            "/api/v1/sample/hello?item=3",
            "/api/v1/sample/info?view=detailed"
        ],
        "ip_pool": [f"198.18.1.{i}" for i in range(1, 26)],  # 25 distinct client IPs
        "concurrency": 4,
        "target_rps": 12,
        "duration": 10
    },
    {
        "name": "2_concentrated_flood",
        "description": "High-volume HTTP flood targeting single endpoint /api/v1/sample/hello from 2 concentrated IPs",
        "ground_truth": "ATTACK",
        "endpoints": ["/api/v1/sample/hello"],
        "ip_pool": ["198.51.100.10", "198.51.100.11"],  # 2 concentrated attacker IPs
        "concurrency": 20,
        "target_rps": 60,
        "duration": 10
    },
    {
        "name": "3_distributed_flood",
        "description": "High-volume HTTP flood targeting single endpoint /api/v1/sample/hello from 50 distributed botnet IPs",
        "ground_truth": "ATTACK",
        "endpoints": ["/api/v1/sample/hello"],
        "ip_pool": [f"198.51.100.{i}" for i in range(1, 51)],  # 50 distributed botnet IPs
        "concurrency": 20,
        "target_rps": 60,
        "duration": 10
    },
    {
        "name": "4_low_rate_flood",
        "description": "Low-rate HTTP flood (4-6 RPS) staying below volumetric surge thresholds on legitimate endpoints",
        "ground_truth": "ATTACK",
        "endpoints": ["/api/v1/sample/hello"],
        "ip_pool": ["198.51.100.20", "198.51.100.21", "198.51.100.22"],
        "concurrency": 2,
        "target_rps": 5,
        "duration": 10
    },
    {
        "name": "5_honeypot_tripwire",
        "description": "Adversary scanner accessing decoy endpoint /admin-backup/ triggering deterministic tripwire",
        "ground_truth": "ATTACK",
        "endpoints": ["/admin-backup/"],
        "ip_pool": ["203.0.113.199"],
        "concurrency": 2,
        "target_rps": 4,
        "duration": 6
    },
    {
        "name": "6_flash_crowd",
        "description": "Viral legitimate traffic surge across 10 diverse endpoints from 100 widely distributed IPs",
        "ground_truth": "FLASH_CROWD",
        "endpoints": [
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
        ],
        "ip_pool": [f"198.18.{random.randint(1, 250)}.{random.randint(1, 250)}" for _ in range(100)],
        "concurrency": 18,
        "target_rps": 55,
        "duration": 10
    },
    {
        "name": "7_ambiguous_traffic",
        "description": "Moderate traffic surge (20-24 RPS) near the 1.8x baseline threshold with intermediate entropy",
        "ground_truth": "SUSPICIOUS",
        "endpoints": ["/api/v1/sample/hello", "/api/v1/sample/info"],
        "ip_pool": [f"198.18.2.{i}" for i in range(1, 7)],  # 6 semi-concentrated IPs
        "concurrency": 6,
        "target_rps": 22,
        "duration": 8
    }
]

def run_benchmark(output_path: Optional[str] = None):
    """Main benchmark suite entrypoint."""
    results_file = output_path or RESULTS_PATH
    print("=" * 70)
    print(" CloudShield Live Repeatable Benchmark Suite")
    print(f" Target URL: {BASE_URL}")
    print(f" Output File: {results_file}")
    print("=" * 70)

    token = load_simulation_token()
    if not token:
        print("[ERROR] SIMULATION_TOKEN is not configured in environment or .env file.", file=sys.stderr)
        print("Please configure SIMULATION_TOKEN before executing benchmark runs.", file=sys.stderr)
        sys.exit(1)

    print("[CONFIG] Simulation token loaded successfully (value masked).")

    # Verify target availability
    health = http_get_json(f"{BASE_URL}/health")
    if not health or health.get("status") != "healthy":
        print(f"[ERROR] Target service at {BASE_URL} is not responding or not healthy.", file=sys.stderr)
        sys.exit(1)

    # Pre-flight safety: prevent silent overwrite of existing results file
    if os.path.exists(results_file):
        ts_backup = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_stem = os.path.splitext(os.path.basename(results_file))[0]
        backup_path = os.path.join(os.path.dirname(results_file), f"{base_stem}_{ts_backup}.bak.json")
        try:
            os.rename(results_file, backup_path)
            print(f"[SAFETY] Existing results file detected. Archived to: {backup_path} (silent overwrite prevented).")
        except Exception as e:
            print(f"[ERROR] Existing results file '{results_file}' could not be archived: {e}. Refusing to proceed.", file=sys.stderr)
            sys.exit(1)

    # Pre-flight safety: refuse to start if initial clean baseline cannot be independently verified on all backends
    print("[PRE-FLIGHT] Verifying clean initial system baseline across all backends...")
    initial_reset = reset_system_state()
    if not initial_reset.get("reset_verified"):
        print("[ERROR] Initial system reset could not be verified across all backends. Refusing to start benchmark.", file=sys.stderr)
        print(f"Details: {initial_reset.get('backend_verifications')}", file=sys.stderr)
        sys.exit(1)
    print("[PRE-FLIGHT SUCCESS] Baseline verified clean across all backends. Ready to start scenarios.")

    results = []
    benchmark_aborted = False
    abort_reason = None
    final_reset: Dict[str, Any] = {}

    try:
        for sc in SCENARIOS:
            res = run_single_scenario(sc, token)
            results.append(res)
    except KeyboardInterrupt:
        benchmark_aborted = True
        abort_reason = "KeyboardInterrupt (Ctrl+C pressed by user)"
        print("\n[ABORT] Benchmark execution interrupted by user (KeyboardInterrupt).", file=sys.stderr)
    except Exception as e:
        benchmark_aborted = True
        abort_reason = f"Unhandled Exception: {str(e)}"
        print(f"\n[ABORT] Benchmark execution failed with exception: {e}", file=sys.stderr)
    finally:
        print("\n[CLEANUP] Executing mandatory post-run system state cleanup and verification...")
        try:
            final_reset = reset_system_state()
            if final_reset.get("reset_verified"):
                print("[CLEANUP SUCCESS] Post-benchmark system state verified clean across all backends.")
            else:
                print("[CLEANUP WARNING] Post-benchmark reset verification incomplete or unconfirmed. Please check backend states manually.", file=sys.stderr)
        except Exception as cleanup_err:
            final_reset = {
                "reset_verified": False,
                "cleanup_exception": str(cleanup_err),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            print(f"[CLEANUP ERROR] Post-benchmark cleanup encountered an exception: {cleanup_err}", file=sys.stderr)

    # Compute overall metrics for completed scenarios
    metrics = compute_benchmark_metrics(results) if results else {}

    incomplete_scenarios = [r["scenario_name"] for r in results if r.get("rate_limited_or_incomplete", False)]
    all_fully_delivered = (len(incomplete_scenarios) == 0 and not benchmark_aborted)
    eval_validity = "CONTROLLED_RATE_VALID" if all_fully_delivered else "RATE_LIMITED_OR_INCOMPLETE"

    output_payload = {
        "benchmark_metadata": {
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": BASE_URL,
            "results_file": os.path.basename(results_file),
            "simulation_token_configured": True,
            "total_scenarios_evaluated": len(results),
            "benchmark_completed": not benchmark_aborted,
            "abort_reason": abort_reason,
            "scheduler_type": "Precision Monotonic Rate-Controlled Scheduler (v2)",
            "evaluation_validity": eval_validity,
            "all_workloads_fully_delivered": all_fully_delivered,
            "incomplete_scenarios": incomplete_scenarios,
            "metric_scope_disclosure": (
                "Precision, recall, FPR, and FNR are scenario-level metrics evaluating whether CloudShield "
                "classifies each of the 7 test scenarios into the correct high-level verdict. "
                "They do NOT represent individual request-level packet inspection metrics."
            ),
            "workload_validity_note": (
                "Workload validity strictly requires all configured scheduling slots to be dispatched and completed without backpressure "
                "or missed slots. A missed scheduling slot indicates the scheduler timer hit the immutable duration deadline before the final "
                "slot could be submitted (unattempted workload). This is strictly distinct from submitted requests that timed out or failed in "
                "worker threads, and distinct from Nginx HTTP 503 rejections (which represent completed HTTP transactions). "
                "Runs with any missed slots or backpressure remain marked RATE_LIMITED_OR_INCOMPLETE."
            ),
            "ttd_measurement_caveat": (
                "Detection latency is reported via two distinct metrics: (1) time_to_first_alert_sec (legacy alias time_to_detect_sec) "
                "measuring elapsed time to the first non-NORMAL state, and (2) time_to_ground_truth_match_sec measuring elapsed time to the "
                "first observation matching the scenario ground-truth label. Resolution is limited by the 4.0s background evaluation loop "
                "in backend/app/main.py and 0.5s observer polling cadence. Observed TTD values are discrete measurements quantized to "
                "evaluation intervals (~4s, ~8s), not continuous line-rate detection latency."
            ),
            "scaling_mode_disclosure": (
                "Tier 3 horizontal autoscaling executes as SIMULATED_LOCAL in local Docker environments without AWS credentials; "
                "no actual cloud instances or additional container replicas are provisioned unless live AWS ASG credentials are explicitly configured."
            ),
            "safety_limits": {
                "max_concurrency_workers": 25,
                "max_target_rps": 65,
                "max_scenario_duration_sec": 12
            },
            "limitations_and_residual_state": [
                "Nginx access log telemetry uses a 10s sliding window; an 11s pause is enforced between scenarios.",
                "EWMA baselines in entropy_engine evolve dynamically on normal traffic and are not hard-reset.",
                "Docker Desktop on Windows NATs direct host connections to 172.28.0.1; simulation channel is required for synthetic source IPs.",
                "Tier 3 horizontal autoscaling executes as SIMULATED_LOCAL in local Docker environments; no real cloud infrastructure expansion occurs."
            ]
        },
        "scenario_results": results,
        "summary_metrics": metrics,
        "final_cleanup": final_reset
    }

    # Write results if any scenario ran
    if results:
        os.makedirs(os.path.dirname(results_file), exist_ok=True)
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2)

    if results and not benchmark_aborted:
        print("\n" + "=" * 70)
        print(" BENCHMARK COMPLETE — SUMMARY REPORT")
        print("=" * 70)
        print(f"Exact Match Accuracy: {metrics['multiclass_evaluation']['exact_match_accuracy'] * 100:.1f}% "
              f"({metrics['multiclass_evaluation']['correct_matches']}/{metrics['multiclass_evaluation']['total_scenarios']} scenarios)")

        bin_eval = metrics["binary_evaluation"]
        print(f"Binary Evaluation (Attack vs Non-Attack - Scenario Level):")
        print(f"  TP: {bin_eval['true_positives']} | FP: {bin_eval['false_positives']} | TN: {bin_eval['true_negatives']} | FN: {bin_eval['false_negatives']}")
        print(f"  Precision: {bin_eval['precision'] if bin_eval['precision'] is not None else 'N/A'}")
        print(f"  Recall:    {bin_eval['recall'] if bin_eval['recall'] is not None else 'N/A'}")
        print(f"  FPR:       {bin_eval['false_positive_rate'] if bin_eval['false_positive_rate'] is not None else 'N/A'}")
        print(f"  FNR:       {bin_eval['false_negative_rate'] if bin_eval['false_negative_rate'] is not None else 'N/A'}")

        print("\nScenario Performance Summary:")
        print(f"{'Scenario':<25} {'Ground Truth':<12} {'Observed':<12} {'Matched':<8} {'Alert TTD':<12} {'GT TTD':<10} {'Disp RPS':<10} {'Comp RPS':<10} {'Availability':<12}")
        print("-" * 115)
        for r in results:
            matched = "YES" if r["classification_matched"] else "NO"
            avail = f"{r['legitimate_probes']['availability_pct']}%"
            disp_rps = r.get("dispatch_window_rps", r.get("achieved_rps", 0.0))
            comp_rps = r.get("completion_throughput_rps", r.get("achieved_rps", 0.0))
            alert_ttd = f"{r.get('time_to_first_alert_sec')}s" if r.get('time_to_first_alert_sec') is not None else "N/A"
            gt_ttd = f"{r.get('time_to_ground_truth_match_sec')}s" if r.get('time_to_ground_truth_match_sec') is not None else "N/A"
            print(f"{r['scenario_name']:<25} {r['ground_truth_label']:<12} {r['observed_classification']:<12} {matched:<8} {alert_ttd:<12} {gt_ttd:<10} {disp_rps:<10.1f} {comp_rps:<10.1f} {avail:<12}")

        print(f"\nFull detailed observations written to: {results_file}")
        print("=" * 70)
    elif benchmark_aborted:
        print(f"\n[INFO] Partial results for {len(results)} scenarios saved to: {results_file}")

def run_scheduler_self_test(test_duration: float = 3.0) -> Dict[str, Any]:
    """
    Isolated rate-control self-test that does NOT send traffic to CloudShield or any network target.
    Verifies:
    1. Accurate pacing and deadline compliance for 12, 22, 55, and 60 RPS with normal fast tasks.
    2. Backpressure handling and missed slot detection with slow tasks.
    3. Worker exception accounting without corrupting completed results.
    4. Unfinished task detection and bounded drain timeout without process hanging.
    5. Mathematical reconciliation of all request and slot counts.
    """
    print("=" * 115)
    print(" RateControlledScheduler Comprehensive Isolated Self-Test (No Network Traffic)")
    print(f" Test Clock: time.perf_counter() monotonic | Subtests: Pacing, Backpressure, Errors, Drain Timeout")
    print("=" * 115)

    def fast_dummy_task():
        time.sleep(0.005)
        return 200

    test_rates = [12.0, 22.0, 55.0, 60.0]
    self_test_results = []

    print("\n--- [Subtest 1/4] Paced Fast Tasks: Accuracy, Duration Bounding & Count Reconciliation ---")
    print(f"{'Target':<8} {'Workers':<8} {'Slots':<8} {'Submit':<8} {'Done':<8} {'Disp Dur':<10} {'Comp Dur':<10} {'Disp RPS':<10} {'Comp RPS':<10} {'Err%':<8} {'Bounded?':<8}")
    print("-" * 115)

    for rps in test_rates:
        concurrency = 4 if rps <= 12 else (6 if rps <= 22 else 20)
        sched = RateControlledScheduler(target_rps=rps, duration=test_duration, concurrency=concurrency)
        task_results, stats = sched.execute(fast_dummy_task)

        disp_err_pct = abs(stats["dispatch_window_rps"] - rps) / rps * 100.0
        stats["dispatch_error_pct"] = round(disp_err_pct, 2)
        comp_err_pct = abs(stats["completed_request_throughput_rps"] - rps) / rps * 100.0
        stats["completion_error_pct"] = round(comp_err_pct, 2)
        self_test_results.append(stats)

        # Strict correctness and count reconciliation assertions
        assert stats["dispatch_deadline_respected"] is True, f"Deadline violated for target {rps} RPS"
        assert stats["total_scheduling_slots"] == stats["submitted_requests"] + stats["missed_scheduling_slots"], \
            f"Slot count reconciliation failed for {rps} RPS: {stats['total_scheduling_slots']} != {stats['submitted_requests']} + {stats['missed_scheduling_slots']}"
        assert stats["submitted_requests"] == stats["completed_requests"] + stats["worker_errors"] + stats["unfinished_requests"], \
            f"Submitted count reconciliation failed for {rps} RPS: {stats['submitted_requests']} != {stats['completed_requests']} + {stats['worker_errors']} + {stats['unfinished_requests']}"
        assert stats["worker_errors"] == 0, f"Unexpected worker error for {rps} RPS"
        assert stats["worker_timeouts"] == 0, f"Unexpected worker timeout for {rps} RPS"
        assert stats["completed_requests"] == len(task_results), f"Completed count does not match results length for {rps} RPS"

        disp_dur = f"{stats['timestamps']['dispatch_duration_sec']:.3f}s"
        comp_dur = f"{stats['timestamps']['total_completion_duration_sec']:.3f}s"
        disp_rps_str = f"{stats['dispatch_window_rps']:.2f}"
        comp_rps_str = f"{stats['completed_request_throughput_rps']:.2f}"
        bounded_str = "YES" if stats["dispatch_deadline_respected"] else "NO"

        print(f"{stats['configured_target_rps']:<8.1f} {stats['concurrency']:<8} {stats['total_scheduling_slots']:<8} "
              f"{stats['submitted_requests']:<8} {stats['completed_requests']:<8} {disp_dur:<10} {comp_dur:<10} "
              f"{disp_rps_str:<10} {comp_rps_str:<10} {disp_err_pct:<8.1f}% {bounded_str:<8}")

    print("\n--- [Subtest 2/4] Backpressure & Missed Slot Detection (Slow Tasks) ---")
    slow_sched = RateControlledScheduler(
        target_rps=30.0,
        duration=0.5,
        concurrency=2,
        max_queue=3,
        drain_timeout_sec=1.0
    )
    slow_results, slow_stats = slow_sched.execute(lambda: (time.sleep(0.12), 200)[1])
    print(f"  Target RPS: 30.0 | Duration: 0.5s | Concurrency: 2 | Max Queue: 3")
    print(f"  Slots: {slow_stats['total_scheduling_slots']} | Submitted: {slow_stats['submitted_requests']} | Completed: {slow_stats['completed_requests']}")
    print(f"  Backpressure Events: {slow_stats['backpressure_wait_events']} | Missed Slots: {slow_stats['missed_scheduling_slots']}")
    print(f"  Deadline Respected: {slow_stats['dispatch_deadline_respected']} | Workload Delivered: {slow_stats['workload_fully_delivered']}")
    print(f"  Rate-Limited/Incomplete Flag: {slow_stats['rate_limited_or_incomplete']}")

    assert slow_stats["backpressure_wait_events"] > 0, "Backpressure was not triggered"
    assert slow_stats["missed_scheduling_slots"] > 0, "Missed slots expected under heavy backpressure"
    assert slow_stats["dispatch_deadline_respected"] is True, "Deadline was violated during backpressure"
    assert slow_stats["rate_limited_or_incomplete"] is True, "Run should be flagged rate-limited/incomplete"
    assert slow_stats["total_scheduling_slots"] == slow_stats["submitted_requests"] + slow_stats["missed_scheduling_slots"], \
        f"Slot count reconciliation failed under backpressure: {slow_stats['total_scheduling_slots']} != {slow_stats['submitted_requests']} + {slow_stats['missed_scheduling_slots']}"
    assert slow_stats["submitted_requests"] == slow_stats["completed_requests"] + slow_stats["worker_errors"] + slow_stats["unfinished_requests"], \
        f"Submitted count reconciliation failed under backpressure: {slow_stats['submitted_requests']} != {slow_stats['completed_requests']} + {slow_stats['worker_errors']} + {slow_stats['unfinished_requests']}"
    print(f"  Reconciliation: slots ({slow_stats['total_scheduling_slots']}) == submitted ({slow_stats['submitted_requests']}) + missed ({slow_stats['missed_scheduling_slots']}) [ASSERTION PASSED]")
    print(f"  Reconciliation: submitted ({slow_stats['submitted_requests']}) == completed ({slow_stats['completed_requests']}) + errors ({slow_stats['worker_errors']}) + unfinished ({slow_stats['unfinished_requests']}) [ASSERTION PASSED]")
    print("  [PASS] Backpressure and slot skipping verified cleanly.")

    print("\n--- [Subtest 3/4] Worker Exception Isolation & Results Integrity ---")
    err_sched = RateControlledScheduler(
        target_rps=10.0,
        duration=0.3,
        concurrency=2,
        drain_timeout_sec=0.5
    )
    def failing_task():
        time.sleep(0.005)
        raise ValueError("Simulated worker compute exception")

    err_results, err_stats = err_sched.execute(failing_task)
    print(f"  Target RPS: 10.0 | Duration: 0.3s | Slots: {err_stats['total_scheduling_slots']}")
    print(f"  Submitted: {err_stats['submitted_requests']} | Completed: {err_stats['completed_requests']} | Worker Errors: {err_stats['worker_errors']}")
    print(f"  Results List Size: {len(err_results)} (strictly completed tasks, zero synthetic errors)")
    print(f"  Rate-Limited/Incomplete Flag: {err_stats['rate_limited_or_incomplete']}")

    assert err_stats["worker_errors"] == err_stats["submitted_requests"], "Worker errors count mismatch"
    assert err_stats["completed_requests"] == 0, "Failing tasks must not count as completed"
    assert len(err_results) == 0, "Results list must not contain synthetic error strings"
    assert err_stats["rate_limited_or_incomplete"] is True, "Error run should be marked incomplete"
    assert err_stats["dispatch_deadline_respected"] is True, "Deadline was violated"
    assert err_stats["total_scheduling_slots"] == err_stats["submitted_requests"] + err_stats["missed_scheduling_slots"], \
        f"Slot count reconciliation failed on worker errors: {err_stats['total_scheduling_slots']} != {err_stats['submitted_requests']} + {err_stats['missed_scheduling_slots']}"
    assert err_stats["submitted_requests"] == err_stats["completed_requests"] + err_stats["worker_errors"] + err_stats["unfinished_requests"], \
        f"Submitted count reconciliation failed on worker errors: {err_stats['submitted_requests']} != {err_stats['completed_requests']} + {err_stats['worker_errors']} + {err_stats['unfinished_requests']}"
    print(f"  Reconciliation: slots ({err_stats['total_scheduling_slots']}) == submitted ({err_stats['submitted_requests']}) + missed ({err_stats['missed_scheduling_slots']}) [ASSERTION PASSED]")
    print(f"  Reconciliation: submitted ({err_stats['submitted_requests']}) == completed ({err_stats['completed_requests']}) + errors ({err_stats['worker_errors']}) + unfinished ({err_stats['unfinished_requests']}) [ASSERTION PASSED]")
    print("  [PASS] Worker exceptions captured without corrupting completed results.")

    print("\n--- [Subtest 4/4] Bounded Drain Timeout & Unfinished Task Accounting ---")
    drain_sched = RateControlledScheduler(
        target_rps=5.0,
        duration=0.2,
        concurrency=2,
        drain_timeout_sec=0.08
    )
    # Task takes 0.30s, exceeding total duration (0.2s) + drain_timeout (0.08s) = 0.28s
    # Uses strictly local time.sleep dummy task; sends zero network requests to CloudShield
    t_drain_start = time.perf_counter()
    drain_results, drain_stats = drain_sched.execute(lambda: (time.sleep(0.30), 200)[1])
    t_drain_elapsed = time.perf_counter() - t_drain_start

    print(f"  Target RPS: 5.0 | Duration: 0.2s | Drain Timeout: 0.08s | Task Sleep: 0.30s")
    print(f"  Scheduler Execution Returned In: {t_drain_elapsed:.3f}s (bounded by drain timeout ~0.28s, NOT waiting for task 0.30s)")
    print(f"  Submitted: {drain_stats['submitted_requests']} | Completed: {drain_stats['completed_requests']}")
    print(f"  Drain Timed Out: {drain_stats['drain_timed_out']} | Worker Timeouts: {drain_stats['worker_timeouts']} | Unfinished: {drain_stats['unfinished_requests']}")
    print(f"  Cancelled Pending: {drain_stats['cancelled_pending_requests']} | Running at Shutdown: {drain_stats['running_at_shutdown_requests']}")
    print(f"  Results List Size: {len(drain_results)} (zero synthetic timeout records)")
    print(f"  Throughput: {drain_stats['completed_request_throughput_rps']:.2f} req/s (calculated strictly from completed)")

    # Assert scheduler returned promptly at bounded timeout rather than waiting for 0.30s task
    assert t_drain_elapsed < 0.34, f"Scheduler did not return after drain timeout! Elapsed: {t_drain_elapsed:.3f}s"
    assert drain_stats["drain_timed_out"] is True, "Drain timeout was not triggered"
    assert drain_stats["worker_timeouts"] > 0, "Worker timeouts count was not recorded"
    assert drain_stats["unfinished_requests"] > 0, "Unfinished requests count was not recorded"
    assert drain_stats["unfinished_requests"] == drain_stats["cancelled_pending_requests"] + drain_stats["running_at_shutdown_requests"], \
        "Unfinished partition reconciliation failed"
    assert drain_stats["running_at_shutdown_requests"] == 1, "Expected 1 actively running request at drain timeout"
    assert drain_stats["cancelled_pending_requests"] == 0, "Expected 0 pending requests"
    assert drain_stats["completed_requests"] == 0, "Unfinished task must not count as completed"
    assert len(drain_results) == 0, "Results list must not contain synthetic timeout records"
    assert drain_stats["completed_request_throughput_rps"] == 0.0, "Throughput must be 0 for 0 completed tasks"
    assert drain_stats["rate_limited_or_incomplete"] is True, "Timed-out run must be marked rate-limited/incomplete"
    assert drain_stats["dispatch_deadline_respected"] is True, "Deadline was violated"
    assert drain_stats["total_scheduling_slots"] == drain_stats["submitted_requests"] + drain_stats["missed_scheduling_slots"], \
        f"Slot count reconciliation failed on drain timeout: {drain_stats['total_scheduling_slots']} != {drain_stats['submitted_requests']} + {drain_stats['missed_scheduling_slots']}"
    assert drain_stats["submitted_requests"] == drain_stats["completed_requests"] + drain_stats["worker_errors"] + drain_stats["unfinished_requests"], \
        f"Submitted count reconciliation failed on drain timeout: {drain_stats['submitted_requests']} != {drain_stats['completed_requests']} + {drain_stats['worker_errors']} + {drain_stats['unfinished_requests']}"
    print(f"  Reconciliation: slots ({drain_stats['total_scheduling_slots']}) == submitted ({drain_stats['submitted_requests']}) + missed ({drain_stats['missed_scheduling_slots']}) [ASSERTION PASSED]")
    print(f"  Reconciliation: submitted ({drain_stats['submitted_requests']}) == completed ({drain_stats['completed_requests']}) + errors ({drain_stats['worker_errors']}) + unfinished ({drain_stats['unfinished_requests']}) [ASSERTION PASSED]")

    # Explicit acknowledgment of Python thread limitation and clean exit wait:
    # A running thread in ThreadPoolExecutor cannot be forcibly aborted from Python.
    # We yield 0.35s so the 0.30s dummy task completes naturally before process exit.
    time.sleep(0.35)
    print("  [PASS] Drain timeout bounded and unfinished tasks accurately accounted without process hang.")

    print("\n" + "=" * 115)
    print(" ALL 4 ISOLATED SCHEDULER SUBTESTS PASSED WITH 100% COUNT RECONCILIATION")
    print(" Mathematical Guarantee: submitted_requests == completed_requests + worker_errors + unfinished_requests")
    print(" Mathematical Guarantee: total_scheduling_slots == submitted_requests + missed_scheduling_slots")
    print(" DISCLOSURE: These are isolated scheduler timing measurements, NOT network benchmark results.")
    print("=" * 115)
    return {
        "pacing_results": self_test_results,
        "backpressure_stats": slow_stats,
        "error_stats": err_stats,
        "drain_stats": drain_stats
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudShield Repeatable Live Benchmark Suite")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run isolated rate-control scheduler self-test without network traffic"
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Run safe reset and independent baseline verification across all backends without traffic"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help=f"Path to output JSON results file (default: docs/{DEFAULT_RESULTS_NAME})"
    )
    args = parser.parse_args()

    if args.self_test:
        run_scheduler_self_test()
    elif args.cleanup_only:
        print("=" * 70)
        print(" CloudShield Standalone Backend Reset & Verification Check")
        print(f" Target URL: {BASE_URL}")
        print("=" * 70)
        res = reset_system_state()
        print("\nVerification Results:")
        for node, details in res.get("backend_verifications", {}).items():
            clean_str = "CLEAN (NORMAL, NONE, 0 blocked)" if details.get("is_clean") else "DIRTY/UNVERIFIED"
            print(f"  Backend [{node}] ({details.get('container')}): {clean_str}")
            print(f"    State: {details.get('classification')} | Tier: {details.get('mitigation_tier')} | Blocked IPs: {details.get('blocked_ip_count')} ({details.get('blocked_ips')})")
        if res.get("reset_verified"):
            print("\n[SUCCESS] Both backends independently verified clean: NORMAL, NONE, empty blocklists.")
            sys.exit(0)
        else:
            print("\n[FAILURE] Independent backend verification failed.", file=sys.stderr)
            sys.exit(1)
    else:
        run_benchmark(output_path=args.output)
