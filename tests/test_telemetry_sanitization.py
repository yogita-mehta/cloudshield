import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

import pytest
from app.core.proxy import (
    extract_client_ip,
    is_trusted_proxy,
    is_simulation_ip_allowed,
    is_simulation_token_valid,
    get_origin_ip,
)
from app.services.monitoring import is_internal_polling_request, read_recent_access_logs
import app.services.monitoring as monitoring_module

TEST_SIM_TOKEN = "cloudshield-test-token-2026"

# ---------------------------------------------------------------------------
# 1. Endpoint Filtering Tests
# ---------------------------------------------------------------------------

def test_endpoint_filtering_identifies_internal_polling():
    """Verify that dashboard, Prometheus, and health poll queries are classified as internal."""
    internal_queries = [
        ("/api/v1/monitoring/metrics", "GET"),
        ("/api/v1/monitoring/history", "GET"),
        ("/api/v1/detection/status", "GET"),
        ("/api/v1/detection/status?refresh=true", "GET"),
        ("/api/v1/mitigation/status", "GET"),
        ("/api/v1/auth/me", "GET"),
        ("/api/v1/health", "GET"),
        ("/health", "GET"),
        ("/metrics", "GET"),
        ("/stub_status", "GET"),
        ("/nginx-health", "GET"),
        ("/favicon.ico", "GET"),
        ("/api/v1/incidents/", "GET"),
        ("/api/v1/incidents", "GET"),
    ]
    for uri, method in internal_queries:
        assert is_internal_polling_request(uri, method) is True, f"Expected {method} {uri} to be filtered"

def test_endpoint_filtering_preserves_application_and_honeypot_traffic():
    """Verify that benign app routes and honeypot decoy tripwires are NEVER filtered."""
    legitimate_queries = [
        ("/api/v1/sample/hello", "GET"),
        ("/api/v1/sample/hello?page=2", "GET"),
        ("/api/v1/sample/info", "GET"),
        ("/", "GET"),
        ("/api/v1/items/123", "GET"),
        # Honeypots MUST be preserved so detection engine catches tripwire breaches
        ("/admin-backup/", "GET"),
        ("/wp-login.php", "GET"),
        ("/wp-login.php", "POST"),
        ("/hidden-admin.html", "GET"),
        # Administrative mutations (e.g. POST to create incident or update config)
        ("/api/v1/incidents/", "POST"),
    ]
    for uri, method in legitimate_queries:
        assert is_internal_polling_request(uri, method) is False, f"Expected {method} {uri} to be preserved"

# ---------------------------------------------------------------------------
# 2. Client-IP Attribution and Anti-Spoofing Tests
# ---------------------------------------------------------------------------

def test_untrusted_peer_cannot_spoof_client_ip():
    """If request arrives directly from untrusted IP, client-supplied headers MUST be ignored."""
    untrusted_attacker = "198.51.100.99"
    # Attacker attempts to claim they are localhost (to bypass blocklist)
    resolved = extract_client_ip(
        peer_ip=untrusted_attacker,
        xff_header="127.0.0.1",
        x_real_ip="127.0.0.1"
    )
    assert resolved == untrusted_attacker

def test_trusted_proxy_resolves_real_client_ip():
    """When peer is a trusted proxy, resolve the client from X-Forwarded-For."""
    nginx_proxy = "172.28.0.10"
    real_client = "203.0.113.42"
    resolved = extract_client_ip(peer_ip=nginx_proxy, xff_header=real_client)
    assert resolved == real_client

def test_trusted_proxy_chain_traversal_right_to_left():
    """When multiple hops exist, right-to-left traversal picks the first non-trusted hop."""
    nginx_proxy = "172.28.0.10"
    trusted_internal = "127.0.0.1"
    real_client = "198.51.100.50"
    # Chain: [real_client, trusted_internal] arriving via nginx_proxy
    xff = f"{real_client}, {trusted_internal}"
    resolved = extract_client_ip(peer_ip=nginx_proxy, xff_header=xff)
    assert resolved == real_client

def test_docker_bridge_gateway_not_trusted_as_proxy():
    """
    Requirement 4: Verify Docker Desktop's bridge IP (172.28.0.1) is NOT a trusted proxy.
    Direct requests arriving from 172.28.0.1 cannot spoof client IP via headers.
    """
    assert is_trusted_proxy("172.28.0.1") is False
    # If a request arrives with peer_ip 172.28.0.1, XFF headers are ignored
    resolved = extract_client_ip(peer_ip="172.28.0.1", xff_header="203.0.113.195")
    assert resolved == "172.28.0.1"

def test_attacker_prepending_spoofed_ip_in_xff_is_defeated():
    """
    Attacker sends XFF: '127.0.0.1, <attacker_ip>'.
    Traversing right-to-left identifies <attacker_ip> and ignores the spoofed 127.0.0.1.
    """
    nginx_proxy = "172.28.0.10"
    attacker_ip = "198.51.100.77"
    spoofed_chain = f"127.0.0.1, {attacker_ip}"
    resolved = extract_client_ip(peer_ip=nginx_proxy, xff_header=spoofed_chain)
    assert resolved == attacker_ip

def test_client_cannot_claim_loopback_allowlist_via_headers():
    """
    Verify that under NO circumstances can a client obtain 127.0.0.1 or allowlist immunity
    by crafting forwarding headers.
    """
    nginx_proxy = "172.28.0.10"
    # Case 1: Attacker sends XFF: 127.0.0.1
    resolved_1 = extract_client_ip(peer_ip=nginx_proxy, xff_header="127.0.0.1")
    assert resolved_1 != "127.0.0.1"
    assert resolved_1 == nginx_proxy

    # Case 2: Attacker sends XFF: localhost
    resolved_2 = extract_client_ip(peer_ip=nginx_proxy, xff_header="localhost")
    assert resolved_2 != "localhost"
    assert resolved_2 != "127.0.0.1"

    # Case 3: Attacker sends X-Real-IP: 127.0.0.1
    resolved_3 = extract_client_ip(peer_ip=nginx_proxy, x_real_ip="127.0.0.1")
    assert resolved_3 != "127.0.0.1"

def test_controlled_simulation_mode_with_valid_token(monkeypatch):
    """
    Verify that controlled lab simulations with valid token can inject synthetic
    source IPs from permitted test documentation subnets (RFC 5737 / RFC 2544).
    """
    monkeypatch.setenv("SIMULATION_TOKEN", TEST_SIM_TOKEN)
    sim_ip = "198.51.100.88"
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token=TEST_SIM_TOKEN,
        sim_ip=sim_ip
    )
    assert resolved == sim_ip

def test_controlled_simulation_cannot_simulate_allowlisted_loopback(monkeypatch):
    """
    Even in simulation mode with a valid token, attempting to simulate loopback
    or allowlisted infrastructure IPs is strictly blocked.
    """
    monkeypatch.setenv("SIMULATION_TOKEN", TEST_SIM_TOKEN)
    nginx_proxy = "172.28.0.10"
    # Attempting to simulate 127.0.0.1 must be rejected
    resolved = extract_client_ip(
        peer_ip=nginx_proxy,
        sim_token=TEST_SIM_TOKEN,
        sim_ip="127.0.0.1"
    )
    assert resolved != "127.0.0.1"
    assert resolved == nginx_proxy

def test_simulation_with_invalid_token_is_ignored(monkeypatch):
    """If simulation token is invalid or missing, simulated IP is ignored."""
    monkeypatch.setenv("SIMULATION_TOKEN", TEST_SIM_TOKEN)
    nginx_proxy = "172.28.0.10"
    resolved = extract_client_ip(
        peer_ip=nginx_proxy,
        sim_token="invalid-unauthorized-token",
        sim_ip="198.51.100.88"
    )
    assert resolved != "198.51.100.88"
    assert resolved == nginx_proxy

def test_trusted_proxy_detection_helper():
    """Verify is_trusted_proxy identifies Nginx proxy, localhost, and testclient, but NOT Docker bridge."""
    assert is_trusted_proxy("127.0.0.1") is True
    assert is_trusted_proxy("172.28.0.10") is True  # Ingress Nginx proxy
    assert is_trusted_proxy("172.28.0.1") is False   # Docker bridge gateway/NAT is NOT a trusted proxy
    assert is_trusted_proxy("testclient") is True
    assert is_trusted_proxy("203.0.113.1") is False
    assert is_trusted_proxy("8.8.8.8") is False
    assert is_trusted_proxy(None) is False

# ---------------------------------------------------------------------------
# 3. Millisecond Timestamp Parsing & Log Window Filtering Integration
# ---------------------------------------------------------------------------

def test_read_recent_access_logs_with_msec_and_filtering(tmp_path, monkeypatch):
    """
    Test log ingestion with millisecond timestamps, backward compatibility with
    time_local, and verified endpoint filtering.
    """
    monkeypatch.setenv("SIMULATION_TOKEN", TEST_SIM_TOKEN)
    log_file = tmp_path / "test_access.log"
    now = time.time()

    sample_logs = [
        # 1. Controlled simulation attack request with valid sim token & IP
        {
            "time_local": datetime.fromtimestamp(now - 1.0, tz=timezone.utc).isoformat(),
            "msec": f"{now - 1.0:.3f}",
            "remote_addr": "172.28.0.10",
            "x_forwarded_for": "172.28.0.10",
            "sim_token": TEST_SIM_TOKEN,
            "sim_ip": "198.51.100.11",
            "request_method": "GET",
            "request_uri": "/api/v1/sample/hello",
            "status": 200,
            "body_bytes_sent": 128,
            "request_time": 0.005
        },
        # 2. Honeypot decoy hit with valid simulation identity
        {
            "time_local": datetime.fromtimestamp(now - 2.0, tz=timezone.utc).isoformat(),
            "msec": f"{now - 2.0:.3f}",
            "remote_addr": "172.28.0.10",
            "x_forwarded_for": "172.28.0.10",
            "sim_token": TEST_SIM_TOKEN,
            "sim_ip": "203.0.113.99",
            "request_method": "GET",
            "request_uri": "/admin-backup/",
            "status": 403,
            "body_bytes_sent": 256,
            "request_time": 0.002
        },
        # 3. Dashboard polling query (must be filtered out when filter_internal=True)
        {
            "time_local": datetime.fromtimestamp(now - 1.5, tz=timezone.utc).isoformat(),
            "msec": f"{now - 1.5:.3f}",
            "remote_addr": "172.28.0.10",
            "x_forwarded_for": "172.28.0.10",
            "request_method": "GET",
            "request_uri": "/api/v1/monitoring/metrics",
            "status": 200,
            "body_bytes_sent": 512,
            "request_time": 0.010
        },
        # 4. Another dashboard poll query
        {
            "time_local": datetime.fromtimestamp(now - 1.2, tz=timezone.utc).isoformat(),
            "msec": f"{now - 1.2:.3f}",
            "remote_addr": "172.28.0.10",
            "x_forwarded_for": "172.28.0.10",
            "request_method": "GET",
            "request_uri": "/api/v1/detection/status",
            "status": 200,
            "body_bytes_sent": 400,
            "request_time": 0.008
        },
        # 5. Legacy log entry without 'msec' (backward compatibility with time_local)
        {
            "time_local": datetime.fromtimestamp(now - 0.8, tz=timezone.utc).isoformat(),
            "remote_addr": "172.28.0.10",
            "sim_token": TEST_SIM_TOKEN,
            "sim_ip": "198.51.100.22",
            "request_method": "GET",
            "request_uri": "/api/v1/sample/info",
            "status": 200,
            "body_bytes_sent": 300,
            "request_time": 0.004
        }
    ]

    with open(log_file, "w", encoding="utf-8") as f:
        for entry in sample_logs:
            f.write(json.dumps(entry) + "\n")

    orig_path = monitoring_module.LOGS_PATH
    monitoring_module.LOGS_PATH = str(log_file)
    try:
        # Filtered analysis (default for traffic & entropy evaluation)
        filtered_entries = read_recent_access_logs(seconds_window=10, filter_internal=True)
        # Should return entries 1 (hello), 2 (honeypot), 5 (info) -> exactly 3 entries
        assert len(filtered_entries) == 3
        uris = [e["request_uri"] for e in filtered_entries]
        assert "/api/v1/sample/hello" in uris
        assert "/admin-backup/" in uris
        assert "/api/v1/sample/info" in uris
        assert "/api/v1/monitoring/metrics" not in uris
        assert "/api/v1/detection/status" not in uris

        # Verify client-IP resolution resolved simulated IPs
        client_ips = [e["remote_addr"] for e in filtered_entries]
        assert "198.51.100.11" in client_ips
        assert "203.0.113.99" in client_ips
        assert "198.51.100.22" in client_ips

        # Verify timestamps are parsed floats
        for entry in filtered_entries:
            assert isinstance(entry.get("timestamp"), float)

        # Unfiltered mode should return all 5 entries
        unfiltered_entries = read_recent_access_logs(seconds_window=10, filter_internal=False)
        assert len(unfiltered_entries) == 5
    finally:
        monitoring_module.LOGS_PATH = orig_path

# ---------------------------------------------------------------------------
# 4. End-to-End FastAPI Middleware & Allowlist Bypass Regression Tests
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient
from app.main import app
from app.services.mitigation import mitigation_engine

api_client = TestClient(app)

def test_regression_e2e_normal_request():
    """Verify normal requests receive HTTP 200 and attribute origin cleanly."""
    resp = api_client.get("/api/v1/sample/hello")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["client_ip"] == "testclient"

def test_regression_e2e_loopback_allowlist_bypass_blocked():
    """
    Verify that an attacker IP blocked by Tier 2 firewall CANNOT bypass mitigation
    simply by sending X-Forwarded-For: 127.0.0.1.
    """
    attacker_ip = "198.51.100.99"
    mitigation_engine.block_ip(attacker_ip, reason="Automated Tier 2 block test")
    try:
        # Case 1: Attacker sends request without headers -> Blocked
        resp1 = api_client.get(
            "/api/v1/sample/hello",
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert resp1.status_code == 403
        assert "Access Denied" in resp1.text

        # Case 2: Attacker crafts XFF claiming to be loopback 127.0.0.1 -> MUST STILL BE BLOCKED
        resp2 = api_client.get(
            "/api/v1/sample/hello",
            headers={
                "X-Forwarded-For": f"{attacker_ip}, 127.0.0.1"
            }
        )
        # Because candidate 127.0.0.1 is rejected and falls back, client is still attributed and blocked
        assert resp2.status_code == 403
        assert "Access Denied" in resp2.text

        # Case 3: Attacker crafts single hop XFF: 127.0.0.1
        resp3 = api_client.get(
            "/api/v1/sample/hello",
            headers={"X-Forwarded-For": "127.0.0.1"}
        )
        # 127.0.0.1 is rejected, resolving to peer_ip ('testclient')
        assert resp3.status_code == 200
        assert resp3.json()["client_ip"] != "127.0.0.1"
    finally:
        mitigation_engine.unblock_ip(attacker_ip)

def test_regression_e2e_controlled_simulation_mode(monkeypatch):
    """
    Verify that simulation scripts using valid simulation tokens can inject synthetic IPs
    which are correctly handled and attributed by the sample endpoint.
    """
    monkeypatch.setenv("SIMULATION_TOKEN", TEST_SIM_TOKEN)
    sim_ip = "198.51.100.66"
    resp = api_client.get(
        "/api/v1/sample/hello",
        headers={
            "X-Simulation-Token": TEST_SIM_TOKEN,
            "X-Simulated-IP": sim_ip
        }
    )
    assert resp.status_code == 200
    assert resp.json()["client_ip"] == sim_ip

# ---------------------------------------------------------------------------
# 5. Simulation Token State Regression Tests (Unset, Empty, Whitespace, Incorrect, Valid)
# ---------------------------------------------------------------------------

def test_simulation_channel_disabled_when_token_unset(monkeypatch):
    """Verify simulation mode is completely disabled when SIMULATION_TOKEN is unset."""
    monkeypatch.delenv("SIMULATION_TOKEN", raising=False)
    assert is_simulation_token_valid("any-token") is False
    assert is_simulation_token_valid("") is False
    assert is_simulation_token_valid(None) is False
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token="any-token",
        sim_ip="198.51.100.88"
    )
    assert resolved == "172.28.0.10"

def test_simulation_channel_disabled_when_token_empty(monkeypatch):
    """Verify simulation mode is completely disabled when SIMULATION_TOKEN is empty string."""
    monkeypatch.setenv("SIMULATION_TOKEN", "")
    assert is_simulation_token_valid("") is False
    assert is_simulation_token_valid(" ") is False
    assert is_simulation_token_valid("any-token") is False
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token="any-token",
        sim_ip="198.51.100.88"
    )
    assert resolved == "172.28.0.10"

def test_simulation_channel_disabled_when_token_whitespace(monkeypatch):
    """Verify whitespace-only configured SIMULATION_TOKEN can never authenticate requests."""
    monkeypatch.setenv("SIMULATION_TOKEN", "   \t  ")
    assert is_simulation_token_valid("   ") is False
    assert is_simulation_token_valid("any-token") is False
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token="   ",
        sim_ip="198.51.100.88"
    )
    assert resolved == "172.28.0.10"

def test_simulation_channel_rejects_incorrect_token(monkeypatch):
    """Verify simulation channel rejects mismatching client token."""
    monkeypatch.setenv("SIMULATION_TOKEN", "super-secret-token")
    assert is_simulation_token_valid("wrong-token") is False
    assert is_simulation_token_valid("") is False
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token="wrong-token",
        sim_ip="198.51.100.88"
    )
    assert resolved == "172.28.0.10"

def test_simulation_channel_accepts_valid_configured_token(monkeypatch):
    """Verify simulation channel accepts exact matching configured token with allowed synthetic IP."""
    configured_secret = "cloudshield-lab-prod-token-2026"
    monkeypatch.setenv("SIMULATION_TOKEN", configured_secret)
    assert is_simulation_token_valid(configured_secret) is True
    assert is_simulation_token_valid(f"  {configured_secret}  ") is True
    resolved = extract_client_ip(
        peer_ip="172.28.0.10",
        sim_token=configured_secret,
        sim_ip="198.51.100.88"
    )
    assert resolved == "198.51.100.88"

# ---------------------------------------------------------------------------
# 6. Docker Gateway / Internal Infrastructure Protection Regression Tests
# ---------------------------------------------------------------------------

def test_docker_gateway_and_internal_ips_protected_from_blocking():
    """
    Verify that Docker bridge gateway (172.28.0.1, 172.17.0.1), loopback, and internal
    container IPs are strictly protected and cannot be added to mitigation blocklist.
    """
    protected_ips = ["172.28.0.1", "172.17.0.1", "127.0.0.1", "172.28.0.11", "172.28.0.12"]
    for ip in protected_ips:
        assert mitigation_engine.is_ip_protected(ip) is True
        result = mitigation_engine.block_ip(ip, reason="Test attempt to block gateway")
        assert result is False
        assert mitigation_engine.is_ip_blocked(ip) is False
        assert ip not in mitigation_engine.blocked_ips

def test_root_health_endpoint():
    """Verify root / endpoint returns HTTP 200 with health details."""
    resp = api_client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "CloudShield"
    assert data["status"] == "healthy"


