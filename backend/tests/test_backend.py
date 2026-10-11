import sys
import os
from pathlib import Path

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import Base, engine
from app.services.entropy import entropy_engine
from app.services.mitigation import mitigation_engine
from app.core.aws_client import aws_manager

@pytest.fixture(autouse=True)
def setup_database():
    """Ensure all database tables are created before running tests."""
    Base.metadata.create_all(bind=engine)
    yield

client = TestClient(app)

def test_root_health():
    """Test that the top-level /health endpoint returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CloudShield"

def test_api_v1_health():
    """Test /api/v1/health endpoint with DB connectivity check."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"

def test_metrics_endpoint():
    """Test /metrics Prometheus scrape endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "cloudshield_http_requests_total" in response.text or "process_cpu_seconds_total" in response.text

def test_incident_lifecycle():
    """Test creating and retrieving an incident."""
    new_incident = {
        "classification": "SUSPICIOUS",
        "mitigation_tier": "TIER_1",
        "source_ip": "10.0.0.99",
        "requests_per_sec": 350.0,
        "baseline_rps": 60.0,
        "url_entropy": 0.95,
        "ip_entropy": 1.20,
        "verdict_reason": "High request volume on single URI",
        "is_active": True
    }
    create_resp = client.post("/api/v1/incidents/", json=new_incident)
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["id"] is not None
    assert created_data["classification"] == "SUSPICIOUS"

    # Fetch incident list
    list_resp = client.get("/api/v1/incidents/")
    assert list_resp.status_code == 200
    incidents = list_resp.json()
    assert len(incidents) >= 1
    assert any(i["id"] == created_data["id"] for i in incidents)

def test_sample_upstream_endpoint():
    """Test sample upstream app endpoint."""
    response = client.get("/api/v1/sample/hello")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "served_by" in data

def test_entropy_calculation():
    """Test Shannon entropy calculation and baseline tracking."""
    # Balanced distribution (high entropy)
    diverse_ips = [f"192.168.1.{i}" for i in range(16)]
    diverse_urls = [f"/endpoint/{i}" for i in range(16)]
    res_high = entropy_engine.analyze_entropy(diverse_ips, diverse_urls)
    assert res_high["ip_entropy"] > 3.0
    assert res_high["url_entropy"] > 3.0

    # Concentrated distribution (low entropy)
    flood_ips = ["192.168.1.1"] * 20
    flood_urls = ["/api/v1/sample/hello"] * 20
    res_low = entropy_engine.analyze_entropy(flood_ips, flood_urls)
    assert res_low["ip_entropy"] == 0.0
    assert res_low["url_entropy"] == 0.0
    assert res_low["top_ip_concentration_pct"] == 100.0

def test_mitigation_tier_escalation_and_hysteresis():
    """Test tier escalation, cooldown hysteresis, and allowlist protection."""
    mitigation_engine.active_tier = "NONE"
    mitigation_engine.normal_cycles_count = 0

    # Escalate to Tier 1
    mitigation_engine.escalate_tier("TIER_1", reason="Moderate surge")
    assert mitigation_engine.active_tier == "TIER_1"

    # Escalate to Tier 2
    mitigation_engine.escalate_tier("TIER_2", reason="Adversary IP detected")
    assert mitigation_engine.active_tier == "TIER_2"

    # Test Allowlist protection
    assert mitigation_engine.is_ip_blocked("127.0.0.1") is False
    assert mitigation_engine.block_ip("127.0.0.1", reason="Should be ignored") is False

    # Block an untrusted attacker IP
    test_attacker = "198.51.100.77"
    blocked = mitigation_engine.block_ip(test_attacker, reason="Malicious probe")
    assert blocked is True
    assert mitigation_engine.is_ip_blocked(test_attacker) is True

    # Unblock
    mitigation_engine.unblock_ip(test_attacker)
    assert mitigation_engine.is_ip_blocked(test_attacker) is False

    # Test Hysteresis Cooldown
    # Requires 3 consecutive normal cycles to de-escalate one tier
    mitigation_engine.evaluate_cooldown("NORMAL")
    assert mitigation_engine.active_tier == "TIER_2"  # Cycle 1
    mitigation_engine.evaluate_cooldown("NORMAL")
    assert mitigation_engine.active_tier == "TIER_2"  # Cycle 2
    next_tier = mitigation_engine.evaluate_cooldown("NORMAL")  # Cycle 3: de-escalates to TIER_1
    assert next_tier == "TIER_1"
    assert mitigation_engine.active_tier == "TIER_1"

def test_honeypot_decoy_endpoints():
    """Test honeypot tripwire decoy access and immediate trapping."""
    # Decoy returns 403 Forbidden
    resp = client.get("/admin-backup/", headers={"X-Forwarded-For": "203.0.113.88"})
    assert resp.status_code == 403
    assert "Forbidden" in resp.text

    # Honeypot stats endpoint returns hit count
    stats_resp = client.get("/api/v1/honeypot/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_hits"] >= 1
    assert "/admin-backup/" in stats["decoy_endpoints"]

def test_admin_authentication_and_controls():
    """Test admin login, token generation, and threshold configuration."""
    # Bad credentials
    bad_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert bad_login.status_code == 401

    # Valid credentials
    good_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cloudshield2026"})
    assert good_login.status_code == 200
    token = good_login.json()["token"]
    assert token is not None

    # Get config with bearer token
    cfg_resp = client.get("/api/v1/admin/config", headers={"Authorization": f"Bearer {token}"})
    assert cfg_resp.status_code == 200
    assert "ewma_rps" in cfg_resp.json()

def test_aws_integration_simulation():
    """Test AWS failover and scale-out in local development simulation mode."""
    status = aws_manager.get_status()
    assert status["current_active_proxy"] == "PRIMARY"
    assert status["mode"] in ["AWS_LIVE", "SIMULATION_MODE"]

    # Trigger Route53 failover
    failover_event = aws_manager.trigger_route53_failover(reason="Unit test tier 4 test")
    assert failover_event["target_proxy"] == "SECONDARY"
    assert aws_manager.current_active_proxy == "SECONDARY"

    # Restore primary
    restore_event = aws_manager.restore_route53_primary(reason="Unit test recovery")
    assert restore_event["target_proxy"] == "PRIMARY"
    assert aws_manager.current_active_proxy == "PRIMARY"

    # Scale out ASG
    scale_event = aws_manager.scale_out_backend_pool(desired_capacity=4)
    assert scale_event["desired_capacity"] == 4
