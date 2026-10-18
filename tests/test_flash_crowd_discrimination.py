import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

# Ensure backend directory is in sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

import pytest
from app.services.entropy import EntropyEngine
from app.services.detection import DetectionEngine


# ---------------------------------------------------------------------------
# Stage 3 Proposal A: Focused Flash-Crowd vs Attack Discrimination Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_detection_engine():
    """Provides a fresh DetectionEngine and reset EntropyEngine/MitigationEngine for isolated testing."""
    engine = DetectionEngine()
    # Reset baselines to canonical values
    from app.services.entropy import entropy_engine
    entropy_engine.ewma_url_entropy = 2.5
    entropy_engine.ewma_ip_entropy = 2.8
    entropy_engine.ewma_rps = 5.0
    entropy_engine.std_url_entropy = 0.4
    entropy_engine.std_ip_entropy = 0.4
    from app.services.mitigation import mitigation_engine
    mitigation_engine.active_tier = "NONE"
    mitigation_engine.normal_cycles_count = 0
    mitigation_engine.blocked_ips.clear()
    return engine


@pytest.mark.asyncio
async def test_high_url_diversity_during_flash_crowd(clean_detection_engine):
    """
    Scenario: Legitimate traffic surge with high URL diversity across many pages.
    Goal: Verify that high URL diversity (url_entropy > baseline) results in url_z_drop == 0.0
    and is correctly classified as FLASH_CROWD, rather than falsely flagged as ATTACK.
    """
    from app.services.entropy import entropy_engine
    engine = clean_detection_engine

    # 16 distinct endpoints visited by 64 distinct clients
    diverse_urls = [f"/products/item-{i}" for i in range(16)] * 4
    diverse_ips = [f"198.51.100.{i}" for i in range(64)]

    # 1. Entropy Engine Level Check
    entropy_res = entropy_engine.analyze_entropy(diverse_ips, diverse_urls)
    assert entropy_res["url_entropy"] == 4.0  # log2(16) = 4.0 bits
    assert entropy_res["url_entropy"] > entropy_res["url_entropy_baseline"]  # 4.0 > 2.5
    # Two-tailed z-score is high (deviation from 2.5 is 1.5 -> z = 3.75)
    assert entropy_res["url_z_score"] > 2.0
    # BUT directional drop is exactly 0.0 (diversity increased, not collapsed!)
    assert entropy_res["url_z_drop"] == 0.0
    assert entropy_res["top_ip_concentration_pct"] < 5.0

    # 2. Detection Decision Rule Check
    mock_metrics = {
        "requests_per_sec": 48.0,  # Surge > 30.0 RPS and > 3.5 * baseline (5.0)
        "cpu_utilization": 35.0,
        "error_rate_5xx": 2.0,      # Low error rate (< 15.0%)
        "latency_ms": 25.0
    }
    mock_logs = [{"remote_addr": ip, "request_uri": uri} for ip, uri in zip(diverse_ips, diverse_urls)]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "FLASH_CROWD", (
        f"Expected FLASH_CROWD for high URL diversity surge, got {result['classification']}. "
        f"Reason: {result['verdict_reason']}"
    )
    assert result["mitigation_tier"] == "TIER_3"
    assert result["url_z_drop"] == 0.0
    assert "Flash crowd pattern" in result["verdict_reason"]


@pytest.mark.asyncio
async def test_concentrated_flood_with_low_url_diversity(clean_detection_engine):
    """
    Scenario: Concentrated L7 flood targeting a single URL from a single source IP.
    Goal: Verify that collapsed URL entropy (0.0) yields url_z_drop > 2.0, and combined
    with high top-IP concentration is decisively classified as ATTACK.
    """
    from app.services.entropy import entropy_engine
    engine = clean_detection_engine

    single_target_urls = ["/api/v1/search?q=heavy"] * 100
    single_ip_flood = ["203.0.113.55"] * 100

    # 1. Entropy Engine Level Check
    entropy_res = entropy_engine.analyze_entropy(single_ip_flood, single_target_urls)
    assert entropy_res["url_entropy"] == 0.0
    assert entropy_res["url_z_drop"] > 2.0  # (2.5 - 0.0) / 0.4 = 6.25
    assert entropy_res["top_ip_concentration_pct"] == 100.0

    # 2. Detection Decision Rule Check
    mock_metrics = {
        "requests_per_sec": 60.0,
        "cpu_utilization": 85.0,
        "error_rate_5xx": 0.0,
        "latency_ms": 120.0
    }
    mock_logs = [{"remote_addr": ip, "request_uri": uri} for ip, uri in zip(single_ip_flood, single_target_urls)]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "ATTACK"
    assert result["mitigation_tier"] == "TIER_2"  # Tier 2 because top_ip_pct > 60%
    assert result["url_z_drop"] > 2.0
    assert "Traffic flood" in result["verdict_reason"]


@pytest.mark.asyncio
async def test_distributed_flood_traffic(clean_detection_engine):
    """
    Scenario: Distributed botnet flood targeting a single URL from 100 distinct bot IPs.
    Goal: Verify that Proposal A preserves strong detection of distributed attacks:
    even though top-IP concentration is low (< 5%), the drop in URL diversity (url_z_drop > 2.0)
    correctly triggers an ATTACK classification.
    """
    from app.services.entropy import entropy_engine
    engine = clean_detection_engine

    single_target_urls = ["/api/v1/search?q=bot"] * 100
    bot_ips = [f"192.0.2.{i}" for i in range(100)]  # 100 distinct IPs

    # 1. Entropy Engine Level Check
    entropy_res = entropy_engine.analyze_entropy(bot_ips, single_target_urls)
    assert entropy_res["url_entropy"] == 0.0
    assert entropy_res["url_z_drop"] > 2.0  # Drop from baseline 2.5 to 0.0
    assert entropy_res["top_ip_concentration_pct"] == 1.0  # Balanced IP distribution

    # 2. Detection Decision Rule Check
    mock_metrics = {
        "requests_per_sec": 60.0,
        "cpu_utilization": 80.0,
        "error_rate_5xx": 5.0,  # Below 15.0% error rate threshold
        "latency_ms": 150.0
    }
    mock_logs = [{"remote_addr": ip, "request_uri": uri} for ip, uri in zip(bot_ips, single_target_urls)]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    # Must be classified as ATTACK via url_z_drop even though top_ip_pct and error_rate did not trigger
    assert result["classification"] == "ATTACK", (
        f"Distributed flood must be detected as ATTACK via url_z_drop, got {result['classification']}"
    )
    assert result["mitigation_tier"] == "TIER_1"  # Tier 1 because top_ip_pct <= 60%
    assert result["url_z_drop"] > 2.0


@pytest.mark.asyncio
async def test_normal_traffic(clean_detection_engine):
    """
    Scenario: Routine browsing traffic within normal rate and diversity bounds.
    Goal: Verify that normal traffic is classified as NORMAL with tier NONE.
    """
    engine = clean_detection_engine

    normal_urls = ["/api/v1/sample/hello", "/api/v1/sample/info", "/items", "/"] * 5
    normal_ips = [f"10.0.0.{i}" for i in range(20)]

    mock_metrics = {
        "requests_per_sec": 8.0,  # Well below 15.0 RPS threshold
        "cpu_utilization": 15.0,
        "error_rate_5xx": 0.0,
        "latency_ms": 12.0
    }
    mock_logs = [{"remote_addr": ip, "request_uri": uri} for ip, uri in zip(normal_ips, normal_urls)]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "NORMAL"
    assert result["mitigation_tier"] == "NONE"
    assert "within baseline thresholds" in result["verdict_reason"]


@pytest.mark.asyncio
async def test_missing_or_insufficient_telemetry(clean_detection_engine):
    """
    Scenario: Startup or zero-traffic period where telemetry logs are empty.
    Goal: Verify graceful handling without division by zero, crashes, or false alarms.
    """
    from app.services.entropy import entropy_engine
    engine = clean_detection_engine

    # 1. Entropy Engine Empty Input
    empty_res = entropy_engine.analyze_entropy([], [])
    assert empty_res["url_entropy"] == 0.0
    assert empty_res["ip_entropy"] == 0.0
    assert empty_res["top_ip"] is None
    assert empty_res["top_ip_concentration_pct"] == 0.0
    assert EntropyEngine.calculate_shannon_entropy([]) == 0.0

    # 2. Detection Engine Empty Telemetry
    mock_metrics = {
        "requests_per_sec": 0.0,
        "cpu_utilization": 10.0,
        "error_rate_5xx": 0.0,
        "latency_ms": 0.0
    }
    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=[]):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "NORMAL"
    assert result["mitigation_tier"] == "NONE"
    assert result["honeypot_hit_count"] == 0
    assert "within baseline thresholds" in result["verdict_reason"]


# ---------------------------------------------------------------------------
# Stage 3A: Error-Rate Disambiguation & Telemetry Partitioning Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_rate_limited_503_during_flash_crowd(clean_detection_engine):
    """
    Scenario: High URL diversity flash crowd generates edge 503s because Nginx rate limit is reached,
    but upstream backends are healthy.
    Goal: Verify that proxy-generated 503s (upstream_addr == "") do NOT count toward
    upstream_error_rate_5xx, allowing the engine to correctly classify FLASH_CROWD.
    """
    engine = clean_detection_engine

    diverse_urls = [f"/products/item-{i}" for i in range(16)] * 4
    diverse_ips = [f"198.51.100.{i}" for i in range(64)]

    # Mock metrics: total error_rate_5xx is 22.0% (due to proxy drops), but upstream_error_rate is 0.0%
    mock_metrics = {
        "requests_per_sec": 55.0,  # Surge > 30.0 RPS
        "cpu_utilization": 40.0,
        "error_rate_5xx": 22.0,                  # Lumps all 5xx
        "upstream_error_rate_5xx": 0.0,          # Zero upstream failures
        "proxy_rate_limited_rate_503": 22.0,     # Nginx front-door drops
        "latency_ms": 15.0
    }
    # 75% 200 responses with upstream_addr, 25% 503 responses with empty upstream_addr
    mock_logs = []
    for i, (ip, uri) in enumerate(zip(diverse_ips, diverse_urls)):
        if i % 4 == 0:
            mock_logs.append({"remote_addr": ip, "request_uri": uri, "status": 503, "upstream_addr": ""})
        else:
            mock_logs.append({"remote_addr": ip, "request_uri": uri, "status": 200, "upstream_addr": "172.28.0.11:8000"})

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "FLASH_CROWD", (
        f"Flash crowd with proxy 503s must NOT be classified as ATTACK. Got: {result['classification']}"
    )
    assert result["mitigation_tier"] == "TIER_3"
    assert result["upstream_error_rate_5xx"] == 0.0


@pytest.mark.asyncio
async def test_upstream_backend_failure_during_surge(clean_detection_engine):
    """
    Scenario: Traffic surge where upstream backends are failing (HTTP 500/502/504 with upstream_addr populated).
    Goal: Verify that genuine upstream backend errors (upstream_error_rate_5xx > 15%) trigger ATTACK.
    """
    engine = clean_detection_engine

    diverse_urls = [f"/products/item-{i}" for i in range(16)] * 4
    diverse_ips = [f"198.51.100.{i}" for i in range(64)]

    # Mock metrics: upstream_error_rate_5xx is 20.0% (> 15.0% threshold)
    mock_metrics = {
        "requests_per_sec": 55.0,
        "cpu_utilization": 85.0,
        "error_rate_5xx": 20.0,
        "upstream_error_rate_5xx": 20.0,         # Upstream backends failing!
        "proxy_rate_limited_rate_503": 0.0,
        "latency_ms": 450.0
    }
    # 20% 500 responses with upstream_addr populated
    mock_logs = []
    for i, (ip, uri) in enumerate(zip(diverse_ips, diverse_urls)):
        if i % 5 == 0:
            mock_logs.append({"remote_addr": ip, "request_uri": uri, "status": 500, "upstream_addr": "172.28.0.11:8000"})
        else:
            mock_logs.append({"remote_addr": ip, "request_uri": uri, "status": 200, "upstream_addr": "172.28.0.12:8000"})

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "ATTACK", (
        f"Upstream failures (>15%) during surge must be classified as ATTACK. Got: {result['classification']}"
    )
    assert result["mitigation_tier"] == "TIER_1"
    assert result["upstream_error_rate_5xx"] == 20.0


@pytest.mark.asyncio
async def test_randomized_url_attack_evasion_and_404_boundary(clean_detection_engine):
    """
    Scenario: Adversary mounts a distributed flood with random unique URLs to artificially inflate URL entropy.
    Goal: Test and document the evasion boundary:
    1. If all random URLs return 200, high URL entropy causes classification as FLASH_CROWD (demonstrating the limitation).
    2. Verifies that url_z_drop is 0.0 despite the traffic being malicious.
    """
    from app.services.entropy import entropy_engine
    engine = clean_detection_engine

    # 100 completely unique randomized URLs across 100 distinct bot IPs
    random_urls = [f"/search?rand={i}_{i*7}" for i in range(100)]
    bot_ips = [f"198.51.100.{i}" for i in range(100)]

    entropy_res = entropy_engine.analyze_entropy(bot_ips, random_urls)
    assert entropy_res["url_entropy"] > 6.0  # Maximal entropy
    assert entropy_res["url_z_drop"] == 0.0   # No drop in diversity

    mock_metrics = {
        "requests_per_sec": 55.0,
        "cpu_utilization": 40.0,
        "error_rate_5xx": 0.0,
        "upstream_error_rate_5xx": 0.0,
        "proxy_rate_limited_rate_503": 0.0,
        "latency_ms": 20.0
    }
    mock_logs = [{"remote_addr": ip, "request_uri": uri, "status": 200, "upstream_addr": "172.28.0.11:8000"}
                 for ip, uri in zip(bot_ips, random_urls)]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=mock_logs):
        result = await engine.evaluate_traffic()

    # Confirms that pure URL entropy cannot distinguish random-URL flood from flash crowd if status is 200
    assert result["classification"] == "FLASH_CROWD"
    assert result["url_z_drop"] == 0.0


@pytest.mark.asyncio
async def test_telemetry_upstream_vs_proxy_error_partitioning():
    """
    Scenario: Verify that get_current_metrics() accurately partitions Nginx-level 503s
    from upstream application 500s using the upstream_addr log field.
    """
    from app.services.monitoring import get_current_metrics

    # Create synthetic log entries:
    # 10 x HTTP 200 (upstream_addr="172.28.0.11:8000")
    # 5  x HTTP 503 (upstream_addr="")               -> Proxy rate limited
    # 5  x HTTP 500 (upstream_addr="172.28.0.12:8000") -> Upstream error
    sample_logs = []
    for _ in range(10):
        sample_logs.append({"status": 200, "upstream_addr": "172.28.0.11:8000", "request_time": 0.01, "body_bytes_sent": 200})
    for _ in range(5):
        sample_logs.append({"status": 503, "upstream_addr": "", "request_time": 0.0, "body_bytes_sent": 197})
    for _ in range(5):
        sample_logs.append({"status": 500, "upstream_addr": "172.28.0.12:8000", "request_time": 0.05, "body_bytes_sent": 150})

    with patch("app.services.monitoring.read_recent_access_logs", return_value=sample_logs), \
         patch("app.services.monitoring.query_prometheus", new=AsyncMock(return_value=0.0)):
        metrics = await get_current_metrics()

    # Total 20 logs:
    # 10 total 5xx errors -> error_rate_5xx = 10 / 20 * 100 = 50.0%
    # 5 upstream 5xx errors -> upstream_error_rate_5xx = 5 / 20 * 100 = 25.0%
    # 5 proxy 503 errors -> proxy_rate_limited_rate_503 = 5 / 20 * 100 = 25.0%
    assert metrics["error_rate_5xx"] == 50.0
    assert metrics["upstream_error_rate_5xx"] == 25.0
    assert metrics["proxy_rate_limited_rate_503"] == 25.0


@pytest.mark.asyncio
async def test_proxy_rate_limited_503_at_moderate_load_stays_normal(clean_detection_engine):
    """
    Scenario: Moderate traffic below the surge threshold experiences proxy 503 drops,
    but upstream application backends are completely healthy (upstream_error_rate == 0).
    Goal: Verify that Nginx-level 503 drops do NOT falsely trigger a SUSPICIOUS verdict.
    """
    engine = clean_detection_engine
    mock_metrics = {
        "requests_per_sec": 12.0,
        "cpu_utilization": 25.0,
        "error_rate_5xx": 20.0,
        "upstream_error_rate_5xx": 0.0,
        "proxy_rate_limited_rate_503": 20.0,
        "latency_ms": 20.0
    }
    sample_logs = [
        {"remote_addr": f"192.168.1.{i}", "request_uri": f"/api/v1/item/{i}", "status": 200, "upstream_addr": "172.28.0.11:8000"}
        for i in range(16)
    ] + [
        {"remote_addr": f"192.168.1.{i+20}", "request_uri": f"/api/v1/item/{i}", "status": 503, "upstream_addr": ""}
        for i in range(4)
    ]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=sample_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "NORMAL", (
        f"Proxy 503 drops must not cause SUSPICIOUS classification. Got: {result['classification']}"
    )
    assert result["mitigation_tier"] == "NONE"


@pytest.mark.asyncio
async def test_upstream_backend_failure_at_moderate_load_triggers_suspicious(clean_detection_engine):
    """
    Scenario: Moderate traffic where upstream backend genuinely fails (> 10% 5xx errors with upstream_addr).
    Goal: Verify that genuine upstream backend errors trigger SUSPICIOUS with TIER_1 escalation.
    """
    engine = clean_detection_engine
    mock_metrics = {
        "requests_per_sec": 12.0,
        "cpu_utilization": 30.0,
        "error_rate_5xx": 15.0,
        "upstream_error_rate_5xx": 15.0,
        "proxy_rate_limited_rate_503": 0.0,
        "latency_ms": 45.0
    }
    sample_logs = [
        {"remote_addr": f"192.168.1.{i}", "request_uri": f"/api/v1/item/{i}", "status": 200, "upstream_addr": "172.28.0.11:8000"}
        for i in range(17)
    ] + [
        {"remote_addr": f"192.168.1.{i+20}", "request_uri": f"/api/v1/item/{i}", "status": 500, "upstream_addr": "172.28.0.12:8000"}
        for i in range(3)
    ]

    with patch("app.services.detection.get_current_metrics", new=AsyncMock(return_value=mock_metrics)), \
         patch("app.services.detection.read_recent_access_logs", return_value=sample_logs):
        result = await engine.evaluate_traffic()

    assert result["classification"] == "SUSPICIOUS"
    assert result["mitigation_tier"] == "TIER_1"
    assert "Elevated upstream 5xx error rate: 15.0%" in result["verdict_reason"]


def test_unverified_reset_prevents_scenario_traffic_from_starting():
    """
    Goal: Verify strict fail-closed safety in benchmark runner.
    If reset_system_state() reports reset_verified=False (e.g., node unreachable or unclean),
    run_single_scenario() must immediately raise RuntimeError and abort before starting
    probes, observer threads, or generating any network traffic.
    """
    import sys
    sys.path.insert(0, ".")
    from scripts.benchmark_suite import run_single_scenario

    unclean_reset_info = {
        "reset_verified": False,
        "actions": ["Tier reset failed"],
        "tier_reset_confirmed_nodes": [],
        "backend_verifications": {
            "172.28.0.11:8000": {"container": "cloudshield-backend-1", "is_clean": False, "blocked_ip_count": 1}
        },
        "baseline_state": "UNVERIFIED"
    }

    dummy_scenario = {
        "name": "mock_unverified_scenario",
        "ground_truth": "ATTACK",
        "duration": 5,
        "concurrency": 2,
        "target_rps": 10,
        "endpoints": ["/api/v1/sample/hello"],
        "ip_pool": ["198.51.100.1"]
    }

    with patch("scripts.benchmark_suite.reset_system_state", return_value=unclean_reset_info), \
         patch("scripts.benchmark_suite.send_scenario_request") as mock_send_req, \
         patch("scripts.benchmark_suite.RateControlledScheduler.execute") as mock_sched_exec:

        with pytest.raises(RuntimeError) as exc_info:
            run_single_scenario(dummy_scenario, sim_token="dummy-token")

        assert "Refusing to execute scenario on unverified baseline" in str(exc_info.value)
        # Verify that zero scenario requests were dispatched
        assert mock_send_req.call_count == 0
        assert mock_sched_exec.call_count == 0


def test_detection_latencies_initial_suspicious_followed_by_attack():
    """
    Goal: Verify that multi-stage escalation distinguishes time to first alert from time to ground-truth match.
    In Scenario 2 (concentrated flood), the system first observed SUSPICIOUS at ~4.12s, then escalated to ATTACK at ~8.75s.
    The benchmark measurement must report:
    - time_to_first_alert_sec == 4.12 (first_alert_classification == "SUSPICIOUS")
    - time_to_ground_truth_match_sec == 8.75
    - time_to_detect_sec == 4.12 (preserved alias)
    """
    from scripts.benchmark_suite import compute_detection_latencies

    t0 = 1000.0
    mock_observations = [
        {"poll_time": t0 + 2.06, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 4.12, "classification": "SUSPICIOUS", "active_tier": "TIER_1"},
        {"poll_time": t0 + 6.18, "classification": "SUSPICIOUS", "active_tier": "TIER_1"},
        {"poll_time": t0 + 8.75, "classification": "ATTACK", "active_tier": "TIER_2"},
        {"poll_time": t0 + 10.02, "classification": "ATTACK", "active_tier": "TIER_2"}
    ]

    latencies = compute_detection_latencies(mock_observations, traffic_start_time=t0, ground_truth="ATTACK")

    assert latencies["time_to_first_alert_sec"] == 4.12
    assert latencies["first_alert_classification"] == "SUSPICIOUS"
    assert latencies["time_to_ground_truth_match_sec"] == 8.75
    assert latencies["time_to_detect_sec"] == 4.12


def test_detection_latencies_scenario_never_reaches_ground_truth():
    """
    Goal: Verify that when a scenario never triggers or never reaches its ground-truth classification
    (e.g., Scenario 4 low-rate flood remaining NORMAL throughout), the metrics do not fabricate
    a detection time and strictly return None.
    """
    from scripts.benchmark_suite import compute_detection_latencies

    t0 = 2000.0
    mock_observations = [
        {"poll_time": t0 + 2.0, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 4.0, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 6.0, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 8.0, "classification": "NORMAL", "active_tier": "NONE"}
    ]

    latencies = compute_detection_latencies(mock_observations, traffic_start_time=t0, ground_truth="ATTACK")

    assert latencies["time_to_first_alert_sec"] is None
    assert latencies["first_alert_classification"] is None
    assert latencies["time_to_ground_truth_match_sec"] is None
    assert latencies["time_to_detect_sec"] is None


def test_detection_latencies_normal_traffic_baseline():
    """
    Goal: Verify that baseline normal traffic (ground truth NORMAL) with all NORMAL observations
    reports None for all detection latencies (no false alerts, no fabricated match times).
    """
    from scripts.benchmark_suite import compute_detection_latencies

    t0 = 3000.0
    mock_observations = [
        {"poll_time": t0 + 2.0, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 4.0, "classification": "NORMAL", "active_tier": "NONE"}
    ]

    latencies = compute_detection_latencies(mock_observations, traffic_start_time=t0, ground_truth="NORMAL")

    assert latencies["time_to_first_alert_sec"] is None
    assert latencies["first_alert_classification"] is None
    assert latencies["time_to_ground_truth_match_sec"] is None
    assert latencies["time_to_detect_sec"] is None


def test_detection_latencies_direct_ground_truth_match():
    """
    Goal: Verify that when the first alert directly matches the scenario ground truth
    (e.g., Scenario 6 flash crowd or Scenario 3 distributed flood), both metrics match.
    """
    from scripts.benchmark_suite import compute_detection_latencies

    t0 = 4000.0
    mock_observations = [
        {"poll_time": t0 + 2.0, "classification": "NORMAL", "active_tier": "NONE"},
        {"poll_time": t0 + 4.15, "classification": "FLASH_CROWD", "active_tier": "TIER_3"}
    ]

    latencies = compute_detection_latencies(mock_observations, traffic_start_time=t0, ground_truth="FLASH_CROWD")

    assert latencies["time_to_first_alert_sec"] == 4.15
    assert latencies["first_alert_classification"] == "FLASH_CROWD"
    assert latencies["time_to_ground_truth_match_sec"] == 4.15
    assert latencies["time_to_detect_sec"] == 4.15
