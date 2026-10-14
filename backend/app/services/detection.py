import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.services.monitoring import get_current_metrics, read_recent_access_logs
from app.services.entropy import entropy_engine
from app.services.mitigation import mitigation_engine
from app.db.session import SessionLocal
from app.models.incident import Incident

logger = logging.getLogger("cloudshield.detection")

DECOY_PATHS = ["/admin-backup/", "/wp-login.php", "/hidden-admin.html"]

class DetectionEngine:
    def __init__(self):
        self.last_incident_time: float = 0.0
        self.incident_cooldown_seconds: int = 15  # Cooldown between recording duplicate incidents
        self.current_state: str = "NORMAL"        # NORMAL, SUSPICIOUS, ATTACK, FLASH_CROWD
        self.current_verdict: Dict[str, Any] = {}
        self.simulation_verdict: Optional[Dict[str, Any]] = None

    def set_simulation(self, classification: str, tier: str, url_entropy: float = 0.0, rps: float = 1.0, verdict_reason: str = "Simulation"):
        self.current_state = classification
        self.simulation_verdict = {
            "timestamp": datetime.utcnow().isoformat(),
            "classification": classification,
            "mitigation_tier": tier,
            "requests_per_sec": rps,
            "baseline_rps": round(entropy_engine.ewma_rps, 1),
            "cpu_utilization": 2.5,
            "error_rate_5xx": 0.0,
            "latency_ms": 25.0,
            "url_entropy": url_entropy,
            "url_entropy_baseline": 2.5,
            "url_z_score": 5.0 if url_entropy < 1.0 else 0.5,
            "ip_entropy": 0.0 if classification == "ATTACK" else 2.8,
            "ip_entropy_baseline": 2.8,
            "top_ip": "203.0.113.199" if classification == "ATTACK" else "Diverse Cluster (50+ IPs)",
            "top_ip_concentration_pct": 100.0 if classification == "ATTACK" else 15.0,
            "honeypot_hit_count": 1 if "honeypot" in verdict_reason.lower() else 0,
            "verdict_reason": verdict_reason
        }
        self.current_verdict = self.simulation_verdict
        mitigation_engine.active_tier = tier

    def clear_simulation(self):
        self.simulation_verdict = None
        self.current_verdict = {}
        self.current_state = "NORMAL"

    async def evaluate_traffic(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Executes a single multi-signal detection cycle.
        Returns the evaluation report.
        """
        if self.simulation_verdict is not None:
            return self.simulation_verdict
        # 1. Gather Telemetry
        metrics = await get_current_metrics()
        recent_logs = read_recent_access_logs(seconds_window=10)

        # Extract IPs, URLs, and check honeypot hits
        ips = [log.get("remote_addr") for log in recent_logs if log.get("remote_addr")]
        urls = [log.get("request_uri") for log in recent_logs if log.get("request_uri")]

        honeypot_hits = []
        for log in recent_logs:
            uri = log.get("request_uri", "")
            ip = log.get("remote_addr")
            if ip and ip not in mitigation_engine.allowlist and any(decoy in uri for decoy in DECOY_PATHS):
                honeypot_hits.append({
                    "ip": ip,
                    "uri": uri,
                    "timestamp": log.get("time_local")
                })

        # 2. Entropy & Feature Analysis
        entropy_res = entropy_engine.analyze_entropy(ips, urls)
        
        rps = metrics.get("requests_per_sec", 0.0)
        baseline_rps = entropy_engine.ewma_rps
        cpu = metrics.get("cpu_utilization", 0.0)
        error_rate = metrics.get("error_rate_5xx", 0.0)
        latency = metrics.get("latency_ms", 0.0)

        url_entropy = entropy_res["url_entropy"]
        url_z = entropy_res["url_z_score"]
        ip_entropy = entropy_res["ip_entropy"]
        top_ip = entropy_res["top_ip"]
        top_ip_pct = entropy_res["top_ip_concentration_pct"]

        # 3. Decision Logic & Rule Evaluation
        reasons = []
        classification = "NORMAL"
        mitigation_tier = "NONE"

        # Check Honeypot first (high confidence)
        if honeypot_hits:
            classification = "ATTACK"
            mitigation_tier = "TIER_2"
            bad_ips = list(set(h["ip"] for h in honeypot_hits))
            reasons.append(f"Honeypot decoy accessed by IP(s): {', '.join(bad_ips)}")
            for bad_ip in bad_ips:
                mitigation_engine.block_ip(bad_ip, reason="Accessed honeypot decoy")

        # Check Request Rate & Entropy
        elif rps > max(baseline_rps * 3.5, 30.0):
            # Surge detected - Distinguish Attack vs Flash Crowd
            if url_z > 2.0 or top_ip_pct > 55.0 or error_rate > 15.0:
                classification = "ATTACK"
                mitigation_tier = "TIER_2" if top_ip_pct > 60.0 else "TIER_1"
                reasons.append(
                    f"Traffic flood: {rps} req/s (baseline {baseline_rps:.1f} req/s). "
                    f"Low URL entropy ({url_entropy:.2f}, z={url_z}) and high top-IP concentration ({top_ip_pct}%)."
                )
                if top_ip and top_ip_pct > 60.0:
                    mitigation_engine.block_ip(top_ip, reason=f"Accounted for {top_ip_pct}% of flood traffic")
            else:
                # High traffic volume, but diverse URLs and balanced IP distribution
                classification = "FLASH_CROWD"
                mitigation_tier = "TIER_3"  # Scale out capacity to serve legitimate users
                reasons.append(
                    f"Legitimate traffic surge: {rps} req/s with healthy URL diversity ({url_entropy:.2f}) "
                    f"and distributed IPs (top IP only {top_ip_pct}%). Flash crowd pattern."
                )

        elif rps > max(baseline_rps * 1.8, 15.0) or cpu > 70.0 or error_rate > 10.0:
            classification = "SUSPICIOUS"
            mitigation_tier = "TIER_1"
            if rps > baseline_rps * 1.8:
                reasons.append(f"Moderate RPS elevation: {rps} req/s vs baseline {baseline_rps:.1f} req/s.")
            if cpu > 70.0:
                reasons.append(f"Elevated CPU load: {cpu}%.")
            if error_rate > 10.0:
                reasons.append(f"Elevated 5xx error rate: {error_rate}%.")

        else:
            classification = "NORMAL"
            mitigation_tier = "NONE"
            reasons.append("All metrics within baseline thresholds.")
            # Update baseline on normal traffic
            entropy_engine.update_baselines(ip_entropy, url_entropy, rps, is_normal=True)

        self.current_state = classification
        verdict_summary = "; ".join(reasons)

        # 4. Mitigation Escalation & Hysteresis Recovery Trigger
        if mitigation_tier != "NONE":
            mitigation_engine.escalate_tier(mitigation_tier, reason=verdict_summary)
        else:
            # Trigger cooldown and automatic recovery check
            recovered_tier = mitigation_engine.evaluate_cooldown("NORMAL")
            if recovered_tier is not None:
                reasons.append(f"Auto-recovery transitioned to tier: {recovered_tier}")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "classification": classification,
            "mitigation_tier": mitigation_engine.active_tier,
            "requests_per_sec": rps,
            "baseline_rps": round(baseline_rps, 1),
            "cpu_utilization": cpu,
            "error_rate_5xx": error_rate,
            "latency_ms": latency,
            "url_entropy": url_entropy,
            "url_entropy_baseline": entropy_res["url_entropy_baseline"],
            "url_z_score": url_z,
            "ip_entropy": ip_entropy,
            "ip_entropy_baseline": entropy_res["ip_entropy_baseline"],
            "top_ip": top_ip,
            "top_ip_concentration_pct": top_ip_pct,
            "honeypot_hit_count": len(honeypot_hits),
            "verdict_reason": verdict_summary
        }
        self.current_verdict = result

        # 5. Persist Incident to Database (with cooldown)
        if classification in ["ATTACK", "FLASH_CROWD", "SUSPICIOUS"]:
            now = time.time()
            if now - self.last_incident_time > self.incident_cooldown_seconds:
                self.last_incident_time = now
                close_db = False
                if db is None:
                    db = SessionLocal()
                    close_db = True
                try:
                    incident = Incident(
                        classification=classification,
                        mitigation_tier=mitigation_engine.active_tier,
                        source_ip=top_ip,
                        requests_per_sec=rps,
                        baseline_rps=baseline_rps,
                        url_entropy=url_entropy,
                        ip_entropy=ip_entropy,
                        verdict_reason=verdict_summary,
                        is_active=True
                    )
                    db.add(incident)
                    db.commit()
                    logger.info(f"Recorded incident {classification} (Tier {mitigation_engine.active_tier})")
                except Exception as e:
                    logger.error(f"Failed to record incident: {e}")
                finally:
                    if close_db:
                        db.close()

        return result

# Global singleton detection engine
detection_engine = DetectionEngine()
