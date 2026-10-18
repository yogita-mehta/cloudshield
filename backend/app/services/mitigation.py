import os
import time
import logging
from typing import Set, Dict, Any, List, Optional

logger = logging.getLogger("cloudshield.mitigation")

BLOCKLIST_FILE = os.getenv("NGINX_BLOCKLIST_PATH", "/app/nginx_conf/blocklist.conf")

# Default protected allowlist (loopback, internal service nodes, monitoring probes)
DEFAULT_ALLOWLIST: Set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "172.28.0.10",
    "172.28.0.20",
    "172.28.0.21",
    "172.28.0.22",
    "172.28.0.30"
}

class MitigationEngine:
    """
    Tiered Escalation & Recovery Engine for CloudShield:
    - Tier 1: Nginx Rate Limiting & Connection Limiting
    - Tier 2: IP Blocklist (Nginx deny include + in-memory firewall)
    - Tier 3: Upstream Scale-Out
    - Tier 4: Proxy / DNS Failover
    Includes Cooldown, Hysteresis, and Automatic Recovery.
    """
    def __init__(self):
        self.active_tier: str = "NONE"  # NONE, TIER_1, TIER_2, TIER_3, TIER_4
        self.blocked_ips: Set[str] = set()
        self.allowlist: Set[str] = set(DEFAULT_ALLOWLIST)
        self.tier_activated_time: float = 0.0
        self.normal_cycles_count: int = 0
        self.recovery_cycles_threshold: int = 3  # Requires 3 consecutive normal cycles to recover
        self.tier_history: List[Dict[str, Any]] = []

        # Load existing blocklist from disk if available
        self._load_blocklist_from_disk()

    def _load_blocklist_from_disk(self):
        """Reads existing deny directives from blocklist.conf."""
        if os.path.exists(BLOCKLIST_FILE):
            try:
                mtime = os.path.getmtime(BLOCKLIST_FILE)
                if mtime > getattr(self, "_blocklist_mtime", 0.0):
                    self._blocklist_mtime = mtime
                    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("deny ") and line.endswith(";"):
                                ip = line[5:-1].strip()
                                if ip and ip not in self.allowlist:
                                    self.blocked_ips.add(ip)
            except Exception as e:
                logger.error(f"Error loading blocklist: {e}")

    def _sync_nginx_blocklist(self):
        """Writes Nginx deny directives to blocklist.conf."""
        try:
            os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
            with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
                f.write("# CloudShield Tier 2 Automated IP Blocklist\n")
                f.write(f"# Updated at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
                for ip in sorted(self.blocked_ips):
                    f.write(f"deny {ip};\n")
            self._blocklist_mtime = os.path.getmtime(BLOCKLIST_FILE)
            logger.info(f"Synchronized {len(self.blocked_ips)} IPs to Nginx blocklist.conf")
        except Exception as e:
            logger.error(f"Failed to write blocklist.conf: {e}")

    def is_ip_blocked(self, ip: str) -> bool:
        """Checks if an IP is currently blocked (and not allowlisted)."""
        if not ip or ip in self.allowlist:
            return False
        if ip in self.blocked_ips:
            return True
        # Check shared persistent disk blocklist for cross-node synchronization
        self._load_blocklist_from_disk()
        return ip in self.blocked_ips

    def block_ip(self, ip: str, reason: str = "Attack behavior detected") -> bool:
        """
        Adds an IP to the blocklist and triggers Tier 2 defense.
        Returns True if newly blocked, False if already blocked or allowlisted.
        """
        if not ip or ip in self.allowlist:
            logger.info(f"IP {ip} is protected by allowlist; block ignored.")
            return False

        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self._sync_nginx_blocklist()
            self.escalate_tier("TIER_2", reason=f"Blocked offending IP {ip}: {reason}")
            logger.warning(f"[TIER 2] Blocked IP {ip} ({reason})")
            return True
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Removes an IP from the blocklist."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self._sync_nginx_blocklist()
            logger.info(f"Unblocked IP {ip}")
            return True
        return False

    def escalate_tier(self, target_tier: str, reason: str):
        """
        Escalates or changes mitigation tier with timestamp recording.
        """
        tiers_order = ["NONE", "TIER_1", "TIER_2", "TIER_3", "TIER_4"]
        current_idx = tiers_order.index(self.active_tier) if self.active_tier in tiers_order else 0
        target_idx = tiers_order.index(target_tier) if target_tier in tiers_order else 0

        # Escalate if higher tier or explicit override
        if target_idx > current_idx or target_tier != self.active_tier:
            old_tier = self.active_tier
            self.active_tier = target_tier
            self.tier_activated_time = time.time()
            self.normal_cycles_count = 0  # Reset recovery counter
            
            event = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                "from_tier": old_tier,
                "to_tier": target_tier,
                "reason": reason
            }
            self.tier_history.append(event)
            logger.warning(f"Mitigation Escalation: {old_tier} -> {target_tier} ({reason})")

            # AWS Infrastructure Orchestration
            try:
                from app.core.aws_client import aws_manager
                if target_tier == "TIER_3":
                    aws_manager.scale_out_backend_pool(desired_capacity=4)
                elif target_tier == "TIER_4":
                    aws_manager.trigger_route53_failover(reason=reason)
            except Exception as e:
                logger.error(f"Error invoking AWS integration: {e}")

    def evaluate_cooldown(self, current_classification: str) -> Optional[str]:
        """
        Cooldown & Hysteresis:
        If traffic has returned to NORMAL for at least N cycles, automatically
        de-escalates tiers until recovery back to NONE.
        """
        if self.active_tier == "NONE":
            self.normal_cycles_count = 0
            return None

        if current_classification == "NORMAL":
            self.normal_cycles_count += 1
            if self.normal_cycles_count >= self.recovery_cycles_threshold:
                # De-escalate tier step by step
                tiers_order = ["NONE", "TIER_1", "TIER_2", "TIER_3", "TIER_4"]
                current_idx = tiers_order.index(self.active_tier)
                next_tier = tiers_order[max(0, current_idx - 1)]
                
                old_tier = self.active_tier
                self.active_tier = next_tier
                self.normal_cycles_count = 0  # Reset for next step
                
                reason = f"Hysteresis Recovery: Traffic normal for {self.recovery_cycles_threshold} cycles."
                self.tier_history.append({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                    "from_tier": old_tier,
                    "to_tier": next_tier,
                    "reason": reason
                })
                logger.info(f"Mitigation Recovery: {old_tier} -> {next_tier}")

                # If recovering from Tier 4, restore Route53 Primary DNS routing
                if old_tier == "TIER_4" and next_tier != "TIER_4":
                    try:
                        from app.core.aws_client import aws_manager
                        aws_manager.restore_route53_primary(reason=reason)
                    except Exception as e:
                        logger.error(f"Error restoring Route53 primary DNS: {e}")

                return next_tier
        else:
            self.normal_cycles_count = 0

        return None

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive mitigation system status."""
        from app.core.aws_client import aws_manager
        return {
            "active_tier": self.active_tier,
            "blocked_ip_count": len(self.blocked_ips),
            "blocked_ips": sorted(list(self.blocked_ips)),
            "allowlist": sorted(list(self.allowlist)),
            "tier_history": self.tier_history[-10:],
            "recovery_cycles_consecutive": self.normal_cycles_count,
            "recovery_threshold": self.recovery_cycles_threshold,
            "aws_integration": aws_manager.get_status()
        }

# Global singleton mitigation engine
mitigation_engine = MitigationEngine()
