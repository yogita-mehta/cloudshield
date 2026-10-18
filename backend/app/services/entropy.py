import math
from collections import Counter
from typing import List, Dict, Tuple, Any

class EntropyEngine:
    """
    Shannon Entropy & EWMA Baseline Engine for CloudShield.
    Computes Shannon entropy H = -sum(p * log2(p)) for source IPs and URLs.
    Maintains Exponential Weighted Moving Average (EWMA) and computes absolute deviation.
    """
    def __init__(self, alpha: float = 0.15):
        self.alpha = alpha  # EWMA smoothing factor
        
        # Baselines (initialized to normal web browsing values)
        self.ewma_ip_entropy: float = 2.8
        self.ewma_url_entropy: float = 2.5
        self.ewma_rps: float = 5.0
        
        # Standard deviation estimates
        self.std_ip_entropy: float = 0.4
        self.std_url_entropy: float = 0.4
        self.std_rps: float = 2.0

    @staticmethod
    def calculate_shannon_entropy(elements: List[str]) -> float:
        """
        Calculates Shannon entropy: H = -sum(p_i * log2(p_i))
        Range: 0 (all elements identical) to log2(N) (maximum diversity).
        """
        if not elements:
            return 0.0
        total = len(elements)
        counts = Counter(elements)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def update_baselines(self, ip_entropy: float, url_entropy: float, rps: float, is_normal: bool = True):
        """Updates EWMA baselines only when traffic is classified as normal/healthy."""
        if is_normal and rps > 0:
            # Update IP entropy baseline with boundary clamping [1.0, 6.0]
            if ip_entropy > 0.5:
                raw_ip = (self.alpha * ip_entropy) + ((1 - self.alpha) * self.ewma_ip_entropy)
                self.ewma_ip_entropy = round(max(1.0, min(6.0, raw_ip)), 3)

            # Proposal B: Guard against baseline poisoning from single-endpoint probe or low-rate floods
            # Only update URL baseline if traffic demonstrates genuine multi-path diversity
            if url_entropy > 0.8:
                raw_url = (self.alpha * url_entropy) + ((1 - self.alpha) * self.ewma_url_entropy)
                self.ewma_url_entropy = round(max(1.5, min(4.0, raw_url)), 3)

            # Update RPS baseline with boundary clamping [1.0, 25.0]
            raw_rps = (self.alpha * rps) + ((1 - self.alpha) * self.ewma_rps)
            self.ewma_rps = round(max(1.0, min(25.0, raw_rps)), 1)

    def analyze_entropy(self, ips: List[str], urls: List[str]) -> Dict[str, Any]:
        """
        Calculates current entropy for IPs and URLs, compares against EWMA,
        and returns absolute deviation and z-scores.
        """
        current_ip_entropy = self.calculate_shannon_entropy(ips)
        current_url_entropy = self.calculate_shannon_entropy(urls)

        # Deviation from baseline
        ip_deviation = abs(current_ip_entropy - self.ewma_ip_entropy)
        url_deviation = abs(current_url_entropy - self.ewma_url_entropy)

        ip_z_score = round(ip_deviation / max(self.std_ip_entropy, 0.05), 2)
        url_z_score = round(url_deviation / max(self.std_url_entropy, 0.05), 2)

        # Directional drop deviation: positive only when entropy drops below baseline (collapse in URL diversity)
        url_drop_deviation = max(0.0, self.ewma_url_entropy - current_url_entropy)
        url_z_drop = round(url_drop_deviation / max(self.std_url_entropy, 0.05), 2)

        # Top IP concentration calculation
        top_ip_percentage = 0.0
        top_ip = None
        if ips:
            counts = Counter(ips).most_common(1)
            if counts:
                top_ip = counts[0][0]
                top_ip_percentage = round((counts[0][1] / len(ips)) * 100.0, 1)

        return {
            "ip_entropy": current_ip_entropy,
            "ip_entropy_baseline": round(self.ewma_ip_entropy, 3),
            "ip_deviation": round(ip_deviation, 3),
            "ip_z_score": ip_z_score,
            "url_entropy": current_url_entropy,
            "url_entropy_baseline": round(self.ewma_url_entropy, 3),
            "url_deviation": round(url_deviation, 3),
            "url_z_score": url_z_score,
            "url_z_drop": url_z_drop,
            "top_ip": top_ip,
            "top_ip_concentration_pct": top_ip_percentage
        }

# Global singleton engine
entropy_engine = EntropyEngine()
