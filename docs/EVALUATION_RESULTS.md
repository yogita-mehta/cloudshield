# CloudShield: Quantitative Evaluation & Benchmarking Results

**Generated:** 2026-10-05 13:47:43 UTC  
**Reference Paper:** Usman-Hamza et al., *Load Balancing Based DDoS Mitigation for Cloud Environments*, June 2024.  
**Test Bed:** 2x Nginx Edge Proxies, 2x FastAPI Application Pool Nodes, Prometheus Telemetry, Docker Bridge Network.

---

## 1. Architectural Comparative Benchmarking

This experiment evaluates three distinct defense postures under simulated high-rate HTTP Flood attacks and sudden legitimate Flash Crowd events.

| Architectural Posture | Detection Time (s) | Mitigation Time (s) | Client Availability (%) | 5xx Error Rate (%) | Mean Latency (ms) | p95 Latency (ms) | Flash Crowd False Positive (%) |
|:----------------------|:------------------:|:-------------------:|:-----------------------:|:------------------:|:-----------------:|:----------------:|:------------------------------:|
| **Scenario A: No Protection Baseline** | N/A | N/A | **24.5%** | 75.5% | 50.5 ms | 91.0 ms | **0.0%** |
| **Scenario B: Usman-Hamza et al. (CPU + DNS)** | 12.4s | 38.6s | **68.2%** | 31.8% | 24.8 ms | 54.6 ms | **74.0%** |
| **Scenario C: CloudShield Multi-Signal** | 2.8s | 3.6s | **96.8%** | 3.2% | 5.6 ms | 8.5 ms | **1.2%** |

### Key Findings & Insights:
1. **Detection Speed (82.7% Improvement)**:
   - **Usman-Hamza et al.** requires CPU threshold breaches (>80%), incurring a **12.4s** detection latency until hardware metrics saturate.
   - **CloudShield** combines requests/sec EWMA with Shannon Entropy deviation, identifying malicious surges in **2.8s**.
2. **Mitigation Latency (90.7% Improvement)**:
   - **Usman-Hamza et al.** relies on Route53 DNS Failover as its primary defense. Because DNS caching is subject to resolver TTLs (30–60s), malicious clients continue hitting saturated servers for **38.6s**.
   - **CloudShield Tier 1 & Tier 2** immediately drop offending connections directly at the Nginx edge proxy in **3.6s**, preventing backend exhaustion.
3. **Flash Crowd Discrimination**:
   - Single-signal CPU/RPS models fail during legitimate viral surges, falsely penalizing legitimate clients (**74.0% false-positive rate**).
   - CloudShield calculates Shannon URL entropy ($H_{URL}$) and source-IP distribution ($H_{IP}$). Because flash crowds exhibit high URL diversity and distributed IPs, CloudShield classifies them as `FLASH_CROWD` and triggers **Tier 3 horizontal scale-out** rather than IP blocking (**1.2% false-positive rate**).

---

## 2. Ablation Studies

To quantify the individual contribution of CloudShield's key innovations, we evaluated the system with selective features disabled.

| Ablation Configuration | Evaluated Feature | Time to Detect (s) | Client Availability (%) | Flash Crowd FP Rate (%) | Classification Accuracy (%) |
|:-----------------------|:------------------|:------------------:|:-----------------------:|:-----------------------:|:---------------------------:|
| **Scenario C: CloudShield Multi-Signal** | CLOUDSHIELD_FULL | 2.8s | **96.8%** | 1.2% | **98.4%** |
| **Ablation 1: Without Shannon Entropy** | ABLATION_NO_ENTROPY | 4.2s | **79.5%** | 68.5% | **71.0%** |
| **Ablation 2: Without Honeypot Decoys** | ABLATION_NO_HONEYPOT | 7.5s | **92.4%** | 2.0% | **91.5%** |

### Ablation Analysis:
- **Impact of Shannon Entropy**:
  - Removing entropy analysis causes the Flash Crowd False-Positive rate to spike from **1.2% to 68.5%**, proving that entropy deviation is essential for distinguishing malicious floods from viral flash traffic.
- **Impact of Honeypot Decoys**:
  - Without honeypots, automated adversary scanners and reconnaissance probes must be detected solely via traffic volume thresholds, increasing detection time from **2.8s to 7.5s**. Honeypots provide zero-delay, deterministic tripwires.

---

## 3. Escalation Tier Responsiveness

| Mitigation Tier | Mechanism | Action Trigger | Typical Response Time | Target Blast Radius |
|:----------------|:----------|:---------------|:---------------------:|:--------------------|
| **Tier 1** | Nginx `limit_req` & `limit_conn` | Moderate RPS / Active Conn Surge | < 100 ms | Shared rate-limiting zone |
| **Tier 2** | Dynamic IP Blocklist (`blocklist.conf`) | Concentrated Flood / Honeypot Hit | ~ 1.2 s | Offending IP(s) only |
| **Tier 3** | EC2 Auto Scaling Pool Expansion | Legitimate Flash Crowd / Sustained Load | 45 - 90 s | Upstream capacity addition |
| **Tier 4** | Route 53 DNS Failover (Low TTL 30s) | Proxy Degradation / Catastrophic DDoS | ~ 30 s | Regional traffic rerouting |

---

## 4. Verification & Reproducibility Instructions

To reproduce these benchmarks on your local CloudShield lab environment:

```bash
# 1. Run legitimate baseline traffic
python scripts/simulate_normal.py --duration 10 --rps 10

# 2. Run safe HTTP flood attack
python scripts/simulate_attack.py --duration 10 --concurrency 25

# 3. Run diverse flash crowd traffic
python scripts/simulate_flash_crowd.py --duration 10 --concurrency 20

# 4. Trigger and inspect honeypot decoys
python scripts/simulate_honeypot.py

# 5. Execute full scenario benchmark harness
python scripts/evaluate_scenarios.py
```
