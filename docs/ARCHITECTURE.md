# CloudShield System Architecture

CloudShield is an automated monitoring and tiered mitigation system designed to detect and neutralize DDoS attacks while distinguishing them from legitimate flash crowds.

Based on the research framework by **Usman-Hamza et al. (June 2024)**, CloudShield extends basic load balancing and CPU-threshold failover into a **multi-signal, entropy-aware, tiered defense platform**.

---

## 1. High-Level Traffic & Data Flow

```
                                [ Client Traffic ]
               (Legitimate Users, HTTP Flooders, Decoy Scanners)
                                       │
                                       ▼
                       [ Ingress / Routing Layer ]
                      - Local: Docker Port 8080
                      - AWS: Route 53 (Low TTL = 30s)
                                       │
                                       ▼
                     [ Multi-Proxy Edge Tier (Nginx) ]
                     - Tier 1: limit_req & limit_conn
                     - Tier 2: Dynamic blocklist.conf include
                     - Stub Status & JSON Access Logs
                                       │
                                       ▼
                   [ Application Server Pool (FastAPI) ]
                     - backend-1 (172.28.0.11:8000)
                     - backend-2 (172.28.0.12:8000)
                     - In-Memory IP Filtering Middleware
                     - Honeypot Decoys (/admin-backup/, /wp-login.php)
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
      [ Prometheus Exporters ]                      [ Shared Persistence ]
      - node_exporter (:9100)                       - SQLite / PostgreSQL
      - nginx-exporter (:9113)                      - Incident History
      - Prometheus (:9090)                          - Cross-Node Blocklist
                 │
                 ▼
     [ CloudShield Detection Engine ]
     - EWMA Baseline Tracking
     - Shannon Source-IP Entropy
     - Shannon URL Entropy
     - Top-IP Concentration Metric
     - Verdict Classifier (NORMAL / SUSPICIOUS / ATTACK / FLASH_CROWD)
                 │
                 ▼
     [ Multi-Tier Mitigation Engine ]
     - Tier 1: Nginx Rate/Conn Limiting
     - Tier 2: Dynamic IP Blocklist & Fast-Path Drop
     - Tier 3: Upstream Horizontal Scale-Out
     - Tier 4: Route 53 DNS Failover (boto3)
     - Cooldown & Hysteresis Recovery State Machine
                 │
                 ▼
      [ React Dashboard & Admin UI ]
      - Live Telemetry Charts (Recharts)
      - "Why Was This Flagged?" Explanation Modal
      - Admin Control & Override Panel
```

---

## 2. Multi-Signal Detection Engine & Mathematics

Rather than relying on brittle, single-dimensional thresholds (e.g. CPU > 80%), CloudShield correlates multiple live signals:

### 1. Shannon Entropy Formulation
For a collection of $N$ observed requests in a sliding window (10s), the probability distribution of attribute $x$ (source IP or target URL) is:
$$p(x_i) = \frac{\text{count}(x_i)}{N}$$

The Shannon Entropy $H(X)$ is computed in bits:
$$H(X) = - \sum_{i=1}^{k} p(x_i) \log_2 p(x_i)$$

- **Source IP Entropy ($H_{IP}$)**: Measures distribution of clients.
  * Distributed attack (botnet) or flash crowd $\rightarrow$ high $H_{IP}$.
  * Single-IP or small botnet flood $\rightarrow$ low $H_{IP}$.
- **URL Entropy ($H_{URL}$)**: Measures diversity of requested resources.
  * Legitimate browsing / flash crowd $\rightarrow$ high $H_{URL}$ (users visit many URLs).
  * Targeted HTTP flood $\rightarrow$ low $H_{URL}$ (adversary hammers specific URI).

### 2. EWMA Baseline & Deviation ($z$-score)
CloudShield maintains Exponential Weighted Moving Averages (EWMA) updated during `NORMAL` traffic:
$$EWMA_t = \alpha \cdot X_t + (1 - \alpha) \cdot EWMA_{t-1} \quad (\alpha = 0.15)$$

Standard deviation and $z$-score measure statistically significant divergence:
$$z = \frac{|X_t - EWMA|}{\sigma}$$

### 3. Traffic Classification Matrix

| Traffic Type | RPS Surge | URL Entropy | Source IP Entropy | Top-IP Concentration | Honeypot Decoys | Verdict | Escalation Tier |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Normal Traffic** | $\le 1.8\times$ baseline | Baseline ($\pm 1.5\sigma$) | Baseline ($\pm 1.5\sigma$) | $\le 30\%$ | 0 hits | **NORMAL** | **NONE** (Recover) |
| **Moderate Surge** | $1.8\times - 3.5\times$ | Normal | Normal | $\le 45\%$ | 0 hits | **SUSPICIOUS** | **TIER 1** |
| **HTTP Flood DDoS** | $> 3.5\times$ baseline | Collapsed ($z > 2.0$) | Low / Moderate | $> 55\%$ | 0 hits | **ATTACK** | **TIER 2** |
| **Flash Crowd** | $> 3.5\times$ baseline | High / Diverse ($z \le 1.5$) | High / Diverse | $\le 30\%$ | 0 hits | **FLASH_CROWD** | **TIER 3** |
| **Adversary Recon** | Any volume | Any | Any | Any | $\ge 1$ hit | **ATTACK** | **TIER 2** (Instant) |

---

## 3. Tiered Mitigation Escalation & Hysteresis

To prevent flapping (rapid oscillation between blocked and unblocked states), CloudShield incorporates a strict **hysteresis recovery cycle**:

```
[ NONE ] ──(Moderate Surge)──> [ TIER 1 ] ──(Flood DDoS / Recon)──> [ TIER 2 ]
   ▲                               │                                    │
   │ (3 Normal Cycles)             │ (3 Normal Cycles)                  │ (Sustained Flood)
   └───────────────────────────────┴────────────────────────────────────┤
                                                                        ▼
[ TIER 4: DNS Failover ] <──(Proxy Saturated)── [ TIER 3: Scale Out ] <─┘
```

1. **Escalation**: Fast, proactive escalation when attack signals breach thresholds.
2. **De-escalation (Hysteresis)**: Requires $N = 3$ consecutive normal evaluation cycles (12 seconds) before stepping down to the preceding tier.
3. **Allowlist Invariant**: Local loopback, internal docker bridge (`172.28.0.0/16`), and health monitors are strictly protected from blocklisting.

---

## 4. Honeypot Decoys & Zero-Delay Tripwires

Decoy endpoints mimicking common web application paths are exposed:
- `/admin-backup/`: Administrative directory tripwire.
- `/wp-login.php`: Common CMS brute-force attack target.
- `/hidden-admin.html`: Hidden administrator portal.

An unauthorized request to any decoy immediately:
1. Returns HTTP 403 to the client.
2. Extracts the originating client IP from the `X-Forwarded-For` header.
3. Automatically appends the IP to `nginx/conf.d/blocklist.conf` and in-memory filter sets.
4. Records a high-confidence security incident in the database.
