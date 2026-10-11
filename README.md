# CloudShield — Load-Balancing-Based DDoS Mitigation for Cloud Environments

> **College Capstone Project**  
> Based on the research paper: *Load Balancing Based DDoS Mitigation for Cloud Environments* (Usman-Hamza et al., June 2024).

CloudShield is an automated monitoring and multi-tiered mitigation system designed to detect, classify, and neutralize DDoS attacks in cloud and containerized environments. By combining **Shannon Entropy analysis**, **EWMA baseline deviation**, and **honeypot tripwires**, CloudShield accurately differentiates malicious HTTP floods from legitimate viral flash crowds.

---

## Architecture Overview

```
Client Traffic ──> Route 53 (Low TTL 30s) / Local Port 8080
                         │
                         ▼
             [ Nginx Edge Proxy Tier ]
             - Tier 1: limit_req & limit_conn
             - Tier 2: Dynamic blocklist.conf include
             - Prometheus Stub Status & JSON Logs
                         │
                         ▼
         [ Application Server Pool (FastAPI) ]
         - backend-1 (172.28.0.11:8000)
         - backend-2 (172.28.0.12:8000)
         - Shared SQLite Database (/app/data/cloudshield.db)
         - Honeypot Decoys (/admin-backup/, /wp-login.php)
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
[ Prometheus Engine ]           [ CloudShield Detection & Mitigation ]
- node_exporter (:9100)         - Shannon Entropy (IP & URL)
- nginx-exporter (:9113)        - EWMA Baseline & z-Score Tracking
- Prometheus (:9090)            - 4-Tier Escalation & Hysteresis
                                - Boto3 Route53 DNS Failover
```

---

## Features Across All 9 Phases

1. **Phase 1 — Local MVP**: Docker Compose bridge network (`172.28.0.0/16`) running multi-node FastAPI upstream pool behind Nginx reverse proxy with JSON access logging and shared SQLite persistence.
2. **Phase 2 — Monitoring**: Prometheus scraping `node_exporter`, `nginx-prometheus-exporter`, and FastAPI metrics. Live telemetry API for requests/sec, CPU %, active connections, latency, and 5xx error rate.
3. **Phase 3 — Detection Engine**: Multi-signal classification into `NORMAL`, `SUSPICIOUS`, `ATTACK`, and `FLASH_CROWD`. Real-time Shannon Entropy ($H = -\sum p_i \log_2 p_i$) for source IPs and URLs with EWMA baseline tracking.
4. **Phase 4 — Mitigation Engine**: Escalation state machine across Tier 1 (Rate/Conn limit), Tier 2 (IP blocklist & Nginx deny include), Tier 3 (Scale out), and Tier 4 (DNS failover) with 3-cycle hysteresis recovery and allowlist protection.
5. **Phase 5 — Honeypot Decoys**: Realistic decoy tripwires at `/admin-backup/`, `/wp-login.php`, and `/hidden-admin.html` with instant Tier 2 IP trapping.
6. **Phase 6 — "Why Was This Flagged?" Panel**: Forensic explanation modal displaying exact signal values, baseline comparisons, entropy values, and verdict rationales.
7. **Phase 7 — Admin / Control Panel**: Token authentication (`admin` / `cloudshield2026`), manual tier overrides, threshold tuning, and blocklist unblock controls.
8. **Phase 8 — AWS / Terraform**: Infrastructure as Code for Multi-AZ VPC, active-active Nginx proxies, Auto-Scaling backend pool, low-TTL Route53 failover DNS routing, and `boto3` cloud orchestration with graceful local fallback.
9. **Phase 9 — Evaluation & Testing**: Complete simulation scripts (`simulate_normal.py`, `simulate_attack.py`, `simulate_flash_crowd.py`, `simulate_honeypot.py`) and benchmarking harness (`evaluate_scenarios.py`) with ablation studies.

---

## Repository Structure

```
cloudshield/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Health, Auth, Admin, Detection, Monitoring, Honeypot, Incidents
│   │   ├── core/            # Config, Boto3 AWS client & DNS failover manager
│   │   ├── db/              # SQLAlchemy session & SQLite database setup
│   │   ├── models/          # Incident ORM schema
│   │   ├── schemas/         # Pydantic request/response models
│   │   ├── services/        # Entropy, Detection, Mitigation, Monitoring services
│   │   └── main.py          # FastAPI application, middleware, lifecycle loop
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # TelemetryCharts, WhyFlaggedModal, AdminPanel
│   │   ├── App.jsx          # Dashboard layout & live polling
│   │   └── index.css        # Tailwind CSS styles
│   ├── package.json
│   └── vite.config.js
├── nginx/
│   ├── nginx.conf           # JSON log formatting & connection buffers
│   └── conf.d/
│       ├── default.conf     # Upstream pooling, rate limiting, and honeypot routes
│       └── blocklist.conf   # Dynamic deny directives managed by CloudShield
├── monitoring/
│   └── prometheus.yml       # Scrape configs for backends, nginx-exporter, node-exporter
├── terraform/
│   ├── providers.tf         # AWS provider (>= 5.30)
│   ├── variables.tf         # Multi-AZ VPC, subnets, EC2 types, domain configuration
│   ├── main.tf              # VPC, Security Groups, IAM Roles, Proxies, ASG, Route53
│   ├── outputs.tf           # Provisioned IPs, DNS records, zone IDs
│   ├── terraform.tfvars.example
│   └── user_data/           # Cloud-init scripts for Nginx and Backend nodes
├── scripts/
│   ├── simulate_normal.py   # Legitimate user traffic simulation
│   ├── simulate_attack.py   # High-concurrency safe HTTP flood simulation
│   ├── simulate_flash_crowd.py # High-volume legitimate surge with high URL entropy
│   ├── simulate_honeypot.py # Probes honeypot decoys and verifies auto-block
│   ├── evaluate_scenarios.py # Benchmarking harness (baselines & ablation)
│   └── verify_phases.py    # Automated end-to-end multi-service test suite
├── tests/
│   └── test_backend.py      # Pytest unit & integration tests (10/10 passing)
├── docs/
│   ├── ARCHITECTURE.md      # System architecture and mathematical formulas
│   ├── AWS_DEPLOYMENT.md    # Complete AWS deployment guide
│   ├── EVALUATION_RESULTS.md # Comparative benchmark tables and findings
│   └── EVALUATION_RESULTS.json # Raw benchmark metric data
├── docker-compose.yml       # Multi-service local orchestration
└── README.md
```

---

## How to Run the Project

### 1. Prerequisites
- Docker & Docker Compose
- Python 3.10+ (for local test scripts)

### 2. Start all containers
```bash
docker compose up -d
```

### 3. Verify container status
```bash
docker compose ps
```
All 7 services will be running:
- `cloudshield-frontend` (`http://localhost:3000`)
- `cloudshield-nginx` (`http://localhost:8080`)
- `cloudshield-backend-1` (`172.28.0.11:8000`)
- `cloudshield-backend-2` (`172.28.0.12:8000`)
- `cloudshield-prometheus` (`http://localhost:9090`)
- `cloudshield-node-exporter` (`http://localhost:9100`)
- `cloudshield-nginx-exporter` (`http://localhost:9113`)

---

## Running Verification and Test Suites

### 1. End-to-End System Verification (Phases 1-7)
```bash
python scripts/verify_phases.py
```
*Result: 8/8 tests passed (100.0%) across health, load balancing, metrics, detection, entropy, honeypot, auth, and frontend.*

### 2. Pytest Unit & Integration Suite
```bash
docker exec cloudshield-backend-1 pytest -v /app/test_backend.py
```
*Result: 10/10 passed (100.0%) covering entropy math, tier escalation, hysteresis, tripwires, admin auth, and AWS simulation.*

---

## How to Demonstrate DDoS Mitigation Safely

All attack simulations are strictly contained within your local loopback infrastructure (`http://localhost:8080`).

### Demo 1: Honeypot Decoy Trapping (Instant Tier 2)
```bash
python scripts/simulate_honeypot.py
```
1. Attacker IP `203.0.113.199` probes decoy `/admin-backup/`.
2. CloudShield returns `403 Forbidden` and records a high-confidence tripwire.
3. CloudShield automatically appends `deny 203.0.113.199;` to `nginx/conf.d/blocklist.conf`.
4. Subsequent requests to benign endpoints (`/api/v1/sample/hello`) from that IP are blocked with `403 Access Denied`.

### Demo 2: HTTP Flood Attack Mitigation
```bash
python scripts/simulate_attack.py --duration 10 --concurrency 25
```
- Sends a surge targeting a single URL.
- Detection engine detects low URL entropy ($z > 2.0$) and high RPS surge.
- Escalates to **Tier 1** (Nginx rate limiting returns `503 Service Temporarily Unavailable`) and **Tier 2** (top-offender IP blocklist).

### Demo 3: Flash Crowd Differentiation
```bash
python scripts/simulate_flash_crowd.py --duration 10 --concurrency 20
```
- Sends high aggregate request volume across diverse endpoints with distributed simulated IPs.
- Detection engine measures healthy URL entropy and balanced IP concentration.
- Classifies traffic as `FLASH_CROWD` and escalates to **Tier 3** (horizontal scale-out) **without blocking legitimate users**.

### Demo 4: "Why Was This Flagged?" Modal & Admin Controls
1. Open the Dashboard: [http://localhost:3000](http://localhost:3000).
2. Click on any incident row or click **Why was this flagged?** to inspect signal comparison bars.
3. Open **Admin Panel** and sign in:
   - **Username**: `admin`
   - **Password**: `cloudshield2026`
4. Test manual tier overrides, unblock IPs, or adjust EWMA sensitivity.

---

## Evaluation Benchmark Results

Comprehensive benchmarking via `scripts/evaluate_scenarios.py`:

| Architectural Posture | Detection Time (s) | Mitigation Time (s) | Client Availability (%) | 5xx Error Rate (%) | Flash Crowd FP Rate (%) |
|:----------------------|:------------------:|:-------------------:|:-----------------------:|:------------------:|:-----------------------:|
| **Scenario A: No Protection** | N/A | N/A | 24.5% | 75.5% | 0.0% |
| **Scenario B: Usman-Hamza et al. (CPU+DNS)** | 12.4s | 38.6s | 68.2% | 31.8% | 74.0% |
| **Scenario C: CloudShield Multi-Signal** | **2.8s** | **3.6s** | **96.8%** | **3.2%** | **1.2%** |

### Key Improvements:
- **82.7% faster detection** than single-signal CPU threshold approaches.
- **90.7% faster mitigation** by acting at the local Nginx tier rather than waiting for 30–60s DNS TTL propagation.
- **72.8% reduction in false positives** on viral flash crowds via Shannon Entropy analysis.

---

## AWS Deployment & Manual Setup Requirements

The Terraform configuration in `terraform/` provisions:
- Multi-AZ VPC with public and private subnets.
- 2x Active-Active Nginx reverse proxies with low-TTL (30s) Route53 failover routing policy.
- Auto Scaling Group for the backend application server pool.
- IAM Instance Profile with least-privilege policies (zero hardcoded secrets).

### What Requires Manual Setup on AWS:
1. **AWS Credentials**: Run `aws configure` on your workstation or attach an IAM role before running `terraform apply`.
2. **Domain Registration**: If using a public domain, update your domain registrar's NS records to point to Route53's assigned nameservers.
3. **AWS Account Limits**: Ensure your AWS account quota allows at least 4 EC2 instances and 1 Elastic IP in the selected region.

---

## System Limitations & Non-Automatable Items

1. **Carrier-Grade Volumetric DDoS (Layer 3/4)**: CloudShield operates at Layer 7 (HTTP/HTTPS application layer). Terabit-scale SYN floods or UDP amplification floods must be mitigated by cloud provider edge infrastructure (e.g. AWS Shield / Cloudflare) before reaching the EC2/VPC boundary.
2. **Client DNS Resolver Caching**: Although Route53 TTL is configured to 30s, non-compliant recursive DNS resolvers that ignore low TTLs may delay client redirection during Tier 4 DNS failover.
3. **IP Spoofing over TCP**: In a local lab environment using HTTP headers (`X-Forwarded-For`), client IPs can be simulated. In live internet environments, Layer 7 proxies evaluate the true TCP socket remote IP (`$remote_addr`).
