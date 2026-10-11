# CloudShield — Phase 1: Local MVP Architecture & Verification

## 1. Overview
Phase 1 establishes the baseline containerized architecture for CloudShield:
- **Client Traffic Path**: Client → Nginx Reverse Proxy (`:8080`) → Upstream Application Server Pool (`backend-1:8000`, `backend-2:8000`).
- **Telemetry Scrape Path**: Prometheus (`:9090`) scrapes `/metrics` from backend instances every 5s.
- **Operator Interface**: React + Vite + Tailwind Dashboard (`:3000`) connecting to CloudShield API.
- **Persistence**: SQLite / SQLAlchemy database storing incident models and mitigation tiers.

## 2. Directory Structure
```
cloudshield/
├── backend/
│   ├── app/
│   │   ├── api/v1/         # Endpoints: health, incidents, sample app
│   │   ├── core/           # Settings & environment configuration
│   │   ├── db/             # SQLAlchemy engine & session dependency
│   │   ├── models/         # Database models (Incident)
│   │   ├── schemas/        # Pydantic schemas (Incident, Health)
│   │   └── main.py         # FastAPI application entrypoint & Prometheus metrics
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/     # Navbar, StatCard, StatusBadge, IncidentTable
│   │   ├── services/       # API client for CloudShield backend
│   │   ├── App.jsx         # Dashboard view with live health & verification panel
│   │   └── main.jsx
│   ├── Dockerfile
│   ├── package.json
│   └── vite.config.js
├── nginx/
│   ├── nginx.conf          # JSON access log format & core settings
│   └── conf.d/default.conf # Upstream pool definition & reverse proxy block
├── monitoring/
│   └── prometheus.yml      # 5s scrape interval config for backend pool
├── scripts/
│   ├── verify_phase1.py    # Automated end-to-end verification suite
│   └── test_traffic.py     # Safe lab traffic generator
├── tests/
│   └── test_backend.py     # Pytest unit tests for API endpoints
├── docker-compose.yml      # Multi-service composition
├── .env.example
├── .gitignore
└── README.md
```

## 3. Exposed Ports & Services
| Service | Container Port | Host Port | Role |
| :--- | :--- | :--- | :--- |
| **Nginx Proxy** | 80 | **8080** | Ingress reverse proxy & load balancer with JSON access logs |
| **Backend 1** | 8000 | Internal | Upstream pool node 1 (FastAPI app & metrics) |
| **Backend 2** | 8000 | Internal | Upstream pool node 2 (FastAPI app & metrics) |
| **Prometheus** | 9090 | **9090** | Time-series metrics engine (5s scrape interval) |
| **Frontend UI**| 80 | **3000** | Operator dashboard (React + Tailwind) |

## 4. Key Endpoints
- `GET http://localhost:8080/nginx-health` — Nginx internal health status
- `GET http://localhost:8080/health` — Top-level load-balancer health probe
- `GET http://localhost:8080/api/v1/health` — Detailed health check (app + DB status)
- `GET http://localhost:8080/api/v1/sample/hello` — Sample upstream app endpoint returning `served_by` node
- `GET http://localhost:8080/api/v1/incidents/` — Incident log retrieval
- `POST http://localhost:8080/api/v1/incidents/` — Record new incident
- `GET http://localhost:9090` — Prometheus Web UI & query console
- `GET http://localhost:3000` — CloudShield Web Dashboard
