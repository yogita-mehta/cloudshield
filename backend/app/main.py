import time
import json
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.core.config import settings
from app.db.session import engine, Base
# Import models to ensure they are registered with Base.metadata
from app.models.incident import Incident
from app.api.v1.router import api_router
from app.services.detection import detection_engine
from app.services.mitigation import mitigation_engine

# Prometheus Metrics
REQUEST_COUNT = Counter(
    "cloudshield_http_requests_total",
    "Total HTTP requests handled by CloudShield backend",
    ["method", "endpoint", "status_code", "server_node"]
)
REQUEST_LATENCY = Histogram(
    "cloudshield_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"]
)

async def run_detection_loop():
    """Background continuous evaluation loop."""
    await asyncio.sleep(3.0)  # Initial grace period
    while True:
        try:
            await detection_engine.evaluate_traffic()
        except Exception:
            pass
        await asyncio.sleep(4.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create DB tables if they do not exist
    Base.metadata.create_all(bind=engine)
    # Start continuous background detection loop
    detection_task = asyncio.create_task(run_detection_loop())
    yield
    detection_task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CloudShield: Load-Balancing-Based DDoS Mitigation System Backend",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Instrumentation & Tier 2 IP Firewall Middleware
from app.core.proxy import get_origin_ip

@app.middleware("http")
async def monitor_and_filter_requests(request: Request, call_next):
    # 1. Tier 2 IP Blocklist Filter
    client_ip = get_origin_ip(request)
    if mitigation_engine.is_ip_blocked(client_ip):
        return Response(
            content=json.dumps({
                "detail": "Access Denied: IP blocked by CloudShield Tier 2 automated mitigation",
                "ip": client_ip,
                "mitigation_tier": "TIER_2"
            }),
            status_code=403,
            media_type="application/json"
        )

    # 2. Timing & Metrics
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    # Record metrics
    endpoint = request.url.path
    status_code = str(response.status_code)
    
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=endpoint,
        status_code=status_code,
        server_node=settings.SERVER_NAME
    ).inc()
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=endpoint
    ).observe(duration)
    
    # Attach tracking headers
    response.headers["X-Backend-Node"] = settings.SERVER_NAME
    response.headers["X-Mitigation-Tier"] = mitigation_engine.active_tier
    return response

# Prometheus scraping endpoint
@app.get("/metrics", tags=["Monitoring"])
def metrics():
    """Prometheus metrics scrape target."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Root-level health endpoint (useful for load balancers)
@app.get("/health", tags=["Health"])
def root_health():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "server_node": settings.SERVER_NAME,
        "mitigation_tier": mitigation_engine.active_tier
    }

# Root-level application endpoint
@app.get("/", tags=["Health"])
def root():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "server_node": settings.SERVER_NAME,
        "mitigation_tier": mitigation_engine.active_tier
    }

# Include API v1 routers
app.include_router(api_router, prefix=settings.API_V1_STR)

# Phase 5: Honeypot Decoys mounted at root level for direct interception
from app.api.v1.honeypot import decoy_admin_backup, decoy_wp_login, decoy_hidden_admin
app.add_api_route("/admin-backup/", decoy_admin_backup, methods=["GET", "POST"])
app.add_api_route("/wp-login.php", decoy_wp_login, methods=["GET", "POST"])
app.add_api_route("/hidden-admin.html", decoy_hidden_admin, methods=["GET"])

