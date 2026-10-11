import time
from datetime import datetime
from fastapi import APIRouter, Request, Response, Depends, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from app.db.session import get_db
from app.models.incident import Incident
from app.services.mitigation import mitigation_engine

router = APIRouter()

# In-memory log of honeypot triggers
_honeypot_log: List[Dict[str, Any]] = []

def get_origin_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "127.0.0.1")

def record_honeypot_hit(request: Request, endpoint: str, db: Session):
    """Processes a honeypot trigger event."""
    client_ip = get_origin_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    timestamp = datetime.utcnow()

    hit_record = {
        "timestamp": timestamp.isoformat(),
        "ip": client_ip,
        "endpoint": endpoint,
        "user_agent": user_agent
    }
    _honeypot_log.append(hit_record)

    # 1. Trigger Tier 2 IP Blocklist
    blocked = mitigation_engine.block_ip(client_ip, reason=f"Accessed honeypot decoy '{endpoint}'")

    # 2. Record High-Confidence Incident in DB
    try:
        incident = Incident(
            classification="ATTACK",
            mitigation_tier="TIER_2",
            source_ip=client_ip,
            requests_per_sec=1.0,
            baseline_rps=5.0,
            url_entropy=0.0,
            ip_entropy=0.0,
            verdict_reason=f"High-confidence tripwire: Client accessed honeypot decoy endpoint '{endpoint}'. Auto-blocked in Tier 2.",
            is_active=True
        )
        db.add(incident)
        db.commit()
    except Exception as e:
        pass

    return client_ip

@router.get("/stats", response_model=Dict[str, Any])
@router.get("/status", response_model=Dict[str, Any])
def get_honeypot_status(db: Session = Depends(get_db)):
    """Returns all recorded honeypot hits from shared database."""
    db_hits = db.query(Incident).filter(Incident.verdict_reason.like("%honeypot%")).all()
    db_ips = {inc.source_ip for inc in db_hits if inc.source_ip}
    memory_ips = {h["ip"] for h in _honeypot_log}
    total_ips = db_ips.union(memory_ips)
    return {
        "total_hits": max(len(db_hits), len(_honeypot_log)),
        "trapped_ips": len(total_ips),
        "recent_hits": [
            {
                "timestamp": inc.timestamp.isoformat() if inc.timestamp else datetime.utcnow().isoformat(),
                "ip": inc.source_ip,
                "endpoint": "decoy",
                "user_agent": "scanner"
            }
            for inc in db_hits[-10:]
        ] if db_hits else _honeypot_log[-10:],
        "decoy_endpoints": ["/admin-backup/", "/wp-login.php", "/hidden-admin.html"]
    }

# Decoy 1: Admin Backup
@router.get("/admin-backup/", response_class=HTMLResponse)
def decoy_admin_backup(request: Request, db: Session = Depends(get_db)):
    record_honeypot_hit(request, "/admin-backup/", db)
    return HTMLResponse(
        content="<html><body><h1>403 Forbidden</h1><p>Access denied to administrative backup directory.</p></body></html>",
        status_code=403
    )

# Decoy 2: WordPress Login
@router.api_route("/wp-login.php", methods=["GET", "POST"], response_class=HTMLResponse)
def decoy_wp_login(request: Request, db: Session = Depends(get_db)):
    record_honeypot_hit(request, "/wp-login.php", db)
    return HTMLResponse(
        content="""
        <html>
        <head><title>WordPress &rsaquo; Log In</title></head>
        <body style="font-family:sans-serif; background:#f1f1f1; padding:50px; text-align:center;">
          <div style="background:#fff; max-width:350px; margin:auto; padding:25px; border-radius:5px; box-shadow:0 1px 3px rgba(0,0,0,0.13);">
            <h2>WordPress Admin</h2>
            <p style="color:#d63638; font-size:13px;">Error: Invalid login credentials.</p>
          </div>
        </body>
        </html>
        """,
        status_code=403
    )

# Decoy 3: Hidden Admin
@router.get("/hidden-admin.html", response_class=HTMLResponse)
def decoy_hidden_admin(request: Request, db: Session = Depends(get_db)):
    record_honeypot_hit(request, "/hidden-admin.html", db)
    return HTMLResponse(
        content="<html><body><h1>403 Access Denied</h1><p>Security violation logged.</p></body></html>",
        status_code=403
    )
