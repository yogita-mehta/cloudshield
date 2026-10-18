import os
from datetime import datetime
from fastapi import APIRouter, Request
from app.core.config import settings

from app.core.proxy import get_origin_ip

router = APIRouter()

# Local request counter to demonstrate load distribution
_counter = 0

@router.get("/hello")
def sample_hello(request: Request):
    """Sample public endpoint behind Nginx load balancer to test upstream distribution."""
    global _counter
    _counter += 1
    
    client_ip = get_origin_ip(request)
    
    return {
        "message": "Hello from CloudShield upstream application pool!",
        "served_by": settings.SERVER_NAME,
        "instance_id": os.getenv("HOSTNAME", "unknown"),
        "request_number": _counter,
        "client_ip": client_ip,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "success"
    }

@router.get("/info")
def sample_info():
    """Returns metadata about the node running this application instance."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "server_node": settings.SERVER_NAME,
        "environment": settings.ENVIRONMENT,
        "hostname": os.getenv("HOSTNAME", "unknown"),
        "timestamp": datetime.utcnow().isoformat()
    }
