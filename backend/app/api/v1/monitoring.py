from fastapi import APIRouter
from typing import Dict, Any, List
from app.services.monitoring import get_current_metrics, get_metrics_history, query_prometheus

router = APIRouter()

@router.get("/metrics", response_model=Dict[str, Any])
async def get_metrics():
    """Retrieve real-time telemetry metrics snapshot."""
    return await get_current_metrics()

@router.get("/history", response_model=List[Dict[str, Any]])
def get_history():
    """Retrieve time-series telemetry history for charting."""
    return get_metrics_history()

@router.get("/exporters")
async def check_exporters():
    """Check health of Prometheus exporter targets."""
    node_up = await query_prometheus("up{job='node-exporter'}")
    nginx_up = await query_prometheus("up{job='nginx-exporter'}")
    backend_up = await query_prometheus("count(up{job='cloudshield-backends'} == 1)")
    return {
        "node_exporter": "healthy" if node_up == 1.0 else "pending",
        "nginx_exporter": "healthy" if nginx_up == 1.0 else "pending",
        "active_backends": int(backend_up)
    }
