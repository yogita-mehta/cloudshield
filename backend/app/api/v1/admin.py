from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

from app.services.entropy import entropy_engine
from app.services.mitigation import mitigation_engine
from app.services.detection import detection_engine

router = APIRouter()

class ConfigUpdateRequest(BaseModel):
    alpha: float = 0.15
    baseline_rps: float = 5.0
    recovery_cycles: int = 3

@router.get("/config", response_model=Dict[str, Any])
def get_system_config():
    """Retrieve configurable detection and mitigation parameters."""
    return {
        "alpha": entropy_engine.alpha,
        "ewma_rps": round(entropy_engine.ewma_rps, 2),
        "ewma_ip_entropy": round(entropy_engine.ewma_ip_entropy, 3),
        "ewma_url_entropy": round(entropy_engine.ewma_url_entropy, 3),
        "recovery_cycles_threshold": mitigation_engine.recovery_cycles_threshold,
        "incident_cooldown_seconds": detection_engine.incident_cooldown_seconds
    }

@router.post("/config", response_model=Dict[str, Any])
def update_system_config(req: ConfigUpdateRequest):
    """Update runtime detection and recovery parameters."""
    if 0.01 <= req.alpha <= 0.99:
        entropy_engine.alpha = req.alpha
    if req.baseline_rps > 0:
        entropy_engine.ewma_rps = req.baseline_rps
    if req.recovery_cycles >= 1:
        mitigation_engine.recovery_cycles_threshold = req.recovery_cycles

    return {
        "success": True,
        "config": get_system_config()
    }

@router.post("/reset", response_model=Dict[str, Any])
def reset_system():
    """Reset system to baseline, clear blocklist, and deactivate mitigation tiers."""
    mitigation_engine.active_tier = "NONE"
    mitigation_engine.blocked_ips.clear()
    mitigation_engine._sync_nginx_blocklist()
    
    detection_engine.current_state = "NORMAL"
    detection_engine.current_verdict = {}
    detection_engine.clear_simulation()
    
    entropy_engine.ewma_rps = 5.0
    entropy_engine.ewma_ip_entropy = 2.8
    entropy_engine.ewma_url_entropy = 2.5
    
    return {
        "success": True,
        "message": "CloudShield system successfully reset to baseline operational state."
    }
