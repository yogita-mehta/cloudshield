from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List

from app.services.mitigation import mitigation_engine

router = APIRouter()

class TierOverrideRequest(BaseModel):
    tier: str
    reason: str = "Manual operator intervention"

class IPActionRequest(BaseModel):
    ip: str
    reason: str = "Manual operator action"

@router.get("/status", response_model=Dict[str, Any])
def get_mitigation_status():
    """Retrieve active mitigation tier, blocked IP list, and history."""
    return mitigation_engine.get_status()

@router.post("/tier", response_model=Dict[str, Any])
def set_mitigation_tier(req: TierOverrideRequest):
    """Manually escalate or set the active mitigation tier."""
    valid_tiers = ["NONE", "TIER_1", "TIER_2", "TIER_3", "TIER_4"]
    tier_upper = req.tier.upper()
    if tier_upper not in valid_tiers:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Must be one of: {valid_tiers}")
    mitigation_engine.escalate_tier(tier_upper, reason=req.reason)
    return mitigation_engine.get_status()

@router.post("/block", response_model=Dict[str, Any])
def manual_block_ip(req: IPActionRequest):
    """Manually add an IP address to the blocklist."""
    blocked = mitigation_engine.block_ip(req.ip, reason=req.reason)
    return {
        "success": blocked,
        "ip": req.ip,
        "message": f"IP {req.ip} added to Tier 2 blocklist" if blocked else f"IP {req.ip} could not be blocked (protected or already blocked)",
        "mitigation_status": mitigation_engine.get_status()
    }

@router.post("/unblock", response_model=Dict[str, Any])
def manual_unblock_ip(req: IPActionRequest):
    """Manually remove an IP address from the blocklist."""
    unblocked = mitigation_engine.unblock_ip(req.ip)
    return {
        "success": unblocked,
        "ip": req.ip,
        "message": f"IP {req.ip} removed from blocklist" if unblocked else f"IP {req.ip} was not in blocklist",
        "mitigation_status": mitigation_engine.get_status()
    }
