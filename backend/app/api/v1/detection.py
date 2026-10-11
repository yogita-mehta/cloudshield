from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.db.session import get_db
from app.services.detection import detection_engine
from app.services.entropy import entropy_engine

router = APIRouter()

@router.get("/status", response_model=Dict[str, Any])
async def get_detection_status():
    """Retrieve current classification state and signal values."""
    if not detection_engine.current_verdict:
        # Run an initial evaluation if none exists
        return await detection_engine.evaluate_traffic()
    return detection_engine.current_verdict

@router.post("/evaluate", response_model=Dict[str, Any])
async def trigger_evaluation(db: Session = Depends(get_db)):
    """Triggers an immediate evaluation cycle."""
    return await detection_engine.evaluate_traffic(db=db)

@router.get("/entropy", response_model=Dict[str, Any])
def get_entropy_details():
    """Retrieve current entropy state and EWMA baselines."""
    return {
        "ewma_ip_entropy": entropy_engine.ewma_ip_entropy,
        "ewma_url_entropy": entropy_engine.ewma_url_entropy,
        "ewma_rps": entropy_engine.ewma_rps,
        "alpha": entropy_engine.alpha
    }
