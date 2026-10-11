from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class IncidentBase(BaseModel):
    classification: str = "NORMAL"
    mitigation_tier: str = "NONE"
    source_ip: Optional[str] = None
    requests_per_sec: float = 0.0
    baseline_rps: float = 0.0
    url_entropy: float = 0.0
    ip_entropy: float = 0.0
    verdict_reason: Optional[str] = None
    is_active: bool = True

class IncidentCreate(IncidentBase):
    pass

class IncidentResponse(IncidentBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
