from typing import Dict, Any
from pydantic import BaseModel

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    server_node: str
    environment: str
    database: str
    details: Dict[str, Any] = {}
