from fastapi import APIRouter
from app.api.v1 import (
    health,
    incidents,
    sample,
    monitoring,
    detection,
    mitigation,
    honeypot,
    auth,
    admin
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(sample.router, prefix="/sample", tags=["Sample Application"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring Telemetry"])
api_router.include_router(detection.router, prefix="/detection", tags=["Detection Engine"])
api_router.include_router(mitigation.router, prefix="/mitigation", tags=["Mitigation Engine"])
api_router.include_router(honeypot.router, prefix="/honeypot", tags=["Honeypot Decoys"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin & Controls"])
