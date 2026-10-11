from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.config import settings
from app.db.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    """Health check endpoint checking application and database status."""
    db_status = "connected"
    try:
        # Simple test query to verify DB connection
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unreachable: {str(e)}"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        server_node=settings.SERVER_NAME,
        environment=settings.ENVIRONMENT,
        database=db_status,
        details={
            "database_url_type": settings.DATABASE_URL.split(":")[0],
            "api_version": "v1"
        }
    )
