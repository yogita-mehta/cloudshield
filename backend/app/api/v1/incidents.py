from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.incident import Incident
from app.schemas.incident import IncidentCreate, IncidentResponse

router = APIRouter()

@router.get("/", response_model=List[IncidentResponse])
def get_incidents(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieve list of incidents ordered by most recent."""
    incidents = (
        db.query(Incident)
        .order_by(Incident.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return incidents

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db)
):
    """Record a new security / DDoS incident."""
    incident = Incident(**incident_in.model_dump())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """Retrieve a single incident by ID."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
def resolve_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """Mark an incident as resolved/inactive."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.is_active = False
    db.commit()
    db.refresh(incident)
    return incident
