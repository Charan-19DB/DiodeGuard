"""Threats Router — returns classified alerts grouped as threats"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.rbac import require_analyst_or_admin
from app.models.models import Alert, User
from app.schemas.schemas import AlertOut

router = APIRouter()


@router.get("/", response_model=List[AlertOut])
def list_threats(
    threat_class: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    """List all detected threats (high-confidence alerts only ≥ 0.75)."""
    q = db.query(Alert).filter(Alert.confidence_score >= 0.75)
    if threat_class:
        q = q.filter(Alert.threat_class == threat_class)
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{threat_id}", response_model=AlertOut)
def get_threat(threat_id: UUID, db: Session = Depends(get_db), _: User = Depends(require_analyst_or_admin)):
    alert = db.query(Alert).filter(Alert.id == threat_id, Alert.confidence_score >= 0.75).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat not found")
    return alert
