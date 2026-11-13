"""Alerts Router"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.rbac import get_current_user, require_analyst_or_admin
from app.models.models import Alert, User
from app.schemas.schemas import AlertOut, AlertAcknowledge

router = APIRouter()


@router.get("/", response_model=List[AlertOut])
def list_alerts(
    severity: Optional[str] = Query(None),
    threat_class: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity)
    if threat_class:
        q = q.filter(Alert.threat_class == threat_class)
    if acknowledged is not None:
        q = q.filter(Alert.acknowledged == acknowledged)
    return q.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: UUID, db: Session = Depends(get_db), _: User = Depends(require_analyst_or_admin)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(
    alert_id: UUID,
    payload: AlertAcknowledge,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = payload.acknowledged
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)

    # Broadcast acknowledgement via WebSocket
    import asyncio
    from app.routers.ws import manager
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(manager.broadcast({
                "type": "ALERT_ACKNOWLEDGED",
                "data": {"alert_id": str(alert.id), "acknowledged": True, "acknowledged_by": str(current_user.username)}
            }))
    except Exception:
        pass

    return alert
