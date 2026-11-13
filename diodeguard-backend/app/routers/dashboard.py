"""Dashboard Router — summary stats and timeline"""

from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.rbac import require_analyst_or_admin
from app.models.models import Alert, Flow, User
from app.schemas.schemas import DashboardSummary, TimelinePoint

router = APIRouter()


@router.get("/summary", response_model=DashboardSummary)
def get_summary(db: Session = Depends(get_db), _: User = Depends(require_analyst_or_admin)):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    critical = db.query(func.count(Alert.id)).filter(Alert.severity == "Critical").scalar() or 0
    high = db.query(func.count(Alert.id)).filter(Alert.severity == "High").scalar() or 0
    medium = db.query(func.count(Alert.id)).filter(Alert.severity == "Medium").scalar() or 0
    low = db.query(func.count(Alert.id)).filter(Alert.severity == "Low").scalar() or 0
    unacknowledged = db.query(func.count(Alert.id)).filter(Alert.acknowledged == False).scalar() or 0
    total_flows = db.query(func.count(Flow.id)).scalar() or 0
    alerts_24h = db.query(func.count(Alert.id)).filter(Alert.timestamp >= last_24h).scalar() or 0

    # Top threat class
    top_row = (
        db.query(Alert.threat_class, func.count(Alert.id).label("cnt"))
        .group_by(Alert.threat_class)
        .order_by(func.count(Alert.id).desc())
        .first()
    )
    top_threat = top_row[0] if top_row else None
    detection_rate = round((total_alerts / max(total_flows, 1)) * 100, 2)

    return DashboardSummary(
        total_alerts=total_alerts,
        critical_alerts=critical,
        high_alerts=high,
        medium_alerts=medium,
        low_alerts=low,
        unacknowledged=unacknowledged,
        total_flows=total_flows,
        alerts_last_24h=alerts_24h,
        top_threat_class=top_threat,
        detection_rate=detection_rate,
    )


@router.get("/timeline", response_model=List[TimelinePoint])
def get_timeline(
    hours: int = 24,
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    """Returns hourly alert counts for the last N hours."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    rows = (
        db.query(
            func.date_trunc("hour", Alert.timestamp).label("ts"),
            func.count(Alert.id).label("cnt"),
        )
        .filter(Alert.timestamp >= since)
        .group_by(func.date_trunc("hour", Alert.timestamp))
        .order_by(func.date_trunc("hour", Alert.timestamp))
        .all()
    )
    return [TimelinePoint(timestamp=row.ts, count=row.cnt) for row in rows]
