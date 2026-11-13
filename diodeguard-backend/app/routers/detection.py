"""Detection Router — run predictions via the ML engine"""

from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.rbac import require_analyst_or_admin
from app.models.models import Alert, User
from app.schemas.schemas import PredictRequest, PredictResponse, AlertOut, DetectionModelOut

router = APIRouter()


@router.post("/predict", response_model=PredictResponse)
def predict(
    payload: PredictRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    """
    Run the ML detection engine on a single flow.
    Stores resulting alerts in the database and returns them.
    """
    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "diodeguard-ml"))
        from pipeline.detector import DiodeGuardDetector
        detector = DiodeGuardDetector()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"ML engine unavailable: {e}")

    flow = payload.flow
    flow_id = flow.get("flow_id", str(datetime.now(timezone.utc).timestamp()))
    flow["flow_id"] = flow_id

    # Ensure Flow exists in DB to satisfy foreign key constraint
    from app.models.models import Flow
    existing_flow = db.query(Flow).filter(Flow.flow_id == flow_id).first()
    if not existing_flow:
        ts = flow.get("timestamp")
        flow_ts = datetime.fromisoformat(ts) if isinstance(ts, str) else datetime.now(timezone.utc)
        new_flow = Flow(
            flow_id=flow_id,
            timestamp=flow_ts,
            src_ip=flow.get("src_ip", "0.0.0.0"),
            dst_ip=flow.get("dst_ip", "0.0.0.0"),
            src_port=int(flow.get("src_port", 0)),
            dst_port=int(flow.get("dst_port", 0)),
            protocol=flow.get("protocol", "TCP"),
            features={k: v for k, v in flow.items() if k not in ("flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
        )
        db.add(new_flow)
        db.flush()

    raw_alerts = detector.score_flow(flow)

    saved_alerts = []
    for a in raw_alerts:
        db_alert = Alert(
            flow_id=a["flow_id"],
            timestamp=datetime.fromisoformat(a["timestamp"]) if isinstance(a["timestamp"], str) else a["timestamp"],
            threat_class=a["threat_class"],
            confidence_score=a["confidence_score"],
            severity=a["severity"],
            evidence=a.get("evidence"),
            src_ip=a.get("src_ip"),
            dst_ip=a.get("dst_ip"),
            src_port=a.get("src_port"),
            dst_port=a.get("dst_port"),
            protocol=a.get("protocol"),
        )
        db.add(db_alert)
        saved_alerts.append(a)

    db.commit()

    # Broadcast via WebSocket if connections active
    import asyncio
    from app.routers.ws import manager
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            for a in saved_alerts:
                asyncio.create_task(manager.broadcast({"type": "NEW_ALERT", "data": a}))
    except Exception:
        pass

    return PredictResponse(
        flow_id=flow_id,
        alerts=saved_alerts,
        processed_at=datetime.now(timezone.utc),
    )


@router.get("/", response_model=List[AlertOut])
def list_detections(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
