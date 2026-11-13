"""Traffic Router — flow ingestion and retrieval"""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware.rbac import require_analyst_or_admin
from app.models.models import Flow, User
from app.schemas.schemas import FlowIngest, FlowOut

router = APIRouter()


@router.post("/ingest", response_model=FlowOut, status_code=status.HTTP_201_CREATED)
def ingest_flow(payload: FlowIngest, db: Session = Depends(get_db)):
    """Ingest a flow record (called by ML pipeline, no auth required for internal use)."""
    existing = db.query(Flow).filter(Flow.flow_id == payload.flow_id).first()
    if existing:
        return existing
    flow = Flow(
        flow_id=payload.flow_id,
        timestamp=payload.timestamp,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        src_port=payload.src_port,
        dst_port=payload.dst_port,
        protocol=payload.protocol,
        features=payload.features,
    )
    db.add(flow)
    db.commit()
    db.refresh(flow)

    # Broadcast via WebSocket
    import asyncio
    from app.routers.ws import manager
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(manager.broadcast({
                "type": "NEW_FLOW",
                "data": {
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "protocol": flow.protocol,
                    "timestamp": flow.timestamp.isoformat() if flow.timestamp else None,
                }
            }))
    except Exception:
        pass

    return flow


@router.get("/", response_model=List[FlowOut])
def list_flows(
    src_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(require_analyst_or_admin),
):
    q = db.query(Flow)
    if src_ip:
        q = q.filter(Flow.src_ip == src_ip)
    if protocol:
        q = q.filter(Flow.protocol == protocol)
    return q.order_by(Flow.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{flow_id}", response_model=FlowOut)
def get_flow(flow_id: str, db: Session = Depends(get_db), _: User = Depends(require_analyst_or_admin)):
    flow = db.query(Flow).filter(Flow.flow_id == flow_id).first()
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow
