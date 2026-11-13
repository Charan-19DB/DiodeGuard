"""
Alert Emitter
Writes detected alerts from the ML pipeline into PostgreSQL
using a direct SQLAlchemy connection (no FastAPI dependency).
"""

import os
import sys
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://diodeguard:password@localhost:5432/diodeguard")

engine = create_engine(POSTGRES_URL, pool_pre_ping=True)

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id         TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    threat_class    TEXT NOT NULL,
    confidence_score FLOAT NOT NULL,
    severity        TEXT NOT NULL,
    evidence        JSONB,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    acknowledged    BOOLEAN DEFAULT FALSE,
    acknowledged_by UUID,
    acknowledged_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
"""

CREATE_FLOWS_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id         TEXT UNIQUE NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    features        JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
"""


def init_tables():
    with engine.connect() as conn:
        conn.execute(text(CREATE_ALERTS_TABLE))
        conn.execute(text(CREATE_FLOWS_TABLE))
        # Ensure migration consistency if tables already existed
        conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_by UUID;"))
        conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;"))
        conn.commit()
    print("[AlertEmitter] Tables ensured.")


def emit_alert(alert: dict):
    """Insert a single alert record. Alerts are append-only."""
    sql = text("""
        INSERT INTO alerts
            (id, flow_id, timestamp, threat_class, confidence_score,
             severity, evidence, src_ip, dst_ip, src_port, dst_port, protocol)
        VALUES
            (:id, :flow_id, :timestamp, :threat_class, :confidence_score,
             :severity, :evidence, :src_ip, :dst_ip, :src_port, :dst_port, :protocol)
    """)
    params = {
        "id": alert.get("alert_id", str(uuid.uuid4())),
        "flow_id": alert["flow_id"],
        "timestamp": alert["timestamp"],
        "threat_class": alert["threat_class"],
        "confidence_score": alert["confidence_score"],
        "severity": alert["severity"],
        "evidence": json.dumps(alert.get("evidence", {})),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol"),
    }
    with engine.connect() as conn:
        conn.execute(sql, params)
        conn.commit()


def emit_flow(flow: dict):
    """Upsert a flow record."""
    sql = text("""
        INSERT INTO flows
            (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, features)
        VALUES
            (:flow_id, :timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :features)
        ON CONFLICT (flow_id) DO NOTHING
    """)
    params = {
        "flow_id": flow["flow_id"],
        "timestamp": flow.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "src_port": flow.get("src_port"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol"),
        "features": json.dumps({k: v for k, v in flow.items()
                                 if k not in ("flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol")}),
    }
    with engine.connect() as conn:
        conn.execute(sql, params)
        conn.commit()


if __name__ == "__main__":
    init_tables()
    print("[AlertEmitter] Ready. Waiting for alerts from detector...")
