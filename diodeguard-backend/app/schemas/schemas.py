"""
Pydantic Schemas for all API request/response models
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8)
    role: str = Field(default="analyst", pattern="^(admin|analyst)$")


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserOut(BaseModel):
    id: UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern="^(admin|analyst)$")


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------

class FlowIngest(BaseModel):
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    features: Optional[Dict[str, Any]] = None


class FlowOut(BaseModel):
    id: UUID
    flow_id: str
    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    features: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class AlertCreate(BaseModel):
    flow_id: str
    timestamp: datetime
    threat_class: str
    confidence_score: float
    severity: str
    evidence: Optional[Dict[str, Any]] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


class AlertOut(BaseModel):
    id: UUID
    flow_id: str
    timestamp: datetime
    threat_class: str
    confidence_score: float
    severity: str
    evidence: Optional[Dict[str, Any]]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    acknowledged: bool
    acknowledged_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AlertAcknowledge(BaseModel):
    acknowledged: bool = True


# ---------------------------------------------------------------------------
# Detection / Prediction
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    flow: Dict[str, Any]


class PredictResponse(BaseModel):
    flow_id: str
    alerts: List[Dict[str, Any]]
    processed_at: datetime


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class DashboardSummary(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    unacknowledged: int
    total_flows: int
    alerts_last_24h: int
    top_threat_class: Optional[str]
    detection_rate: float


class TimelinePoint(BaseModel):
    timestamp: datetime
    count: int
    threat_class: Optional[str]


# ---------------------------------------------------------------------------
# Detection Model Metadata
# ---------------------------------------------------------------------------

class DetectionModelOut(BaseModel):
    id: UUID
    name: str
    threat_class: str
    version: str
    algorithm: Optional[str]
    sha256_hash: Optional[str]
    f1_score: Optional[float]
    precision: Optional[float]
    recall: Optional[float]
    auc: Optional[float]
    is_active: bool
    trained_at: Optional[datetime]

    class Config:
        from_attributes = True
