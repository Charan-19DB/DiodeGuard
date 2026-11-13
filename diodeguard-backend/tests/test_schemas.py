import pytest
pytest.importorskip("email_validator")

from datetime import datetime, timezone
import uuid
import pytest
from pydantic import ValidationError

from app.schemas.schemas import (
    UserRegister,
    UserLogin,
    AlertCreate,
    AlertOut,
    FlowIngest,
)


def test_user_register_validation():
    # Valid
    user = UserRegister(
        email="test@example.com",
        username="testuser",
        password="ValidPassword123!",
        role="analyst",
    )
    assert user.email == "test@example.com"
    assert user.role == "analyst"

    # Invalid role
    with pytest.raises(ValidationError):
        UserRegister(
            email="test@example.com",
            username="testuser",
            password="ValidPassword123!",
            role="superadmin",
        )


def test_alert_schema():
    now = datetime.now(timezone.utc)
    alert = AlertCreate(
        flow_id="flow-test-12345",
        timestamp=now,
        threat_class="DDoS",
        confidence_score=0.94,
        severity="Critical",
        evidence={"packets_per_sec": 55000},
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=44552,
        dst_port=80,
        protocol="TCP",
    )
    assert alert.threat_class == "DDoS"
    assert alert.confidence_score == 0.94
    assert alert.severity == "Critical"
