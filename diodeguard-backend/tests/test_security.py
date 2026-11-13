import pytest
pytest.importorskip("jose")
pytest.importorskip("passlib")

from app.core.security import hash_password, verify_password, create_access_token, decode_token


def test_password_hashing():
    plain = "SuperSecretPassword123!"
    hashed = hash_password(plain)
    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_flow():
    subject = "analyst@diodeguard.local"
    role = "analyst"
    token = create_access_token(subject=subject, role=role)
    assert isinstance(token, str)
    assert len(token) > 20

    payload = decode_token(token)
    assert payload["sub"] == subject
    assert payload["role"] == role
    assert "exp" in payload
