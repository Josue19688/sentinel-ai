import pytest
import jwt
from unittest.mock import patch
from app.auth.jwt_handler import create_access_token, create_refresh_token, decode_token
from app.config import settings

def test_create_and_decode_access_token():
    token = create_access_token("u1", "test@test.com", "admin", 1)
    payload = decode_token(token)
    assert payload["sub"] == "u1"
    assert payload["email"] == "test@test.com"
    assert payload["role"] == "admin"
    assert payload["version"] == 1
    assert payload["type"] == "access"
    assert "jti" in payload

def test_create_and_decode_refresh_token():
    token = create_refresh_token("u1", 1)
    payload = decode_token(token)
    assert payload["sub"] == "u1"
    assert payload["version"] == 1
    assert payload["type"] == "refresh"
    assert "jti" not in payload

def test_invalid_signature():
    token = create_access_token("u1", "test@test.com", "admin", 1)
    tampered_token = token[:-5] + "aaaaa"
    with pytest.raises(jwt.InvalidTokenError):
        decode_token(tampered_token)

def test_expired_signature():
    with patch.object(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", -1):
        token_expired = create_access_token("u1", "test@test.com", "admin", 1)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(token_expired)
