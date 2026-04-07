import pytest
from unittest.mock import patch, AsyncMock
from app.main import app
from app.auth.dependencies import get_current_user, CurrentUser
from app.schemas.auth import TokenResponse

def override_get_current_user():
    return CurrentUser(id="1", email="admin@test.com", role="admin", version=1)

app.dependency_overrides[get_current_user] = override_get_current_user

@pytest.mark.asyncio
@patch('app.api.auth_router.AuthService')
async def test_auth_register(mock_auth_service, client):
    mock_auth_service.register = AsyncMock(return_value={"id": "123", "email": "test@test.com"})
    body = {
        "email": "test@test.com",
        "password": "Password123!",
        "role": "analyst",
        "first_name": "Test",
        "last_name": "User"
    }
    response = await client.post("/auth/register", json=body)
    assert response.status_code == 201

@pytest.mark.asyncio
@patch('app.api.auth_router.AuthService')
async def test_auth_login_and_logout(mock_auth_service, client):
    mock_auth_service.login = AsyncMock(return_value=("access_idx", "refresh_idx"))
    
    body = {"email": "test@test.com", "password": "Password123!"}
    res_login = await client.post("/auth/login", json=body)
    assert res_login.status_code == 200
    assert "access_token" in res_login.json()
    
    mock_auth_service.logout = AsyncMock(return_value=None)
    res_logout = await client.post("/auth/logout", headers={"Authorization": "Bearer access_idx"})
    assert res_logout.status_code == 204

@pytest.mark.asyncio
@patch('app.api.auth_router.AuthService')
async def test_auth_refresh(mock_auth_service, client):
    mock_auth_service.refresh = AsyncMock(return_value=("access2", "refresh2"))
    res = await client.post("/auth/refresh", json={"refresh_token": "refresh_idx"})
    assert res.status_code == 200
    assert res.json()["access_token"] == "access2"

@pytest.mark.asyncio
async def test_rate_limiting(client):
    body = {"email": "test@test.com", "password": "Password123!"}
    # Send 10 fast requests
    with patch('app.api.auth_router.AuthService.login', new_callable=AsyncMock) as mock_login:
        mock_login.return_value = ("access", "refresh")
        for _ in range(9):
            await client.post("/auth/login", json=body)
        
        # 10th should be rate limited (since 1st was in previous test, wait we use sliding window)
        # Actually sliding window is tied to IP. The IP is 'testclient' usually.
        # Let's hit it a few more times until 429
        status = 200
        for _ in range(5):
            res = await client.post("/auth/login", json=body)
            if res.status_code == 429:
                status = 429
                break
        assert status == 429
