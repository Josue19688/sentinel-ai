import os
import sys
from unittest.mock import MagicMock, AsyncMock

# Mock out difficult C-extensions that fail to build on Python 3.11+ Windows
sys.modules['asyncpg'] = MagicMock()
mock_pool = MagicMock()
mock_pool.acquire.return_value.__aenter__ = AsyncMock()
mock_pool.acquire.return_value.__aexit__ = AsyncMock()
sys.modules['asyncpg'].create_pool = AsyncMock(return_value=mock_pool)

sys.modules['river'] = MagicMock()
sys.modules['river.forest'] = MagicMock()
sys.modules['river.anomaly'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()
sys.modules['psycopg2.extensions'] = MagicMock()
sys.modules['psycopg2.extras'] = MagicMock()
sys.modules['celery'] = MagicMock()
sys.modules['redis'] = MagicMock()

class FakeRedis:
    def __init__(self):
        self.data = {}
    async def incr(self, key):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]
    async def expire(self, key, time):
        pass
    async def get(self, key):
        return self.data.get(key)
    async def set(self, key, val):
        self.data[key] = val
    async def close(self):
        pass

mock_aioredis = MagicMock()
mock_aioredis.from_url.return_value = FakeRedis()
sys.modules['redis.asyncio'] = mock_aioredis
sys.modules['prometheus_fastapi_instrumentator'] = MagicMock()
sys.modules['prometheus_fastapi_instrumentator'].Instrumentator.return_value.instrument.return_value.expose = MagicMock()

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Set testing environment before importing app
os.environ["APP_ENV"] = "TESTING"
os.environ["SECRET_KEY"] = "test_secret_key"
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key"

class FakeRedis:
    def __init__(self):
        self.data = {}
    async def incr(self, key):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]
    async def expire(self, key, time):
        pass
    async def get(self, key):
        return self.data.get(key)
    async def set(self, key, val):
        self.data[key] = val
    async def close(self):
        pass

_fake_redis_instance = FakeRedis()

async def mock_get_redis():
    return _fake_redis_instance

async def mock_get_pool():
    mock_pool = MagicMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock()
    mock_pool.acquire.return_value.__aexit__ = AsyncMock()
    return mock_pool

import app.db
app.db.get_redis = mock_get_redis
app.db.get_pool = mock_get_pool

from app.main import app

@pytest_asyncio.fixture
async def client():
    """Cliente HTTP async para tests de integración."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac

@pytest.fixture
def sample_event():
    """Evento de seguridad de prueba."""
    return {
        "source": "test-siem",
        "event_type": "authentication_failure",
        "severity": "medium",
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.10",
        "timestamp": "2025-01-01T00:00:00Z"
    }
