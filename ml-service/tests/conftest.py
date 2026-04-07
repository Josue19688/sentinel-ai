import os
import sys
from unittest.mock import MagicMock

# Mock out difficult C-extensions that fail to build on Python 3.14 Windows
sys.modules['asyncpg'] = MagicMock()
sys.modules['river'] = MagicMock()
sys.modules['river.forest'] = MagicMock()
sys.modules['river.anomaly'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()
sys.modules['psycopg2.extensions'] = MagicMock()
sys.modules['psycopg2.extras'] = MagicMock()
sys.modules['celery'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['redis.asyncio'] = MagicMock()
sys.modules['prometheus_fastapi_instrumentator'] = MagicMock()

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Set testing environment before importing app
os.environ["APP_ENV"] = "TESTING"
os.environ["SECRET_KEY"] = "test_secret_key"
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key"
os.environ["APP_ENV"] = "TESTING"
os.environ["SECRET_KEY"] = "test_secret_key"
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key"

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
