import pytest
from unittest.mock import patch, AsyncMock
from app.audit.hash_chain import verify_chain, log_audit_event
import json
import hashlib

@pytest.mark.asyncio
@patch('app.audit.hash_chain.get_db_conn')
async def test_empty_chain(mock_db):
    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = []
    mock_db.return_value.__aenter__.return_value = mock_conn

    res = await verify_chain()
    assert res["status"] == "empty"
    assert res["verified"] is True

@pytest.mark.asyncio
@patch('app.audit.hash_chain.get_db_conn')
async def test_compromised_chain(mock_db):
    content = json.dumps({
        "event_type": "LOGIN",
        "entity_id": "u1",
        "actor": "admin",
        "payload": {"ip":"1.1.1.1"},
        "previous_hash": "GENESIS"
    }, sort_keys=True)
    real_hash = hashlib.sha256(content.encode()).hexdigest()

    rec1 = {
        "id": 1,
        "event_type": "LOGIN",
        "entity_id": "u1",
        "actor": "admin",
        "payload": '{"ip":"1.1.1.1"}',
        "current_hash": real_hash
    }
    
    rec2 = {
        "id": 2,
        "event_type": "LOGOUT",
        "entity_id": "u1",
        "actor": "admin",
        "payload": '{}',
        "current_hash": "tampered_fake_hash"
    }

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [rec1, rec2]
    mock_db.return_value.__aenter__.return_value = mock_conn

    res = await verify_chain()
    assert res["status"] == "COMPROMISED"
    assert res["broken_at_record"] == 2
