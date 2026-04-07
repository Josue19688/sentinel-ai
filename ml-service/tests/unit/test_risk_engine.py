import pytest
from unittest.mock import MagicMock, patch
from app.calculator.risk_engine import calculate_risk

@patch('app.calculator.risk_engine._calculate_aro')
@patch('app.calculator.risk_engine._calculate_history_context')
def test_risk_engine_calculations(mock_history, mock_aro):
    mock_aro.return_value = {"aro": 0.5, "sample_size": 2, "period_days": 30, "confidence": "medium"}
    mock_history.return_value = {"attack_count": 5, "first_occurrence": False, "recurrence": True}

    conn = MagicMock()
    asset_meta = {
        "valor_activo": 10000.0,
        "valor_confidencialidad": 5,
        "valor_integridad": 1,
        "valor_disponibilidad": 1,
    }
    
    result = calculate_risk(conn, "client1", "asset1", "ransomware_activity", asset_meta, 0.8)
    
    assert result["ef"] == 0.90
    assert result["sle"] == 9000.0
    assert result["aro"] == 0.5
    assert result["ale"] == 4500.0
    assert "disponibilidad" in result["impacted_dimensions"]

@patch('app.calculator.risk_engine._calculate_aro')
@patch('app.calculator.risk_engine._calculate_history_context')
def test_risk_engine_zero_value(mock_history, mock_aro):
    mock_aro.return_value = {"aro": 1.0, "sample_size": 0, "period_days": 0, "confidence": "low"}
    mock_history.return_value = {"attack_count": 0, "first_occurrence": True, "recurrence": False}

    conn = MagicMock()
    asset_meta = {
        "valor_activo": 0.0,
        "valor_confidencialidad": 3,
        "valor_integridad": 3,
        "valor_disponibilidad": 3,
    }
    
    result = calculate_risk(conn, "client1", "asset1", "none", asset_meta, 0.1)
    
    assert result["ef"] == 0.10
    assert result["sle"] == 0.0
    assert result["ale"] == 0.0
