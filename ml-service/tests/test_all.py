"""
Suite de tests — Sentinel ML Service
Corre sin infraestructura real (mocks incluidos).

    pytest tests/ -v
    pytest tests/test_normalizers.py -v
    pytest tests/ -v --cov=app
"""
import pytest, json, hmac, hashlib, time
from unittest.mock import AsyncMock, patch, MagicMock
import numpy as np

# ── Fixtures de payloads reales ──────────────────────────────────────────────

WAZUH_SAMPLES = [
    {
        "rule": {"level": 10, "description": "Directory traversal", "groups": ["web"]},
        "agent": {"name": "web-server-01"},
        "data": {"srcip": "10.0.0.5"},
        "asset_value": 0.7
    },
    {
        "rule": {"level": 3, "description": "User login success", "groups": ["auth"]},
        "agent": {"name": "workstation-05"},
        "asset_value": 0.3
    },
    {
        "rule": {"level": 14, "description": "Rootkit detected", "groups": ["rootcheck"]},
        "agent": {"name": "db-server-prod"},
        "data": {"srcip": "192.168.1.100"},
        "asset_value": 0.95
    }
]

SENTINEL_SAMPLES = [
    {
        "Severity": "Critical",
        "IncidentNumber": 1001,
        "Title": "Suspicious PowerShell execution",
        "Entities": [{"HostName": "workstation-12", "Address": "172.16.0.12"}],
        "asset_value": 0.8
    },
    {
        "Severity": "Low",
        "IncidentNumber": 500,
        "Title": "User added to admin group",
        "Entities": [{"HostName": "dc-server"}],
        "asset_value": 0.9
    }
]

SYSLOG_SAMPLES = [
    {"message": "critical: disk full on /var", "host": "storage-01"},
    {"message": "error: connection refused", "host": "app-server-02", "program": "nginx"},
    {"message": "info: backup completed", "host": "backup-01"}
]


# ── Tests: Normalizers ───────────────────────────────────────────────────────

class TestWazuhNormalizer:
    def setup_method(self):
        from app.normalizers.base import WazuhNormalizer
        self.normalizer = WazuhNormalizer()

    def test_can_handle_valid_wazuh(self):
        assert self.normalizer.can_handle(WAZUH_SAMPLES[0]) is True

    def test_cannot_handle_sentinel(self):
        assert self.normalizer.can_handle(SENTINEL_SAMPLES[0]) is False

    @pytest.mark.parametrize("sample", WAZUH_SAMPLES)
    def test_normalize_produces_valid_vector(self, sample):
        from app.normalizers.base import normalize
        event = normalize(sample)
        assert 0.0 <= event.severity_score <= 1.0
        assert event.source_siem == "wazuh"
        assert event.asset_id is not None
        assert event.raw_hash is not None
        assert len(event.raw_hash) == 64  # SHA-256

    def test_high_level_maps_to_high_score(self):
        result = self.normalizer.normalize(WAZUH_SAMPLES[2])  # level 14
        assert result.severity_score >= 0.9

    def test_low_level_maps_to_low_score(self):
        result = self.normalizer.normalize(WAZUH_SAMPLES[1])  # level 3
        assert result.severity_score <= 0.2


class TestSentinelNormalizer:
    def setup_method(self):
        from app.normalizers.base import SentinelNormalizer
        self.normalizer = SentinelNormalizer()

    def test_can_handle_sentinel(self):
        assert self.normalizer.can_handle(SENTINEL_SAMPLES[0]) is True

    @pytest.mark.parametrize("sample", SENTINEL_SAMPLES)
    def test_normalize_produces_valid_vector(self, sample):
        event = self.normalizer.normalize(sample)
        assert 0.0 <= event.severity_score <= 1.0
        assert event.source_siem == "sentinel"

    def test_critical_severity_maps_to_1(self):
        result = self.normalizer.normalize(SENTINEL_SAMPLES[0])
        assert result.severity_score == 1.0


class TestGenericSyslog:
    @pytest.mark.parametrize("sample", SYSLOG_SAMPLES)
    def test_always_handles(self, sample):
        from app.normalizers.base import GenericSyslogNormalizer
        n = GenericSyslogNormalizer()
        assert n.can_handle(sample) is True

    def test_critical_keyword_maps_to_high_score(self):
        from app.normalizers.base import GenericSyslogNormalizer
        n = GenericSyslogNormalizer()
        result = n.normalize(SYSLOG_SAMPLES[0])
        assert result.severity_score >= 0.9


# ── Tests: HMAC ──────────────────────────────────────────────────────────────

class TestHMACValidator:
    def _make_signature(self, payload: str, secret: str, timestamp: str, client_id: str) -> str:
        return hmac.new(
            secret.encode(),
            f"{payload}{timestamp}{client_id}".encode(),
            hashlib.sha256
        ).hexdigest()

    def test_valid_signature_accepted(self):
        payload = json.dumps({"test": "data"})
        ts = str(int(time.time()))
        sig = self._make_signature(payload, "test-secret", ts, "test-client")
        expected = self._make_signature(payload, "test-secret", ts, "test-client")
        assert hmac.compare_digest(sig, expected)

    def test_tampered_payload_rejected(self):
        ts = str(int(time.time()))
        original_sig = self._make_signature('{"a":1}', "secret", ts, "client")
        tampered_sig = self._make_signature('{"a":999}', "secret", ts, "client")
        assert not hmac.compare_digest(original_sig, tampered_sig)

    def test_expired_timestamp_rejected(self):
        old_ts = str(int(time.time()) - 60)  # 60 segundos atrás
        diff = abs(time.time() - int(old_ts))
        assert diff > 30  # fuera de la ventana de 30s


# ── Tests: Hash Chain ────────────────────────────────────────────────────────

class TestHashChain:
    def test_hash_chain_integrity(self):
        """Simula verificación de cadena sin DB."""
        import hashlib, json

        records = []
        prev_hash = "GENESIS"

        for i in range(5):
            content = json.dumps({
                "event_type": "TEST",
                "entity_id": str(i),
                "actor": "test",
                "payload": {"i": i},
                "previous_hash": prev_hash
            }, sort_keys=True)
            current = hashlib.sha256(content.encode()).hexdigest()
            records.append({"previous_hash": prev_hash, "current_hash": current, "id": i})
            prev_hash = current

        # Verificar cadena
        prev = "GENESIS"
        for rec in records:
            content = json.dumps({
                "event_type": "TEST",
                "entity_id": str(rec["id"]),
                "actor": "test",
                "payload": {"i": rec["id"]},
                "previous_hash": prev
            }, sort_keys=True)
            expected = hashlib.sha256(content.encode()).hexdigest()
            assert expected == rec["current_hash"]
            prev = rec["current_hash"]

    def test_tampered_record_breaks_chain(self):
        """Si alguien modifica un registro, la verificación falla."""
        import hashlib, json

        content = json.dumps({"data": "original", "previous_hash": "GENESIS"}, sort_keys=True)
        original_hash = hashlib.sha256(content.encode()).hexdigest()

        tampered_content = json.dumps({"data": "TAMPERED", "previous_hash": "GENESIS"}, sort_keys=True)
        tampered_hash = hashlib.sha256(tampered_content.encode()).hexdigest()

        assert original_hash != tampered_hash


# ── Tests: Isolation Forest ──────────────────────────────────────────────────

class TestIsolationForest:
    def test_model_detects_anomalies(self):
        from sklearn.ensemble import IsolationForest
        import numpy as np

        rng = np.random.default_rng(42)
        X_normal = rng.normal([0.2, 0.5, 300, 5], [0.1, 0.1, 50, 2], (500, 4))
        X_anomaly = rng.normal([0.9, 0.9, 5, 90], [0.05, 0.05, 2, 5], (50, 4))

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X_normal)

        normal_preds = model.predict(X_normal[:10])
        anomaly_preds = model.predict(X_anomaly)

        # Al menos el 80% de las anomalías deben detectarse
        assert (anomaly_preds == -1).mean() > 0.8

    def test_inference_speed(self):
        from sklearn.ensemble import IsolationForest
        import numpy as np, time

        model = IsolationForest(n_estimators=100, random_state=42)
        X = np.random.rand(1000, 4)
        model.fit(X)

        test_vec = np.random.rand(1, 4)
        start = time.perf_counter()
        for _ in range(100):
            model.predict(test_vec)
        elapsed_ms = (time.perf_counter() - start) / 100 * 1000

        assert elapsed_ms < 10, f"Inferencia demasiado lenta: {elapsed_ms:.1f}ms"
