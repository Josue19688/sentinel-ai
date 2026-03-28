"""
Universal SIEM Normalizer
Transforma logs heterogéneos en un vector de features estándar.
Arquitectura de plugins: cada SIEM tiene su propio módulo.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
import hashlib, json


@dataclass
class NormalizedEvent:
    """Vector de features estándar para el modelo de IA."""
    source_siem:     str
    asset_id:        str
    severity_score:  float          # 0.0 - 1.0 normalizado
    asset_value:     float          # 0.0 - 1.0 (valor del activo)
    timestamp_delta: float          # segundos desde el evento anterior del mismo activo
    event_type:      str
    src_ip:          Optional[str]
    raw_hash:        str            # SHA-256 del log original (trazabilidad)
    features_vector: dict           # vector completo para el modelo


class BaseNormalizer(ABC):
    @abstractmethod
    def can_handle(self, raw: dict) -> bool:
        """Retorna True si este plugin puede procesar el log."""

    @abstractmethod
    def normalize(self, raw: dict) -> NormalizedEvent:
        """Transforma el log crudo en NormalizedEvent."""

    def _hash_raw(self, raw: dict) -> str:
        return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


class WazuhNormalizer(BaseNormalizer):
    """Plugin para alertas de Wazuh (niveles 1-15)."""

    LEVEL_TO_SCORE = {
        range(1, 4):  0.1,
        range(4, 7):  0.3,
        range(7, 10): 0.6,
        range(10, 13): 0.8,
        range(13, 16): 1.0,
    }

    def can_handle(self, raw: dict) -> bool:
        return "rule" in raw and "agent" in raw

    def normalize(self, raw: dict) -> NormalizedEvent:
        level = raw.get("rule", {}).get("level", 0)
        score = next(
            (v for r, v in self.LEVEL_TO_SCORE.items() if level in r), 0.5
        )
        return NormalizedEvent(
            source_siem    = "wazuh",
            asset_id       = raw.get("agent", {}).get("name", "unknown"),
            severity_score = score,
            asset_value    = raw.get("asset_value", 0.5),
            timestamp_delta= raw.get("_timestamp_delta", 0.0),
            event_type     = raw.get("rule", {}).get("description", "unknown"),
            src_ip         = raw.get("data", {}).get("srcip"),
            raw_hash       = self._hash_raw(raw),
            features_vector= {
                "severity_score":  score,
                "rule_level":      level,
                "asset_value":     raw.get("asset_value", 0.5),
                "timestamp_delta": raw.get("_timestamp_delta", 0.0),
                "event_type_id":   hash(raw.get("rule", {}).get("groups", [""])[0]) % 100
            }
        )


class SentinelNormalizer(BaseNormalizer):
    """Plugin para Microsoft Sentinel."""

    SEVERITY_MAP = {"Low": 0.2, "Medium": 0.5, "High": 0.8, "Critical": 1.0}

    def can_handle(self, raw: dict) -> bool:
        return "Severity" in raw and "IncidentNumber" in raw

    def normalize(self, raw: dict) -> NormalizedEvent:
        score = self.SEVERITY_MAP.get(raw.get("Severity", "Low"), 0.2)
        return NormalizedEvent(
            source_siem    = "sentinel",
            asset_id       = raw.get("Entities", [{}])[0].get("HostName", "unknown"),
            severity_score = score,
            asset_value    = raw.get("asset_value", 0.5),
            timestamp_delta= raw.get("_timestamp_delta", 0.0),
            event_type     = raw.get("Title", "unknown"),
            src_ip         = raw.get("Entities", [{}])[0].get("Address"),
            raw_hash       = self._hash_raw(raw),
            features_vector= {
                "severity_score":  score,
                "incident_id":     raw.get("IncidentNumber", 0) % 10000,
                "asset_value":     raw.get("asset_value", 0.5),
                "timestamp_delta": raw.get("_timestamp_delta", 0.0),
                "event_type_id":   hash(raw.get("Title", "")) % 100
            }
        )


class GenericSyslogNormalizer(BaseNormalizer):
    """Catch-all para pfSense, firewalls, EDRs sin integración directa."""

    SEVERITY_KEYWORDS = {
        "critical": 1.0, "crit": 1.0,
        "error": 0.7, "err": 0.7,
        "warning": 0.4, "warn": 0.4,
        "notice": 0.2, "info": 0.1
    }

    def can_handle(self, raw: dict) -> bool:
        return True  # siempre aplica como fallback

    def normalize(self, raw: dict) -> NormalizedEvent:
        msg = str(raw.get("message", "")).lower()
        score = next(
            (v for k, v in self.SEVERITY_KEYWORDS.items() if k in msg), 0.3
        )
        return NormalizedEvent(
            source_siem    = "syslog",
            asset_id       = raw.get("host", raw.get("hostname", "unknown")),
            severity_score = score,
            asset_value    = raw.get("asset_value", 0.5),
            timestamp_delta= raw.get("_timestamp_delta", 0.0),
            event_type     = raw.get("program", "syslog"),
            src_ip         = raw.get("src_ip"),
            raw_hash       = self._hash_raw(raw),
            features_vector= {
                "severity_score":  score,
                "asset_value":     raw.get("asset_value", 0.5),
                "timestamp_delta": raw.get("_timestamp_delta", 0.0),
                "event_type_id":   hash(raw.get("program", "")) % 100
            }
        )


# ── Router de plugins ───────────────────────────────────────────────────────
_PLUGINS = [WazuhNormalizer(), SentinelNormalizer(), GenericSyslogNormalizer()]

def normalize(raw: dict) -> NormalizedEvent:
    for plugin in _PLUGINS:
        if plugin.can_handle(raw):
            return plugin.normalize(raw)
    raise ValueError("No normalizer found (should never happen — GenericSyslog is catch-all)")
