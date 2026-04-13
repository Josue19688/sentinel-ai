"""
normalizer/semantic_extractor.py
===============================
Motor de extracción semántica para logs de SIEM.
Identifica Atacante (src_ip) y Víctima (victim_ip) basándose en contexto forense.
"""
import re
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Expresión regular robusta para IPv4
_RE_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

# ── HINTS DE SEGURIDAD ────────────────────────────────────────────────────────

# Palabras que indican IP de origen (el ATACANTE).
_SRCIP_HINTS = {
    'src', 'src_ip', 'srcip', 'source', 'source_ip', 'sourceip',
    'attacker', 'attackerip', 'attacker_ip', 'remote_ip', 'remoteip',
    'rhost', 'origin', 'client_ip', 'clientip', 'src_host',
}

# Palabras que indican IP de destino (la VÍCTIMA).
_VICTIM_IP_HINTS = {
    'dst', 'dst_ip', 'dstip', 'destination', 'destip', 'target',
    'target_ip', 'victim', 'victim_ip', 'local_ip', 'localip',
    'server_ip', 'serverip', 'agent_ip', 'agentip',
}

# Contextos de reporte (donde reside el agente = VÍCTIMA).
_AGENT_CONTEXTS = {'agent', 'manager', 'reporter', 'observer', 'host'}

# Contextos de datos (donde vienen los detalles del ataque = ATACANTE).
_FORENSIC_CONTEXTS = {'data', 'event', 'full_log', 'previous_output'}

def extract(obj: Any) -> dict:
    collector = _Collector()
    collector.walk(obj)
    return collector.result()

class _Collector:
    def __init__(self):
        self._src_candidates: list[tuple[float, str]] = []
        self._victim_candidates: list[tuple[float, str]] = []
        self._asset_candidates: list[tuple[float, str]] = []
        self._event_candidates: list[tuple[float, str]] = []
        self._all_text: list[str] = []

    def walk(self, obj: Any, key: str = "", parent: str = "", depth: int = 0):
        if depth > 10: return
        
        k_lower = key.lower()
        p_lower = parent.lower()

        if isinstance(obj, dict):
            for k, v in obj.items():
                self.walk(v, k, k_lower, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self.walk(item, key, parent, depth + 1)
        elif isinstance(obj, str):
            self._all_text.append(obj)
            self._eval_str(obj, k_lower, p_lower)
        elif isinstance(obj, (int, float)):
            pass # Implementar si se requieren scores numericos

    def _eval_str(self, val: str, key: str, parent: str):
        ip_match = _RE_IPV4.search(val)
        if ip_match:
            ip = ip_match.group(0)
            
            # --- Lógica Maestra de Mapeo ---
            
            # 1. Prioridad para Atacante (srcip, rhost, etc.)
            if key in _SRCIP_HINTS:
                self._src_candidates.append((1.8, ip))
            
            # 2. Prioridad para Víctima (donde está el agente)
            elif key == 'ip' and parent in _AGENT_CONTEXTS:
                # Log de Wazuh: agent.ip es la víctima
                self._victim_candidates.append((1.8, ip))
            
            elif key in _VICTIM_IP_HINTS:
                self._victim_candidates.append((1.5, ip))
                
            # 3. Contextos genéricos
            elif parent in _AGENT_CONTEXTS:
                self._victim_candidates.append((1.0, ip))
            elif parent in _FORENSIC_CONTEXTS:
                self._src_candidates.append((1.0, ip))
            else:
                self._src_candidates.append((0.5, ip))

        # Asset Detection
        if key in {'name', 'hostname', 'asset_id', 'agent_name'} and 2 < len(val) < 64:
            self._asset_candidates.append((1.5 if 'agent' in key or 'name' in key else 1.0, val))

        # Event Detection
        if key in {'description', 'event_type', 'full_log'} and len(val) > 5:
            if 'PAM' in val or 'failed' in val or 'blocked' in val:
                self._event_candidates.append((1.5, val))

    def result(self) -> dict:
        def _best(c): return sorted(c, key=lambda x: x[0], reverse=True)[0][1] if c else None
        
        src = _best(self._src_candidates)
        vic = _best(self._victim_candidates)
        
        # Fallback de emergencia: si solo hay una IP en todo el log
        if not src and vic:
             # Si solo detectamos una IP y parece ser del agente, el atacante 
             # podria estar escondido en el texto plano
             for text in self._all_text:
                 m = _RE_IPV4.search(text)
                 if m and m.group(0) != vic:
                     src = m.group(0)
                     break
        
        return {
            "src_ip": src,
            "victim_ip": vic,
            "asset_id": _best(self._asset_candidates) or "unknown",
            "event_type": _best(self._event_candidates) or "Security Event"
        }
