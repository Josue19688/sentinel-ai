"""
sandbox/explainer.py
====================
Responsabilidad ÚNICA: generar el campo shap_motive — la explicación
en lenguaje humano de por qué un grupo de eventos fue marcado como anómalo.

ISO 42001 §7.2 — Transparencia del Sistema de IA:
  El sistema de IA debe poder explicar sus decisiones en términos
  comprensibles para un analista SOC. Un score de 0.87 no es suficiente.
  "Comando peligroso: vssadmin delete shadows. IP externa: 45.12.33.102.
  Densidad: 33%." sí lo es.

Estrategia de explicación (por prioridad):
  1. Acciones destructivas (danger_score >= 0.9) — la señal más fuerte
  2. Comandos peligrosos en texto libre (wget miner, nc -e, mimikatz...)
  3. Nombres de los eventos más frecuentes entre las anomalías
  4. IPs externas presentes en los eventos anómalos
  5. Fallback: "Desviación estadística multidimensional"

Extensión:
  Para agregar un nuevo tipo de evidencia, agregar un nuevo bloque
  en generate() siguiendo el patrón existente. El resto del sistema
  no necesita cambios.
"""

import re
import logging
import pandas as pd

logger = logging.getLogger(__name__)


# ── Columnas donde pueden vivir nombres de eventos ───────────────────────────
_EVENT_COLS = [
    "eventName", "Operation", "EventName", "LowLevelCategory",
    "events_0_name", "description", "verb", "input",
]

# ── Columnas donde pueden vivir IPs ──────────────────────────────────────────
_IP_COLS = [
    "src_ip", "sourceIPAddress", "ipAddress", "SourceIp",
    "clientip", "remote_addr",
]

# ── Columnas donde pueden vivir comandos ejecutados ──────────────────────────
_CMD_COLS = ["input", "CommandLine", "command", "cmd", "cmdline"]

# ── Regex de comandos peligrosos ─────────────────────────────────────────────
_DANGER_CMD_RE = re.compile(
    r"wget|curl|chmod\s*\+x|miner|nc\s+-e|pty\.spawn|"
    r"rm\s+-rf|vssadmin|mimikatz|lsass|base64.*-d|"
    r"powershell.*-enc|iex.*webclient",
    re.IGNORECASE,
)

# Prefijo de redes privadas (para detectar IPs externas)
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.",
                     "172.18.", "172.19.", "172.2", "127.")


# ── Función principal ─────────────────────────────────────────────────────────

def generate(
    full_df: pd.DataFrame,
    anomalies_df: pd.DataFrame,
    asset_id: str,
) -> str:
    """
    Genera la explicación textual de por qué este activo fue marcado.

    Parámetros:
      full_df      → todos los eventos del activo en esta sesión
      anomalies_df → solo los eventos marcados como anómalos
      asset_id     → nombre del activo (para logging)

    Retorna un string legible para el analista SOC.
    """
    density = len(anomalies_df) / max(len(full_df), 1)
    parts   = []

    # 1. Acciones destructivas ────────────────────────────────────────────────
    if "danger_score" in anomalies_df.columns:
        max_danger = anomalies_df["danger_score"].max()
        if max_danger >= 0.9:
            parts.append("Acciones destructivas detectadas (Delete/Stop/Disable)")

    # 2. Comandos peligrosos en texto libre ───────────────────────────────────
    for col in _CMD_COLS:
        if col not in anomalies_df.columns:
            continue
        candidates = anomalies_df[col].dropna().astype(str)
        dangerous  = candidates[candidates.apply(
            lambda v: bool(_DANGER_CMD_RE.search(v))
        )]
        if len(dangerous) > 0:
            sample = dangerous.iloc[0][:70].strip()
            parts.append(f"Comando peligroso: {sample}")
            break  # Una muestra es suficiente

    # 3. Nombres de eventos más frecuentes ───────────────────────────────────
    for col in _EVENT_COLS:
        if col not in anomalies_df.columns:
            continue
        top_events = (
            anomalies_df[col]
            .value_counts()
            .head(3)
            .index
            .tolist()
        )
        clean = [
            str(e) for e in top_events
            if str(e) not in ("nan", "None", "")
        ]
        if clean:
            parts.append(f"Eventos: {', '.join(clean)}")
            break

    # 4. IPs externas ─────────────────────────────────────────────────────────
    for col in _IP_COLS:
        if col not in anomalies_df.columns:
            continue
        all_ips  = anomalies_df[col].dropna().unique()
        external = [
            str(ip) for ip in all_ips
            if not str(ip).startswith(_PRIVATE_PREFIXES)
        ]
        if external:
            parts.append(f"IP externa: {external[0]}")
            break

    # 5. Fallback ─────────────────────────────────────────────────────────────
    if not parts:
        parts.append("Desviación estadística multidimensional")

    explanation = ". ".join(parts) + f". Densidad de anomalías: {int(density * 100)}%."
    logger.debug(f"explainer: {asset_id} → {explanation[:80]}")
    return explanation
