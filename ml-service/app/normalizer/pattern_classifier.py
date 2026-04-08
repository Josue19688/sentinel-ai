"""
normalizer/pattern_classifier.py
==================================
Responsabilidad ÚNICA: dado un texto libre + metadatos del evento,
decidir qué patrón de ataque representa.

Separado del normalizador para poder:
  - Actualizarlo sin tocar la extracción
  - Testearlo de forma independiente
  - Agregar nuevos patrones sin romper lo existente
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PatternResult:
    pattern: str        # nombre del patrón detectado
    confidence: float   # 0.0 – 1.0
    reason: str         # explicación legible para el analista


def classify(text: str, severity_score: float = 0.0, command: str = "") -> PatternResult:
    """
    Clasifica el patrón de ataque a partir de texto libre y metadatos.
    Estrategia: Evalúa todos los posibles patrones y elige el de mayor CONFIANZA.
    Esto evita que un patrón genérico (ej. whoami) tape uno crítico (ej. mimikatz).
    """
    full_text = f"{text} {command}".lower()
    candidates: list[PatternResult] = []
    
    # ── 1. Ransomware / destrucción de datos ─────────────────────────────────
    if _matches(full_text, [
        r'vssadmin.delete.shadows', r'delete.shadows',
        r'multiple.file.delete', r'ransomware',
        r'wbadmin.delete', r'bcdedit.*recoveryenabled.no',
    ]):
        candidates.append(PatternResult("ransomware_activity", 0.95,
            "Eliminación de shadow copies o actividad masiva de borrado de archivos."))

    # ── 2. Reverse shell / C2 ────────────────────────────────────────────────
    if _matches(full_text, [
        r'nc[.\s]+-e.cmd', r'nc[.\s]+-e./bin/bash',
        r'python.*pty\.spawn.*bash',
        r'reverse.shell', r'c2', r'beacon',
        r'cobalt.strike', r'asyncrat',
        r'/bin/bash.*socket', r'4444|4445|1337',
    ]):
        candidates.append(PatternResult("c2_reverse_shell", 0.95,
            "Comando de reverse shell o conexión a C2 detectado."))

    # ── 3. Persistencia (tareas, servicios, registros) ───────────────────────
    if _matches(full_text, [
        r'schtask', r'scheduled.task', r'taskname',
        r'reg.add.*run', r'hklm.*run', r'hkcu.*run',
        r'new.service', r'sc.create',
        r'crontab.*-[el]', r'\.bashrc|\.profile|\.bash_profile',
    ]):
        candidates.append(PatternResult("persistence", 0.85,
            "Creación de tarea programada, servicio o clave de registro para persistencia."))

    # ── 4. Escalación de privilegios / agregar admin ──────────────────────────
    if _matches(full_text, [
        r'net.group.*domain.admins.*\/add',
        r'net.localgroup.administrators.*\/add',
        r'globaladmin', r'adminmemberadded',
        r'add_user_to_admin', r'attachuserpolicy.*administratoraccess',
        r'external_hacker', r'backdoor_user',
    ]):
        candidates.append(PatternResult("privilege_escalation", 0.9,
            "Usuario añadido a grupo de administradores o rol de alto privilegio."))

    # ── 5. Evasión de defensa ─────────────────────────────────────────────────
    if _matches(full_text, [
        r'reg.delete.*windows.defender',
        r'stopservice.*windefend', r'disable.*defender',
        r'stopLogging', r'archivefindings',
        r'audit.log.*cleared', r'history.-c',
        r'rm.*\/var\/log', r'disablekey',
    ]):
        candidates.append(PatternResult("defense_evasion", 0.9,
            "Intento de desactivar defensas, borrar logs o evadir detección."))

    # ── 6. Credential dumping / robo de credenciales ─────────────────────────
    if _matches(full_text, [
        r'lsass.*\.dmp', r'procdump.*lsass',
        r'mimikatz', r'comsvcs.*minidump',
        r'credential.dump', r'\/etc\/shadow',
        r'cat.\/etc\/passwd', r'hashdump',
    ]):
        candidates.append(PatternResult("credential_theft", 0.9,
            "Volcado de credenciales o acceso a archivos de contraseñas del sistema."))

    # ── 7. Reconocimiento / enumeración ──────────────────────────────────────
    if _matches(full_text, [
        r'nmap', r'port.scan', r'masscan',
        r'portscan', r'network.scan', r'syn.flood',
        r'list.secrets', r'describeinstances', r'listbuckets',
        r'getbucketlocation', r'getcalleridentity',
        r'find.*-perm.*4000', r'crontab.-l',
        r'whoami', r'sudo.-l', r'netstat.-a',
    ]):
        candidates.append(PatternResult("reconnaissance", 0.75,
            "Actividad de reconocimiento: enumeración de recursos, usuarios o configuración."))

    # ── 8. Exfiltración de datos ──────────────────────────────────────────────
    if _matches(full_text, [
        r'filedownloaded', r'file.downloaded',
        r'mysqldump', r'pg_dump',
        r'large.transfer', r'exfil',
        r'transfer.document.ownership',
        r'delete.drive.item', r'filedeleted.*backup',
        r'operation.*filedownloaded.*analista',  # descarga masiva M365
    ]):
        # Evitar falso positivo: si ya detectamos C2, el riesgo ya está cubierto con mayor score
        if not any(c.pattern == "c2_reverse_shell" for c in candidates):
            candidates.append(PatternResult("data_exfiltration", 0.8,
                "Descarga masiva de archivos o transferencia sospechosa de datos."))

    # ── 9. Ejecución sospechosa (PowerShell, scripts) ────────────────────────
    if _matches(full_text, [
        r'powershell.*-enc', r'powershell.*-nop.*hidden',
        r'iex.*new-object.*webclient',
        r'base64.*encoded', r'wscript', r'cscript',
        r'mshta', r'regsvr32', r'rundll32',
        r'authorize_api_client.*untrusted',
    ]):
        candidates.append(PatternResult("suspicious_execution", 0.85,
            "Ejecución sospechosa: script ofuscado, descarga en memoria o LOLBin."))

    # ── 10. Ataque web (SQLi, XSS) ───────────────────────────────────────────
    if _matches(full_text, [
        r"' or '1'='1", r'sqli.pattern', r'sql.injection',
        r'<script.*alert', r'xss.detected',
        r'\/etc\/passwd.*(403|200)', r'\/admin\/config',
        r'web.exploit',
    ]):
        candidates.append(PatternResult("web_attack", 0.85,
            "Intento de ataque web: inyección SQL, XSS o acceso a recursos sensibles."))

    # ── 11. Fuerza bruta / autenticación fallida ──────────────────────────────
    if _matches(full_text, [
        r'wpa.authentication.failure',
        r'failed.password', r'authentication.fail',
        r'invalid.user', r'bad.password',
        r'login.failure', r'login_failure',
        r'event_4625', r'multiple.failed',
    ]):
        candidates.append(PatternResult("brute_force_attempt", 0.8,
            "Múltiples fallos de autenticación o ataque de fuerza bruta."))

    # ── 12. Actividad de IoT anómala ──────────────────────────────────────────
    if _matches(full_text, [
        r'override_open', r'valve.*override',
        r'factory.*boiler', r'pressure.*psi',
        r'temp.*critical', r'sensor.*anomaly',
    ]):
        candidates.append(PatternResult("iot_anomaly", 0.8,
            "Comportamiento anómalo en dispositivo IoT / sistema de control industrial."))

    # ── 12b. Acciones destructivas en Kubernetes ─────────────────────────────
    if _matches(full_text, [
        r'verb.*delete.*objectref.*deployment',
        r'"verb".*"delete"',
        r'delete.*deployment', r'delete.*namespace',
        r'external.hacker.*delete', r'delete.*database',
    ]):
        candidates.append(PatternResult("cloud_attack", 0.85,
            "Eliminación destructiva de recursos en clúster Kubernetes."))

    # ── 13. Acceso no autorizado en cloud ────────────────────────────────────
    if _matches(full_text, [
        r'createuser.*backdoor', r'createbackdoor',
        r'putbucketpolicy.*root', r'deletedbinstance',
        r'deletebucket', r'terminateinstances',
    ]):
        candidates.append(PatternResult("cloud_attack", 0.9,
            "Actividad destructiva o de backdoor en infraestructura cloud."))

    # ── 14. Rogue AP / amenaza WiFi ──────────────────────────────────────────
    if _matches(full_text, [
        r'rogue.access.point', r'evil.twin',
        r'deauth', r'deauthenticated',
    ]):
        candidates.append(PatternResult("wireless_threat", 0.8,
            "Punto de acceso malicioso o ataque de deautenticación WiFi."))

    # ── 15. Fallback y selección final ──────────────────────────────────────
    if not candidates:
        if severity_score >= 0.8:
            return PatternResult("high_severity_event", 0.5,
                "Evento de alta severidad sin patrón específico identificado.")
        return PatternResult("none", 0.0, "Sin patrón de ataque reconocido.")

    # Retornar el de mayor confianza (Best Match)
    return max(candidates, key=lambda x: x.confidence)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _matches(text: str, patterns: list[str]) -> bool:
    """True si alguno de los patrones hace match en el texto."""
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)
