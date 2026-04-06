"""
sandbox/scoring.py
==================
Responsabilidad ÚNICA: convertir nombres de eventos/operaciones
en un score numérico de peligro (0.0 – 1.0).

Por qué existe este módulo:
  Los logs de SIEMs cloud (AWS CloudTrail, Google Workspace, M365) no
  tienen columnas numéricas de severidad. Un IsolationForest que solo
  ve hashes de strings no puede distinguir "DeleteDBInstance" de
  "ListBuckets" — ambos producen vectores similares.

  Este módulo pre-calcula un danger_score semántico ANTES de que el
  dato llegue al ML, dando al modelo una señal numérica real.

Seguridad (ISO 42001 §8.3 — guardrail de envenenamiento):
  El danger_score actúa como un "veto determinista":
  Si un evento tiene score >= 0.9, se fuerza como anomalía
  independientemente de lo que diga el IsolationForest.
  Esto evita que un atacante que envenena el baseline pueda hacer
  que "DeleteDBInstance" sea aprendido como comportamiento normal.

Extensión:
  Para agregar un nuevo SIEM o plataforma, solo añadir palabras
  clave a los sets correspondientes. No tocar ningún otro archivo.
"""


# ── Vocabulario de peligro ────────────────────────────────────────────────────
# Cada set contiene palabras clave en lowercase.
# El match es por substring: "deletedbinstance" contiene "delete" → HIGH.

DANGER_HIGH = frozenset({
    # Destrucción / eliminación
    "delete", "destroy", "terminate", "remove", "purge", "wipe", "erase",
    # Desactivación de defensas
    "disable", "stoplogging", "archivefindings", "disablekey",
    # Operaciones destructivas específicas de cloud
    "deletebucket", "deletedbinstance", "deleteuser",
    # Control industrial
    "override", "emergency_stop", "force_close",
})

DANGER_MED = frozenset({
    # Creación / modificación de recursos
    "create", "modify", "update", "attach", "put", "set",
    "change", "add", "insert", "upload", "write",
    # Operaciones IAM que pueden escalar privilegios
    "createuser", "attachuserpolicy", "putbucketpolicy",
    "adminmemberadded", "add_user_to_admin",
    # Movimiento de datos
    "transfer", "export", "download",
})

DANGER_LOW = frozenset({
    # Operaciones de lectura
    "get", "list", "describe", "read", "view", "show", "fetch",
    # Autenticación normal
    "login", "logout", "consolelogin", "check", "verify",
    # Navegación
    "navigate", "open", "access",
})


# ── Función principal ─────────────────────────────────────────────────────────

def danger_score(event_name: str) -> float:
    """
    Convierte el nombre de un evento en un score de peligro 0.0–1.0.

    Proceso:
      1. Normaliza a lowercase
      2. Busca coincidencia por substring en cada nivel
      3. Devuelve el score del primer match (orden: HIGH → MED → LOW)
      4. Si no hay match: score neutro 0.3

    Ejemplos:
      danger_score("DeleteDBInstance") → 1.0
      danger_score("CreateUser")       → 0.5
      danger_score("ListBuckets")      → 0.1
      danger_score("SomeUnknown")      → 0.3
    """
    v = str(event_name).lower()

    for word in DANGER_HIGH:
        if word in v:
            return 1.0

    for word in DANGER_MED:
        if word in v:
            return 0.5

    for word in DANGER_LOW:
        if word in v:
            return 0.1

    return 0.3   # Desconocido — neutro


def is_forced_anomaly(score: float) -> bool:
    """
    Guardrail ISO 42001 §8.3: si el danger_score es crítico,
    el evento se trata como anomalía sin importar el ML.
    Evita el envenenamiento del baseline con acciones destructivas.
    """
    return score >= 0.9
