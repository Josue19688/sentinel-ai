#!/usr/bin/env python3
"""
Sentinel ML — Script de Integración Universal
Funciona con: Wazuh, Splunk, Microsoft Sentinel, Suricata,
              iptables, Cisco ASA, pfSense, AWS CloudTrail,
              o cualquier herramienta que genere JSON.

Instalación: pip install requests
Uso:
  # Wazuh (configura en /var/ossec/etc/ossec.conf):
  python3 sentinel_integration.py alert_file.json

  # Cualquier otra herramienta — pasa el JSON directo:
  echo '{"host":"server","message":"critical error"}' | python3 sentinel_integration.py

  # Test de conectividad:
  python3 sentinel_integration.py --test
"""
import sys, json, requests

# ── CONFIGURACIÓN (solo esto necesitas cambiar) ──────────────
SENTINEL_URL    = "https://tu-sentinel.ejemplo.com"
SENTINEL_KEY    = "snl_XXXXX"   # generado por Sentinel al registrarte
SENTINEL_SECRET = "XXXXX"       # generado por Sentinel al registrarte
# ─────────────────────────────────────────────────────────────

ENDPOINT = f"{SENTINEL_URL}/gateway/analyze"
HEADERS  = {
    "X-API-Key":    SENTINEL_KEY,
    "X-API-Secret": SENTINEL_SECRET,
    "Content-Type": "application/json"
}


def send(alert: dict):
    """Envía cualquier alerta a Sentinel. Él detecta el formato."""
    try:
        r = requests.post(ENDPOINT, json=alert, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"[Sentinel] {data['risk_level'].upper()} — {data['pattern']} — {data['action']}")
            if data['risk_level'] == 'high':
                print(f"[!] {data['reason']}")
        else:
            print(f"[Sentinel] Error {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"[Sentinel] Conexión fallida: {e}")


def test_connection():
    """Verifica que la integración funciona."""
    test_alert = {
        "rule":  {"level": 10, "description": "Test de conexión Sentinel"},
        "agent": {"name":  "test-host"},
        "data":  {"srcip": "1.2.3.4"}
    }
    print("Enviando alerta de prueba a Sentinel...")
    send(test_alert)


if __name__ == "__main__":
    if "--test" in sys.argv:
        test_connection()
        sys.exit(0)

    # Leer alerta — desde archivo (Wazuh) o stdin (cualquier otro)
    try:
        if len(sys.argv) > 1:
            with open(sys.argv[1]) as f:
                alert = json.load(f)
        else:
            raw = sys.stdin.read().strip()
            alert = json.loads(raw) if raw else {}

        if alert:
            send(alert)

    except json.JSONDecodeError:
        print("[Sentinel] El input no es JSON válido")
    except Exception as e:
        print(f"[Sentinel] Error: {e}")
