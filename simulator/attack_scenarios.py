"""
Sentinel Simulator — Generador de eventos de ataque realistas
Permite probar todo el sistema sin SIEM real ni GRC conectado.

Uso:
    python attack_scenarios.py --scenario lateral_movement
    python attack_scenarios.py --scenario brute_force
    python attack_scenarios.py --scenario normal  # para entrenar baseline
    python attack_scenarios.py --all              # todos los escenarios
"""
import httpx, hmac, hashlib, time, json, argparse, os

ML_API_URL  = os.getenv("ML_API_URL", "http://localhost:8001")
CLIENT_ID   = os.getenv("CLIENT_ID", "sim-client")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "sim-secret-dev")


SCENARIOS = {

    "lateral_movement": [
        {
            "_description": "Paso 1: Escaneo de directorios en servidor web",
            "rule": {"level": 10, "description": "Directory traversal scan detected",
                     "groups": ["web", "attack"]},
            "agent": {"name": "web-server-prod"},
            "data": {"srcip": "192.168.1.105"},
            "asset_value": 0.7
        },
        {
            "_description": "Paso 2: SSH exitoso desde mismo IP hacia DB (4 min después)",
            "_delay_s": 240,
            "rule": {"level": 12, "description": "SSH authentication success from suspicious IP",
                     "groups": ["sshd", "authentication_success"]},
            "agent": {"name": "db-server-prod"},
            "data": {"srcip": "192.168.1.105"},
            "asset_value": 0.95
        }
    ],

    "brute_force": [
        {
            "_description": f"Intento {i+1}/20 de fuerza bruta SSH",
            "_delay_s": 3,
            "rule": {"level": 8, "description": "Multiple SSH authentication failures",
                     "groups": ["sshd", "authentication_failed"]},
            "agent": {"name": "bastion-host"},
            "data": {"srcip": "10.0.0.55"},
            "asset_value": 0.6
        }
        for i in range(20)
    ],

    "data_exfiltration": [
        {
            "_description": "Descarga masiva de datos fuera de horario",
            "rule": {"level": 11, "description": "Large data transfer to external IP at unusual hour",
                     "groups": ["firewall", "data_loss"]},
            "agent": {"name": "fileserver-01"},
            "data": {"srcip": "10.0.0.22"},
            "asset_value": 0.9
        }
    ],

    "sentinel_alert": [
        {
            "_description": "Alerta crítica de Microsoft Sentinel",
            "Severity": "Critical",
            "IncidentNumber": 4892,
            "Title": "Suspicious PowerShell execution with encoded command",
            "Entities": [{"HostName": "workstation-42", "Address": "172.16.0.42"}],
            "asset_value": 0.75
        }
    ],

    "normal": [
        {
            "_description": f"Evento normal #{i+1}",
            "_delay_s": 1,
            "rule": {"level": 2, "description": "User logged in successfully",
                     "groups": ["authentication_success"]},
            "agent": {"name": f"workstation-{i+1:02d}"},
            "data": {"srcip": f"192.168.1.{10+i}"},
            "asset_value": 0.3
        }
        for i in range(30)
    ]
}


def sign_request(payload: str) -> tuple[str, str]:
    timestamp = str(int(time.time()))
    sig = hmac.new(
        CLIENT_SECRET.encode(),
        f"{payload}{timestamp}{CLIENT_ID}".encode(),
        hashlib.sha256
    ).hexdigest()
    return sig, timestamp


def send_event(event: dict) -> tuple:
    clean = {k: v for k, v in event.items() if not k.startswith("_")}
    payload = json.dumps(clean)
    signature, timestamp = sign_request(payload)

    try:
        r = httpx.post(
            f"{ML_API_URL}/infer",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Client-ID": CLIENT_ID,
                "X-GRC-Signature": signature,
                "X-Timestamp": timestamp
            },
            timeout=10
        )
        if r.status_code != 200:
            print(f"  [ERROR] HTTP {r.status_code}: {r.text[:200]}")
            return {}, {}
        return r.json(), dict(r.headers)
    except Exception as e:
        print(f"  [ERROR] Conexión fallida: {e}")
        return {}, {}


def run_scenario(name: str):
    events = SCENARIOS.get(name)
    if not events:
        print(f"Escenario '{name}' no encontrado. Disponibles: {list(SCENARIOS.keys())}")
        return

    print(f"\n{'='*60}")
    print(f"ESCENARIO: {name.upper()}")
    print(f"{'='*60}")

    for event in events:
        desc = event.get("_description", "Evento")
        delay = event.get("_delay_s", 0)

        print(f"\n→ {desc}")
        if delay:
            print(f"  (simulando {delay}s de delay...)")
            time.sleep(min(delay, 3))  # max 3s real en demo

        result, headers = send_event(event)

        mode = headers.get("x-model-mode", "?")
        latency = headers.get("x-latency-ms", "?")

        score = result.get('anomaly_score', 0)
        aro   = result.get('aro_suggested', 0)
        print(f"  anomaly_score: {float(score):.3f}")
        print(f"  aro_suggested: {float(aro):.2f}")
        print(f"  lateral_movement: {result.get('lateral_movement_detected', False)}")
        print(f"  model_mode: {mode} | latency: {latency}ms")
        if mode == "DUMMY":
            print(f"  [INFO] Modelo en modo DUMMY — conectividad validada")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Attack Simulator")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()))
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    if args.all:
        for name in SCENARIOS:
            run_scenario(name)
            time.sleep(2)
    elif args.scenario:
        run_scenario(args.scenario)
    else:
        parser.print_help()
