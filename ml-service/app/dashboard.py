"""
Dashboard de status — HTML puro servido por FastAPI.
Sin Grafana, sin dependencias externas.
Acceso: http://localhost:8080
"""
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.db import get_db_conn
from app.config import settings


dashboard_app = FastAPI()


@dashboard_app.get("/")
async def index():
    return await render_dashboard()


async def render_dashboard():
    stats = await _get_stats()
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="1200">
  <title>Sentinel ML — Dashboard</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: Arial, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
    h1 {{ font-size: 1.5rem; color: #60a5fa; margin-bottom: 0.25rem; }}
    .subtitle {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: #1e2330; border-radius: 10px; padding: 1.25rem; border: 1px solid #2d3748; }}
    .card .label {{ font-size: 0.75rem; color: #64748b; margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: .05em; }}
    .card .value {{ font-size: 1.75rem; font-weight: bold; color: #f1f5f9; }}
    .card .sub {{ font-size: 0.75rem; color: #64748b; margin-top: 0.25rem; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: bold; }}
    .green {{ background: #14532d; color: #4ade80; }}
    .amber {{ background: #451a03; color: #fbbf24; }}
    .red   {{ background: #450a0a; color: #f87171; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e2330; border-radius: 10px; overflow: hidden; }}
    th {{ background: #1b3a6b; color: #93c5fd; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; }}
    td {{ padding: 0.65rem 1rem; font-size: 0.85rem; border-bottom: 1px solid #2d3748; }}
    tr:last-child td {{ border-bottom: none; }}
    .mode-dummy {{ color: #94a3b8; }}
    .mode-shadow {{ color: #fbbf24; }}
    .mode-live  {{ color: #4ade80; }}
    .footer {{ margin-top: 2rem; color: #334155; font-size: 0.75rem; text-align: center; }}
    .sandbox-container {{ margin-top: 3rem; background: #1e2330; padding: 1.5rem; border-radius: 10px; border: 1px solid #2d3748; }}
    .sandbox-container h2 {{ color: #818cf8; font-size: 1.25rem; margin-bottom: 0.5rem; }}
    .sandbox-container input {{ padding: 0.5rem; background: #0f1117; color: white; border: 1px solid #475569; border-radius: 5px; margin-right: 1rem; }}
    .sandbox-container button {{ padding: 0.5rem 1rem; background: #2563eb; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; transition: background 0.2s; }}
    .sandbox-container button:hover {{ background: #1d4ed8; }}
    .sandbox-container .status {{ margin-top: 1rem; color: #fbbf24; font-size: 0.85rem; font-weight: bold; }}
    .sandbox-container pre {{ margin-top: 1rem; background: #0f1117; padding: 1rem; border-radius: 5px; color: #a5b4fc; overflow-x: auto; font-size: 0.85rem; font-family: monospace; border: 1px dashed #475569; min-height: 100px; }}
  </style>
</head>
<body>
  <h1>GRC ML Service</h1>
  <p class="subtitle">Motor de detección de anomalías — actualiza cada 20 minutos.</p>

  <div class="grid">
    <div class="card">
      <div class="label">Modo del modelo</div>
      <div class="value mode-{stats['mode'].lower()}">{stats['mode']}</div>
      <div class="sub">X-Model-Mode header</div>
    </div>
    <div class="card">
      <div class="label">Circuit Breaker</div>
      <div class="value"><span class="badge {'green' if stats['cb'] == 'CLOSED' else 'amber' if stats['cb'] == 'HALF_OPEN' else 'red'}">{stats['cb']}</span></div>
      <div class="sub">Estado del ML Service</div>
    </div>
    <div class="card">
      <div class="label">Eventos hoy</div>
      <div class="value">{stats['events_today']}</div>
      <div class="sub">Logs normalizados</div>
    </div>
    <div class="card">
      <div class="label">Pendientes</div>
      <div class="value">{stats['pending']}</div>
      <div class="sub">Requieren aprobación</div>
    </div>
    <div class="card">
      <div class="label">Aprobadas</div>
      <div class="value" style="color:#4ade80">{stats['approved']}</div>
      <div class="sub">Últimas 24h</div>
    </div>
    <div class="card">
      <div class="label">Rechazadas</div>
      <div class="value" style="color:#f87171">{stats['rejected']}</div>
      <div class="sub">Últimas 24h</div>
    </div>
  </div>

  <table>
    <thead>
      <tr><th>ID</th><th>Activo</th><th>Anomaly Score</th><th>Estado</th><th>SHAP</th><th>Creada</th></tr>
    </thead>
    <tbody>
      {''.join(_rec_row(r) for r in stats['recent']) if stats['recent'] else '<tr><td colspan="6" style="text-align:center;color:#475569">Sin recomendaciones aún. Ejecuta el simulador.</td></tr>'}
    </tbody>
  </table>

  <div class="sandbox-container">
    <h2>🧪 Laboratorio Forense (Sandbox Tester UI)</h2>
    <p class="subtitle" style="margin-bottom:1rem;">Prueba la subida de un JSON o JSONL crudo al Motor Agnóstico. Devuelve métricas financieras sin procesar.</p>
    <input type="file" id="sandboxFile" accept=".json,.jsonl" />
    <button onclick="testSandbox()">Procesar Archivo</button>
    <div class="status" id="testStatus">Esperando archivo...</div>
    <pre id="sandboxResult">AQUÍ APARECERÁ EL JSON PURO DEL RESULTADO ISO 27005...</pre>
  </div>

  <p class="footer">GRC ML Service v1.0 — ISO 27001 / 42001 — Modo: {stats['mode']}</p>
  
  <script>
  async function testSandbox() {{
      const fileInput = document.getElementById('sandboxFile');
      if (!fileInput.files.length) return alert('Selecciona un archivo json o jsonl');
      
      document.getElementById('testStatus').innerText = '⏳ Subiendo archivo por Multipart (Paso 1/2)...';
      document.getElementById('sandboxResult').innerText = '';
      
      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('allow_telemetry_training', 'true');
      
      try {{
          const urlGateway = 'http://localhost:8001/gateway/sandbox';
          let res = await fetch(urlGateway, {{ method: 'POST', body: formData }});
          if (!res.ok) throw new Error("Fallo al subir archivo. HTTP " + res.status);
          
          let data = await res.json();
          const sessionId = data.session_id;
          
          document.getElementById('testStatus').innerText = `✅ ¡Ingesta exitosa! Dispacheado al Celery Worker (Session ID: ${{sessionId}})\n🧠 Calculando IsolationForest (Esperando 3s)...`;
          
          setTimeout(async () => {{
              document.getElementById('testStatus').innerText = `🧠 Solicitando Pipeline Híbrido al backend...`;
              let resPol = await fetch(urlGateway + '/' + sessionId);
              let finalData = await resPol.json();
              document.getElementById('testStatus').innerText = `✅ Evaluación Financiera (ALE) y Geométrica Completada`;
              document.getElementById('sandboxResult').innerText = JSON.stringify(finalData, null, 2);
          }}, 3000);
          
      }} catch(err) {{
          document.getElementById('testStatus').innerText = '❌ Error de Conexión: ' + err.message;
      }}
  }}
  </script>
</body>
</html>"""
    return HTMLResponse(html)


def _rec_row(r):
    score = float(r.get('anomaly_score', 0))
    color = '#f87171' if score > 0.7 else '#fbbf24' if score > 0.4 else '#4ade80'
    status = r.get('status', '')
    status_color = 'amber' if status == 'PENDING' else 'green' if status == 'APPROVED' else 'red'
    shap = '✓' if r.get('shap_ready') else '...'
    ts = str(r.get('created_at', ''))[:16]
    rid = str(r.get('id', ''))[:8]
    return f"""<tr>
      <td style="color:#64748b;font-size:0.75rem">{rid}...</td>
      <td>{r.get('asset_id','—')}</td>
      <td style="color:{color};font-weight:bold">{score:.3f}</td>
      <td><span class="badge {status_color}">{status}</span></td>
      <td style="color:#64748b">{shap}</td>
      <td style="color:#64748b">{ts}</td>
    </tr>"""


async def _get_stats() -> dict:
    try:
        async with get_db_conn() as conn:
            cb_row = await conn.fetchrow("SELECT state FROM ml_circuit_breaker LIMIT 1")
            ev_row = await conn.fetchrow(
                "SELECT COUNT(*) as c FROM normalized_features WHERE created_at > NOW() - INTERVAL '1 day'"
            )
            pend = await conn.fetchval("SELECT COUNT(*) FROM ml_recommendations WHERE status='PENDING'")
            appr = await conn.fetchval(
                "SELECT COUNT(*) FROM ml_recommendations WHERE status='APPROVED' AND created_at > NOW() - INTERVAL '1 day'"
            )
            reje = await conn.fetchval(
                "SELECT COUNT(*) FROM ml_recommendations WHERE status='REJECTED' AND created_at > NOW() - INTERVAL '1 day'"
            )
            recent = await conn.fetch(
                "SELECT id, asset_id, anomaly_score, status, shap_ready, created_at FROM ml_recommendations ORDER BY created_at DESC LIMIT 10"
            )
        return {
            "mode": settings.MODEL_MODE,
            "cb": cb_row["state"] if cb_row else "UNKNOWN",
            "events_today": ev_row["c"] if ev_row else 0,
            "pending": pend or 0,
            "approved": appr or 0,
            "rejected": reje or 0,
            "recent": [dict(r) for r in recent]
        }
    except Exception:
        return {"mode": settings.MODEL_MODE, "cb": "ERROR", "events_today": 0,
                "pending": 0, "approved": 0, "rejected": 0, "recent": []}


if __name__ == "__main__":
    uvicorn.run("app.dashboard:dashboard_app", host="0.0.0.0", port=8080, reload=False)
