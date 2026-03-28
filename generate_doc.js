const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  LevelFormat, Footer, Header, PageBreak, TabStopType,
  TabStopPosition, SimpleField
} = require("docx");
const fs = require("fs");

// ── Colores corporativos ────────────────────────────────────
const C = {
  navy:      "1B3A6B",
  blue:      "185FA5",
  lightBlue: "E6F1FB",
  teal:      "0F6E56",
  lightTeal: "E1F5EE",
  amber:     "854F0B",
  lightAmb:  "FAEEDA",
  red:       "A32D2D",
  lightRed:  "FCEBEB",
  green:     "3B6D11",
  lightGreen:"EAF3DE",
  gray:      "444441",
  lightGray: "F1EFE8",
  white:     "FFFFFF",
  border:    "CCCCCC",
};

// ── Helpers de párrafo ──────────────────────────────────────
const p = (text, opts = {}) => new Paragraph({
  children: [new TextRun({ text, font: "Arial", size: opts.size || 22,
    bold: opts.bold || false, color: opts.color || "000000",
    italics: opts.italic || false })],
  alignment: opts.align || AlignmentType.LEFT,
  spacing: { before: opts.spaceBefore || 80, after: opts.spaceAfter || 80 },
  indent: opts.indent ? { left: opts.indent } : undefined,
});

const pBullet = (text, ref = "bullets") => new Paragraph({
  numbering: { reference: ref, level: 0 },
  children: [new TextRun({ text, font: "Arial", size: 22 })],
  spacing: { before: 40, after: 40 },
});

const pCode = (text) => new Paragraph({
  children: [new TextRun({ text, font: "Courier New", size: 18, color: "1B3A6B" })],
  spacing: { before: 20, after: 20 },
  indent: { left: 720 },
  shading: { fill: "F1EFE8", type: ShadingType.CLEAR },
});

const spacer = (n = 1) => Array(n).fill(new Paragraph({ children: [new TextRun("")], spacing: { before: 60, after: 60 } }));

const sectionTitle = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  children: [new TextRun({ text, font: "Arial", size: 32, bold: true, color: C.navy })],
  spacing: { before: 320, after: 160 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: C.blue, space: 4 } },
});

const subTitle = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  children: [new TextRun({ text, font: "Arial", size: 26, bold: true, color: C.blue })],
  spacing: { before: 200, after: 100 },
});

const subSubTitle = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_3,
  children: [new TextRun({ text, font: "Arial", size: 24, bold: true, color: C.gray })],
  spacing: { before: 140, after: 80 },
});

// ── Tabla genérica ──────────────────────────────────────────
const border = { style: BorderStyle.SINGLE, size: 1, color: C.border };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

const headerCell = (text, width, color = C.navy) => new TableCell({
  borders, width: { size: width, type: WidthType.DXA },
  shading: { fill: color, type: ShadingType.CLEAR },
  margins: cellMargins,
  children: [new Paragraph({ children: [new TextRun({ text, font: "Arial", size: 20, bold: true, color: C.white })] })]
});

const dataCell = (text, width, fill = C.white, textColor = "000000") => new TableCell({
  borders, width: { size: width, type: WidthType.DXA },
  shading: { fill, type: ShadingType.CLEAR },
  margins: cellMargins,
  children: [new Paragraph({ children: [new TextRun({ text, font: "Arial", size: 20, color: textColor })] })]
});

// ── Tabla de riesgos con badge de color ─────────────────────
const riskRow = (risk, severity, mitigation, color) => new TableRow({
  children: [
    dataCell(risk, 3000),
    new TableCell({
      borders, width: { size: 1200, type: WidthType.DXA },
      shading: { fill: color, type: ShadingType.CLEAR }, margins: cellMargins,
      children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: severity, font: "Arial", size: 18, bold: true,
          color: severity === "ALTO" ? C.red : severity === "MEDIO" ? C.amber : C.green })] })]
    }),
    dataCell(mitigation, 5160),
  ]
});

// ═══════════════════════════════════════════════════════════════
// DOCUMENTO
// ═══════════════════════════════════════════════════════════════
const doc = new Document({
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022",
          alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.",
          alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: C.navy },
        paragraph: { spacing: { before: 320, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: C.blue },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: C.gray },
        paragraph: { spacing: { before: 140, after: 80 }, outlineLevel: 2 } },
    ]
  },
  sections: [{
    properties: {
      page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: C.blue, space: 4 } },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: "SENTINEL ML SERVICE", font: "Arial", size: 18, bold: true, color: C.navy }),
            new TextRun({ text: "   |   Documentación Técnica v1.0", font: "Arial", size: 18, color: C.gray }),
          ]
        })]
      })
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: C.border, space: 4 } },
          spacing: { before: 80 },
          tabStops: [{ type: TabStopType.RIGHT, position: 9360 }],
          children: [
            new TextRun({ text: "Confidencial — Uso interno", font: "Arial", size: 16, color: C.gray }),
            new TextRun({ text: "\tPágina ", font: "Arial", size: 16, color: C.gray }),
            new SimpleField({ instruction: "PAGE", cachedValue: "1", dirty: false }),
          ]
        })]
      })
    },
    children: [

      // ══════════════════════════════════════════════════════
      // PORTADA
      // ══════════════════════════════════════════════════════
      ...spacer(3),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 0, after: 120 },
        children: [new TextRun({ text: "SENTINEL ML SERVICE", font: "Arial", size: 64, bold: true, color: C.navy })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 0, after: 80 },
        children: [new TextRun({ text: "Motor de Detección de Anomalías para GRC", font: "Arial", size: 36, color: C.blue })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: C.blue, space: 8 } },
        spacing: { before: 0, after: 200 },
        children: [new TextRun({ text: "", size: 22 })]
      }),
      ...spacer(1),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 80, after: 40 },
        children: [new TextRun({ text: "Documentación Técnica — v1.0", font: "Arial", size: 24, color: C.gray })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 40, after: 40 },
        children: [new TextRun({ text: "ISO 27001 · ISO 27005 · ISO 42001", font: "Arial", size: 22, color: C.teal, bold: true })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 40, after: 200 },
        children: [new TextRun({ text: "Optimizado para estaciones de trabajo con 8 GB RAM", font: "Arial", size: 20, color: C.gray, italics: true })]
      }),
      ...spacer(4),

      // Tabla de metadatos
      new Table({
        width: { size: 6000, type: WidthType.DXA },
        columnWidths: [2000, 4000],
        rows: [
          new TableRow({ children: [headerCell("Clasificación", 2000), dataCell("Confidencial — Uso Interno", 4000)] }),
          new TableRow({ children: [headerCell("Versión", 2000), dataCell("1.0.0", 4000)] }),
          new TableRow({ children: [headerCell("Estado", 2000), dataCell("En Desarrollo — Fase II", 4000, C.lightAmb)] }),
          new TableRow({ children: [headerCell("Stack", 2000), dataCell("Python 3.11 · FastAPI · PostgreSQL · Docker", 4000)] }),
          new TableRow({ children: [headerCell("Normativas", 2000), dataCell("ISO 27001, ISO 27005, ISO 42001", 4000)] }),
        ]
      }),

      // Salto de página
      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 1. RESUMEN EJECUTIVO
      // ══════════════════════════════════════════════════════
      sectionTitle("1. Resumen Ejecutivo"),
      p("Sentinel ML Service es un microservicio de inteligencia artificial diseñado para transformar sistemas GRC (Governance, Risk & Compliance) de reactivos a proactivos. El sistema detecta anomalías en logs de seguridad en tiempo real y genera recomendaciones auditables bajo los estándares ISO 27001, ISO 27005 e ISO 42001."),
      ...spacer(1),
      p("El sistema está optimizado para correr completamente en una laptop o estación de trabajo con 8 GB de RAM, sin requerir infraestructura cloud, GPUs ni licencias de software. Todo el stack se orquesta con Docker Compose en un solo comando.", { bold: false }),
      ...spacer(1),
      subTitle("1.1 Propuesta de valor"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2500, 6860],
        rows: [
          new TableRow({ children: [headerCell("Capacidad", 2500), headerCell("Descripción", 6860)] }),
          new TableRow({ children: [dataCell("Detección en <50ms", 2500, C.lightTeal, C.teal), dataCell("Isolation Forest con inferencia en tiempo real sin GPU", 6860)] }),
          new TableRow({ children: [dataCell("Zero-Day Ready", 2500, C.lightTeal, C.teal), dataCell("Detecta ataques nunca vistos sin reglas predefinidas", 6860)] }),
          new TableRow({ children: [dataCell("Human-in-the-Loop", 2500, C.lightTeal, C.teal), dataCell("Control humano obligatorio bajo ISO 42001 antes de aplicar cambios", 6860)] }),
          new TableRow({ children: [dataCell("Auditoría Inmutable", 2500, C.lightTeal, C.teal), dataCell("Hash Chain SHA-256 verificable por SQL, sin blockchain externa", 6860)] }),
          new TableRow({ children: [dataCell("SHAP Explicable", 2500, C.lightTeal, C.teal), dataCell("Explicaciones en español para auditores — disponibles en <30s", 6860)] }),
          new TableRow({ children: [dataCell("Multi-cliente", 2500, C.lightTeal, C.teal), dataCell("HMAC-SHA256 con Client ID/Secret — listo para SaaS", 6860)] }),
        ]
      }),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 2. ARQUITECTURA
      // ══════════════════════════════════════════════════════
      sectionTitle("2. Arquitectura del Sistema"),
      p("El sistema sigue una arquitectura de microservicios desacoplados. La carga computacional de la IA nunca afecta la disponibilidad del GRC Core. Cada componente falla de forma independiente con fallback automático."),
      ...spacer(1),
      subTitle("2.1 Componentes principales"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2200, 1400, 5760],
        rows: [
          new TableRow({ children: [headerCell("Componente", 2200), headerCell("RAM Est.", 1400), headerCell("Función", 5760)] }),
          new TableRow({ children: [dataCell("GRC Core (FastAPI)", 2200), dataCell("~350 MB", 1400), dataCell("API de inferencia, endpoints de gobernanza, health checks", 5760)] }),
          new TableRow({ children: [dataCell("PostgreSQL + TimescaleDB", 2200), dataCell("~400 MB", 1400), dataCell("Feature Store con retención automática de 90 días vía pg_partman", 5760)] }),
          new TableRow({ children: [dataCell("ML Service (Isolation Forest)", 2200), dataCell("~450 MB", 1400), dataCell("Motor de detección de anomalías, carga y verifica modelo con SHA-256", 5760)] }),
          new TableRow({ children: [dataCell("Celery + Redis", 2200), dataCell("~330 MB", 1400), dataCell("Worker asíncrono para SHAP — nunca bloquea la inferencia", 5760)] }),
          new TableRow({ children: [dataCell("Sistema y Docker", 2200), dataCell("~2 GB", 1400), dataCell("SO, runtime de contenedores, overhead de red", 5760)] }),
          new TableRow({ children: [
            dataCell("TOTAL", 2200, C.lightBlue, C.blue),
            dataCell("~3.5 GB", 1400, C.lightBlue, C.blue),
            dataCell("Margen libre: ~4.5 GB para IDE, demos y sistema operativo", 5760, C.lightBlue, C.blue)
          ]}),
        ]
      }),
      ...spacer(1),
      subTitle("2.2 Flujo de datos end-to-end"),
      pBullet("SIEM (Wazuh/Sentinel) envía evento crudo en formato JSON al GRC Core."),
      pBullet("El SIEM Normalizer detecta el tipo de log y lo transforma al vector de features estándar."),
      pBullet("El vector se almacena en normalized_features (Feature Store) con su SHA-256."),
      pBullet("El GRC llama POST /infer con el vector. La respuesta llega en <50ms."),
      pBullet("En paralelo, Celery encola el cálculo de SHAP (disponible en ~30s)."),
      pBullet("Se crea un registro MlRecommendation en estado PENDIENTE."),
      pBullet("El COMPANY_ADMIN aprueba o rechaza. La decisión se firma en el AuditLog con Hash Chain."),
      ...spacer(1),
      subTitle("2.3 Modos de operación"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [1600, 1800, 5960],
        rows: [
          new TableRow({ children: [headerCell("Modo", 1600), headerCell("Fase", 1800), headerCell("Comportamiento", 5960)] }),
          new TableRow({ children: [dataCell("DUMMY", 1600, C.lightGray), dataCell("Fase II", 1800), dataCell("Retorna scores fijos de 0.5. Valida conectividad. Header X-Model-Mode: DUMMY visible.", 5960)] }),
          new TableRow({ children: [dataCell("SHADOW", 1600, C.lightAmb), dataCell("Fase III", 1800), dataCell("Modelo real activo, genera recomendaciones reales pero sin impacto en el GRC.", 5960)] }),
          new TableRow({ children: [dataCell("LIVE", 1600, C.lightTeal), dataCell("Fase IV", 1800), dataCell("Gobernanza completa. Recomendaciones requieren aprobación humana obligatoria.", 5960)] }),
        ]
      }),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 3. ESTRUCTURA DE ARCHIVOS
      // ══════════════════════════════════════════════════════
      sectionTitle("3. Estructura de Archivos y Dockerización"),
      subTitle("3.1 Árbol de directorios"),
      pCode("sentinel-ml/"),
      pCode("├── docker-compose.yml          # Stack completo en un comando"),
      pCode("├── .env.example                # Variables de entorno documentadas"),
      pCode("├── scripts/"),
      pCode("│   └── init_db.sql             # Schema completo con TimescaleDB"),
      pCode("├── ml-service/"),
      pCode("│   ├── Dockerfile"),
      pCode("│   ├── requirements.txt"),
      pCode("│   └── app/"),
      pCode("│       ├── main.py             # FastAPI — /infer, /health, /recommendations"),
      pCode("│       ├── config.py           # Settings via pydantic-settings"),
      pCode("│       ├── worker.py           # Celery — SHAP asíncrono"),
      pCode("│       ├── auth/"),
      pCode("│       │   ├── hmac_validator.py    # Verificación por request"),
      pCode("│       │   └── client_manager.py    # CLI de aprovisionamiento"),
      pCode("│       ├── models/"),
      pCode("│       │   ├── trainer.py           # Entrenamiento Isolation Forest"),
      pCode("│       │   ├── inferrer.py          # Inferencia + movimiento lateral"),
      pCode("│       │   └── registry.py          # Versionado de modelos"),
      pCode("│       ├── normalizers/"),
      pCode("│       │   ├── base.py              # Wazuh + Sentinel + Syslog"),
      pCode("│       │   └── fixtures/            # Payloads reales para pytest"),
      pCode("│       ├── audit/"),
      pCode("│       │   └── hash_chain.py        # SHA-256 encadenado"),
      pCode("│       └── drift/"),
      pCode("│           └── psi_monitor.py       # PSI + Circuit Breaker"),
      pCode("├── simulator/"),
      pCode("│   └── attack_scenarios.py     # 5 escenarios de ataque simulados"),
      pCode("└── tests/"),
      pCode("    └── test_all.py             # Tests sin infraestructura real"),
      ...spacer(1),
      subTitle("3.2 Levantar el sistema"),
      p("Todos los comandos se ejecutan desde la raíz del proyecto:"),
      ...spacer(1),
      pCode("# 1. Configurar variables de entorno"),
      pCode("cp .env.example .env"),
      ...spacer(1),
      pCode("# 2. Levantar todo el stack"),
      pCode("docker compose up -d"),
      ...spacer(1),
      pCode("# 3. Verificar que todo esté vivo"),
      pCode("curl http://localhost:8001/health"),
      ...spacer(1),
      pCode("# 4. Correr suite de tests"),
      pCode("docker compose exec ml-api pytest tests/ -v"),
      ...spacer(1),
      pCode("# 5. Entrenar primer modelo con datos sintéticos"),
      pCode("docker compose exec ml-api python -m app.models.trainer --mode synthetic"),
      ...spacer(1),
      pCode("# 6. Simular escenarios de ataque"),
      pCode("docker compose --profile testing run simulator python attack_scenarios.py --all"),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 4. SEGURIDAD (MLSecOps)
      // ══════════════════════════════════════════════════════
      sectionTitle("4. Seguridad — MLSecOps"),
      p("La IA es un vector de ataque. El sistema implementa defensas en cuatro capas independientes."),
      ...spacer(1),
      subTitle("4.1 Autenticación HMAC-SHA256"),
      p("Cada request al endpoint /infer debe incluir tres headers obligatorios:"),
      pBullet("X-Client-ID: identificador del cliente registrado en la base de datos."),
      pBullet("X-GRC-Signature: HMAC-SHA256 del payload + timestamp + client_id firmado con el client_secret."),
      pBullet("X-Timestamp: timestamp Unix. Requests con más de 30 segundos de diferencia son rechazados automáticamente para prevenir replay attacks."),
      ...spacer(1),
      p("El servidor recalcula la firma con el mismo algoritmo y usa hmac.compare_digest() para comparación en tiempo constante, previniendo timing attacks.", { italic: true }),
      ...spacer(1),
      subTitle("4.2 Integridad del modelo (MLSecOps)"),
      pBullet("Cada archivo .pkl tiene un .sha256 generado en el momento del entrenamiento."),
      pBullet("Antes de cargar cualquier modelo en memoria, el inferrer recalcula el SHA-256 y lo compara con el archivo de referencia."),
      pBullet("Si hay discrepancia (posible tampering), el sistema lanza RuntimeError y el Circuit Breaker se abre automáticamente."),
      ...spacer(1),
      subTitle("4.3 Hash Chain de auditoría (ISO 27001 A.12.4.2)"),
      p("Cada registro del AuditLog incluye el campo previous_hash con el SHA-256 del registro anterior. La cadena comienza con el valor literal 'GENESIS'. El endpoint GET /audit/verify recorre toda la cadena y recalcula cada hash. Si un registro fue modificado manualmente en la base de datos, la cadena se rompe en ese punto y el sistema reporta el ID exacto del registro comprometido."),
      ...spacer(1),
      subTitle("4.4 Circuit Breaker"),
      p("El Circuit Breaker tiene tres estados persistidos en la tabla ml_circuit_breaker:"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [1800, 3000, 4560],
        rows: [
          new TableRow({ children: [headerCell("Estado", 1800), headerCell("Condición", 3000), headerCell("Comportamiento", 4560)] }),
          new TableRow({ children: [dataCell("CLOSED", 1800, C.lightTeal, C.teal), dataCell("Operación normal", 3000), dataCell("ML Service responde normalmente", 4560)] }),
          new TableRow({ children: [dataCell("OPEN", 1800, C.lightRed, C.red), dataCell("5+ fallos consecutivos o PSI > 0.2", 3000), dataCell("Fallback automático a lógica determinista ISO 27005", 4560)] }),
          new TableRow({ children: [dataCell("HALF_OPEN", 1800, C.lightAmb, C.amber), dataCell("60s después de OPEN", 3000), dataCell("Prueba si el servicio se recuperó con un request de prueba", 4560)] }),
        ]
      }),
      ...spacer(1),
      subTitle("4.5 PSI Monitor (Drift Detection)"),
      p("El Population Stability Index compara la distribución de severity_score entre la última semana y las tres semanas anteriores. Un PSI mayor a 0.2 indica que el formato de logs del SIEM cambió significativamente (por ejemplo, una actualización de Wazuh), y el sistema apaga la IA automáticamente para evitar falsos positivos masivos."),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 5. NORMALIZACIÓN SIEM
      // ══════════════════════════════════════════════════════
      sectionTitle("5. Universal SIEM Normalizer"),
      p("El Normalizer es el componente más crítico del sistema. Transforma logs heterogéneos de distintos proveedores en un vector de features estándar que el modelo puede procesar."),
      ...spacer(1),
      subTitle("5.1 Arquitectura de plugins"),
      p("El router prueba los plugins en orden de especificidad. El último plugin (GenericSyslog) actúa como catch-all y nunca falla:"),
      pBullet("WazuhNormalizer: detecta logs con los campos rule y agent. Mapea niveles 1-15 a scores 0.0-1.0."),
      pBullet("SentinelNormalizer: detecta logs con Severity e IncidentNumber. Mapea Low/Medium/High/Critical a scores."),
      pBullet("GenericSyslogNormalizer: catch-all para pfSense, firewalls, EDRs. Analiza keywords en el campo message."),
      ...spacer(1),
      subTitle("5.2 Vector de features estándar"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2500, 1500, 5360],
        rows: [
          new TableRow({ children: [headerCell("Feature", 2500), headerCell("Rango", 1500), headerCell("Descripción", 5360)] }),
          new TableRow({ children: [dataCell("severity_score", 2500), dataCell("0.0 – 1.0", 1500), dataCell("Severidad normalizada del evento", 5360)] }),
          new TableRow({ children: [dataCell("asset_value", 2500), dataCell("0.0 – 1.0", 1500), dataCell("Valor del activo involucrado (configurado por el cliente)", 5360)] }),
          new TableRow({ children: [dataCell("timestamp_delta", 2500), dataCell("segundos", 1500), dataCell("Tiempo desde el evento anterior del mismo activo", 5360)] }),
          new TableRow({ children: [dataCell("event_type_id", 2500), dataCell("0 – 100", 1500), dataCell("Hash del tipo de evento normalizado a rango entero", 5360)] }),
        ]
      }),
      ...spacer(1),
      subTitle("5.3 Suite de tests obligatoria"),
      p("Cada plugin tiene fixtures de payloads reales capturados de Wazuh y Sentinel. Los tests deben ejecutarse en CI/CD antes de cualquier deploy para detectar cambios de formato de logs:"),
      pCode("pytest tests/test_all.py::TestWazuhNormalizer -v"),
      pCode("pytest tests/test_all.py::TestSentinelNormalizer -v"),
      pCode("pytest tests/test_all.py::TestGenericSyslog -v"),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 6. MODELO DE IA
      // ══════════════════════════════════════════════════════
      sectionTitle("6. Modelo de Inteligencia Artificial"),
      subTitle("6.1 Isolation Forest — Justificación"),
      p("Se seleccionó Isolation Forest como algoritmo principal por tres razones técnicas:"),
      pBullet("No supervisado: no requiere datos etiquetados de ataques para comenzar. Detecta lo que es estadísticamente raro en el contexto de cada activo."),
      pBullet("Zero-Day Ready: detecta ataques nunca vistos que no están en las reglas del SIEM, porque el criterio es anomalía, no coincidencia de regla."),
      pBullet("Bajo consumo: inferencia en <10ms por vector. Sin GPU requerida. Entrenamiento completo en <2 minutos con 10,000 registros en CPU."),
      ...spacer(1),
      subTitle("6.2 Estrategia Cold Start — Weak Supervision"),
      p("El problema del 'huevo y la gallina': no hay datos etiquetados de ataques porque el sistema aún no está en producción. La solución es Weak Supervision:"),
      pBullet("Fase de recolección: el SIEM Normalizer puebla el Feature Store silenciosamente durante las Fases I y II."),
      pBullet("Etiquetado automático: todo evento que el SIEM clasificó con severity_score > 0.75 se etiqueta automáticamente como anomalía (label = -1). El resto es tráfico normal (label = 1)."),
      pBullet("Resultado: dataset de miles de filas sin esfuerzo manual, listo para el primer entrenamiento en la Fase III."),
      ...spacer(1),
      subTitle("6.3 Dry-run antes de publicar"),
      p("Antes de registrar un modelo nuevo en el registry, siempre ejecutar el modo --dry-run para verificar que el F1 Score mejora respecto al modelo activo:"),
      pCode("python -m app.models.trainer --mode historical --dry-run"),
      p("El sistema mostrará el F1 Score, la cantidad de muestras y la distribución de anomalías sin guardar nada. Solo si las métricas son satisfactorias se procede sin --dry-run.", { italic: true }),
      ...spacer(1),
      subTitle("6.4 SHAP — Explicabilidad (ISO 42001)"),
      p("SHAP (SHapley Additive exPlanations) calcula la contribución de cada feature a la puntuación de anomalía. Es obligatorio bajo ISO 42001 para garantizar que la IA no sea una caja negra."),
      ...spacer(1),
      p("Implementación crítica: SHAP nunca corre en el path síncrono de inferencia. Se encola en Celery y la explicación queda disponible en la recomendación en aproximadamente 30 segundos. Ejemplo de explicación generada:"),
      ...spacer(1),
      pCode("\"La frecuencia de eventos es inusual — delta de 3s vs. baseline normal de 300s.\""),
      pCode("\"Activo de alto valor (95%) involucrado en un evento anómalo.\""),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 7. DETECCIÓN AVANZADA
      // ══════════════════════════════════════════════════════
      sectionTitle("7. Detección Avanzada de Amenazas"),
      subTitle("7.1 Detección de movimiento lateral"),
      p("El inferrer analiza no solo el evento actual sino su contexto histórico en el Feature Store. La lógica es:"),
      pBullet("Si el evento tiene severity_score >= 0.6 y un src_ip definido."),
      pBullet("Y existe un evento de tipo SSH authentication success desde el mismo src_ip."),
      pBullet("Hacia un activo diferente, en los últimos 5 minutos."),
      pBullet("Entonces el campo lateral_movement_detected = true en la respuesta."),
      ...spacer(1),
      p("Esto permite detectar el patrón clásico de ataque: escaneo de servidor web → pivoting SSH hacia la base de datos, antes de que se complete la cadena de exfiltración."),
      ...spacer(1),
      subTitle("7.2 Calibración de eficacia de controles"),
      p("Si los logs del SIEM muestran que un control específico (por ejemplo, Firewall A.12.1.1) está dejando pasar paquetes anómalos que debería bloquear, el sistema genera una recomendación de degradar el valor_eficacia del control en el GRC. Esto recalcula automáticamente el riesgo residual y dispara alertas de cumplimiento antes de que se pierda la certificación ISO 27001."),
      ...spacer(1),
      subTitle("7.3 Correlación multi-activo"),
      p("El Feature Store indexado por asset_id y src_ip permite buscar patrones que afectan múltiples activos en ventanas de tiempo configurables. Las consultas están optimizadas con índices TimescaleDB y se ejecutan en milisegundos incluso con 90 días de histórico."),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 8. ROADMAP
      // ══════════════════════════════════════════════════════
      sectionTitle("8. Roadmap de Implementación — 6 Meses"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [1200, 1600, 2600, 3960],
        rows: [
          new TableRow({ children: [
            headerCell("Fase", 1200), headerCell("Duración", 1600),
            headerCell("Entregable", 2600), headerCell("Criterio de cierre", 3960)
          ]}),
          new TableRow({ children: [
            dataCell("I", 1200, C.lightGreen, C.green),
            dataCell("Semanas 1–6", 1600),
            dataCell("Docker Compose + SIEM Normalizer recolectando datos", 2600),
            dataCell("500 eventos normalizados sin errores en 48h continuas", 3960)
          ]}),
          new TableRow({ children: [
            dataCell("II", 1200, C.lightBlue, C.blue),
            dataCell("Semanas 7–11", 1600),
            dataCell("Integración con modelo DUMMY. Validación de conectividad.", 2600),
            dataCell("100% de requests al /infer retornan respuesta con header X-Model-Mode: DUMMY", 3960)
          ]}),
          new TableRow({ children: [
            dataCell("III", 1200, C.lightAmb, C.amber),
            dataCell("Semanas 12–18", 1600),
            dataCell("Isolation Forest en modo SHADOW. Sin impacto real en GRC.", 2600),
            dataCell("F1 Score > 0.70 en dataset de validación. PSI < 0.2 por 2 semanas consecutivas.", 3960)
          ]}),
          new TableRow({ children: [
            dataCell("IV", 1200, C.lightTeal, C.teal),
            dataCell("Semanas 19–24", 1600),
            dataCell("Gobernanza completa activa + SHAP asíncrono + auditoría ISO.", 2600),
            dataCell("Simulación de auditoría exitosa: evidencia trazable de log SIEM a decisión humana.", 3960)
          ]}),
        ]
      }),
      ...spacer(1),
      subTitle("8.1 Hitos técnicos por fase"),
      p("Fase I — Infraestructura:", { bold: true }),
      pBullet("Docker Compose levanta GRC Core, PostgreSQL, Redis y ML Worker sin errores."),
      pBullet("Schema de base de datos aplicado con TimescaleDB y pg_partman configurado."),
      pBullet("SIEM Normalizer procesando logs de Wazuh (plugin real o simulado)."),
      pBullet("Tests unitarios pasando al 100%."),
      ...spacer(1),
      p("Fase II — Validación:", { bold: true }),
      pBullet("Endpoint /infer respondiendo con X-Model-Mode: DUMMY visible en todos los responses."),
      pBullet("HMAC auth validado con el simulador (attack_scenarios.py)."),
      pBullet("Hash Chain generando y verificando correctamente."),
      pBullet("Circuit Breaker abriendo y cerrando ante fallos simulados."),
      ...spacer(1),
      p("Fase III — Observación:", { bold: true }),
      pBullet("Primer modelo Isolation Forest entrenado con --dry-run validado."),
      pBullet("Recomendaciones visibles en la interfaz con anomaly_score real."),
      pBullet("SHAP asíncrono retornando explicaciones en español en <30s."),
      pBullet("Detección de movimiento lateral funcionando con escenarios simulados."),
      ...spacer(1),
      p("Fase IV — Producción:", { bold: true }),
      pBullet("Flujo de aprobación COMPANY_ADMIN completamente funcional."),
      pBullet("PSI monitor corriendo semanalmente y reportando drift."),
      pBullet("Documentación ISO 42001 generada automáticamente por cada inferencia."),
      pBullet("Auditoría interna simulada exitosa con evidencia trazable end-to-end."),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 9. PRUEBAS SIN GRC
      // ══════════════════════════════════════════════════════
      sectionTitle("9. Estrategia de Pruebas sin GRC Real"),
      p("El sistema puede demostrarse completamente funcional sin ningún GRC ni SIEM real. El módulo simulator/ contiene cinco escenarios de ataque que cubren los casos de uso principales."),
      ...spacer(1),
      subTitle("9.1 Escenarios incluidos en el simulador"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2400, 1800, 5160],
        rows: [
          new TableRow({ children: [headerCell("Escenario", 2400), headerCell("SIEM Simulado", 1800), headerCell("Qué valida", 5160)] }),
          new TableRow({ children: [dataCell("lateral_movement", 2400), dataCell("Wazuh", 1800), dataCell("Detección de escaneo + SSH pivoting en < 5 minutos entre activos distintos", 5160)] }),
          new TableRow({ children: [dataCell("brute_force", 2400), dataCell("Wazuh", 1800), dataCell("20 intentos fallidos de SSH — detección de patrón de volumen", 5160)] }),
          new TableRow({ children: [dataCell("data_exfiltration", 2400), dataCell("Wazuh", 1800), dataCell("Transferencia masiva fuera de horario — anomalía de timestamp_delta", 5160)] }),
          new TableRow({ children: [dataCell("sentinel_alert", 2400), dataCell("Sentinel", 1800), dataCell("Alerta crítica de PowerShell — validación del plugin Sentinel", 5160)] }),
          new TableRow({ children: [dataCell("normal", 2400), dataCell("Wazuh", 1800), dataCell("30 eventos normales — para entrenar el baseline del modelo", 5160)] }),
        ]
      }),
      ...spacer(1),
      subTitle("9.2 Secuencia de demo completa"),
      p("Esta secuencia demuestra el sistema end-to-end en menos de 15 minutos en cualquier laptop:"),
      pBullet("Paso 1: docker compose up -d — stack completo levantado.", "numbers"),
      pBullet("Paso 2: python -m app.models.trainer --mode synthetic — modelo entrenado con datos sintéticos.", "numbers"),
      pBullet("Paso 3: python attack_scenarios.py --scenario normal — 30 eventos normales alimentan el baseline.", "numbers"),
      pBullet("Paso 4: python attack_scenarios.py --scenario lateral_movement — ataque simulado detectado.", "numbers"),
      pBullet("Paso 5: GET /recommendations — recomendación visible en estado PENDIENTE.", "numbers"),
      pBullet("Paso 6: POST /recommendations/{id}/approve — decisión humana firmada en AuditLog.", "numbers"),
      pBullet("Paso 7: GET /audit/verify — cadena de hash verificada e íntegra.", "numbers"),
      ...spacer(1),
      subTitle("9.3 Health check del modelo"),
      p("El endpoint /health/model retorna el estado operacional completo del sistema, incluyendo si el modelo está degradado, cuándo fue entrenado por última vez y el PSI actual. Esto permite detectar problemas antes de que afecten las recomendaciones."),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 10. USOS ADICIONALES
      // ══════════════════════════════════════════════════════
      sectionTitle("10. Casos de Uso Adicionales"),
      p("El sistema fue diseñado como un microservicio independiente. Más allá del GRC, puede aplicarse a los siguientes casos de uso sin modificaciones arquitectónicas."),
      ...spacer(1),
      subTitle("10.1 SOC autónomo para PyMEs"),
      p("Muchas empresas pequeñas no pueden costear un analista de seguridad 24/7. El sistema puede correr en un VPS de bajo costo y actuar como un SOC básico que detecta anomalías en logs, genera tickets automáticos y escala solo los eventos de alta confianza a un humano."),
      ...spacer(1),
      subTitle("10.2 Auditoría continua de proveedores (ISO 27001 A.15)"),
      p("En lugar de auditar a un proveedor una vez al año con documentos estáticos, se conecta el SIEM del proveedor al sistema y se obtiene visibilidad continua de su postura de seguridad. Cualquier degradación del anomaly_score histórico genera una alerta de cumplimiento automáticamente."),
      ...spacer(1),
      subTitle("10.3 Detección de insider threats"),
      p("El Isolation Forest detecta comportamientos estadísticamente raros independientemente de si el origen es externo o interno. Un empleado que descarga 10 GB a las 2am o accede a activos fuera de su perfil habitual genera un anomaly_score alto, igual que un atacante externo."),
      ...spacer(1),
      subTitle("10.4 Due diligence en fusiones y adquisiciones"),
      p("Cuando una empresa va a ser adquirida, este sistema puede generar en semanas un informe de postura de seguridad histórica con evidencia trazable (Hash Chain) que normalmente toma meses de trabajo manual de auditoría."),
      ...spacer(1),
      subTitle("10.5 Plataforma SaaS multi-tenant"),
      p("La arquitectura HMAC con Client ID/Secret ya está preparada para múltiples clientes desde el Día 1. Con una capa de billing y una UI de onboarding, es un producto vendible a múltiples organizaciones desde el mismo servidor. El aprovisionamiento de nuevos clientes toma menos de un minuto vía client_manager.py."),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 11. RIESGOS Y MITIGACIONES
      // ══════════════════════════════════════════════════════
      sectionTitle("11. Riesgos y Mitigaciones"),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [2800, 1200, 5360],
        rows: [
          new TableRow({ children: [headerCell("Riesgo", 2800), headerCell("Nivel", 1200), headerCell("Mitigación implementada", 5360)] }),
          riskRow("SHAP bloquea inferencia en producción", "ALTO", "SHAP en Celery worker asíncrono. Inferencia no espera resultado SHAP.", C.lightRed),
          riskRow("Formato de logs del SIEM cambia con update", "ALTO", "PSI Monitor detecta drift y abre Circuit Breaker. Suite de pytest fixtures por plugin.", C.lightRed),
          riskRow("Feature Store sin política de retención llena el disco", "ALTO", "pg_partman configurado desde Día 1 con ventana de 90 días. ~40-60 GB máximo.", C.lightRed),
          riskRow("Stakeholders confunden modo DUMMY con sistema en producción", "MEDIO", "Header X-Model-Mode en todos los responses. Aviso visible en dashboard.", C.lightAmb),
          riskRow("Model poisoning — dataset de entrenamiento manipulado", "MEDIO", "Hash Chain del AuditLog valida integridad histórica antes de entrenar.", C.lightAmb),
          riskRow("Modelo nuevo peor que el activo sube a producción", "MEDIO", "Flag --dry-run obligatorio antes de registrar. F1 Score comparado vs. modelo activo.", C.lightAmb),
          riskRow("Hash Chain confundida con blockchain compleja", "BAJO", "Implementación documentada: campo previous_hash + SHA-256 en PostgreSQL. Sin overhead.", C.lightGreen),
          riskRow("Inferencia supera 50ms bajo carga", "BAJO", "Isolation Forest es O(log n) en predicción. Benchmark: <10ms en pruebas con 100 iteraciones.", C.lightGreen),
        ]
      }),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 12. CRITERIOS DE ÉXITO
      // ══════════════════════════════════════════════════════
      sectionTitle("12. Criterios de Éxito Medibles"),
      p("Sin estas métricas, no se puede saber si el sistema funciona correctamente o solo aparenta funcionar."),
      ...spacer(1),
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [3000, 2000, 4360],
        rows: [
          new TableRow({ children: [headerCell("Métrica", 3000), headerCell("Target", 2000), headerCell("Cómo medirlo", 4360)] }),
          new TableRow({ children: [dataCell("Latencia de inferencia (p95)", 3000), dataCell("< 50ms", 2000), dataCell("Header X-Latency-Ms en cada response", 4360)] }),
          new TableRow({ children: [dataCell("Falsos positivos (Fase III)", 3000), dataCell("< 15%", 2000), dataCell("Ratio de rechazos en ml_recommendations", 4360)] }),
          new TableRow({ children: [dataCell("Falsos positivos (Fase IV)", 3000), dataCell("< 8%", 2000), dataCell("Active learning con feedback de aprobaciones", 4360)] }),
          new TableRow({ children: [dataCell("Cobertura de eventos SIEM", 3000), dataCell("100%", 2000), dataCell("0 errores en el Normalizer. GenericSyslog como catch-all.", 4360)] }),
          new TableRow({ children: [dataCell("Uptime del Circuit Breaker", 3000), dataCell("99.5%", 2000), dataCell("Estado CLOSED en tabla ml_circuit_breaker", 4360)] }),
          new TableRow({ children: [dataCell("SHAP disponible", 3000), dataCell("< 30s", 2000), dataCell("Campo shap_ready = true en la recomendación", 4360)] }),
          new TableRow({ children: [dataCell("Uso de disco (Feature Store)", 3000), dataCell("< 60 GB", 2000), dataCell("Con retención de 90 días y volumen típico de SIEM", 4360)] }),
          new TableRow({ children: [dataCell("F1 Score del modelo", 3000), dataCell("> 0.70", 2000), dataCell("Salida del trainer.py antes de registrar el modelo", 4360)] }),
          new TableRow({ children: [dataCell("Verificación de Hash Chain", 3000), dataCell("INTACT", 2000), dataCell("GET /audit/verify retorna status: INTACT", 4360)] }),
        ]
      }),

      new Paragraph({ children: [new PageBreak()] }),

      // ══════════════════════════════════════════════════════
      // 13. CONCLUSIÓN
      // ══════════════════════════════════════════════════════
      sectionTitle("13. Conclusión"),
      p("Sentinel ML Service es un sistema de detección de anomalías listo para producción, no un prototipo. Cada componente tiene un propósito técnico específico y una ruta de fallback en caso de fallo."),
      ...spacer(1),
      p("Los principios que guían el diseño son tres:"),
      pBullet("La IA apoya al auditor, no lo reemplaza. El control humano es obligatorio bajo ISO 42001 en modo LIVE."),
      pBullet("El sistema debe poder demostrarse funcionando hoy. Sin cloud, sin GPU, sin GRC real — solo Docker Compose y un laptop."),
      pBullet("La seguridad es parte del diseño, no un add-on. HMAC, Hash Chain, verificación de integridad del modelo y Circuit Breaker son componentes de primera clase."),
      ...spacer(1),
      p("Con el roadmap de 6 fases, criterios de éxito medibles por fase y un simulador de ataques incluido, el equipo tiene todo lo necesario para pasar de documento a sistema funcionando sin ambigüedad."),
      ...spacer(2),
      new Paragraph({
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: C.blue, space: 8 } },
        spacing: { before: 200, after: 80 },
        children: [new TextRun({ text: "Sentinel ML Service — v1.0.0 — Documentación Técnica", font: "Arial", size: 18, color: C.gray, italics: true })]
      }),
      p("ISO 27001 · ISO 27005 · ISO 42001 · Optimizado para 8 GB RAM", { color: C.blue, align: AlignmentType.CENTER }),
    ]
  }]
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync("/mnt/user-data/outputs/Sentinel_ML_Service_Documentacion_Tecnica_v1.docx", buf);
  console.log("Documento generado correctamente.");
});
