"""
services/smart_importer.py
---------------------------
Motor de importacion masiva de activos desde Excel/CSV.
Detecta columnas automaticamente por nombre y contenido.
Retorna ImportResult (items + filas_con_error) — sin hacks de Pydantic.
"""
from __future__ import annotations
import io
import re
import logging
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

import pandas as pd
from fastapi import HTTPException

logger = logging.getLogger(__name__)


@dataclass
class ImportResult:
    items:         list[dict]
    ignored_rows:  list[dict] = field(default_factory=list)

    @property
    def total_ok(self) -> int:
        return len(self.items)

    @property
    def total_errors(self) -> int:
        return len(self.ignored_rows)


# ── Aliases para columnas del inventario de activos ────────────────────────────
_ALIASES: dict[str, list[str]] = {
    "nombre_activo":           ["nombre", "nombre activo", "asset", "activo", "asset name", "recurso"],
    "tipo_activo":             ["tipo", "tipo activo", "tipo de activo", "categoria", "categoria activo"],
    "hostname":                ["host", "hostname", "equipo", "nombre equipo", "nombre del equipo", "server"],
    "ip_address":              ["ip", "ip address", "direccion ip", "ipv4", "ip host"],
    "mac_address":             ["mac", "mac address", "direccion mac"],
    "technical_id":            ["id tecnico", "technical id", "agent id", "sensor id", "uuid agente"],
    "propietario":             ["propietario", "dueno", "owner", "responsable", "lider"],
    "custodio":                ["custodio", "guardian"],
    "administrador":           ["administrador", "admin", "gestor"],
    "propietario_informacion": ["propietario info", "owner info", "dueno informacion"],
    "ubicacion":               ["ubicacion", "lugar", "sede", "oficina", "sitio"],
    "departamento":            ["departamento", "area", "unidad", "gerencia", "seccion"],
    "descripcion":             ["descripcion", "detalle", "resumen", "notas"],
    "observaciones":           ["observaciones", "comentarios", "notas adicionales"],
    "estado_parcheo":          ["parcheo", "estado parcheo", "parches", "vulnerable", "actualizado"],
    "clasificacion_criticidad":["criticidad", "clasificacion", "importancia", "nivel", "prioridad"],
    "valor_activo":            ["valor", "valor activo", "costo", "monto", "precio", "va"],
    "valor_confidencialidad":  ["confidencialidad", "conf", "cia c", "valor c"],
    "valor_integridad":        ["integridad", "integr", "cia i", "valor i"],
    "valor_disponibilidad":    ["disponibilidad", "disp", "cia d", "valor d"],
    "contiene_pii":            ["pii", "datos personales", "informacion personal"],
    "contiene_pci":            ["pci", "datos pago", "tarjeta"],
    "contiene_phi":            ["phi", "datos salud", "health"],
    "contiene_pfi":            ["pfi", "datos financieros", "financiero"],
}

# Que tipo de dato espera cada columna
_FIELD_TYPES: dict[str, str] = {
    "valor_activo":           "decimal",
    "valor_confidencialidad": "int",
    "valor_integridad":       "int",
    "valor_disponibilidad":   "int",
    "contiene_pii":           "bool",
    "contiene_pci":           "bool",
    "contiene_phi":           "bool",
    "contiene_pfi":           "bool",
}


def _normalize(name: str) -> str:
    """Quita acentos, convierte a minusculas, remueve caracteres no alfanumericos."""
    s = str(name).lower().strip()
    for src, dst in [("á","a"),("é","e"),("í","i"),("ó","o"),("ú","u"),("ñ","n")]:
        s = s.replace(src, dst)
    return re.sub(r"[^a-z0-9 ]", "", s).strip()


def _detect_mapping(df: pd.DataFrame) -> dict[str, str]:
    """
    Mapea columnas del DataFrame a campos del activo.
    Prioridad: nombre exacto > alias > heuristica de contenido.
    """
    df_cols = {_normalize(c): c for c in df.columns}
    mapping: dict[str, str] = {}

    for field_name, aliases in _ALIASES.items():
        # 1. Nombre exacto del campo
        if _normalize(field_name) in df_cols:
            mapping[field_name] = df_cols[_normalize(field_name)]
            continue

        # 2. Alias conocido
        matched = next(
            (df_cols[_normalize(a)] for a in aliases if _normalize(a) in df_cols),
            None,
        )
        if matched:
            mapping[field_name] = matched
            continue

        # 3. Heuristica de contenido
        for col_orig in df.columns:
            if col_orig in mapping.values():
                continue
            sample = df[col_orig].dropna().astype(str).head(10).tolist()
            if not sample:
                continue

            if field_name == "ip_address":
                if any(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) for s in sample):
                    mapping[field_name] = col_orig; break

            if field_name == "mac_address":
                if any(re.match(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$", s) for s in sample):
                    mapping[field_name] = col_orig; break

            if field_name == "valor_activo":
                try:
                    nums = pd.to_numeric(df[col_orig], errors="coerce").dropna()
                    if len(nums) > 0 and float(nums.mean()) > 100 and "id" not in col_orig.lower():
                        mapping[field_name] = col_orig; break
                except Exception:
                    pass

    return mapping


def _cast(value: Any, field_name: str) -> Any:
    """Convierte el valor crudo al tipo esperado por el campo."""
    field_type = _FIELD_TYPES.get(field_name, "str")

    if pd.isna(value) or str(value).strip() == "":
        return None

    val_str = str(value).strip()

    if field_type == "decimal":
        # Soporte formato europeo (1.500,00) y americano ($1,500.00)
        if re.search(r"\d{1,3}(\.\d{3})+(,\d+)?$", val_str):
            val_str = val_str.replace(".", "").replace(",", ".")
        clean = re.sub(r"[^\d.]", "", val_str)
        try:
            return Decimal(clean) if clean else Decimal("0")
        except InvalidOperation:
            return Decimal("0")

    if field_type == "int":
        clean = re.sub(r"\D", "", val_str)
        try:
            v = int(clean) if clean else 0
            return max(1, min(5, v))  # Forzar rango CIA 1-5
        except ValueError:
            return 3  # valor CIA por defecto

    if field_type == "bool":
        return val_str.lower() in ("si", "sí", "yes", "true", "1", "x", "t", "y")

    return val_str  # string por defecto


def parse_excel(
    file_bytes: bytes,
    filename: str,
    extra_defaults: dict[str, Any] | None = None,
) -> ImportResult:
    """
    Carga el archivo Excel/CSV, detecta columnas, parsea y retorna ImportResult.
    Nunca lanza excepcion por filas individuales — las acumula en ignored_rows.
    """
    try:
        if filename.lower().endswith(".csv"):
            df = pd.read_csv(io.BytesIO(file_bytes), encoding="utf-8-sig")
        else:
            df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
    except Exception as e:
        raise HTTPException(400, f"Error leyendo archivo: {e}")

    if df.empty:
        raise HTTPException(400, "El archivo esta vacio.")

    # Quitar filas totalmente vacias
    df = df.dropna(how="all")

    col_map = _detect_mapping(df)
    if not col_map:
        raise HTTPException(
            400,
            "No se reconocio ninguna columna. "
            "Asegurate de que el archivo tenga encabezados como: "
            "Nombre, IP, Hostname, Valor, Confidencialidad, etc."
        )

    items: list[dict]        = []
    ignored_rows: list[dict] = []

    for idx, row in df.iterrows():
        item: dict[str, Any] = (extra_defaults or {}).copy()

        for field_name, col_name in col_map.items():
            item[field_name] = _cast(row[col_name], field_name)

        # Auto-deteccion de flags PII/PCI/PHI/PFI desde columna de clasificacion
        clasif_col = next(
            (c for c in df.columns if "clasifica" in _normalize(c) or "sensibilidad" in _normalize(c)),
            None,
        )
        if clasif_col:
            raw = str(row[clasif_col]).upper()
            if "PII" in raw: item["contiene_pii"] = True
            if "PCI" in raw: item["contiene_pci"] = True
            if "PHI" in raw: item["contiene_phi"] = True
            if "PFI" in raw: item["contiene_pfi"] = True

        # Validacion minima: debe tener nombre_activo
        if not item.get("nombre_activo"):
            ignored_rows.append({
                "fila":   int(idx) + 2,  # +2: header + 0-index
                "motivo": "nombre_activo es obligatorio",
                "datos":  {k: v for k, v in item.items() if v is not None},
            })
            continue

        # Defaults CIA si no vinieron del Excel
        for cia_field, default in [
            ("valor_confidencialidad", 3),
            ("valor_integridad",       3),
            ("valor_disponibilidad",   3),
        ]:
            if item.get(cia_field) is None:
                item[cia_field] = default

        items.append(item)

    if ignored_rows:
        logger.warning(
            "SmartImporter '%s': %d/%d filas ignoradas.",
            filename, len(ignored_rows), len(df),
        )

    return ImportResult(items=items, ignored_rows=ignored_rows)
