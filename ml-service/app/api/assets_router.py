"""
api/assets_router.py
---------------------
CRUD de activos + carga masiva desde Excel/CSV.

Endpoints:
  GET    /assets              lista paginada de activos del cliente
  POST   /assets              crear activo individual
  GET    /assets/{id}         detalle de un activo
  PUT    /assets/{id}         actualizar activo
  DELETE /assets/{id}         eliminar activo
  POST   /assets/upload       carga masiva desde Excel/CSV
"""
import logging
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel, Field

from typing import Annotated
from app.auth.dependencies import CurrentUser, CurrentApiClient, get_current_identity
from app.repositories.asset import (
    get_assets, get_asset_by_id, create_asset,
    update_asset, delete_asset, bulk_insert_assets,
)
from app.services.smart_importer import parse_excel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/assets", tags=["assets"])

_VALID_CRITICIDAD = {"Bajo", "Medio", "Alto", "Crítico"}


# ── Schemas ────────────────────────────────────────────────────────────────────

class AssetIn(BaseModel):
    nombre_activo:             str
    tipo_activo:               Optional[str]     = None
    hostname:                  Optional[str]     = None
    ip_address:                Optional[str]     = None
    mac_address:               Optional[str]     = None
    technical_id:              Optional[str]     = None
    propietario:               Optional[str]     = None
    custodio:                  Optional[str]     = None
    administrador:             Optional[str]     = None
    propietario_informacion:   Optional[str]     = None
    ubicacion:                 Optional[str]     = None
    departamento:              Optional[str]     = None
    descripcion:               Optional[str]     = None
    observaciones:             Optional[str]     = None
    estado_parcheo:            Optional[str]     = None
    clasificacion_criticidad:  Optional[str]     = None
    valor_activo:              Decimal           = Decimal("0")
    valor_confidencialidad:    int               = Field(default=3, ge=1, le=5)
    valor_integridad:          int               = Field(default=3, ge=1, le=5)
    valor_disponibilidad:      int               = Field(default=3, ge=1, le=5)
    contiene_pii:              bool              = False
    contiene_pci:              bool              = False
    contiene_phi:              bool              = False
    contiene_pfi:              bool              = False

    def model_dump_for_db(self) -> dict:
        """Convierte Decimal a float para asyncpg."""
        data = self.model_dump()
        data["valor_activo"] = float(data["valor_activo"])
        return data


class AssetUpdate(BaseModel):
    """Todos los campos son opcionales para soportar PATCH parcial."""
    nombre_activo:             Optional[str]     = None
    tipo_activo:               Optional[str]     = None
    hostname:                  Optional[str]     = None
    ip_address:                Optional[str]     = None
    mac_address:               Optional[str]     = None
    technical_id:              Optional[str]     = None
    propietario:               Optional[str]     = None
    custodio:                  Optional[str]     = None
    administrador:             Optional[str]     = None
    propietario_informacion:   Optional[str]     = None
    ubicacion:                 Optional[str]     = None
    departamento:              Optional[str]     = None
    descripcion:               Optional[str]     = None
    observaciones:             Optional[str]     = None
    estado_parcheo:            Optional[str]     = None
    clasificacion_criticidad:  Optional[str]     = None
    valor_activo:              Optional[Decimal] = None
    valor_confidencialidad:    Optional[int]     = Field(default=None, ge=1, le=5)
    valor_integridad:          Optional[int]     = Field(default=None, ge=1, le=5)
    valor_disponibilidad:      Optional[int]     = Field(default=None, ge=1, le=5)
    contiene_pii:              Optional[bool]    = None
    contiene_pci:              Optional[bool]    = None
    contiene_phi:              Optional[bool]    = None
    contiene_pfi:              Optional[bool]    = None


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("")
async def list_assets(
    skip:  int = Query(0,   ge=0),
    limit: int = Query(100, ge=1, le=500),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await get_assets(client_id, skip=skip, limit=limit)


@router.post("", status_code=201)
async def create_asset_endpoint(
    body: AssetIn,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    if body.clasificacion_criticidad and body.clasificacion_criticidad not in _VALID_CRITICIDAD:
        raise HTTPException(400, f"clasificacion_criticidad debe ser uno de: {_VALID_CRITICIDAD}")
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await create_asset(client_id, body.model_dump_for_db())


@router.get("/{asset_id}")
async def get_asset_endpoint(
    asset_id: int,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    asset = await get_asset_by_id(client_id, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    return asset


@router.put("/{asset_id}")
async def update_asset_endpoint(
    asset_id: int,
    body:     AssetUpdate,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    if "valor_activo" in data:
        data["valor_activo"] = float(data["valor_activo"])
    
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    updated = await update_asset(client_id, asset_id, data)
    if not updated:
        raise HTTPException(404, "Activo no encontrado")
    return updated


@router.delete("/{asset_id}", status_code=204)
async def delete_asset_endpoint(
    asset_id: int,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    success = await delete_asset(client_id, asset_id)
    if not success:
        raise HTTPException(404, "Activo no encontrado")


@router.post("/upload", status_code=202)
async def upload_assets(
    file:        UploadFile = File(...),
    departamento: str       = Form(...),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """
    Carga masiva de activos desde Excel (.xlsx) o CSV.
    """
    if not file.filename.lower().endswith((".xlsx", ".xls", ".csv")):
        raise HTTPException(400, "Solo se aceptan archivos .xlsx, .xls o .csv")

    contents = await file.read()
    result   = parse_excel(
        file_bytes=contents,
        filename=file.filename,
        extra_defaults={"departamento": departamento},
    )

    if not result.items:
        raise HTTPException(400, {
            "mensaje":         "No se encontraron filas validas.",
            "filas_con_error": result.ignored_rows,
            "sugerencia":      "Verifica que el archivo tenga la columna 'Nombre Activo'.",
        })

    # Convertir Decimal a float para asyncpg
    clean_items = []
    for item in result.items:
        if "valor_activo" in item and isinstance(item["valor_activo"], Decimal):
            item["valor_activo"] = float(item["valor_activo"])
        clean_items.append(item)

    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    inserted = await bulk_insert_assets(client_id, clean_items)

    return {
        "status":          "ok",
        "activos_creados": inserted,
        "filas_con_error": result.total_errors,
        "detalle_errores": result.ignored_rows,
        "mensaje":         f"{inserted} activo(s) importado(s) correctamente.",
    }
