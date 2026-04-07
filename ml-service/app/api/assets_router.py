"""
api/assets_router.py
---------------------
CRUD de activos + carga masiva desde Excel/CSV (Refactored a RSR).
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from app.schemas.asset import AssetIn, AssetUpdate
from typing import Annotated
from app.auth.dependencies import CurrentUser, CurrentApiClient, get_current_identity
from app.services.asset_service import AssetService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/assets", tags=["assets"])

@router.get("")
async def list_assets(
    skip:  int = Query(0,   ge=0),
    limit: int = Query(100, ge=1, le=500),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await AssetService.list_assets(client_id, skip=skip, limit=limit)

@router.post("", status_code=201)
async def create_asset_endpoint(
    body: AssetIn,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    try:
        return await AssetService.create_asset(client_id, body)
    except ValueError as e:
        raise HTTPException(400, str(e))

@router.get("/{asset_id}")
async def get_asset_endpoint(
    asset_id: int,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    asset = await AssetService.get_asset(client_id, asset_id)
    if not asset:
        raise HTTPException(404, "Activo no encontrado")
    return asset

@router.put("/{asset_id}")
async def update_asset_endpoint(
    asset_id: int,
    body:     AssetUpdate,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    updated = await AssetService.update_asset(client_id, asset_id, body)
    if not updated:
        raise HTTPException(404, "Activo no encontrado")
    return updated

@router.delete("/{asset_id}", status_code=204)
async def delete_asset_endpoint(
    asset_id: int,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    success = await AssetService.delete_asset(client_id, asset_id)
    if not success:
        raise HTTPException(404, "Activo no encontrado")

@router.post("/upload", status_code=202)
async def upload_assets(
    file: UploadFile = File(...),
    departamento: str = Form(...),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    contents = await file.read()
    try:
        return await AssetService.upload_assets(client_id, contents, file.filename, departamento)
    except ValueError as e:
        raise HTTPException(400, str(e))
