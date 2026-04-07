from typing import List, Dict, Any, Optional
from decimal import Decimal
from app.schemas.asset import AssetIn, AssetUpdate
from app.repositories.asset_sa import (
    get_assets_sa, get_asset_by_id_sa, create_asset_sa,
    update_asset_sa, delete_asset_sa, bulk_insert_assets_sa
)
from app.services.smart_importer import parse_excel

VALID_CRITICIDAD = {"Bajo", "Medio", "Alto", "Crítico"}

class AssetService:
    @staticmethod
    async def list_assets(client_id: str, skip: int, limit: int) -> List[Dict[str, Any]]:
        return await get_assets_sa(client_id, skip=skip, limit=limit)

    @staticmethod
    async def get_asset(client_id: str, asset_id: int) -> Optional[Dict[str, Any]]:
        return await get_asset_by_id_sa(client_id, asset_id)

    @staticmethod
    async def create_asset(client_id: str, body: AssetIn) -> Dict[str, Any]:
        if body.clasificacion_criticidad and body.clasificacion_criticidad not in VALID_CRITICIDAD:
            raise ValueError(f"clasificacion_criticidad debe ser uno de: {VALID_CRITICIDAD}")
        data = body.model_dump_for_db()
        return await create_asset_sa(client_id, data)

    @staticmethod
    async def update_asset(client_id: str, asset_id: int, body: AssetUpdate) -> Optional[Dict[str, Any]]:
        data = {k: v for k, v in body.model_dump().items() if v is not None}
        if "valor_activo" in data and isinstance(data["valor_activo"], Decimal):
            data["valor_activo"] = float(data["valor_activo"])
        return await update_asset_sa(client_id, asset_id, data)

    @staticmethod
    async def delete_asset(client_id: str, asset_id: int) -> bool:
        return await delete_asset_sa(client_id, asset_id)

    @staticmethod
    async def upload_assets(client_id: str, file_bytes: bytes, filename: str, departamento: str) -> dict:
        if not filename.lower().endswith((".xlsx", ".xls", ".csv")):
            raise ValueError("Solo se aceptan archivos .xlsx, .xls o .csv")
            
        result = parse_excel(
            file_bytes=file_bytes,
            filename=filename,
            extra_defaults={"departamento": departamento},
        )
        if not result.items:
            raise ValueError("No se encontraron filas validas. Verifica la columna 'Nombre Activo'.")
            
        clean_items = []
        for item in result.items:
            if "valor_activo" in item and isinstance(item["valor_activo"], Decimal):
                item["valor_activo"] = float(item["valor_activo"])
            clean_items.append(item)
            
        inserted = await bulk_insert_assets_sa(client_id, clean_items)
        return {
            "activos_creados": inserted,
            "filas_con_error": result.total_errors,
            "detalle_errores": result.ignored_rows,
            "mensaje": f"{inserted} activo(s) importado(s) correctamente.",
            "status": "ok"
        }
