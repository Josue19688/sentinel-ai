from pydantic import BaseModel, Field
from typing import Optional
from decimal import Decimal

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
