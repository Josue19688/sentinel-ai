"""
models/asset.py
-----------------
Modelo SQLAlchemy para activos de TI registrados en Sentinel ML.
Almacena datos técnicos, financieros y CIA para cálculos ISO 27005.
"""
from sqlalchemy import (
    Column, Integer, String, Text, Boolean,
    Numeric, DateTime, func, CheckConstraint, Index,
)
from app.db import Base


class Asset(Base):
    __tablename__ = "assets"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    client_id    = Column(String(100), nullable=False, index=True)  # sentinel_key del cliente

    # ── Identidad técnica (usada para correlacionar con eventos SIEM) ─────────
    nombre_activo  = Column(String(255), nullable=False)
    tipo_activo    = Column(String(100), nullable=True)
    hostname       = Column(String(255), nullable=True, index=True)
    ip_address     = Column(String(50),  nullable=True, index=True)
    mac_address    = Column(String(50),  nullable=True)
    technical_id   = Column(String(100), nullable=True, index=True)  # Agent ID Wazuh, etc.

    # ── Contexto organizacional ───────────────────────────────────────────────
    propietario            = Column(String(100), nullable=True)
    custodio               = Column(String(100), nullable=True)
    administrador          = Column(String(100), nullable=True)
    propietario_informacion= Column(String(100), nullable=True)   # ISO 27001 A.8.2.2
    ubiaacion              = Column(String(255), nullable=True)
    departamento           = Column(String(100), nullable=True)
    descripcion            = Column(Text, nullable=True)
    observaciones          = Column(Text, nullable=True)
    estado_parcheo         = Column(String(100), nullable=True)
    clasificacion_criticidad = Column(String(20), nullable=True)  # Bajo|Medio|Alto|Crítico

    # ── Valor financiero (ISO 27005) ──────────────────────────────────────────
    valor_activo = Column(Numeric(20, 2), default=0.0, nullable=False)

    # ── Valoración CIA 1-5 (ISO 27005) ───────────────────────────────────────
    valor_confidencialidad = Column(Integer, default=3, nullable=False)
    valor_integridad       = Column(Integer, default=3, nullable=False)
    valor_disponibilidad   = Column(Integer, default=3, nullable=False)

    # ── Flags de sensibilidad de datos ───────────────────────────────────────
    contiene_pii = Column(Boolean, default=False, nullable=False)
    contiene_pci = Column(Boolean, default=False, nullable=False)
    contiene_phi = Column(Boolean, default=False, nullable=False)
    contiene_pfi = Column(Boolean, default=False, nullable=False)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("valor_confidencialidad BETWEEN 1 AND 5", name="ck_asset_cia_c"),
        CheckConstraint("valor_integridad       BETWEEN 1 AND 5", name="ck_asset_cia_i"),
        CheckConstraint("valor_disponibilidad   BETWEEN 1 AND 5", name="ck_asset_cia_d"),
        CheckConstraint("valor_activo >= 0",                       name="ck_asset_valor"),
        # Busqueda rapida por hostname+client combinado (caso mas frecuente)
        Index("ix_assets_client_hostname", "client_id", "hostname"),
        Index("ix_assets_client_ip",       "client_id", "ip_address"),
    )
