from sqlalchemy import Column, String, Boolean, Integer, DateTime, text, Float
from app.db import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(64), nullable=False)
    
    nombre_activo = Column(String(255), nullable=False)
    tipo_activo = Column(String(100))
    hostname = Column(String(255))
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    technical_id = Column(String(255))
    
    propietario = Column(String(255))
    custodio = Column(String(255))
    administrador = Column(String(255))
    propietario_informacion = Column(String(255))
    
    ubicacion = Column(String(255))
    departamento = Column(String(255))
    descripcion = Column(String)
    observaciones = Column(String)
    estado_parcheo = Column(String(100))
    clasificacion_criticidad = Column(String(50))
    
    valor_activo = Column(Float, server_default="0", nullable=False)
    valor_confidencialidad = Column(Integer, server_default="3", nullable=False)
    valor_integridad = Column(Integer, server_default="3", nullable=False)
    valor_disponibilidad = Column(Integer, server_default="3", nullable=False)
    
    contiene_pii = Column(Boolean, server_default="false", nullable=False)
    contiene_pci = Column(Boolean, server_default="false", nullable=False)
    contiene_phi = Column(Boolean, server_default="false", nullable=False)
    contiene_pfi = Column(Boolean, server_default="false", nullable=False)
    
    created_at = Column(DateTime, server_default=text("now()"), nullable=False)
    updated_at = Column(DateTime, server_default=text("now()"), nullable=False)
