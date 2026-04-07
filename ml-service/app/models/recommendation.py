from sqlalchemy import Column, String, Boolean, Integer, DateTime, Float, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.db import Base
import uuid

class MLRecommendation(Base):
    __tablename__ = "ml_recommendations"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    client_id = Column(String(64), nullable=False)
    asset_id = Column(String(255), nullable=False)
    
    anomaly_score = Column(Float)
    aro_suggested = Column(Float)
    confidence = Column(Float)
    model_version = Column(String(255))
    model_mode = Column(String(50))
    status = Column(String(50), server_default="PENDING")
    
    src_ip = Column(String(45))
    pattern = Column(String(100))
    event_type = Column(String(200))
    river_score = Column(Float)
    nmap_score = Column(Float)
    combined_score = Column(Float)
    river_warmup = Column(Boolean)
    
    ef = Column(Float)
    sle = Column(Float)
    aro = Column(Float)
    ale = Column(Float)
    
    aro_sample_size = Column(Integer)
    aro_period_days = Column(Integer)
    aro_confidence = Column(String(50))
    
    valor_activo_snapshot = Column(Float)
    clasificacion_criticidad = Column(String(50))
    
    cia_snapshot = Column(JSONB)
    impacted_dimensions = Column(JSONB)
    data_flags = Column(JSONB)
    
    shap_values = Column(JSONB)
    shap_ready = Column(Boolean, server_default="false")
    
    attack_count_historical = Column(Integer, server_default="0")
    first_occurrence_pattern = Column(Boolean, server_default="true")
    recurrence_flag = Column(Boolean, server_default="false")
    
    created_at = Column(DateTime, server_default=text("now()"), nullable=False)
