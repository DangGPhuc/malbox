import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base

class AnalysisEvent(Base):
    __tablename__ = "analysis_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)  # process, file, registry, network, dns, http, api, persistence, artifact
    action = Column(String(50), nullable=False, index=True)    # spawn, write, reg_write, connect, etc.
    timestamp = Column(DateTime, nullable=True, index=True)
    process_id = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=True)
    parent_process_id = Column(Integer, nullable=True)
    target_path = Column(String(1024), nullable=True)
    attributes = Column(JSON, default=dict, nullable=False)
    source_tool = Column(String(100), default="sandbox", nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    analysis = relationship("Analysis", back_populates="events")
