import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class BehavioralFinding(Base):
    __tablename__ = "behavioral_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), default="Low", nullable=False)  # Informational, Low, Medium, High, Critical
    confidence = Column(Float, default=1.0, nullable=False)
    mitre_attack_id = Column(String(50), nullable=True, index=True)
    mitre_tactic = Column(String(100), nullable=True)
    supporting_event_ids = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    analysis = relationship("Analysis", back_populates="findings")

