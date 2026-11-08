import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class OrchestrationRecord(Base):
    __tablename__ = "orchestration_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    stage = Column(String(64), nullable=False)
    proposed_action = Column(JSON, default=dict, nullable=False)
    supporting_evidence = Column(JSON, default=dict, nullable=False)
    validation_result = Column(String(32), nullable=False)  # ALLOWED, REJECTED, MODIFIED
    validation_notes = Column(Text, nullable=True)
    final_action = Column(JSON, default=dict, nullable=False)
    execution_outcome = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    analysis = relationship("Analysis", back_populates="orchestration_records")
