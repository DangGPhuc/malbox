import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    executive_summary = Column(Text, nullable=False)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(32), default="Clean", nullable=False)  # Clean, Low, Suspicious, Malicious
    full_report_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    analysis = relationship("Analysis", back_populates="report")
