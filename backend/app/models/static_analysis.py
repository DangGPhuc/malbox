import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, JSON
from app.core.database import Base


class StaticAnalysisRecord(Base):
    __tablename__ = "static_analysis_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = Column(String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True, index=True)
    sample_sha256 = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="QUEUED", nullable=False, index=True)
    ghidra_version = Column(String(64), nullable=True)
    is_partial = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    result_json = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

