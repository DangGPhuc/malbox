import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from app.core.database import Base


class StaticDynamicCorrelationRecord(Base):
    """
    Isolated persistence table for versioned Static/Dynamic Evidence Correlation results.
    Never modifies raw AnalysisEvent, BehavioralFinding, StaticAnalysisRecord, or risk scores.
    """

    __tablename__ = "evidence_correlations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(
        String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sample_id = Column(
        String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sample_sha256 = Column(String(64), nullable=False, index=True)
    static_record_id = Column(String(36), nullable=True)
    status = Column(String(32), nullable=False, index=True)
    source_fingerprint = Column(String(64), nullable=False, index=True)
    is_replay = Column(Boolean, default=False, nullable=False)
    is_partial = Column(Boolean, default=False, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    result_json = Column(JSON, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

