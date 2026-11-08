import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class AnalysisStatus(str, enum.Enum):
    UPLOADED = "UPLOADED"
    PREFLIGHT = "PREFLIGHT"
    PLANNED = "PLANNED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COLLECTING = "COLLECTING"
    NORMALIZING = "NORMALIZING"
    CORRELATING = "CORRELATING"
    SCORING = "SCORING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = Column(String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default=AnalysisStatus.UPLOADED.value, nullable=False, index=True)
    backend_type = Column(String(32), default="replay", nullable=False)
    profile = Column(String(64), default="standard", nullable=False)
    timeout_seconds = Column(Integer, default=120, nullable=False)
    live_mode = Column(Boolean, default=False, nullable=False)
    approved_by_user = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    sample = relationship("Sample", back_populates="analyses")
    events = relationship("AnalysisEvent", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("BehavioralFinding", back_populates="analysis", cascade="all, delete-orphan")
    orchestration_records = relationship("OrchestrationRecord", back_populates="analysis", cascade="all, delete-orphan")
    report = relationship("AnalysisReport", back_populates="analysis", uselist=False, cascade="all, delete-orphan")

