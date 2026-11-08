import uuid
import enum
from datetime import datetime, timezone
from typing import Set, Dict
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base

class SandboxBackendType(str, enum.Enum):
    REPLAY = "replay"
    CAPE = "cape"

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

TERMINAL_STATES: Set[AnalysisStatus] = {
    AnalysisStatus.COMPLETED,
    AnalysisStatus.FAILED,
    AnalysisStatus.CANCELLED,
    AnalysisStatus.TIMED_OUT,
    AnalysisStatus.BLOCKED_BY_POLICY,
}

VALID_STATE_TRANSITIONS: Dict[AnalysisStatus, Set[AnalysisStatus]] = {
    AnalysisStatus.UPLOADED: {
        AnalysisStatus.PREFLIGHT,
        AnalysisStatus.QUEUED,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.BLOCKED_BY_POLICY,
    },
    AnalysisStatus.PREFLIGHT: {
        AnalysisStatus.PLANNED,
        AnalysisStatus.QUEUED,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.BLOCKED_BY_POLICY,
    },
    AnalysisStatus.PLANNED: {
        AnalysisStatus.QUEUED,
        AnalysisStatus.RUNNING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.BLOCKED_BY_POLICY,
    },
    AnalysisStatus.QUEUED: {
        AnalysisStatus.PREFLIGHT,
        AnalysisStatus.RUNNING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.BLOCKED_BY_POLICY,
    },
    AnalysisStatus.RUNNING: {
        AnalysisStatus.COLLECTING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
        AnalysisStatus.BLOCKED_BY_POLICY,
    },
    AnalysisStatus.COLLECTING: {
        AnalysisStatus.NORMALIZING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
    },
    AnalysisStatus.NORMALIZING: {
        AnalysisStatus.CORRELATING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
    },
    AnalysisStatus.CORRELATING: {
        AnalysisStatus.SCORING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
    },
    AnalysisStatus.SCORING: {
        AnalysisStatus.REPORTING,
        AnalysisStatus.CANCELLED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
    },
    AnalysisStatus.REPORTING: {
        AnalysisStatus.COMPLETED,
        AnalysisStatus.FAILED,
        AnalysisStatus.TIMED_OUT,
    },
    AnalysisStatus.COMPLETED: set(),
    AnalysisStatus.FAILED: set(),
    AnalysisStatus.CANCELLED: set(),
    AnalysisStatus.TIMED_OUT: set(),
    AnalysisStatus.BLOCKED_BY_POLICY: set(),
}

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = Column(String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default=AnalysisStatus.QUEUED.value, nullable=False, index=True)
    backend_type = Column(String(32), default=SandboxBackendType.REPLAY.value, nullable=False)
    profile = Column(String(64), default="standard", nullable=False)
    timeout_seconds = Column(Integer, default=120, nullable=False)
    live_mode = Column(Boolean, default=False, nullable=False)
    approved_by_user = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    external_task_id = Column(String(64), nullable=True, index=True)
    replay_scenario_id = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    sample = relationship("Sample", back_populates="analyses")
    events = relationship("AnalysisEvent", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("BehavioralFinding", back_populates="analysis", cascade="all, delete-orphan")
    orchestration_records = relationship("OrchestrationRecord", back_populates="analysis", cascade="all, delete-orphan")
    report = relationship("AnalysisReport", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
