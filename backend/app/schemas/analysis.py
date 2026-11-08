from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator
from app.models.analysis import AnalysisStatus, SandboxBackendType

class AnalysisCreate(BaseModel):
    sample_id: str
    backend_type: SandboxBackendType = Field(
        default=SandboxBackendType.REPLAY,
        description="Execution backend: 'replay' or 'cape'"
    )
    profile: str = Field(
        default="standard",
        description="Analysis profile, e.g. standard, ransomware_focus, infostealer_focus, evasion_focus"
    )
    timeout_seconds: int = Field(default=120, ge=10, le=600)
    live_mode: bool = Field(default=False, description="Enable live malware execution (requires sandbox infrastructure)")
    approved_by_user: bool = Field(default=False, description="Explicit approval for live execution")
    replay_scenario_id: Optional[str] = Field(
        default=None,
        description="Explicit replay scenario selection (e.g. ransomware_wannacry_mock, infostealer_redline_mock)"
    )

    @model_validator(mode="after")
    def validate_backend_mode_consistency(self) -> "AnalysisCreate":
        if self.backend_type == SandboxBackendType.REPLAY and self.live_mode:
            raise ValueError("Inconsistent configuration: Replay backend cannot run in live mode (must have live_mode=false).")
        if self.backend_type == SandboxBackendType.CAPE and not self.live_mode:
            raise ValueError("Inconsistent configuration: CAPE backend requires live_mode=true.")
        if self.live_mode and not self.approved_by_user:
            raise ValueError("Live execution requires explicit analyst authorization (approved_by_user=true).")
        return self

class AnalysisStatusHistoryItem(BaseModel):
    from_status: str
    to_status: str
    timestamp: datetime
    reason: Optional[str] = None

class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sample_id: str
    status: AnalysisStatus
    backend_type: SandboxBackendType
    profile: str
    timeout_seconds: int
    live_mode: bool
    approved_by_user: bool
    error_message: Optional[str] = None
    external_task_id: Optional[str] = None
    replay_scenario_id: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class AnalysisDetailResponse(AnalysisResponse):
    sample_file_name: Optional[str] = None
    sample_sha256: Optional[str] = None
    total_events: int = 0
    total_findings: int = 0
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
