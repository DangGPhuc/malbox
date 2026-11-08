from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.models.analysis import AnalysisStatus

class AnalysisCreate(BaseModel):
    sample_id: str
    backend_type: str = Field(default="replay", description="Execution backend: 'replay' or 'cape'")
    profile: str = Field(default="standard", description="Analysis profile, e.g. standard, ransomware_focus, evasion_focus")
    timeout_seconds: int = Field(default=120, ge=10, le=600)
    live_mode: bool = Field(default=False, description="Enable live malware execution (requires sandbox infrastructure)")
    approved_by_user: bool = Field(default=False, description="Explicit approval for live execution")

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
    backend_type: str
    profile: str
    timeout_seconds: int
    live_mode: bool
    approved_by_user: bool
    error_message: Optional[str] = None
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
