from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class AnalysisPlan(BaseModel):
    profile: str = Field(default="standard", description="Selected sandbox profile")
    execution_timeout_seconds: int = Field(default=120, ge=30, le=600)
    requested_artifacts: List[str] = Field(
        default_factory=lambda: ["pcap", "screenshots", "dropped_files"],
        description="Requested artifact types"
    )
    telemetry_focus: List[str] = Field(
        default_factory=lambda: ["process", "file", "registry", "network"],
        description="Subsystems to focus analysis on"
    )
    rationale: str = Field(..., description="Justification based on preflight PE triage")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    limitations: List[str] = Field(default_factory=list)

class ActionValidationResult(BaseModel):
    action_type: str
    is_allowed: bool
    status: str  # ALLOWED, REJECTED, MODIFIED
    reason: str
    modified_parameters: Optional[Dict[str, Any]] = None

class FollowUpRecommendation(BaseModel):
    needs_second_pass: bool = False
    recommended_profile: Optional[str] = None
    telemetry_gaps_identified: List[str] = Field(default_factory=list)
    prioritized_events: List[str] = Field(default_factory=list)
    rationale: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    stop_recommendation: bool = False
    stop_reason: Optional[str] = None

class OrchestrationRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    stage: str
    proposed_action: Dict[str, Any]
    supporting_evidence: Dict[str, Any]
    validation_result: str
    validation_notes: Optional[str] = None
    final_action: Dict[str, Any]
    execution_outcome: Optional[str] = None
    created_at: datetime
