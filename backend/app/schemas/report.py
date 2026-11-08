from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.finding import FindingResponse

class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str  # Clean, Low, Suspicious, Malicious
    rule_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = 1.0

class MitreTechnique(BaseModel):
    technique_id: str
    tactic: str
    technique_name: str
    description: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    confidence: float = 1.0

class ExtractedIOCs(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    dropped_files: List[Dict[str, Any]] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)

class FullReportSchema(BaseModel):
    analysis_id: str
    generated_at: str
    backend_type: str = "replay"
    is_replay: bool = True
    replay_scenario_id: Optional[str] = None
    provenance_disclaimer: str = (
        "REPLAY DATA PROVENANCE: Telemetry derived from synthetic replay fixture. "
        "All behaviors represent recorded execution rather than live detonation."
    )
    sample_metadata: Dict[str, Any]
    analysis_environment: Dict[str, Any]
    executive_summary: str
    risk_assessment: RiskAssessment
    mitre_attack_mappings: List[MitreTechnique] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)
    extracted_iocs: ExtractedIOCs
    execution_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    process_activity_summary: Dict[str, Any] = Field(default_factory=dict)
    filesystem_activity_summary: Dict[str, Any] = Field(default_factory=dict)
    registry_activity_summary: Dict[str, Any] = Field(default_factory=dict)
    network_activity_summary: Dict[str, Any] = Field(default_factory=dict)
    confidence_and_limitations: Dict[str, Any] = Field(default_factory=dict)
    recommended_follow_up: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)

class ReportResponse(BaseModel):
    id: str
    analysis_id: str
    executive_summary: str
    risk_score: int
    risk_level: str
    backend_type: str = "replay"
    is_replay: bool = True
    replay_scenario_id: Optional[str] = None
    full_report: FullReportSchema
    created_at: datetime

