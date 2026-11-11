from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


ClaimClassification = Literal["FACT", "INFERENCE", "HYPOTHESIS"]
ClaimValidationStatus = Literal["VERIFIED", "UNVERIFIED", "REJECTED"]
ClaimSupportCategory = Literal[
    "DETERMINISTIC_FACT",
    "ANALYST_INFERENCE",
    "UNCERTAIN_HYPOTHESIS",
    "CONSERVATIVE_UNVERIFIED",
    "UNSUPPORTED_OR_FABRICATED",
]
EvidenceCompleteness = Literal["high", "medium", "low"]
FollowUpPriority = Literal["high", "medium", "low"]


class BundleProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    backend_type: str
    is_replay: bool
    replay_scenario_id: Optional[str] = None
    fixture_version: Optional[str] = None
    provenance_statement: str
    environment: Dict[str, Any] = Field(default_factory=dict)


class SampleIdentityEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    sample_id: str
    file_name: str
    file_size: int
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    mime_type: Optional[str] = None
    is_pe: bool = False
    pe_metadata_summary: Dict[str, Any] = Field(default_factory=dict)


class NormalizedEventEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    category: str
    action: str
    timestamp: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    process_name: Optional[str] = None
    target_path: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source_tool: str = "sandbox"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    priority_tier: str = "routine"


class TimelineEntryEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: Optional[str] = None
    category: str
    action: str
    process: Optional[str] = None
    pid: Optional[int] = None
    summary: str


class ProcessRelationshipEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int
    ppid: Optional[int] = None
    name: str
    command_line: Optional[str] = None
    spawn_time: Optional[str] = None
    suspicious: bool = False
    event_count: int = 0
    event_ids: List[str] = Field(default_factory=list)


class NetworkRelationshipEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    protocol: str
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    destination: str
    port: Optional[int] = None
    method_or_query: Optional[str] = None


class DeterministicFindingEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    supporting_event_ids: List[str] = Field(default_factory=list)


class MitreMappingEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    tactic: str
    technique_name: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class IOCReferenceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    dropped_files: List[Dict[str, Any]] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)


class ArtifactEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    name: str
    artifact_type: str
    description: str
    is_synthetic: bool = False
    provenance_note: str
    size_bytes: Optional[int] = None
    source_event_id: Optional[str] = None


class StaticAnalysisPlaceholder(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["not_available", "available", "partial", "failed", "timed_out"] = "not_available"
    tool: str = "ghidra_headless"
    notes: str = (
        "Static disassembly/decompilation (Ghidra Headless) was not executed; "
        "no static function symbols or CFG internals are available."
    )
    analysis_id: Optional[str] = None
    sample_sha256: Optional[str] = None
    ghidra_version: Optional[str] = None
    program_metadata: Optional[Dict[str, Any]] = None
    functions: List[Dict[str, Any]] = Field(default_factory=list)
    ranked_function_count: int = 0
    decompiled_count: int = 0
    decompiled_omitted_for_external_ai: bool = False
    truncation: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)


class TruncationMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    truncated: bool = False
    total_events_available: int = 0
    events_included: int = 0
    events_omitted: int = 0
    timeline_truncated: bool = False
    fields_truncated_count: int = 0
    max_events_limit: int = 120
    max_field_chars: int = 512
    max_bundle_bytes: int = 65536
    estimated_bundle_bytes: int = 0
    prioritization_strategy: str = "deterministic_tier_then_chronological"


class VerifiedEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    sample_identity: SampleIdentityEvidence
    provenance: BundleProvenance
    deterministic_risk_score: int = Field(ge=0, le=100)
    deterministic_risk_level: str
    events: List[NormalizedEventEvidence] = Field(default_factory=list)
    timeline: List[TimelineEntryEvidence] = Field(default_factory=list)
    process_relationships: List[ProcessRelationshipEvidence] = Field(default_factory=list)
    network_relationships: List[NetworkRelationshipEvidence] = Field(default_factory=list)
    findings: List[DeterministicFindingEvidence] = Field(default_factory=list)
    mitre_mappings: List[MitreMappingEvidence] = Field(default_factory=list)
    iocs: IOCReferenceEvidence = Field(default_factory=IOCReferenceEvidence)
    artifacts: List[ArtifactEvidence] = Field(default_factory=list)
    known_limitations: List[str] = Field(default_factory=list)
    static_analysis: StaticAnalysisPlaceholder = Field(default_factory=StaticAnalysisPlaceholder)
    valid_evidence_ids: List[str] = Field(default_factory=list)
    truncation: TruncationMetadata = Field(default_factory=TruncationMetadata)


class TimelineInterpretation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase: str
    summary: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)


class ProposedClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    classification: ClaimClassification
    claim_text: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    caveats: List[str] = Field(default_factory=list)


class AnalyticalClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    classification: ClaimClassification
    claim_text: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    caveats: List[str] = Field(default_factory=list)
    validation_status: ClaimValidationStatus = "UNVERIFIED"
    support_category: ClaimSupportCategory = "CONSERVATIVE_UNVERIFIED"
    requires_human_review: bool = False
    evidence_sources: List[str] = Field(default_factory=list)
    validation_notes: Optional[str] = None


class IOCInterpretation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_value: str
    ioc_type: str
    role_or_context: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence_ids: List[str] = Field(default_factory=list)


class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_confidence: float = Field(ge=0.0, le=1.0)
    evidence_completeness: EvidenceCompleteness
    rationale: str


class EvidenceGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gap_type: str
    description: str
    impact: str


class FollowUpAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: FollowUpPriority
    action: str
    rationale: str
    requires_manual_approval: bool = False


class AIProposedIntelligence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_assessment: str
    behavioral_narrative: str
    timeline_interpretations: List[TimelineInterpretation] = Field(default_factory=list)
    technical_claims: List[ProposedClaim] = Field(default_factory=list)
    ioc_interpretations: List[IOCInterpretation] = Field(default_factory=list)
    confidence_assessment: ConfidenceAssessment
    contradictions_or_gaps: List[EvidenceGap] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    recommended_follow_up_actions: List[FollowUpAction] = Field(default_factory=list)


class AIProviderMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str
    provider: str
    model: str
    tokens_used: int = 0
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
    rules_version: str = "2.0"
    generated_at: str


class ValidationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    total_claims: int = 0
    verified_claims: int = 0
    unverified_claims: int = 0
    rejected_claims: int = 0
    review_required_claims: int = 0
    deterministic_facts: int = 0
    analyst_inferences: int = 0
    uncertain_hypotheses: int = 0
    removed_invalid_evidence_ids: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    fallback_applied: bool = False


class IntelligenceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "2.0"
    analysis_id: str
    is_replay: bool
    replay_scenario_id: Optional[str] = None
    provenance_summary: str
    deterministic_risk_score: int = Field(ge=0, le=100)
    deterministic_risk_level: str
    executive_assessment: str
    behavioral_narrative: str
    timeline_interpretations: List[TimelineInterpretation] = Field(default_factory=list)
    technical_claims: List[AnalyticalClaim] = Field(default_factory=list)
    ioc_interpretations: List[IOCInterpretation] = Field(default_factory=list)
    confidence_assessment: ConfidenceAssessment
    contradictions_or_gaps: List[EvidenceGap] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    recommended_follow_up_actions: List[FollowUpAction] = Field(default_factory=list)
    evidence_truncation: TruncationMetadata
    provider_metadata: AIProviderMetadata
    validation_summary: ValidationSummary

