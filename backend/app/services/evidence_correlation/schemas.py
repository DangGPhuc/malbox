from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


CorrelationRelationship = Literal[
    "DIRECTLY_OBSERVED",
    "CONSISTENT_WITH",
    "CONTRADICTORY",
    "INSUFFICIENT_EVIDENCE",
    "SYNTHETIC_SCENARIO_ONLY",
]

CorrelationStatus = Literal[
    "COMPLETED",
    "PARTIAL",
    "INSUFFICIENT_EVIDENCE",
    "UNSUPPORTED",
    "FAILED",
]

CorrelationEvidenceKind = Literal[
    "static_function",
    "static_import",
    "static_string",
    "dynamic_event",
    "behavioral_finding",
]


class CorrelationEvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ref_id: str
    evidence_kind: CorrelationEvidenceKind
    source_tool: str
    timestamp: Optional[str] = None
    summary: str
    is_synthetic: bool = False
    provenance_scope: Optional[str] = None


class CorrelationConfidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    level: Literal["high", "medium", "low"]
    rationale: str


class CorrelationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    rule_id: str
    analysis_id: str
    sample_sha256: str
    static_references: List[CorrelationEvidenceReference] = Field(default_factory=list)
    dynamic_references: List[CorrelationEvidenceReference] = Field(default_factory=list)
    relationship: CorrelationRelationship
    relationship_summary: str
    explanation: str
    confidence: CorrelationConfidence
    known_limitations: List[str] = Field(default_factory=list)
    behavioral_execution_directly_observed: bool = False

    @model_validator(mode="after")
    def _enforce_execution_claim_invariant(self) -> "CorrelationFinding":
        if self.behavioral_execution_directly_observed:
            if self.relationship != "DIRECTLY_OBSERVED":
                raise ValueError(
                    f"behavioral_execution_directly_observed=True is invalid for relationship '{self.relationship}'."
                )
            if not self.dynamic_references or all(d.is_synthetic for d in self.dynamic_references):
                raise ValueError(
                    "DIRECTLY_OBSERVED requires at least one non-synthetic dynamic runtime trace reference."
                )
        elif self.relationship == "DIRECTLY_OBSERVED":
            raise ValueError(
                "relationship='DIRECTLY_OBSERVED' requires behavioral_execution_directly_observed=True."
            )
        return self


class CorrelationProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    engine_version: str = "1.0.0"
    analysis_id: str
    sample_id: str
    sample_sha256: str
    static_record_id: Optional[str] = None
    static_analysis_id: Optional[str] = None
    static_status: str = "UNAVAILABLE"
    static_provenance_scope: str = "unexecuted"
    dynamic_backend: str
    is_replay: bool
    replay_scenario_id: Optional[str] = None
    sample_identity_verified: bool
    static_reuse_detected: bool = False
    computed_at: str
    source_fingerprint: str
    triggered_automatically: bool = False
    external_ai_used: Literal[False] = False


class CorrelationLimitations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[str] = Field(default_factory=list)
    has_runtime_function_trace: bool = False
    is_replay_synthetic: bool = False
    sample_level_static_reuse: bool = False
    partial_static_coverage: bool = False
    suppressed_ambiguous_count: int = Field(default=0, ge=0)


class CorrelationTruncation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    truncated: bool = False
    total_events_in_analysis: int = Field(default=0, ge=0)
    events_scanned: int = Field(default=0, ge=0)
    events_omitted: int = Field(default=0, ge=0)
    functions_available: int = Field(default=0, ge=0)
    functions_scanned: int = Field(default=0, ge=0)
    candidate_relationships_evaluated: int = Field(default=0, ge=0)
    findings_included: int = Field(default=0, ge=0)
    findings_omitted: int = Field(default=0, ge=0)
    max_events_limit: int = Field(default=250, ge=1)
    max_functions_limit: int = Field(default=120, ge=1)
    max_findings_limit: int = Field(default=30, ge=1)
    max_serialized_bytes: int = Field(default=131072, ge=4096)
    serialized_bytes: int = Field(default=0, ge=0)


class CorrelationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_findings: int = Field(default=0, ge=0)
    directly_observed_count: int = Field(default=0, ge=0)
    consistent_with_count: int = Field(default=0, ge=0)
    contradictory_count: int = Field(default=0, ge=0)
    insufficient_evidence_count: int = Field(default=0, ge=0)
    synthetic_scenario_only_count: int = Field(default=0, ge=0)


class CorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    status: CorrelationStatus
    provenance: CorrelationProvenance
    summary: CorrelationSummary = Field(default_factory=CorrelationSummary)
    findings: List[CorrelationFinding] = Field(default_factory=list)
    limitations: CorrelationLimitations = Field(default_factory=CorrelationLimitations)
    truncation: CorrelationTruncation = Field(default_factory=CorrelationTruncation)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "Static code capabilities (imported APIs, cross-references, strings) never alone prove "
        "runtime execution. Synthetic Replay telemetry represents calibrated fixture scenarios "
        "rather than live execution of the uploaded sample."
    )


class CorrelationBundleSection(BaseModel):
    """
    Compact, pseudocode-free verified correlation context embedded inside VerifiedEvidenceBundle
    and IntelligenceReport (optional for full backward compatibility).
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    status: str
    source_fingerprint: Optional[str] = None
    is_replay: bool
    summary: Dict[str, int] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    truncated: bool = False
    disclaimer: str = (
        "Static code capabilities remain distinct from proven runtime execution; Replay scenario "
        "correlations reflect synthetic reference context only."
    )

