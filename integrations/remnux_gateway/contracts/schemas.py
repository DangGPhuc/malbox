from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GatewayJobStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    SAMPLE_RECEIVED = "SAMPLE_RECEIVED"
    HASH_VERIFIED = "HASH_VERIFIED"
    PREFLIGHT = "PREFLIGHT"
    GUEST_PREPARED = "GUEST_PREPARED"
    TASK_SUBMITTED = "TASK_SUBMITTED"
    EXECUTION_CONFIRMED = "EXECUTION_CONFIRMED"
    COLLECTING = "COLLECTING"
    EXECUTION_FINISHED = "EXECUTION_FINISHED"
    GUEST_RESTORED = "GUEST_RESTORED"
    EVIDENCE_READY = "EVIDENCE_READY"
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    EXECUTION_UNCONFIRMED = "EXECUTION_UNCONFIRMED"


class JobSubmissionRequest(BaseModel):
    analysis_id: str = Field(..., description="Unique Malbox analysis UUID")
    sample_sha256: str = Field(..., description="Expected SHA-256 of the binary")
    filename: str = Field("sample.exe", description="Original filename metadata")
    payload_hex: Optional[str] = Field(None, description="Binary content in hex format for JSON submissions")
    timeout_seconds: int = Field(300, ge=10, le=300, description="Execution window up to 300s")
    approved_by_operator: bool = Field(True, description="Explicit operator authorization flag")


class JobStatusResponse(BaseModel):
    job_id: str
    analysis_id: str
    status: GatewayJobStatus
    sample_sha256: str
    filename: str
    vm_target: str
    snapshot_name: str
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    elapsed_seconds: float = 0.0
    timeout_seconds: int = 300
    execution_confirmed: bool = False
    guest_pid: Optional[int] = None
    error: Optional[str] = None
    cleanup_status: str = "PENDING"
    evidence_bundle_size_bytes: Optional[int] = None
    evidence_manifest_ready: bool = False


class ArtifactMetadata(BaseModel):
    name: str
    path: str
    sha256: str
    size_bytes: int
    category: str


class EvidenceManifest(BaseModel):
    manifest_version: str = "1.0.0"
    analysis_id: str
    job_id: str
    sample_sha256: str
    filename: str
    vm_target: str
    clean_snapshot: str
    created_at: str
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    duration_seconds: float = 0.0
    execution_confirmed: bool = False
    confirmation_source: Optional[str] = None
    network_isolation_status: str = "VERIFIED"
    collector_status: Dict[str, str] = Field(default_factory=dict)
    artifacts: List[ArtifactMetadata] = Field(default_factory=list)
    cleanup_outcome: str = "RESTORED"
    source_provenance: str = "Malbox REMnux Deterministic Gateway"
    error: Optional[str] = None
