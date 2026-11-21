from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


StaticAnalysisStatus = Literal[
    "PENDING",
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "PARTIAL",
    "FAILED",
    "TIMED_OUT",
    "UNAVAILABLE",
    "SKIPPED",
]


def normalize_entry_address(address: str) -> str:
    """Normalizes hex instruction/function address into canonical lowercase 0x... format."""
    cleaned = (address or "").strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("0") or "0"
    return f"0x{cleaned}"


def make_static_function_id(sample_sha256: str, entry_address: str) -> str:
    """
    Constructs a stable, sample-bound function identifier based on the sample
    SHA-256 and canonical function entry address.
    """
    sha_prefix = (sample_sha256 or "unknown").strip().lower()[:16]
    norm_addr = normalize_entry_address(entry_address)
    return f"func:{sha_prefix}:{norm_addr}"


def make_static_string_id(sample_sha256: str, address: str) -> str:
    sha_prefix = (sample_sha256 or "unknown").strip().lower()[:16]
    norm_addr = normalize_entry_address(address)
    return f"str:{sha_prefix}:{norm_addr}"


class StaticAttemptMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: Optional[str] = None
    analysis_id: Optional[str] = None
    status: StaticAnalysisStatus
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    is_usable: bool = False
    same_analysis: bool = True


class StaticAnalysisProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    analysis_id: Optional[str] = None
    sample_id: str
    sample_sha256: str
    source_tool: Literal["ghidra_headless"] = "ghidra_headless"
    ghidra_version: Optional[str] = None
    java_version: Optional[str] = None
    binary_executed: Literal[False] = False
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    execution_duration_ms: Optional[int] = Field(default=None, ge=0)
    project_isolated: bool = True
    os_sandbox: str = "none"
    process_exit_code: Optional[int] = None
    memory_limit_backend: str = "none"
    memory_limit_mb: Optional[int] = Field(default=None, ge=0)
    heap_limit_mb: Optional[int] = Field(default=None, ge=0)
    requested_analysis_id: Optional[str] = None
    provenance_scope: Literal[
        "analysis_specific",
        "sample_level",
        "sample_fallback",
        "unexecuted",
    ] = "analysis_specific"
    provenance_note: Optional[str] = None
    ghidra_enabled: Optional[bool] = None
    latest_attempt: Optional[StaticAttemptMetadata] = None
    usable_evidence: Optional[StaticAttemptMetadata] = None
    showing_preserved_usable_evidence: bool = False


class ProgramMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_name: str
    executable_format: Optional[str] = None
    language_id: Optional[str] = None
    architecture: Optional[str] = None
    endianness: Optional[str] = None
    address_size: Optional[int] = Field(default=None, ge=16, le=64)
    image_base: Optional[str] = None
    entry_points: List[str] = Field(default_factory=list)
    total_functions_discovered: int = Field(default=0, ge=0)
    total_imports: int = Field(default=0, ge=0)
    total_exports: int = Field(default=0, ge=0)
    total_strings: int = Field(default=0, ge=0)


class ImportedSymbol(BaseModel):
    model_config = ConfigDict(extra="forbid")

    library: str
    name: str
    address: Optional[str] = None
    ordinal: Optional[int] = None


class CrossReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_address: str
    to_address: str
    ref_type: str
    from_function_id: Optional[str] = None
    to_function_id: Optional[str] = None
    target_symbol: Optional[str] = None


class FunctionCallRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    caller_function_id: str
    caller_address: str
    caller_name: str
    callee_function_id: Optional[str] = None
    callee_address: Optional[str] = None
    callee_name: str
    is_external_import: bool = False
    call_site_address: Optional[str] = None


class StaticStringEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    string_id: str
    address: str
    value: str
    length: int = Field(ge=0)
    section: Optional[str] = None
    referencing_function_ids: List[str] = Field(default_factory=list)


class FunctionMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    function_id: str
    entry_address: str
    name: str
    size_bytes: int = Field(default=0, ge=0)
    basic_block_count: Optional[int] = Field(default=None, ge=0)
    is_thunk: bool = False
    is_external: bool = False
    # Discovered static functions are NEVER claimed as dynamically executed
    is_executed: Literal[False] = False
    calling_convention: Optional[str] = None
    signature: Optional[str] = None
    imported_api_calls: List[str] = Field(default_factory=list)
    called_function_ids: List[str] = Field(default_factory=list)
    caller_function_ids: List[str] = Field(default_factory=list)
    string_refs: List[str] = Field(default_factory=list)
    xref_in_count: int = Field(default=0, ge=0)
    xref_out_count: int = Field(default=0, ge=0)
    rank_score: float = Field(default=0.0, ge=0.0)
    rank_reasons: List[str] = Field(default_factory=list)


class DecompiledFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    function_id: str
    entry_address: str
    name: str
    pseudocode: str = ""
    pseudocode_bytes: int = Field(default=0, ge=0)
    truncated: bool = False
    decompile_status: Literal["OK", "TIMED_OUT", "ERROR", "SKIPPED_CAP"] = "OK"
    error_message: Optional[str] = None
    provenance_note: str = (
        "Static heuristic C-like pseudocode recovered via Ghidra Decompiler; "
        "not original source code and does not prove runtime execution."
    )


class FunctionAnalysisFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    function_id: str
    entry_address: str
    name: str
    score: float = Field(ge=0.0)
    reasons: List[str] = Field(default_factory=list)
    imported_apis: List[str] = Field(default_factory=list)
    string_signals: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "Advisory static prioritization signal only; API imports or cross-references alone "
        "do not prove malicious intent or runtime execution."
    )


class StaticAnalysisTruncation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    truncated: bool = False
    functions_discovered: int = Field(default=0, ge=0)
    functions_included: int = Field(default=0, ge=0)
    functions_omitted: int = Field(default=0, ge=0)
    decompiled_requested: int = Field(default=0, ge=0)
    decompiled_included: int = Field(default=0, ge=0)
    decompiled_omitted_cap: int = Field(default=0, ge=0)
    strings_included: int = Field(default=0, ge=0)
    strings_omitted: int = Field(default=0, ge=0)
    output_bytes: int = Field(default=0, ge=0)
    max_output_bytes: int = Field(default=524288, ge=1024)
    max_functions: int = Field(default=250, ge=1)
    max_decompile_functions: int = Field(default=10, ge=0)


class StaticAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    status: StaticAnalysisStatus
    provenance: StaticAnalysisProvenance
    program_metadata: Optional[ProgramMetadata] = None
    functions: List[FunctionMetadata] = Field(default_factory=list)
    call_graph: List[FunctionCallRelationship] = Field(default_factory=list)
    cross_references: List[CrossReference] = Field(default_factory=list)
    imports: List[ImportedSymbol] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    strings: List[StaticStringEvidence] = Field(default_factory=list)
    decompiled_functions: List[DecompiledFunction] = Field(default_factory=list)
    ranked_findings: List[FunctionAnalysisFinding] = Field(default_factory=list)
    truncation: StaticAnalysisTruncation = Field(default_factory=StaticAnalysisTruncation)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    is_partial: bool = False

