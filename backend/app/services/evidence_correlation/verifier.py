from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.models.sample import Sample
from app.schemas.static_analysis import (
    FunctionMetadata,
    StaticAnalysisResult,
    normalize_entry_address,
)
from app.services.evidence_correlation.normalization import (
    normalize_api_root,
    parse_hex_address,
)
from app.services.static_analysis.selector import select_static_records

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CORRELATION_RULES_VERSION = "corr-v1.1.0"
TRACE_PROOF_VERSION = "malbox-trace-v1"

# Retained intentionally empty: plain source_tool labels NEVER grant execution proof.
TRUSTED_RUNTIME_TRACE_TOOLS: Set[str] = set()


def _basename_lower(path_like: Optional[str]) -> str:
    if not path_like or not isinstance(path_like, str):
        return ""
    return path_like.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _freeze_attr_value(val: Any) -> Any:
    if isinstance(val, Mapping):
        return MappingProxyType({str(k): _freeze_attr_value(v) for k, v in val.items()})
    if isinstance(val, list):
        return tuple(_freeze_attr_value(v) for v in val)
    return val


def _make_trace_hmac_message(
    *,
    analysis_id: str,
    sample_sha256: str,
    trace_session_id: str,
    source_tool: str,
    module_name: str,
    module_base: str,
    instruction_pointer: str,
    function_id: str,
    function_address: str,
    api_name: str,
) -> bytes:
    canonical = "|".join(
        [
            TRACE_PROOF_VERSION,
            analysis_id.strip(),
            sample_sha256.strip().lower(),
            trace_session_id.strip(),
            (source_tool or "").strip(),
            _basename_lower(module_name),
            normalize_entry_address(module_base),
            normalize_entry_address(instruction_pointer),
            function_id.strip(),
            normalize_entry_address(function_address),
            normalize_api_root(api_name),
        ]
    )
    return canonical.encode("utf-8")


def compute_authenticated_trace_proof(
    *,
    analysis_id: str,
    sample_sha256: str,
    trace_session_id: str,
    source_tool: str,
    module_name: str,
    module_base: str,
    instruction_pointer: str,
    function_id: str,
    function_address: str,
    api_name: str,
    signing_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs a backend-authenticated runtime trace provenance payload signed with
    HMAC-SHA256 bound to analysis ownership, sample SHA-256, runtime module identity,
    loaded base address, instruction pointer, static function ID/entry, and API name.
    """
    secret = (signing_secret if signing_secret is not None else settings.SECRET_KEY).encode("utf-8")
    norm_mod_base = normalize_entry_address(module_base)
    norm_ip = normalize_entry_address(instruction_pointer)
    norm_fn_addr = normalize_entry_address(function_address)
    msg = _make_trace_hmac_message(
        analysis_id=analysis_id,
        sample_sha256=sample_sha256,
        trace_session_id=trace_session_id,
        source_tool=source_tool,
        module_name=module_name,
        module_base=norm_mod_base,
        instruction_pointer=norm_ip,
        function_id=function_id,
        function_address=norm_fn_addr,
        api_name=api_name,
    )
    digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return {
        "version": TRACE_PROOF_VERSION,
        "analysis_id": analysis_id.strip(),
        "sample_sha256": sample_sha256.strip().lower(),
        "trace_session_id": trace_session_id.strip(),
        "module_name": module_name.strip(),
        "module_base": norm_mod_base,
        "instruction_pointer": norm_ip,
        "function_id": function_id.strip(),
        "function_address": norm_fn_addr,
        "api_name": api_name.strip(),
        "hmac_sha256": digest,
    }


@dataclass(frozen=True)
class VerifiedRuntimeTrace:
    analysis_id: str
    sample_sha256: str
    trace_session_id: str
    source_tool: str
    module_name: str
    module_base: int
    instruction_pointer: int
    mapped_static_va: int
    function_id: str
    function_address: str
    norm_api: str


@dataclass(frozen=True)
class NormalizedDynamicEvent:
    """
    Immutable, verified copy of an AnalysisEvent ORM row so correlation logic can
    never mutate or flush altered evidence back to the database.
    """

    id: str
    analysis_id: str
    category: str
    action: str
    timestamp: Optional[datetime]
    process_id: Optional[int]
    process_name: Optional[str]
    target_path: Optional[str]
    source_tool: str
    attributes: Mapping[str, Any]
    raw_attributes_malformed: bool = False
    authenticated_trace: Optional[VerifiedRuntimeTrace] = None


@dataclass
class VerifiedCorrelationContext:
    ok: bool
    analysis: Analysis
    sample: Optional[Sample]
    sample_sha256: str
    is_replay: bool
    replay_scenario_id: Optional[str]
    static_record_id: Optional[str]
    static_result: Optional[StaticAnalysisResult]
    static_provenance_scope: str
    static_reuse_detected: bool
    valid_function_ids: Set[str] = field(default_factory=set)
    valid_string_ids: Set[str] = field(default_factory=set)
    valid_import_keys: Set[str] = field(default_factory=set)
    valid_event_ids: Set[str] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


def verify_correlation_inputs(
    db: Session,
    analysis: Analysis,
    static_override: Optional[StaticAnalysisResult] = None,
) -> VerifiedCorrelationContext:
    """
    Fail-closed verification gate before evidence correlation:
    - Verifies parent sample presence and SHA-256 format.
    - Verifies analysis -> sample ownership alignment.
    - Verifies static analysis provenance & SHA-256 identity without crossing samples.
    - Explicitly detects sample-level static reuse across sibling analyses.
    - Explicitly tags Replay telemetry as synthetic and rejects unverified references.
    """
    sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
    is_replay = bool(analysis.backend_type == "replay")
    scenario_id = analysis.replay_scenario_id if is_replay else None

    if sample is None:
        return VerifiedCorrelationContext(
            ok=False,
            analysis=analysis,
            sample=None,
            sample_sha256="0" * 64,
            is_replay=is_replay,
            replay_scenario_id=scenario_id,
            static_record_id=None,
            static_result=None,
            static_provenance_scope="unexecuted",
            static_reuse_detected=False,
            errors=[f"Parent sample '{analysis.sample_id}' not found; correlation aborted."],
        )

    sample_sha = (sample.sha256 or "").strip().lower()
    if not _SHA256_RE.match(sample_sha):
        return VerifiedCorrelationContext(
            ok=False,
            analysis=analysis,
            sample=sample,
            sample_sha256="0" * 64,
            is_replay=is_replay,
            replay_scenario_id=scenario_id,
            static_record_id=None,
            static_result=None,
            static_provenance_scope="unexecuted",
            static_reuse_detected=False,
            errors=["Sample SHA-256 failed canonical format verification; refusing correlation."],
        )

    warnings: List[str] = []
    errors: List[str] = []
    limitations: List[str] = []

    if is_replay:
        limitations.append(
            f"Replay Mode provenance: telemetry originates exclusively from synthetic scenario "
            f"'{scenario_id or 'default'}'; the uploaded binary ({sample_sha[:16]}...) was NOT executed dynamically."
        )

    static_rec_id: Optional[str] = None
    static_res: Optional[StaticAnalysisResult] = None
    prov_scope = "unexecuted"
    static_reuse = False

    if static_override is not None:
        static_res = static_override
        prov_scope = static_res.provenance.provenance_scope
        static_reuse = bool(
            prov_scope == "sample_fallback"
            or (
                static_res.provenance.analysis_id
                and static_res.provenance.analysis_id != analysis.id
            )
        )
    else:
        sel = select_static_records(
            db=db,
            sample_id=sample.id,
            sample_sha256=sample_sha,
            requested_analysis_id=analysis.id,
            prefer_usable_over_active=True,
        )
        prov_scope = sel.provenance_scope
        if sel.usable_record is not None and isinstance(sel.usable_record.result_json, dict):
            static_rec_id = sel.usable_record.id
            try:
                static_res = StaticAnalysisResult.model_validate(sel.usable_record.result_json)
            except Exception as exc:
                errors.append(f"Stored static result failed strict schema validation: {exc}")
                static_res = None
        elif sel.primary_record is not None and isinstance(sel.primary_record.result_json, dict):
            static_rec_id = sel.primary_record.id
            try:
                static_res = StaticAnalysisResult.model_validate(sel.primary_record.result_json)
            except Exception:
                static_res = None

        static_reuse = bool(
            prov_scope == "sample_fallback"
            or (
                sel.usable_record is not None
                and sel.usable_record.analysis_id not in (None, analysis.id)
            )
        )

    if static_res is not None:
        res_sha = (static_res.provenance.sample_sha256 or "").strip().lower()
        res_sample_id = static_res.provenance.sample_id
        if res_sha != sample_sha or res_sample_id != sample.id:
            errors.append(
                f"Cross-sample static contamination rejected: static record sample/SHA-256 "
                f"({res_sample_id}/{res_sha[:12]}) does not match analysis target ({sample.id}/{sample_sha[:12]})."
            )
            return VerifiedCorrelationContext(
                ok=False,
                analysis=analysis,
                sample=sample,
                sample_sha256=sample_sha,
                is_replay=is_replay,
                replay_scenario_id=scenario_id,
                static_record_id=static_rec_id,
                static_result=None,
                static_provenance_scope=prov_scope,
                static_reuse_detected=static_reuse,
                warnings=warnings,
                errors=errors,
                limitations=limitations,
            )

        if static_res.status not in ("COMPLETED", "PARTIAL"):
            limitations.append(
                f"Static analysis status is '{static_res.status}'; no verified static functions or symbols are available for correlation."
            )
        elif static_res.status == "PARTIAL" or static_res.is_partial or static_res.truncation.truncated:
            limitations.append(
                "Static analysis result is PARTIAL/bounded; omitted functions or strings cannot confirm absence of capabilities."
            )

        if static_reuse and static_res.status in ("COMPLETED", "PARTIAL"):
            origin = static_res.provenance.analysis_id or "sibling-analysis"
            limitations.append(
                f"Sample-level static evidence reuse detected (static facts originated under analysis '{origin}'); "
                "reused safely because SHA-256 byte identity matches."
            )

    expected_prefix = f"func:{sample_sha[:16]}:"
    expected_str_prefix = f"str:{sample_sha[:16]}:"
    valid_fn_ids: Set[str] = set()
    valid_str_ids: Set[str] = set()
    valid_imp_keys: Set[str] = set()

    if static_res is not None and static_res.status in ("COMPLETED", "PARTIAL"):
        for fn in static_res.functions:
            if not fn.function_id.startswith(expected_prefix):
                warnings.append(
                    f"Filtered unverified/cross-sample static function_id '{fn.function_id}'."
                )
                continue
            valid_fn_ids.add(fn.function_id)

        for st in static_res.strings:
            if not st.string_id.startswith(expected_str_prefix):
                warnings.append(
                    f"Filtered unverified/cross-sample static string_id '{st.string_id}'."
                )
                continue
            valid_str_ids.add(st.string_id)

        for imp in static_res.imports:
            valid_imp_keys.add(f"imp:{imp.library.lower()}:{imp.name.lower()}")

    return VerifiedCorrelationContext(
        ok=True,
        analysis=analysis,
        sample=sample,
        sample_sha256=sample_sha,
        is_replay=is_replay,
        replay_scenario_id=scenario_id,
        static_record_id=static_rec_id,
        static_result=static_res,
        static_provenance_scope=prov_scope,
        static_reuse_detected=static_reuse,
        valid_function_ids=valid_fn_ids,
        valid_string_ids=valid_str_ids,
        valid_import_keys=valid_imp_keys,
        warnings=warnings,
        errors=errors,
        limitations=limitations,
    )


def verify_runtime_trace_provenance(
    *,
    event_id: str,
    source_tool: str,
    target_path: Optional[str],
    attrs: Mapping[str, Any],
    analysis_id: str,
    is_replay: bool,
    sample_sha256: Optional[str],
    static_result: Optional[StaticAnalysisResult],
    fn_by_id: Mapping[str, FunctionMetadata],
    expected_modules: Set[str],
    static_image_base: Optional[int],
    signing_secret: Optional[str] = None,
) -> Tuple[Optional[VerifiedRuntimeTrace], Optional[str]]:
    """
    Strictly verifies whether an event carries authentic backend-signed runtime
    instruction-pointer trace provenance binding execution directly to a static function.

    Returns (VerifiedRuntimeTrace, None) on full cryptographic & address-range verification,
    (None, None) for normal untraced events, or (None, warning_message) when a weak/spoofed/
    mismatched execution trace claim was rejected conservatively.
    """
    trace_auth = attrs.get("trace_auth")
    claims_trace = bool(
        trace_auth is not None
        or attrs.get("trace_verified") is not None
        or attrs.get("function_id")
        or attrs.get("function_address")
        or attrs.get("instruction_pointer")
    )
    if not claims_trace:
        return None, None

    if is_replay:
        return (
            None,
            f"Replay Mode rejected runtime trace execution claim on event '{event_id}'; synthetic telemetry cannot prove execution.",
        )

    if not sample_sha256 or not _SHA256_RE.match(sample_sha256):
        return (
            None,
            f"Event '{event_id}' execution trace claim rejected: verified sample SHA-256 unavailable.",
        )

    if static_result is None or static_result.status not in ("COMPLETED", "PARTIAL"):
        return (
            None,
            f"Event '{event_id}' execution trace claim rejected: verified static binary layout unavailable.",
        )

    if not isinstance(trace_auth, Mapping):
        return (
            None,
            f"Unauthenticated trace metadata on event '{event_id}' (tool '{source_tool}') ignored; plain source_tool or trace_verified flags never prove execution.",
        )

    if attrs.get("trace_verified") is False:
        return None, f"Event '{event_id}' rejected: trace_verified=False contradicts execution trace claim."

    if trace_auth.get("version") != TRACE_PROOF_VERSION:
        return None, f"Event '{event_id}' rejected: unsupported trace_auth schema version."

    required_keys = (
        "analysis_id",
        "sample_sha256",
        "trace_session_id",
        "module_name",
        "module_base",
        "instruction_pointer",
        "function_id",
        "function_address",
        "api_name",
        "hmac_sha256",
    )
    for k in required_keys:
        val = trace_auth.get(k)
        if not isinstance(val, str) or not val.strip():
            return None, f"Event '{event_id}' rejected: trace_auth missing required field '{k}'."

    tr_analysis_id = trace_auth["analysis_id"].strip()
    tr_sha = trace_auth["sample_sha256"].strip().lower()
    tr_session = trace_auth["trace_session_id"].strip()
    tr_mod_name = trace_auth["module_name"].strip()
    tr_mod_base_raw = trace_auth["module_base"].strip()
    tr_ip_raw = trace_auth["instruction_pointer"].strip()
    tr_fn_id = trace_auth["function_id"].strip()
    tr_fn_addr_raw = trace_auth["function_address"].strip()
    tr_api_raw = trace_auth["api_name"].strip()
    provided_hmac = trace_auth["hmac_sha256"].strip().lower()

    if len(tr_session) < 4:
        return None, f"Event '{event_id}' rejected: invalid trace_session_id."

    if tr_analysis_id != analysis_id:
        return (
            None,
            f"Event '{event_id}' rejected: trace_auth analysis_id '{tr_analysis_id}' does not match target '{analysis_id}'.",
        )

    if tr_sha != sample_sha256:
        return (
            None,
            f"Event '{event_id}' rejected: trace_auth sample_sha256 mismatch.",
        )

    mod_base = parse_hex_address(tr_mod_base_raw)
    ip = parse_hex_address(tr_ip_raw)
    if mod_base is None or mod_base <= 0 or ip is None or ip < mod_base:
        return (
            None,
            f"Event '{event_id}' rejected: invalid module_base or instruction_pointer runtime address.",
        )

    secret = (signing_secret if signing_secret is not None else settings.SECRET_KEY).encode("utf-8")
    expected_msg = _make_trace_hmac_message(
        analysis_id=tr_analysis_id,
        sample_sha256=tr_sha,
        trace_session_id=tr_session,
        source_tool=source_tool,
        module_name=tr_mod_name,
        module_base=tr_mod_base_raw,
        instruction_pointer=tr_ip_raw,
        function_id=tr_fn_id,
        function_address=tr_fn_addr_raw,
        api_name=tr_api_raw,
    )
    expected_hmac = hmac.new(secret, expected_msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, provided_hmac):
        return (
            None,
            f"Event '{event_id}' rejected: backend trace_auth signature verification failed.",
        )

    mod_base_name = _basename_lower(tr_mod_name)
    if not expected_modules or mod_base_name not in expected_modules:
        return (
            None,
            f"Event '{event_id}' rejected: trace module '{tr_mod_name}' does not match analyzed sample module.",
        )

    if static_image_base is None or static_image_base <= 0:
        return (
            None,
            f"Event '{event_id}' rejected: static PE image_base unavailable to relocate instruction pointer safely.",
        )

    expected_fn_prefix = f"func:{sample_sha256[:16]}:"
    if not tr_fn_id.startswith(expected_fn_prefix):
        return (
            None,
            f"Event '{event_id}' rejected: trace function_id '{tr_fn_id}' failed sample prefix verification.",
        )

    fn = fn_by_id.get(tr_fn_id)
    if fn is None:
        return (
            None,
            f"Event '{event_id}' rejected: traced function_id '{tr_fn_id}' is absent from verified static table.",
        )

    norm_fn_addr = normalize_entry_address(tr_fn_addr_raw)
    if normalize_entry_address(fn.entry_address) != norm_fn_addr:
        return (
            None,
            f"Event '{event_id}' rejected: trace function_address '{norm_fn_addr}' disagrees with static entry '{fn.entry_address}'.",
        )

    top_fn_id = attrs.get("function_id")
    if top_fn_id is not None and str(top_fn_id).strip() and str(top_fn_id).strip() != tr_fn_id:
        return (
            None,
            f"Event '{event_id}' rejected: event attribute function_id '{top_fn_id}' conflicts with trace_auth function_id.",
        )
    top_fn_addr = attrs.get("function_address")
    if top_fn_addr is not None and str(top_fn_addr).strip() and normalize_entry_address(str(top_fn_addr)) != norm_fn_addr:
        return (
            None,
            f"Event '{event_id}' rejected: event attribute function_address conflicts with trace_auth function_address.",
        )

    fn_entry_int = parse_hex_address(fn.entry_address)
    if fn_entry_int is None or int(fn.size_bytes) <= 0:
        return (
            None,
            f"Event '{event_id}' rejected: static function '{fn.function_id}' lacks positive byte bounds for IP range verification.",
        )

    rva = ip - mod_base
    mapped_static_va = static_image_base + rva
    if not (fn_entry_int <= mapped_static_va < fn_entry_int + int(fn.size_bytes)):
        return (
            None,
            f"Event '{event_id}' rejected: relocated instruction pointer 0x{mapped_static_va:x} falls outside static function range "
            f"[0x{fn_entry_int:x}, 0x{fn_entry_int + int(fn.size_bytes):x}).",
        )

    ev_raw_api = str(
        attrs.get("api") or attrs.get("api_name") or attrs.get("function") or target_path or ""
    ).strip()
    norm_ev_api = normalize_api_root(ev_raw_api)
    norm_tr_api = normalize_api_root(tr_api_raw)
    if not norm_ev_api or norm_ev_api != norm_tr_api:
        return (
            None,
            f"Event '{event_id}' rejected: runtime API '{ev_raw_api}' does not match signed trace API '{tr_api_raw}'.",
        )

    fn_norm_apis = {normalize_api_root(a) for a in (fn.imported_api_calls or [])}
    if norm_tr_api not in fn_norm_apis:
        return (
            None,
            f"Event '{event_id}' rejected: API '{norm_tr_api}' is not recorded inside static function '{fn.function_id}'.",
        )

    return (
        VerifiedRuntimeTrace(
            analysis_id=tr_analysis_id,
            sample_sha256=tr_sha,
            trace_session_id=tr_session,
            source_tool=source_tool or "backend-tracer",
            module_name=mod_base_name,
            module_base=mod_base,
            instruction_pointer=ip,
            mapped_static_va=mapped_static_va,
            function_id=fn.function_id,
            function_address=norm_fn_addr,
            norm_api=norm_tr_api,
        ),
        None,
    )


def validate_runtime_events(
    events: List[AnalysisEvent],
    analysis_id: str,
    is_replay: bool,
    *,
    sample_sha256: Optional[str] = None,
    static_result: Optional[StaticAnalysisResult] = None,
    sample_file_name: Optional[str] = None,
    pe_metadata: Optional[Mapping[str, Any]] = None,
    signing_secret: Optional[str] = None,
) -> Tuple[List[NormalizedDynamicEvent], Set[str], List[str], bool]:
    """
    Validates normalized dynamic event records WITHOUT mutating ORM rows:
    - Drops cross-analysis or malformed events.
    - Wraps event attributes in deep read-only MappingProxyType copies.
    - Requires backend-authenticated HMAC trace proof + module/IP/API verification
      before marking any event eligible for DIRECTLY_OBSERVED correlation.
    """
    verified: List[NormalizedDynamicEvent] = []
    valid_event_ids: Set[str] = set()
    warnings: List[str] = []
    has_trusted_trace = False

    fn_by_id: Dict[str, FunctionMetadata] = {}
    expected_modules: Set[str] = set()
    static_image_base: Optional[int] = None

    if sample_file_name:
        bn = _basename_lower(sample_file_name)
        if bn:
            expected_modules.add(bn)

    if static_result is not None and static_result.status in ("COMPLETED", "PARTIAL"):
        for fn in static_result.functions:
            fn_by_id[fn.function_id] = fn
        if static_result.program_metadata is not None:
            pm_name = _basename_lower(static_result.program_metadata.program_name)
            if pm_name:
                expected_modules.add(pm_name)
            static_image_base = parse_hex_address(static_result.program_metadata.image_base)

    if static_image_base is None and isinstance(pe_metadata, Mapping):
        static_image_base = parse_hex_address(pe_metadata.get("image_base"))

    for ev in events:
        if ev.analysis_id != analysis_id:
            warnings.append(
                f"Rejected cross-analysis event '{ev.id}' belonging to '{ev.analysis_id}'."
            )
            continue
        if not ev.category or not ev.action:
            warnings.append(f"Skipped malformed event '{ev.id}' missing category/action.")
            continue

        raw_attrs = ev.attributes
        malformed = False
        if raw_attrs is None:
            frozen_attrs: Mapping[str, Any] = MappingProxyType({})
        elif isinstance(raw_attrs, Mapping):
            frozen_attrs = MappingProxyType({str(k): _freeze_attr_value(v) for k, v in raw_attrs.items()})
        else:
            warnings.append(f"Event '{ev.id}' had non-dict attributes; ignoring attributes safely.")
            frozen_attrs = MappingProxyType({})
            malformed = True

        src_tool = str(ev.source_tool or "sandbox")
        auth_trace, trace_warn = verify_runtime_trace_provenance(
            event_id=str(ev.id),
            source_tool=src_tool,
            target_path=ev.target_path,
            attrs=frozen_attrs,
            analysis_id=analysis_id,
            is_replay=is_replay,
            sample_sha256=sample_sha256,
            static_result=static_result,
            fn_by_id=fn_by_id,
            expected_modules=expected_modules,
            static_image_base=static_image_base,
            signing_secret=signing_secret,
        )
        if trace_warn:
            warnings.append(trace_warn)
        if auth_trace is not None:
            has_trusted_trace = True

        dto = NormalizedDynamicEvent(
            id=str(ev.id),
            analysis_id=str(ev.analysis_id),
            category=str(ev.category),
            action=str(ev.action),
            timestamp=ev.timestamp,
            process_id=ev.process_id,
            process_name=ev.process_name,
            target_path=ev.target_path,
            source_tool=src_tool,
            attributes=frozen_attrs,
            raw_attributes_malformed=malformed,
            authenticated_trace=auth_trace,
        )
        verified.append(dto)
        valid_event_ids.add(dto.id)

    return verified, valid_event_ids, warnings, has_trusted_trace


def compute_static_evidence_digest(static_result: Optional[StaticAnalysisResult]) -> str:
    """Computes a canonical SHA-256 digest over static correlation inputs."""
    hasher = hashlib.sha256()
    if static_result is None:
        hasher.update(b"static:none")
        return hasher.hexdigest()

    pm = static_result.program_metadata
    header = {
        "status": static_result.status,
        "is_partial": bool(static_result.is_partial),
        "truncated": bool(static_result.truncation.truncated),
        "prov_analysis_id": static_result.provenance.analysis_id or "",
        "prov_sha256": (static_result.provenance.sample_sha256 or "").lower(),
        "program_name": pm.program_name if pm else "",
        "image_base": (pm.image_base or "") if pm else "",
        "total_functions_discovered": pm.total_functions_discovered if pm else 0,
        "errors": list(static_result.errors or []),
    }
    hasher.update(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    for fn in sorted(static_result.functions, key=lambda f: (f.entry_address, f.function_id)):
        fn_rec = [
            fn.function_id,
            fn.entry_address,
            fn.name,
            int(fn.size_bytes),
            bool(fn.is_thunk),
            bool(fn.is_external),
            sorted(fn.imported_api_calls),
            sorted(fn.called_function_ids),
            sorted(fn.string_refs),
        ]
        hasher.update(b"|fn|")
        hasher.update(json.dumps(fn_rec, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))

    for imp in sorted(
        static_result.imports,
        key=lambda i: (i.library.lower(), i.name.lower(), i.address or "", i.ordinal or -1),
    ):
        imp_rec = [imp.library.lower(), imp.name, imp.address or "", imp.ordinal]
        hasher.update(b"|imp|")
        hasher.update(json.dumps(imp_rec, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))

    for st in sorted(static_result.strings, key=lambda s: (s.address, s.string_id)):
        st_rec = [st.string_id, st.address, st.value, sorted(st.referencing_function_ids)]
        hasher.update(b"|str|")
        hasher.update(json.dumps(st_rec, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))

    return hasher.hexdigest()


def compute_streaming_evidence_fingerprint(
    db: Session,
    *,
    analysis_id: str,
    sample_sha256: str,
    is_replay: bool,
    scenario_id: Optional[str],
    static_record_id: Optional[str],
    static_result: Optional[StaticAnalysisResult],
    sample_file_name: Optional[str] = None,
    sample_pe_image_base: Optional[str] = None,
    batch_size: int = 200,
) -> Tuple[str, int]:
    """
    Computes a deterministic, content-sensitive SHA-256 fingerprint across ordered
    dynamic event fields (via bounded SQL streaming) and canonical static evidence.
    """
    static_digest = compute_static_evidence_digest(static_result)
    ev_hasher = hashlib.sha256()
    total_events = 0

    stream = (
        db.query(
            AnalysisEvent.id,
            AnalysisEvent.category,
            AnalysisEvent.action,
            AnalysisEvent.timestamp,
            AnalysisEvent.process_id,
            AnalysisEvent.process_name,
            AnalysisEvent.target_path,
            AnalysisEvent.attributes,
            AnalysisEvent.source_tool,
        )
        .filter(AnalysisEvent.analysis_id == analysis_id)
        .order_by(AnalysisEvent.timestamp.asc().nulls_last(), AnalysisEvent.id.asc())
        .yield_per(max(50, int(batch_size)))
    )

    for row in stream:
        total_events += 1
        ev_id, cat, act, ts, pid, pname, tpath, attrs, stool = row
        ts_str = ts.isoformat() if isinstance(ts, datetime) else (str(ts) if ts is not None else "")
        if attrs is None:
            attrs_str = "null"
        elif isinstance(attrs, Mapping):
            attrs_str = json.dumps(
                dict(attrs), sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
            )
        else:
            attrs_str = f"NON_DICT:{type(attrs).__name__}:{repr(attrs)}"

        rec = json.dumps(
            [
                str(ev_id or ""),
                str(cat or ""),
                str(act or ""),
                ts_str,
                pid if pid is not None else "",
                str(pname or ""),
                str(tpath or ""),
                str(stool or ""),
                attrs_str,
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        ev_hasher.update(b"\n")
        ev_hasher.update(rec.encode("utf-8"))

    outer = "|".join(
        [
            CORRELATION_RULES_VERSION,
            analysis_id,
            sample_sha256,
            "replay" if is_replay else "live",
            scenario_id or "",
            static_record_id or "",
            static_result.status if static_result else "UNAVAILABLE",
            _basename_lower(sample_file_name),
            (sample_pe_image_base or "").strip().lower(),
            static_digest,
            str(total_events),
            ev_hasher.hexdigest(),
        ]
    )
    return hashlib.sha256(outer.encode("utf-8")).hexdigest(), total_events
