from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.models.sample import Sample
from app.schemas.static_analysis import StaticAnalysisResult
from app.services.static_analysis.selector import select_static_records

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TRUSTED_RUNTIME_TRACE_TOOLS: Set[str] = {
    "cape-tracer",
    "frida-tracer",
    "etw-callstack",
    "pin-tracer",
}


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
    - Explicitly tags Replay telemetry as synthetic and strips invalid/unowned references.
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


def validate_runtime_events(
    events: List[AnalysisEvent],
    analysis_id: str,
    is_replay: bool,
) -> Tuple[List[AnalysisEvent], Set[str], List[str], bool]:
    """
    Validates normalized dynamic event records, drops wrong-analysis or malformed events,
    sanitizes Replay synthetic attributes, and determines whether any trusted runtime
    module/function callstack trace exists.
    """
    verified: List[AnalysisEvent] = []
    valid_event_ids: Set[str] = set()
    warnings: List[str] = []
    has_trusted_trace = False

    for ev in events:
        if ev.analysis_id != analysis_id:
            warnings.append(
                f"Rejected cross-analysis event '{ev.id}' belonging to '{ev.analysis_id}'."
            )
            continue
        if not ev.category or not ev.action:
            warnings.append(f"Skipped malformed event '{ev.id}' missing category/action.")
            continue
        attrs = ev.attributes if isinstance(ev.attributes, dict) else {}
        if not isinstance(ev.attributes, dict):
            warnings.append(f"Event '{ev.id}' had non-dict attributes; ignoring attributes safely.")
            ev.attributes = {}

        if (
            not is_replay
            and ev.source_tool in TRUSTED_RUNTIME_TRACE_TOOLS
            and attrs.get("trace_verified") is True
            and (attrs.get("function_address") or attrs.get("function_id"))
        ):
            has_trusted_trace = True

        verified.append(ev)
        valid_event_ids.add(ev.id)

    return verified, valid_event_ids, warnings, has_trusted_trace


def compute_evidence_fingerprint(
    analysis_id: str,
    sample_sha256: str,
    is_replay: bool,
    scenario_id: Optional[str],
    static_record_id: Optional[str],
    static_status: str,
    event_count: int,
    first_event_id: Optional[str],
    last_event_id: Optional[str],
) -> str:
    payload = "|".join(
        [
            "corr-v1.0.0",
            analysis_id,
            sample_sha256,
            "replay" if is_replay else "live",
            scenario_id or "",
            static_record_id or "",
            static_status,
            str(event_count),
            first_event_id or "",
            last_event_id or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

