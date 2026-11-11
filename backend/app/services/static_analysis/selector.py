from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.schemas.static_analysis import (
    StaticAnalysisProvenance,
    StaticAnalysisResult,
    StaticAnalysisStatus,
    StaticAnalysisTruncation,
    StaticAttemptMetadata,
)

USABLE_STATIC_STATUSES: Tuple[StaticAnalysisStatus, ...] = ("COMPLETED", "PARTIAL")
ACTIVE_STATIC_STATUSES: Tuple[StaticAnalysisStatus, ...] = ("PENDING", "QUEUED", "RUNNING")
VALID_STATIC_STATUSES = set(
    (
        "PENDING",
        "QUEUED",
        "RUNNING",
        "COMPLETED",
        "PARTIAL",
        "FAILED",
        "TIMED_OUT",
        "UNAVAILABLE",
        "SKIPPED",
    )
)


def _coerce_status(raw: Optional[str], fallback: StaticAnalysisStatus = "FAILED") -> StaticAnalysisStatus:
    if raw in VALID_STATIC_STATUSES:
        return raw  # type: ignore[return-value]
    return fallback


def _to_attempt_metadata(
    record: Optional[StaticAnalysisRecord],
    requested_analysis_id: Optional[str],
) -> Optional[StaticAttemptMetadata]:
    if record is None:
        return None
    st = _coerce_status(record.status)
    same_analysis = True if requested_analysis_id is None else (record.analysis_id == requested_analysis_id)
    return StaticAttemptMetadata(
        job_id=record.id,
        analysis_id=record.analysis_id,
        status=st,
        started_at=record.started_at.isoformat() if record.started_at else None,
        completed_at=record.completed_at.isoformat() if record.completed_at else None,
        error_message=record.error_message,
        is_usable=(st in USABLE_STATIC_STATUSES),
        same_analysis=same_analysis,
    )


def _parse_record_result(record: StaticAnalysisRecord) -> Optional[StaticAnalysisResult]:
    if not isinstance(record.result_json, dict):
        return None
    try:
        return StaticAnalysisResult.model_validate(record.result_json)
    except Exception:
        return None


@dataclass
class SelectedStaticRecords:
    primary_record: Optional[StaticAnalysisRecord]
    latest_attempt_record: Optional[StaticAnalysisRecord]
    usable_record: Optional[StaticAnalysisRecord]
    provenance_scope: str
    showing_preserved_usable: bool
    other_analysis_active_record: Optional[StaticAnalysisRecord] = None


def select_static_records(
    db: Session,
    sample_id: str,
    sample_sha256: str,
    requested_analysis_id: Optional[str] = None,
    prefer_usable_over_active: bool = False,
) -> SelectedStaticRecords:
    """
    Selects authoritative static analysis records with strict provenance guarantees:
    1. Prefers exact analysis-specific attempts before sample-level fallback.
    2. Preserves last usable COMPLETED/PARTIAL evidence when a newer attempt fails/times out.
    3. Never falls back across analyses to an active (QUEUED/RUNNING) or failed job owned by another analysis.
    """
    norm_sha = (sample_sha256 or "").strip().lower()
    sample_records: List[StaticAnalysisRecord] = (
        db.query(StaticAnalysisRecord)
        .filter(
            StaticAnalysisRecord.sample_id == sample_id,
            StaticAnalysisRecord.sample_sha256 == norm_sha,
        )
        .order_by(StaticAnalysisRecord.created_at.desc(), StaticAnalysisRecord.id.desc())
        .all()
    )

    if requested_analysis_id is None:
        latest_sample = sample_records[0] if sample_records else None
        usable_sample = next(
            (r for r in sample_records if r.status in USABLE_STATIC_STATUSES and _parse_record_result(r) is not None),
            None,
        )
        if latest_sample is None:
            return SelectedStaticRecords(None, None, None, "unexecuted", False)

        if latest_sample.status in USABLE_STATIC_STATUSES:
            return SelectedStaticRecords(latest_sample, latest_sample, latest_sample, "sample_level", False)

        if usable_sample is not None:
            if latest_sample.status in ACTIVE_STATIC_STATUSES and not prefer_usable_over_active:
                return SelectedStaticRecords(latest_sample, latest_sample, usable_sample, "sample_level", True)
            return SelectedStaticRecords(usable_sample, latest_sample, usable_sample, "sample_level", True)

        return SelectedStaticRecords(latest_sample, latest_sample, None, "sample_level", False)

    exact_records = [r for r in sample_records if r.analysis_id == requested_analysis_id]
    other_records = [r for r in sample_records if r.analysis_id != requested_analysis_id]

    latest_exact = exact_records[0] if exact_records else None
    usable_exact = next(
        (r for r in exact_records if r.status in USABLE_STATIC_STATUSES and _parse_record_result(r) is not None),
        None,
    )
    usable_other = next(
        (r for r in other_records if r.status in USABLE_STATIC_STATUSES and _parse_record_result(r) is not None),
        None,
    )
    active_other = next(
        (r for r in other_records if r.status in ACTIVE_STATIC_STATUSES),
        None,
    )

    best_usable = usable_exact or usable_other

    if latest_exact is not None:
        if latest_exact.status in USABLE_STATIC_STATUSES:
            return SelectedStaticRecords(latest_exact, latest_exact, latest_exact, "analysis_specific", False)

        if latest_exact.status in ACTIVE_STATIC_STATUSES:
            if prefer_usable_over_active and best_usable is not None:
                scope = "analysis_specific" if best_usable.analysis_id == requested_analysis_id else "sample_fallback"
                return SelectedStaticRecords(best_usable, latest_exact, best_usable, scope, True)
            return SelectedStaticRecords(
                latest_exact,
                latest_exact,
                best_usable,
                "analysis_specific",
                bool(best_usable is not None),
            )

        # Latest exact attempt failed/timed out/unavailable — preserve last usable evidence if present
        if best_usable is not None:
            scope = "analysis_specific" if best_usable.analysis_id == requested_analysis_id else "sample_fallback"
            return SelectedStaticRecords(best_usable, latest_exact, best_usable, scope, True)

        return SelectedStaticRecords(latest_exact, latest_exact, None, "analysis_specific", False)

    # No exact attempts exist under requested_analysis_id: fallback ONLY to usable COMPLETED/PARTIAL records!
    if usable_other is not None:
        return SelectedStaticRecords(
            usable_other,
            other_records[0] if other_records else usable_other,
            usable_other,
            "sample_fallback",
            showing_preserved_usable=False,
            other_analysis_active_record=active_other,
        )

    return SelectedStaticRecords(
        primary_record=None,
        latest_attempt_record=active_other,
        usable_record=None,
        provenance_scope="unexecuted",
        showing_preserved_usable=False,
        other_analysis_active_record=active_other,
    )


def build_static_result_response(
    db: Session,
    sample: Sample,
    requested_analysis_id: Optional[str] = None,
    prefer_usable_over_active: bool = False,
) -> StaticAnalysisResult:
    """
    Constructs a strict StaticAnalysisResult DTO distinguishing latest attempt from last
    usable completed evidence and preventing sample fallback from misrepresenting active jobs
    belonging to other analyses.
    """
    ghidra_enabled = bool(settings.GHIDRA_ENABLED)
    sel = select_static_records(
        db=db,
        sample_id=sample.id,
        sample_sha256=sample.sha256,
        requested_analysis_id=requested_analysis_id,
        prefer_usable_over_active=prefer_usable_over_active,
    )

    latest_meta = _to_attempt_metadata(sel.latest_attempt_record, requested_analysis_id)
    usable_meta = _to_attempt_metadata(sel.usable_record, requested_analysis_id)

    if sel.primary_record is None:
        warnings = ["Ghidra static analysis has not been executed for this sample/analysis."]
        prov_note = (
            "Ghidra Headless static analysis has not been executed for this sample/analysis."
            if ghidra_enabled
            else "Ghidra Headless static analysis is disabled by server configuration (MALBOX_GHIDRA_ENABLED=false)."
        )
        if sel.other_analysis_active_record is not None:
            other_id = sel.other_analysis_active_record.analysis_id or "another analysis"
            other_st = sel.other_analysis_active_record.status
            msg = (
                f"Another analysis ('{other_id}') currently has a {other_st} static job for this sample; "
                "this analysis remains UNAVAILABLE until static evidence completes."
            )
            warnings.append(msg)
            prov_note = f"{prov_note} {msg}"

        return StaticAnalysisResult(
            status="UNAVAILABLE",
            provenance=StaticAnalysisProvenance(
                analysis_id=requested_analysis_id,
                requested_analysis_id=requested_analysis_id,
                sample_id=sample.id,
                sample_sha256=sample.sha256,
                os_sandbox="none",
                provenance_scope="unexecuted",
                provenance_note=prov_note,
                ghidra_enabled=ghidra_enabled,
                latest_attempt=latest_meta,
                usable_evidence=None,
                showing_preserved_usable_evidence=False,
            ),
            truncation=StaticAnalysisTruncation(),
            warnings=warnings,
        )

    rec = sel.primary_record
    provenance_scope = sel.provenance_scope
    if provenance_scope == "sample_fallback":
        origin_id = rec.analysis_id or "sample-level"
        prov_note = (
            f"Shared sample-level static analysis (originally generated under analysis '{origin_id}'); "
            "static disassembly reflects binary SHA-256 bytes and was not re-executed separately for this analysis."
        )
    elif provenance_scope == "sample_level":
        prov_note = "Sample-level static disassembly record tied to quarantined binary SHA-256."
    else:
        prov_note = "Analysis-specific Ghidra Headless static disassembly record for this analysis."

    if sel.showing_preserved_usable and sel.latest_attempt_record is not None and sel.usable_record is not None:
        latest_st = sel.latest_attempt_record.status
        prov_note = (
            f"{prov_note} Preserving last usable {sel.usable_record.status} evidence while latest attempt "
            f"('{sel.latest_attempt_record.id}') is {latest_st}."
        )

    # Determine base payload: if active re-run is primary, carry over prior usable artifacts if available
    parsed = _parse_record_result(rec)
    usable_parsed = _parse_record_result(sel.usable_record) if sel.usable_record is not None else None

    if (
        sel.showing_preserved_usable
        and rec.status in ACTIVE_STATIC_STATUSES
        and usable_parsed is not None
    ):
        base_payload = usable_parsed
        target_status = _coerce_status(rec.status, "RUNNING")
    elif parsed is not None:
        base_payload = parsed
        target_status = _coerce_status(rec.status, parsed.status) if parsed.status != rec.status and rec.status in (
            "QUEUED",
            "RUNNING",
            "FAILED",
            "TIMED_OUT",
        ) else parsed.status
    else:
        base_payload = StaticAnalysisResult(
            status=_coerce_status(rec.status, "FAILED"),
            provenance=StaticAnalysisProvenance(
                analysis_id=rec.analysis_id,
                requested_analysis_id=requested_analysis_id,
                sample_id=sample.id,
                sample_sha256=sample.sha256,
                ghidra_version=rec.ghidra_version,
                started_at=rec.started_at.isoformat() if rec.started_at else None,
                completed_at=rec.completed_at.isoformat() if rec.completed_at else None,
            ),
            truncation=StaticAnalysisTruncation(),
            errors=[rec.error_message] if rec.error_message else [],
            is_partial=bool(rec.is_partial),
        )
        target_status = base_payload.status

    warnings = list(base_payload.warnings)
    if (
        sel.showing_preserved_usable
        and sel.latest_attempt_record is not None
        and sel.latest_attempt_record.id != sel.usable_record.id  # type: ignore[union-attr]
        and sel.latest_attempt_record.status in ("FAILED", "TIMED_OUT")
    ):
        err_msg = sel.latest_attempt_record.error_message or "unspecified failure"
        preserved_note = (
            f"Latest static attempt ({sel.latest_attempt_record.id}, status={sel.latest_attempt_record.status}) "
            f"did not complete ({err_msg}); preserved last usable verified evidence."
        )
        if preserved_note not in warnings:
            warnings.append(preserved_note)

    updated_prov = base_payload.provenance.model_copy(
        update={
            "analysis_id": sel.usable_record.analysis_id if sel.usable_record is not None else rec.analysis_id,
            "requested_analysis_id": requested_analysis_id,
            "provenance_scope": provenance_scope,  # type: ignore[arg-type]
            "provenance_note": prov_note,
            "ghidra_enabled": ghidra_enabled,
            "latest_attempt": latest_meta,
            "usable_evidence": usable_meta,
            "showing_preserved_usable_evidence": sel.showing_preserved_usable,
        }
    )

    return base_payload.model_copy(
        update={
            "status": target_status,
            "provenance": updated_prov,
            "warnings": warnings,
        }
    )
