from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import redact_sensitive_text
from app.models.analysis import Analysis
from app.models.correlation import StaticDynamicCorrelationRecord
from app.models.sample import Sample
from app.schemas.static_analysis import StaticAnalysisResult
from app.services.evidence_correlation.engine import EvidenceCorrelationEngine
from app.services.evidence_correlation.schemas import (
    CorrelationLimitations,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationTruncation,
)

USABLE_CORRELATION_STATUSES = ("COMPLETED", "PARTIAL", "INSUFFICIENT_EVIDENCE", "UNSUPPORTED")


class EvidenceCorrelationService:
    """
    Coordinates idempotent persistence, read-only retrieval, and failure-preserving updates
    for Static/Dynamic Evidence Correlation results without touching deterministic risk scores.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.engine = EvidenceCorrelationEngine(db)

    def _select_records(self, analysis_id: str, sample_sha256: Optional[str] = None):
        """
        Bounded O(1)-row history lookup: fetches at most the single newest attempt and
        the single newest usable record without loading unbounded historical JSON payloads.
        """
        base = self.db.query(StaticDynamicCorrelationRecord).filter(
            StaticDynamicCorrelationRecord.analysis_id == analysis_id
        )
        if sample_sha256:
            base = base.filter(StaticDynamicCorrelationRecord.sample_sha256 == sample_sha256.lower())

        order_cols = (
            StaticDynamicCorrelationRecord.created_at.desc(),
            StaticDynamicCorrelationRecord.id.desc(),
        )
        latest = base.order_by(*order_cols).limit(1).first()
        if latest is not None and latest.status in USABLE_CORRELATION_STATUSES:
            return latest, latest

        usable = (
            base.filter(StaticDynamicCorrelationRecord.status.in_(USABLE_CORRELATION_STATUSES))
            .order_by(*order_cols)
            .limit(1)
            .first()
        )
        return latest, usable

    def get_correlation_readonly(self, analysis_id: str) -> CorrelationResult:
        """
        Strict read-only retrieval:
        - Never executes Ghidra, CAPE, OpenCode, or writes to DB.
        - Preserves last usable result if a later correlation attempt failed.
        - Returns explicit uncomputed state if never run yet.
        """
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis '{analysis_id}' not found.")

        sample = self.db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        sample_sha = (sample.sha256.lower() if sample and sample.sha256 else "0" * 64)
        is_replay = bool(analysis.backend_type == "replay")

        latest_rec, usable_rec = self._select_records(analysis_id, sample_sha256=sample_sha if sample else None)
        chosen = usable_rec or latest_rec
        if chosen is not None and isinstance(chosen.result_json, dict):
            try:
                parsed = CorrelationResult.model_validate(chosen.result_json)
                warnings = list(parsed.warnings)
                if (
                    latest_rec is not None
                    and usable_rec is not None
                    and latest_rec.id != usable_rec.id
                    and latest_rec.status == "FAILED"
                ):
                    msg = (
                        f"Latest correlation recompute ({latest_rec.id}) failed "
                        f"({latest_rec.error_message or 'error'}); preserved previous usable result."
                    )
                    if msg not in warnings:
                        warnings.append(msg)

                current_fp = self.engine.preview_source_fingerprint(analysis_id)
                is_stale = False
                if current_fp and current_fp != parsed.provenance.source_fingerprint:
                    is_stale = True
                    stale_msg = (
                        "Underlying static/dynamic evidence changed since correlation was stored; "
                        "recompute via POST /api/v1/analyses/{analysis_id}/correlation."
                    )
                    if stale_msg not in warnings:
                        warnings.append(stale_msg)

                updated_prov = (
                    parsed.provenance.model_copy(update={"is_stale": True})
                    if is_stale
                    else parsed.provenance
                )
                return self.engine.enforce_serialized_limit(
                    parsed.model_copy(update={"provenance": updated_prov, "warnings": warnings})
                )
            except Exception:
                pass

        return CorrelationResult(
            status="INSUFFICIENT_EVIDENCE",
            provenance=CorrelationProvenance(
                analysis_id=analysis.id,
                sample_id=analysis.sample_id,
                sample_sha256=sample_sha,
                dynamic_backend=analysis.backend_type,
                is_replay=is_replay,
                replay_scenario_id=analysis.replay_scenario_id if is_replay else None,
                sample_identity_verified=bool(sample is not None),
                computed_at=datetime.now(timezone.utc).isoformat(),
                source_fingerprint="uncomputed",
                triggered_automatically=False,
                external_ai_used=False,
            ),
            limitations=CorrelationLimitations(
                items=[
                    "Static/dynamic correlation has not yet been computed for this analysis. "
                    "Use POST /api/v1/analyses/{analysis_id}/correlation to run bounded deterministic correlation."
                ],
                is_replay_synthetic=is_replay,
            ),
            truncation=CorrelationTruncation(),
            warnings=["Correlation not yet persisted for this analysis."],
        )

    def _preserve_previous_usable(
        self,
        prev_usable: Optional[StaticDynamicCorrelationRecord],
        message: str,
        current_fp: Optional[str] = None,
    ) -> Optional[CorrelationResult]:
        if prev_usable is None or not isinstance(prev_usable.result_json, dict):
            return None
        try:
            preserved = CorrelationResult.model_validate(prev_usable.result_json)
            drifted = bool(
                current_fp
                and current_fp != "failed"
                and preserved.provenance.source_fingerprint != current_fp
            )
            prov_upd = preserved.provenance.model_copy(update={"is_stale": drifted})
            warnings = list(preserved.warnings)
            if message not in warnings:
                warnings.append(message)
            return self.engine.enforce_serialized_limit(
                preserved.model_copy(update={"provenance": prov_upd, "warnings": warnings})
            )
        except Exception:
            return None

    def compute_and_persist(
        self,
        analysis_id: str,
        force: bool = False,
        triggered_automatically: bool = False,
        static_override: Optional[StaticAnalysisResult] = None,
    ) -> CorrelationResult:
        """
        Computes bounded deterministic correlation and persists result idempotently.
        - Reuses cached record if source_fingerprint is unchanged and not force.
        - Preserves any existing usable correlation record if recomputation fails.
        """
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis '{analysis_id}' not found.")

        sample = self.db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        sample_sha = (sample.sha256.lower() if sample and sample.sha256 else "0" * 64)
        _, prev_usable = self._select_records(analysis_id, sample_sha256=sample_sha if sample else None)

        if not force and prev_usable is not None:
            current_fp = self.engine.preview_source_fingerprint(
                analysis_id, static_override=static_override
            )
            if current_fp and prev_usable.source_fingerprint == current_fp and isinstance(prev_usable.result_json, dict):
                try:
                    cached = CorrelationResult.model_validate(prev_usable.result_json)
                    if cached.provenance.is_stale:
                        cached = cached.model_copy(
                            update={"provenance": cached.provenance.model_copy(update={"is_stale": False})}
                        )
                    return self.engine.enforce_serialized_limit(cached)
                except Exception:
                    pass

        try:
            computed = self.engine.correlate(
                analysis_id=analysis_id,
                static_override=static_override,
                triggered_automatically=triggered_automatically,
            )
        except Exception as exc:
            self.db.rollback()
            secrets = [
                s
                for s in (
                    settings.TRACE_AUTH_KEY,
                    settings.SECRET_KEY,
                    settings.REPORTING_AUTH_TOKEN,
                    settings.OPERATOR_TOKEN,
                )
                if s
            ]
            safe_err = redact_sensitive_text(
                f"Correlation engine failed ({type(exc).__name__}): {exc}",
                extra_secrets=secrets,
                max_chars=240,
            )
            fail_fp = self.engine.preview_source_fingerprint(analysis_id) or "failed"
            fail_result = self.engine.enforce_serialized_limit(
                CorrelationResult(
                    status="FAILED",
                    provenance=CorrelationProvenance(
                        analysis_id=analysis.id,
                        sample_id=analysis.sample_id,
                        sample_sha256=sample_sha,
                        dynamic_backend=analysis.backend_type,
                        is_replay=(analysis.backend_type == "replay"),
                        replay_scenario_id=analysis.replay_scenario_id if analysis.backend_type == "replay" else None,
                        sample_identity_verified=bool(sample is not None),
                        computed_at=datetime.now(timezone.utc).isoformat(),
                        source_fingerprint=fail_fp,
                        triggered_automatically=triggered_automatically,
                        external_ai_used=False,
                    ),
                    errors=[safe_err],
                )
            )
            self._persist_record(analysis, sample_sha, fail_result, error_message=safe_err)
            preserved = self._preserve_previous_usable(
                prev_usable,
                f"Latest correlation recompute failed ({safe_err}); preserved previous usable result.",
                current_fp=fail_fp,
            )
            if preserved is not None:
                return preserved
            return fail_result

        self._persist_record(
            analysis,
            computed.provenance.sample_sha256,
            computed,
            error_message="; ".join(computed.errors) if computed.errors else None,
        )

        # If verification produced FAILED cleanly while a prior usable result existed, return preserved usable
        if computed.status == "FAILED":
            preserved = self._preserve_previous_usable(
                prev_usable,
                "Latest correlation attempt failed verification; preserved previous usable result.",
                current_fp=computed.provenance.source_fingerprint,
            )
            if preserved is not None:
                return preserved

        return computed

    def _persist_record(
        self,
        analysis: Analysis,
        sample_sha256: str,
        result: CorrelationResult,
        error_message: Optional[str] = None,
    ) -> StaticDynamicCorrelationRecord:
        now_dt = datetime.now(timezone.utc)
        rec = StaticDynamicCorrelationRecord(
            analysis_id=analysis.id,
            sample_id=analysis.sample_id,
            sample_sha256=sample_sha256,
            static_record_id=result.provenance.static_record_id,
            status=result.status,
            source_fingerprint=result.provenance.source_fingerprint,
            is_replay=result.provenance.is_replay,
            is_partial=(result.status == "PARTIAL"),
            findings_count=len(result.findings),
            error_message=error_message,
            result_json=result.model_dump(mode="json"),
            created_at=now_dt,
            updated_at=now_dt,
        )
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

