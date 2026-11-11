from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.schemas.static_analysis import StaticAnalysisResult
from app.services.evidence_correlation.rules import (
    build_static_index,
    run_deterministic_correlation_rules,
)
from app.services.evidence_correlation.schemas import (
    CorrelationBundleSection,
    CorrelationLimitations,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationSummary,
    CorrelationTruncation,
)
from app.services.evidence_correlation.verifier import (
    compute_streaming_evidence_fingerprint,
    validate_runtime_events,
    validate_trace_auth_key,
    verify_correlation_inputs,
)

DEFAULT_MAX_CORR_EVENTS = 250
DEFAULT_MAX_CORR_FUNCTIONS = 120
DEFAULT_MAX_CORR_FINDINGS = 30
DEFAULT_MAX_CORR_BYTES = 131072


class EvidenceCorrelationEngine:
    """
    Deterministic, bounded Static/Dynamic Evidence Correlation Engine.
    - Pure database & verified schema computation (zero Ghidra/CAPE/OpenCode spawns).
    - Preserves deterministic risk scores and Replay Mode synthetic provenance.
    - Never equates static API capability with runtime execution.
    """

    def __init__(
        self,
        db: Session,
        max_events: int = DEFAULT_MAX_CORR_EVENTS,
        max_functions: int = DEFAULT_MAX_CORR_FUNCTIONS,
        max_findings: int = DEFAULT_MAX_CORR_FINDINGS,
        max_bytes: int = DEFAULT_MAX_CORR_BYTES,
        trace_signing_secret: Optional[str] = None,
    ) -> None:
        self.db = db
        self.max_events = max(10, int(max_events))
        self.max_functions = max(10, int(max_functions))
        self.max_findings = max(1, int(max_findings))
        self.max_bytes = max(4096, int(max_bytes))
        self.trace_signing_secret = trace_signing_secret

    def _fetch_bounded_events(self, analysis_id: str, total_count: int) -> List[AnalysisEvent]:
        if total_count <= 0:
            return []

        # Prioritized SQL bounded fetch so high-signal API/network/process/registry/mutation events
        # aren't drowned out when 10,000+ file/noise events exist.
        high_signal: List[AnalysisEvent] = (
            self.db.query(AnalysisEvent)
            .filter(
                AnalysisEvent.analysis_id == analysis_id,
                AnalysisEvent.category.in_(["api", "process", "registry", "network", "dns", "http"]),
            )
            .order_by(AnalysisEvent.timestamp.asc().nulls_last(), AnalysisEvent.id.asc())
            .limit(max(5, self.max_events // 2))
            .all()
        )
        seen_ids = {e.id for e in high_signal}
        remaining = max(0, self.max_events - len(high_signal))
        others: List[AnalysisEvent] = []
        if remaining > 0:
            other_q = self.db.query(AnalysisEvent).filter(
                AnalysisEvent.analysis_id == analysis_id
            )
            if seen_ids:
                other_q = other_q.filter(AnalysisEvent.id.notin_(seen_ids))
            others = (
                other_q.order_by(AnalysisEvent.timestamp.asc().nulls_last(), AnalysisEvent.id.asc())
                .limit(remaining)
                .all()
            )
        combined = [*high_signal, *others]
        combined.sort(key=lambda e: (e.timestamp.isoformat() if e.timestamp else "", e.id))
        return combined[: self.max_events]

    def preview_source_fingerprint(
        self,
        analysis_id: str,
        static_override: Optional[StaticAnalysisResult] = None,
    ) -> Optional[str]:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return None
        ctx = verify_correlation_inputs(self.db, analysis, static_override=static_override)
        if not ctx.ok:
            return None
        pe_meta = ctx.sample.pe_metadata if ctx.sample and isinstance(ctx.sample.pe_metadata, dict) else {}
        fp, _ = compute_streaming_evidence_fingerprint(
            self.db,
            analysis_id=analysis.id,
            sample_sha256=ctx.sample_sha256,
            is_replay=ctx.is_replay,
            scenario_id=ctx.replay_scenario_id,
            static_record_id=ctx.static_record_id,
            static_result=ctx.static_result,
            sample_file_name=ctx.sample.file_name if ctx.sample else None,
            sample_pe_image_base=pe_meta.get("image_base"),
        )
        return fp

    def correlate(
        self,
        analysis_id: str,
        static_override: Optional[StaticAnalysisResult] = None,
        triggered_automatically: bool = False,
    ) -> CorrelationResult:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis '{analysis_id}' not found.")

        computed_at = datetime.now(timezone.utc).isoformat()
        ctx = verify_correlation_inputs(self.db, analysis, static_override=static_override)
        pe_meta = ctx.sample.pe_metadata if ctx.sample and isinstance(ctx.sample.pe_metadata, dict) else {}

        fingerprint, total_events_db = compute_streaming_evidence_fingerprint(
            self.db,
            analysis_id=analysis.id,
            sample_sha256=ctx.sample_sha256,
            is_replay=ctx.is_replay,
            scenario_id=ctx.replay_scenario_id,
            static_record_id=ctx.static_record_id,
            static_result=ctx.static_result,
            sample_file_name=ctx.sample.file_name if ctx.sample else None,
            sample_pe_image_base=pe_meta.get("image_base"),
        )

        bounded_raw_events = self._fetch_bounded_events(analysis.id, total_events_db)
        events, _valid_ev_ids, ev_warnings, has_trusted_trace = validate_runtime_events(
            bounded_raw_events,
            analysis_id=analysis.id,
            is_replay=ctx.is_replay,
            sample_sha256=ctx.sample_sha256 if ctx.ok else None,
            static_result=ctx.static_result,
            sample_file_name=ctx.sample.file_name if ctx.sample else None,
            pe_metadata=pe_meta,
            signing_secret=self.trace_signing_secret,
        )

        static_res = ctx.static_result
        static_status = static_res.status if static_res else "UNAVAILABLE"

        all_warnings = [*ctx.warnings, *ev_warnings]
        if total_events_db > len(events):
            all_warnings.append(
                f"Dynamic telemetry bounded cleanly: scanned {len(events)} of {total_events_db} events."
            )

        active_trace_key = (
            self.trace_signing_secret
            if self.trace_signing_secret is not None
            else settings.TRACE_AUTH_KEY
        )
        trace_key_ok, _ = validate_trace_auth_key(active_trace_key)

        if ctx.is_replay:
            trace_mode = "replay_synthetic_disallowed"
        elif has_trusted_trace:
            trace_mode = "authenticated_runtime_trace_verified"
        elif any("trace" in w.lower() for w in ev_warnings):
            trace_mode = (
                "trace_auth_disabled_or_unconfigured"
                if not trace_key_ok
                else "unauthenticated_or_mismatched_trace_rejected"
            )
        elif not trace_key_ok:
            trace_mode = "trace_auth_disabled"
        else:
            trace_mode = "no_authenticated_runtime_trace"

        provenance = CorrelationProvenance(
            analysis_id=analysis.id,
            sample_id=ctx.sample.id if ctx.sample else analysis.sample_id,
            sample_sha256=ctx.sample_sha256,
            static_record_id=ctx.static_record_id,
            static_analysis_id=static_res.provenance.analysis_id if static_res else None,
            static_status=static_status,
            static_provenance_scope=ctx.static_provenance_scope,
            dynamic_backend=analysis.backend_type,
            is_replay=ctx.is_replay,
            replay_scenario_id=ctx.replay_scenario_id,
            sample_identity_verified=ctx.ok,
            static_reuse_detected=ctx.static_reuse_detected,
            is_stale=False,
            trace_verification_mode=trace_mode,
            computed_at=computed_at,
            source_fingerprint=fingerprint,
            triggered_automatically=triggered_automatically,
            external_ai_used=False,
        )

        # Verification failed -> fail closed cleanly within serialized byte cap
        if not ctx.ok:
            return self.enforce_serialized_limit(
                CorrelationResult(
                    status="FAILED",
                    provenance=provenance,
                    limitations=CorrelationLimitations(
                        items=[*ctx.limitations, "Identity/provenance verification failed."],
                        has_runtime_function_trace=has_trusted_trace,
                        is_replay_synthetic=ctx.is_replay,
                        sample_level_static_reuse=ctx.static_reuse_detected,
                    ),
                    truncation=CorrelationTruncation(
                        total_events_in_analysis=total_events_db,
                        events_scanned=len(events),
                        events_omitted=max(0, total_events_db - len(events)),
                        max_events_limit=self.max_events,
                        max_functions_limit=self.max_functions,
                        max_findings_limit=self.max_findings,
                        max_serialized_bytes=self.max_bytes,
                    ),
                    warnings=all_warnings,
                    errors=ctx.errors,
                )
            )

        # Static analysis absent or failed/queued -> UNSUPPORTED within serialized byte cap
        if static_res is None or static_res.status not in ("COMPLETED", "PARTIAL"):
            return self.enforce_serialized_limit(
                CorrelationResult(
                    status="UNSUPPORTED",
                    provenance=provenance,
                    limitations=CorrelationLimitations(
                        items=[
                            *ctx.limitations,
                            "Static Ghidra disassembly is unavailable; cross-layer correlation cannot establish code-to-behavior links.",
                        ],
                        has_runtime_function_trace=has_trusted_trace,
                        is_replay_synthetic=ctx.is_replay,
                        sample_level_static_reuse=ctx.static_reuse_detected,
                    ),
                    truncation=CorrelationTruncation(
                        total_events_in_analysis=total_events_db,
                        events_scanned=len(events),
                        events_omitted=max(0, total_events_db - len(events)),
                        max_events_limit=self.max_events,
                        max_functions_limit=self.max_functions,
                        max_findings_limit=self.max_findings,
                        max_serialized_bytes=self.max_bytes,
                    ),
                    warnings=all_warnings,
                )
            )

        static_idx = build_static_index(
            static_res=static_res,
            valid_function_ids=ctx.valid_function_ids,
            valid_string_ids=ctx.valid_string_ids,
            max_functions=self.max_functions,
        )

        findings, candidates_eval, suppressed_count = run_deterministic_correlation_rules(
            ctx=ctx,
            static_idx=static_idx,
            events=events,
            max_findings=self.max_findings,
        )

        # Deterministic ordering retains DIRECTLY_OBSERVED / CONTRADICTORY / highest-confidence findings first
        rel_priority = {
            "DIRECTLY_OBSERVED": 0,
            "CONTRADICTORY": 1,
            "CONSISTENT_WITH": 2,
            "SYNTHETIC_SCENARIO_ONLY": 3,
            "INSUFFICIENT_EVIDENCE": 4,
        }
        findings.sort(
            key=lambda f: (
                rel_priority.get(f.relationship, 9),
                -f.confidence.score,
                f.rule_id,
                f.correlation_id,
            )
        )

        limitations_items = list(ctx.limitations)
        if not has_trusted_trace:
            limitations_items.append(
                "No backend-authenticated runtime instruction-pointer/module-offset trace was captured; "
                "function-to-event execution cannot be directly proven."
            )

        partial_static = bool(
            static_res.status == "PARTIAL" or static_res.is_partial or static_res.truncation.truncated
        )
        status = (
            "PARTIAL"
            if (partial_static or total_events_db > len(events))
            else ("COMPLETED" if findings else "INSUFFICIENT_EVIDENCE")
        )

        res = CorrelationResult(
            status=status,
            provenance=provenance,
            summary=_summarize_findings(findings),
            findings=findings,
            limitations=CorrelationLimitations(
                items=limitations_items,
                has_runtime_function_trace=has_trusted_trace,
                is_replay_synthetic=ctx.is_replay,
                sample_level_static_reuse=ctx.static_reuse_detected,
                partial_static_coverage=partial_static,
                suppressed_ambiguous_count=suppressed_count,
            ),
            truncation=CorrelationTruncation(
                truncated=bool(total_events_db > len(events) or len(static_res.functions) > static_idx.functions_scanned),
                total_events_in_analysis=total_events_db,
                events_scanned=len(events),
                events_omitted=max(0, total_events_db - len(events)),
                functions_available=len(static_res.functions),
                functions_scanned=static_idx.functions_scanned,
                candidate_relationships_evaluated=candidates_eval,
                findings_included=len(findings),
                findings_omitted=0,
                max_events_limit=self.max_events,
                max_functions_limit=self.max_functions,
                max_findings_limit=self.max_findings,
                max_serialized_bytes=self.max_bytes,
            ),
            warnings=all_warnings,
        )
        return self.enforce_serialized_limit(res)

    @staticmethod
    def _serialized_size(res: CorrelationResult) -> int:
        return len(json.dumps(res.model_dump(mode="json")).encode("utf-8"))

    def _sync_truncation_metadata(
        self,
        current: CorrelationResult,
        omitted_findings: int,
        extra_truncated: bool,
    ) -> int:
        current.truncation.max_serialized_bytes = self.max_bytes
        current.truncation.findings_included = len(current.findings)
        current.truncation.findings_omitted = omitted_findings
        current.summary = _summarize_findings(current.findings)
        if omitted_findings > 0 or extra_truncated:
            current.truncation.truncated = True
            if omitted_findings > 0 and current.status == "COMPLETED":
                current.status = "PARTIAL"
        # Two-pass convergence ensures serialized_bytes matches actual final JSON size.
        for _ in range(2):
            current.truncation.serialized_bytes = self._serialized_size(current)
        return current.truncation.serialized_bytes

    def _trim_string_list_to_budget(
        self,
        current: CorrelationResult,
        field_owner: object,
        attr_name: str,
        omitted_findings: int,
        max_item_chars: int = 180,
    ) -> Tuple[bool, int]:
        """Truncates oversized strings and pops tail items from a message list until within byte cap."""
        lst: List[str] = list(getattr(field_owner, attr_name) or [])
        if not lst:
            return False, self._sync_truncation_metadata(current, omitted_findings, False)

        changed = False
        shortened = [
            (item[: max_item_chars - 3] + "..." if len(item) > max_item_chars else item)
            for item in lst
        ]
        if shortened != lst:
            lst = shortened
            setattr(field_owner, attr_name, lst)
            changed = True

        size = self._sync_truncation_metadata(current, omitted_findings, changed)
        while size > self.max_bytes and lst:
            lst.pop()
            setattr(field_owner, attr_name, lst)
            changed = True
            size = self._sync_truncation_metadata(current, omitted_findings, True)

        return changed, size

    def enforce_serialized_limit(self, result: CorrelationResult) -> CorrelationResult:
        """
        Enforces hard UTF-8 serialized byte limit across ALL five correlation statuses
        and even when findings == [], converging truncation.serialized_bytes accurately
        on the final payload or falling back to a minimal bounded FAILED result.
        """
        current = result.model_copy(deep=True)
        omitted = current.truncation.findings_omitted
        extra_truncated = False

        # Stage 1: Pop lowest-priority findings from tail until within budget or findings == []
        size = self._sync_truncation_metadata(current, omitted, extra_truncated)
        while size > self.max_bytes and current.findings:
            current.findings.pop()
            omitted += 1
            size = self._sync_truncation_metadata(current, omitted, True)

        if size <= self.max_bytes:
            return CorrelationResult.model_validate(current.model_dump(mode="json"))

        # Stage 2: Trim warnings, limitations, and errors cleanly when findings == [] still exceeds cap
        for owner, attr in (
            (current, "warnings"),
            (current.limitations, "items"),
            (current, "errors"),
        ):
            did_trim, size = self._trim_string_list_to_budget(
                current, owner, attr, omitted, max_item_chars=180
            )
            if did_trim:
                extra_truncated = True
            if size <= self.max_bytes:
                return CorrelationResult.model_validate(current.model_dump(mode="json"))

        # Stage 3: Compact residual strings (disclaimer, provenance optional text) if still oversized
        extra_truncated = True
        current.disclaimer = "Bounded correlation output limit enforced."
        if current.provenance.replay_scenario_id and len(current.provenance.replay_scenario_id) > 64:
            current.provenance.replay_scenario_id = current.provenance.replay_scenario_id[:64]
        size = self._sync_truncation_metadata(current, omitted, True)
        if size <= self.max_bytes:
            return CorrelationResult.model_validate(current.model_dump(mode="json"))

        # Stage 4: Controlled minimal bounded FAILED fallback guaranteed within max_bytes
        minimal_prov = CorrelationProvenance(
            schema_version=current.provenance.schema_version,
            engine_version=current.provenance.engine_version,
            analysis_id=current.provenance.analysis_id[:64],
            sample_id=current.provenance.sample_id[:64],
            sample_sha256=current.provenance.sample_sha256[:64],
            static_status=current.provenance.static_status[:32],
            static_provenance_scope=current.provenance.static_provenance_scope[:32],
            dynamic_backend=current.provenance.dynamic_backend[:32],
            is_replay=current.provenance.is_replay,
            replay_scenario_id=(
                current.provenance.replay_scenario_id[:32]
                if current.provenance.replay_scenario_id
                else None
            ),
            sample_identity_verified=current.provenance.sample_identity_verified,
            static_reuse_detected=current.provenance.static_reuse_detected,
            is_stale=current.provenance.is_stale,
            trace_verification_mode=current.provenance.trace_verification_mode[:48],
            computed_at=current.provenance.computed_at[:40],
            source_fingerprint=current.provenance.source_fingerprint[:64],
            triggered_automatically=current.provenance.triggered_automatically,
            external_ai_used=False,
        )
        fallback = CorrelationResult(
            status="FAILED",
            provenance=minimal_prov,
            summary=CorrelationSummary(),
            findings=[],
            limitations=CorrelationLimitations(
                is_replay_synthetic=minimal_prov.is_replay,
                sample_level_static_reuse=minimal_prov.static_reuse_detected,
            ),
            truncation=CorrelationTruncation(
                truncated=True,
                total_events_in_analysis=current.truncation.total_events_in_analysis,
                events_scanned=current.truncation.events_scanned,
                events_omitted=current.truncation.events_omitted,
                functions_available=current.truncation.functions_available,
                functions_scanned=current.truncation.functions_scanned,
                candidate_relationships_evaluated=current.truncation.candidate_relationships_evaluated,
                findings_included=0,
                findings_omitted=omitted,
                max_events_limit=self.max_events,
                max_functions_limit=self.max_functions,
                max_findings_limit=self.max_findings,
                max_serialized_bytes=self.max_bytes,
            ),
            warnings=[],
            errors=[f"Correlation output reduced to minimal FAILED response to enforce {self.max_bytes}-byte cap."],
            disclaimer="Bounded output limit enforced.",
        )
        size = self._sync_truncation_metadata(fallback, omitted, True)
        if size > self.max_bytes:
            fallback.errors = ["Output byte cap exceeded."]
            self._sync_truncation_metadata(fallback, omitted, True)
        return CorrelationResult.model_validate(fallback.model_dump(mode="json"))


def _summarize_findings(findings: List) -> CorrelationSummary:
    return CorrelationSummary(
        total_findings=len(findings),
        directly_observed_count=sum(1 for f in findings if f.relationship == "DIRECTLY_OBSERVED"),
        consistent_with_count=sum(1 for f in findings if f.relationship == "CONSISTENT_WITH"),
        contradictory_count=sum(1 for f in findings if f.relationship == "CONTRADICTORY"),
        insufficient_evidence_count=sum(1 for f in findings if f.relationship == "INSUFFICIENT_EVIDENCE"),
        synthetic_scenario_only_count=sum(1 for f in findings if f.relationship == "SYNTHETIC_SCENARIO_ONLY"),
    )


def build_correlation_bundle_section(
    result: CorrelationResult,
    max_findings: int = 12,
) -> CorrelationBundleSection:
    """
    Produces a compact, pseudocode-free verified correlation summary safe for inclusion
    in VerifiedEvidenceBundle and IntelligenceReport.
    """
    compact_findings = []
    for f in result.findings[:max_findings]:
        compact_findings.append(
            {
                "correlation_id": f.correlation_id,
                "rule_id": f.rule_id,
                "relationship": f.relationship,
                "relationship_summary": f.relationship_summary[:240],
                "explanation": f.explanation[:360],
                "confidence_score": f.confidence.score,
                "confidence_level": f.confidence.level,
                "behavioral_execution_directly_observed": f.behavioral_execution_directly_observed,
                "static_ref_ids": [r.ref_id for r in f.static_references[:5]],
                "dynamic_ref_ids": [r.ref_id for r in f.dynamic_references[:5]],
                "known_limitations": [lim[:180] for lim in f.known_limitations[:3]],
            }
        )

    return CorrelationBundleSection(
        status=result.status,
        source_fingerprint=result.provenance.source_fingerprint,
        is_replay=result.provenance.is_replay,
        is_stale=result.provenance.is_stale,
        trace_verification_mode=result.provenance.trace_verification_mode,
        has_runtime_function_trace=result.limitations.has_runtime_function_trace,
        summary=result.summary.model_dump(),
        findings=compact_findings,
        limitations=[lim[:220] for lim in result.limitations.items[:8]],
        warnings=[w[:220] for w in result.warnings[:6]],
        truncated=bool(result.truncation.truncated or len(result.findings) > max_findings),
    )
