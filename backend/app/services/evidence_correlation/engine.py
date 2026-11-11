from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy import func
from sqlalchemy.orm import Session

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
    compute_evidence_fingerprint,
    validate_runtime_events,
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
    ) -> None:
        self.db = db
        self.max_events = max(10, int(max_events))
        self.max_functions = max(10, int(max_functions))
        self.max_findings = max(1, int(max_findings))
        self.max_bytes = max(8192, int(max_bytes))

    def _fetch_bounded_events(self, analysis_id: str) -> Tuple[int, List[AnalysisEvent]]:
        total_count = int(
            self.db.query(func.count(AnalysisEvent.id))
            .filter(AnalysisEvent.analysis_id == analysis_id)
            .scalar()
            or 0
        )
        if total_count == 0:
            return 0, []

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
        return total_count, combined[: self.max_events]

    def _get_event_window_bounds(self, analysis_id: str) -> Tuple[int, Optional[str], Optional[str]]:
        total_events = int(
            self.db.query(func.count(AnalysisEvent.id))
            .filter(AnalysisEvent.analysis_id == analysis_id)
            .scalar()
            or 0
        )
        if total_events == 0:
            return 0, None, None
        first_ev = (
            self.db.query(AnalysisEvent.id)
            .filter(AnalysisEvent.analysis_id == analysis_id)
            .order_by(AnalysisEvent.timestamp.asc().nulls_last(), AnalysisEvent.id.asc())
            .first()
        )
        last_ev = (
            self.db.query(AnalysisEvent.id)
            .filter(AnalysisEvent.analysis_id == analysis_id)
            .order_by(AnalysisEvent.timestamp.desc().nulls_last(), AnalysisEvent.id.desc())
            .first()
        )
        return total_events, (first_ev[0] if first_ev else None), (last_ev[0] if last_ev else None)

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
        total_events, first_id, last_id = self._get_event_window_bounds(analysis_id)
        static_status = ctx.static_result.status if ctx.static_result else "UNAVAILABLE"
        return compute_evidence_fingerprint(
            analysis_id=analysis.id,
            sample_sha256=ctx.sample_sha256,
            is_replay=ctx.is_replay,
            scenario_id=ctx.replay_scenario_id,
            static_record_id=ctx.static_record_id,
            static_status=static_status,
            event_count=total_events,
            first_event_id=first_id,
            last_event_id=last_id,
        )

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
        _, first_id, last_id = self._get_event_window_bounds(analysis.id)
        total_events_db, bounded_raw_events = self._fetch_bounded_events(analysis.id)
        events, _valid_ev_ids, ev_warnings, has_trusted_trace = validate_runtime_events(
            bounded_raw_events, analysis_id=analysis.id, is_replay=ctx.is_replay
        )

        static_res = ctx.static_result
        static_status = static_res.status if static_res else "UNAVAILABLE"
        fingerprint = compute_evidence_fingerprint(
            analysis_id=analysis.id,
            sample_sha256=ctx.sample_sha256,
            is_replay=ctx.is_replay,
            scenario_id=ctx.replay_scenario_id,
            static_record_id=ctx.static_record_id,
            static_status=static_status,
            event_count=total_events_db,
            first_event_id=first_id,
            last_event_id=last_id,
        )

        all_warnings = [*ctx.warnings, *ev_warnings]
        if total_events_db > len(events):
            all_warnings.append(
                f"Dynamic telemetry bounded cleanly: scanned {len(events)} of {total_events_db} events."
            )

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
            computed_at=computed_at,
            source_fingerprint=fingerprint,
            triggered_automatically=triggered_automatically,
            external_ai_used=False,
        )

        # Verification failed -> fail closed cleanly without fabricating correlations
        if not ctx.ok:
            return CorrelationResult(
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

        # Static analysis absent or failed/queued -> UNSUPPORTED / INSUFFICIENT_EVIDENCE
        if static_res is None or static_res.status not in ("COMPLETED", "PARTIAL"):
            return CorrelationResult(
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

        # Deterministic finding ordering: DIRECTLY_OBSERVED -> CONTRADICTORY -> CONSISTENT_WITH -> SYNTHETIC_SCENARIO_ONLY -> INSUFFICIENT_EVIDENCE
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
                "No runtime instruction-pointer/module-offset trace was captured; function-to-event execution cannot be directly proven."
            )

        partial_static = bool(static_res.status == "PARTIAL" or static_res.is_partial or static_res.truncation.truncated)
        status = "PARTIAL" if (partial_static or total_events_db > len(events)) else ("COMPLETED" if findings else "INSUFFICIENT_EVIDENCE")

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

    def enforce_serialized_limit(self, result: CorrelationResult) -> CorrelationResult:
        current = result.model_copy(deep=True)
        omitted = current.truncation.findings_omitted

        while True:
            serialized = json.dumps(current.model_dump(mode="json")).encode("utf-8")
            size = len(serialized)
            if size <= self.max_bytes or not current.findings:
                current.truncation.serialized_bytes = size
                current.truncation.findings_included = len(current.findings)
                current.truncation.findings_omitted = omitted
                current.summary = _summarize_findings(current.findings)
                if omitted > 0:
                    current.truncation.truncated = True
                    if current.status == "COMPLETED":
                        current.status = "PARTIAL"
                return CorrelationResult.model_validate(current.model_dump(mode="json"))
            current.findings.pop()
            omitted += 1


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
        summary=result.summary.model_dump(),
        findings=compact_findings,
        limitations=[lim[:220] for lim in result.limitations.items[:8]],
        warnings=[w[:220] for w in result.warnings[:6]],
        truncated=bool(result.truncation.truncated or len(result.findings) > max_findings),
    )
