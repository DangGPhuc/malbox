import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import (
    Analysis,
    AnalysisStatus,
    SandboxBackendType,
    TERMINAL_STATES,
    VALID_STATE_TRANSITIONS,
)
from app.services.sandbox.replay import ReplaySandboxBackend
from app.services.telemetry.normalizer import TelemetryNormalizer
from app.services.detection.engine import DetectionEngine
from app.services.reporting.generator import ReportGenerator
from app.services.orchestration.planner import AnalysisPlanner
from app.services.orchestration.evaluator import ObservationEvaluator
from app.ai.llm_client import get_llm_provider

def safe_update_status(analysis: Analysis, db: Session, target_status: AnalysisStatus) -> bool:
    """
    Updates the analysis status with strict validation against invalid transitions
    and prevents any overwriting of terminal states.
    """
    current_status = AnalysisStatus(analysis.status)
    if current_status in TERMINAL_STATES:
        return False

    if current_status == target_status:
        return True

    valid_targets = VALID_STATE_TRANSITIONS.get(current_status, set())
    if target_status not in valid_targets:
        raise ValueError(
            f"Invalid state transition: Cannot transition from {current_status.value} to {target_status.value}. "
            f"Allowed transitions from {current_status.value}: {[s.value for s in valid_targets]}"
        )

    analysis.status = target_status.value
    db.commit()
    db.refresh(analysis)
    return True

class PipelineWorker:
    """
    Sequential analysis execution worker managing the complete 10-step state machine
    with active AI orchestration, policy-checked controller actions, cancellation signals,
    and timeout monitoring.
    """

    def __init__(self, db: Session, cancel_event: Optional[threading.Event] = None):
        self.db = db
        self.cancel_event = cancel_event

    def _is_cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    def execute_pipeline(self, analysis_id: str) -> Analysis:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found.")

        # Check if already terminal
        if AnalysisStatus(analysis.status) in TERMINAL_STATES:
            return analysis

        raw_results: Dict[str, Any] = {}

        try:
            # Check cancellation before starting
            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 1. PREFLIGHT
            safe_update_status(analysis, self.db, AnalysisStatus.PREFLIGHT)
            analysis.started_at = datetime.now(timezone.utc)
            self.db.commit()

            sample = analysis.sample
            if not sample:
                safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                analysis.error_message = "Associated sample does not exist."
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 2. PLANNED (AI Planning + Policy Validation + Audit Log)
            safe_update_status(analysis, self.db, AnalysisStatus.PLANNED)
            planner = AnalysisPlanner(self.db)
            plan, plan_validation = planner.create_and_validate_plan(analysis)

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 2.5 Automatic Deep Static Analysis using Ghidra (Phase B3)
            # Ensure static analysis record exists or trigger analysis if Ghidra is available
            from app.models.static_analysis import StaticAnalysisRecord
            from app.schemas.static_analysis import (
                StaticAnalysisResult,
                StaticAnalysisProvenance,
                StaticAnalysisTruncation,
            )
            from app.services.static_analysis.worker import static_worker_manager

            existing_static = (
                self.db.query(StaticAnalysisRecord)
                .filter(StaticAnalysisRecord.sample_id == sample.id)
                .order_by(StaticAnalysisRecord.created_at.desc())
                .first()
            )

            if existing_static is None:
                if getattr(settings, "GHIDRA_ENABLED", False) and getattr(settings, "GHIDRA_HOME", ""):
                    try:
                        static_worker_manager.submit_job(
                            db=self.db,
                            sample=sample,
                            analysis_id=analysis.id,
                        )
                    except Exception:
                        pass
                else:
                    now_dt = datetime.now(timezone.utc)
                    unavail_res = StaticAnalysisResult(
                        status="UNAVAILABLE",
                        provenance=StaticAnalysisProvenance(
                            analysis_id=analysis.id,
                            sample_id=sample.id,
                            sample_sha256=sample.sha256,
                            started_at=now_dt.isoformat(),
                            os_sandbox="none",
                            ghidra_enabled=False,
                            provenance_note="Ghidra Headless static analysis is not enabled or not configured on this host.",
                        ),
                        truncation=StaticAnalysisTruncation(),
                        errors=["Ghidra static analysis is disabled or GHIDRA_HOME is unconfigured."],
                    )
                    unavail_rec = StaticAnalysisRecord(
                        sample_id=sample.id,
                        analysis_id=analysis.id,
                        sample_sha256=sample.sha256,
                        status="UNAVAILABLE",
                        result_json=unavail_res.model_dump(mode="json"),
                        error_message="Ghidra static analysis is disabled or GHIDRA_HOME is unconfigured.",
                        created_at=now_dt,
                        completed_at=now_dt,
                    )
                    self.db.add(unavail_rec)
                    self.db.commit()

            # 3. RUNNING (Detonation / Sandbox execution phase)
            safe_update_status(analysis, self.db, AnalysisStatus.RUNNING)
            sample_quarantine_path = Path(sample.quarantine_path)

            # Check backend type & enforce second-layer safety gate
            if analysis.backend_type == SandboxBackendType.CAPE.value:
                # Critical Safety Gate Check immediately before CAPE submission
                if not settings.LIVE_MODE_ENABLED:
                    safe_update_status(analysis, self.db, AnalysisStatus.BLOCKED_BY_POLICY)
                    analysis.error_message = "Safety Policy Violation: Live sandbox execution is disabled server-side."
                    analysis.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return analysis

                if not analysis.live_mode or not analysis.approved_by_user:
                    safe_update_status(analysis, self.db, AnalysisStatus.BLOCKED_BY_POLICY)
                    analysis.error_message = "Safety Policy Violation: CAPE execution requires live_mode=true and approved_by_user=true."
                    analysis.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return analysis

                from app.services.sandbox.cape import CapeSandboxBackend
                sandbox = CapeSandboxBackend()

                # Readiness check before sample submission
                readiness = sandbox.check_readiness()
                if not readiness.get("ready"):
                    safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                    err_msg = f"CAPE backend readiness check failed: {readiness.get('error')}"
                    analysis.error_message = err_msg
                    analysis.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    # Preserve static analysis & triage findings in structured report
                    try:
                        from app.schemas.report import RiskAssessment
                        safe_risk = RiskAssessment(score=0, level="Inconclusive / Incomplete", confidence=0.0)
                        ReportGenerator(self.db).generate_report(
                            analysis.id,
                            safe_risk,
                            ai_summary=f"Dynamic execution unavailable: {err_msg}. Static disassembly and triage findings preserved.",
                            env_metadata={"telemetry_completeness": "UNAVAILABLE", "telemetry_notes": [err_msg]},
                        )
                    except Exception:
                        pass
                    return analysis

                # Translate only explicitly supported, operator-controlled parameters to CAPE request (A1)
                # Never blindly forward internal planning fields (requested_artifacts, telemetry_focus)
                cape_transport_options: Dict[str, Any] = {}
                if getattr(settings, "CAPE_DEFAULT_MACHINE", ""):
                    cape_transport_options["machine"] = settings.CAPE_DEFAULT_MACHINE
                if getattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", ""):
                    cape_transport_options["options"] = f"route={settings.CAPE_DEFAULT_NETWORK_ROUTE}"
                if analysis.profile == "ransomware_focus":
                    cape_transport_options["enforce_timeout"] = "1"

                # Automatic package selection (Phase B4)
                pe_meta = sample.pe_metadata or {}
                is_dll = pe_meta.get("is_dll", False) or sample.file_name.lower().endswith(".dll")
                if is_dll:
                    cape_transport_options["package"] = "dll"
                elif sample.is_pe:
                    cape_transport_options["package"] = "exe"

                backend_task_id = sandbox.submit_sample(
                    sample_path=sample_quarantine_path,
                    profile=analysis.profile,
                    timeout_seconds=analysis.timeout_seconds,
                    options=cape_transport_options if cape_transport_options else None,
                )
                analysis.external_task_id = backend_task_id
                self.db.commit()

                # Poll status until report is ready or timeout (A4 - Monotonic deadline)
                poll_deadline = time.monotonic() + analysis.timeout_seconds + 30
                cape_ready = False
                while time.monotonic() < poll_deadline:
                    if self._is_cancelled():
                        sandbox.cancel_task(backend_task_id)
                        safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis

                    status_info = sandbox.get_task_status(backend_task_id)
                    curr_status = status_info.get("status")
                    is_ready = status_info.get("is_ready_for_report", False)

                    if is_ready or curr_status in ["completed", "reported"]:
                        cape_ready = True
                        break
                    elif curr_status in ["failed", "failed_analysis", "failed_processing"]:
                        safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                        analysis.error_message = f"CAPE analysis failed: {status_info.get('error', 'Execution error')}"
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis
                    elif curr_status == "unauthorized":
                        safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                        analysis.error_message = f"CAPE API authentication failed: {status_info.get('error')}"
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis
                    elif curr_status == "not_found":
                        safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                        analysis.error_message = f"CAPE task not found: {status_info.get('error') or curr_status}"
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis
                    elif curr_status == "cancelled":
                        safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                        analysis.error_message = f"CAPE task cancelled: {status_info.get('error') or curr_status}"
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis

                    time.sleep(settings.CAPE_POLL_INTERVAL_SECONDS)

                if not cape_ready:
                    sandbox.cancel_task(backend_task_id)
                    safe_update_status(analysis, self.db, AnalysisStatus.TIMED_OUT)
                    analysis.error_message = f"Analysis timed out waiting for CAPE sandbox after {analysis.timeout_seconds}s."
                    analysis.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return analysis

            else:
                # Replay backend
                sandbox = ReplaySandboxBackend()
                sandbox_options = {
                    "requested_artifacts": plan.requested_artifacts,
                    "telemetry_focus": plan.telemetry_focus,
                } if plan else None

                backend_task_id = sandbox.submit_sample(
                    sample_path=sample_quarantine_path,
                    profile=analysis.profile,
                    timeout_seconds=analysis.timeout_seconds,
                    scenario_id=analysis.replay_scenario_id,
                    options=sandbox_options,
                )
                analysis.external_task_id = backend_task_id
                self.db.commit()

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 4. COLLECTING
            safe_update_status(analysis, self.db, AnalysisStatus.COLLECTING)
            if analysis.backend_type == SandboxBackendType.CAPE.value:
                remaining_time = max(10.0, poll_deadline - time.monotonic())
                raw_results = sandbox.collect_results(
                    backend_task_id,
                    expected_sha256=sample.sha256,
                    max_timeout=remaining_time,
                    is_cancelled_fn=self._is_cancelled,
                )
            else:
                raw_results = sandbox.collect_results(backend_task_id)

            if analysis.backend_type == SandboxBackendType.REPLAY.value:
                resolved_scen = raw_results.get("metadata", {}).get("scenario_id")
                if resolved_scen:
                    analysis.replay_scenario_id = resolved_scen
                    self.db.commit()

            artifacts_dir = settings.ARTIFACTS_DIR / analysis.id
            sandbox.generate_artifacts(backend_task_id, artifacts_dir)

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 5. NORMALIZING
            safe_update_status(analysis, self.db, AnalysisStatus.NORMALIZING)
            normalizer = TelemetryNormalizer(self.db)
            normalizer.normalize_sandbox_output(analysis.id, raw_results)

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 6. CORRELATING & SCORING (Deterministic Behavioral Detection)
            safe_update_status(analysis, self.db, AnalysisStatus.CORRELATING)
            safe_update_status(analysis, self.db, AnalysisStatus.SCORING)
            detector = DetectionEngine(self.db)
            telemetry_comp = raw_results.get("telemetry_completeness", "COMPLETE")
            findings, risk_assessment = detector.evaluate_behavior(analysis.id, telemetry_completeness=telemetry_comp)

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 7. AI OBSERVATION EVALUATION (Evaluates Real Findings & Telemetry Gaps)
            events = analysis.events or []
            proc_events = [e for e in events if e.category == "process"]
            net_events = [e for e in events if e.category in ["network", "dns", "http"]]

            evaluator = ObservationEvaluator(self.db)
            telemetry_summary = {
                "total_events": len(events),
                "total_processes": len(proc_events),
                "network_events_count": len(net_events),
                "findings_count": len(findings),
                "risk_score": risk_assessment.score,
                "risk_level": risk_assessment.level,
                "detected_rules": [f.rule_id for f in findings],
            }
            # AI Evaluates telemetry and post-detection findings with policy enforcement
            follow_up, follow_up_validation = evaluator.evaluate_observations(analysis, telemetry_summary)
            # The follow-up is classified as an advisory recommendation only (no unexecuted second pass is claimed)

            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            # 8. REPORTING
            safe_update_status(analysis, self.db, AnalysisStatus.REPORTING)
            reporter = ReportGenerator(self.db)
            raw_env = raw_results.get("metadata", {}).get("environment", {}) if "raw_results" in locals() and raw_results else {}
            if "raw_results" in locals() and raw_results:
                meta = raw_results.get("metadata", {})
                if "scenario_id" in meta:
                    raw_env["scenario_id"] = meta["scenario_id"]
                if "fixture_version" in meta:
                    raw_env["fixture_version"] = meta["fixture_version"]
                raw_env["telemetry_completeness"] = raw_results.get("telemetry_completeness") or meta.get("telemetry_completeness", "COMPLETE")
                raw_env["telemetry_notes"] = raw_results.get("telemetry_notes") or meta.get("telemetry_notes", [])
            reporter.generate_report(
                analysis.id,
                risk_assessment,
                ai_summary=None,
                ai_follow_up=follow_up.model_dump(),
                env_metadata=raw_env,
            )

            # Optional deterministic static/dynamic correlation post-processing
            # ONLY when verified usable static evidence already exists (never spawns Ghidra/CAPE/OpenCode).
            try:
                if sample is not None:
                    from app.services.evidence_correlation.service import EvidenceCorrelationService
                    from app.services.static_analysis.selector import select_static_records

                    sel_static = select_static_records(
                        db=self.db,
                        sample_id=sample.id,
                        sample_sha256=sample.sha256,
                        requested_analysis_id=analysis.id,
                        prefer_usable_over_active=True,
                    )
                    if sel_static.usable_record is not None:
                        EvidenceCorrelationService(self.db).compute_and_persist(
                            analysis_id=analysis.id,
                            triggered_automatically=True,
                        )
            except Exception:
                pass

            # Re-read status under lock to avoid race conditions with concurrent cancellation
            if self._is_cancelled():
                safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                return analysis

            self.db.refresh(analysis)
            if AnalysisStatus(analysis.status) in TERMINAL_STATES:
                return analysis

            # 9. COMPLETED
            safe_update_status(analysis, self.db, AnalysisStatus.COMPLETED)
            analysis.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(analysis)
            return analysis

        except Exception as e:
            self.db.rollback()
            current = AnalysisStatus(analysis.status)
            if current not in TERMINAL_STATES:
                analysis.status = AnalysisStatus.FAILED.value
                analysis.error_message = str(e)
                analysis.completed_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(analysis)
            return analysis
