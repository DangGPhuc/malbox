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
                    analysis.error_message = f"CAPE backend readiness check failed: {readiness.get('error')}"
                    analysis.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return analysis

                sandbox_options = {
                    "requested_artifacts": plan.requested_artifacts,
                    "telemetry_focus": plan.telemetry_focus,
                } if plan else None

                backend_task_id = sandbox.submit_sample(
                    sample_path=sample_quarantine_path,
                    profile=analysis.profile,
                    timeout_seconds=analysis.timeout_seconds,
                    options=sandbox_options,
                )
                analysis.external_task_id = backend_task_id
                self.db.commit()

                # Poll status until report is ready or timeout
                poll_deadline = time.time() + analysis.timeout_seconds + 30
                cape_ready = False
                while time.time() < poll_deadline:
                    if self._is_cancelled():
                        sandbox.cancel_task(backend_task_id)
                        safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis

                    status_info = sandbox.get_task_status(backend_task_id)
                    curr_status = status_info.get("status")

                    if curr_status in ["completed", "reported"]:
                        cape_ready = True
                        break
                    elif curr_status == "failed":
                        safe_update_status(analysis, self.db, AnalysisStatus.FAILED)
                        analysis.error_message = f"CAPE analysis failed: {status_info.get('error', 'Execution error')}"
                        analysis.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return analysis
                    elif curr_status == "cancelled":
                        safe_update_status(analysis, self.db, AnalysisStatus.CANCELLED)
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
            findings, risk_assessment = detector.evaluate_behavior(analysis.id)

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
            reporter.generate_report(
                analysis.id,
                risk_assessment,
                ai_summary=None,
                ai_follow_up=follow_up.model_dump(),
                env_metadata=raw_env,
            )

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
