from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.services.sandbox.replay import ReplaySandboxBackend
from app.services.telemetry.normalizer import TelemetryNormalizer
from app.services.detection.engine import DetectionEngine
from app.services.reporting.generator import ReportGenerator

def update_status(analysis: Analysis, db: Session, new_status: AnalysisStatus) -> None:
    analysis.status = new_status.value
    db.commit()
    db.refresh(analysis)

class PipelineWorker:
    """
    Sequential analysis execution worker managing the complete 10-step state machine.
    """

    def __init__(self, db: Session):
        self.db = db

    def execute_pipeline(self, analysis_id: str) -> Analysis:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found.")

        try:
            # 1. PREFLIGHT
            update_status(analysis, self.db, AnalysisStatus.PREFLIGHT)
            analysis.started_at = datetime.now(timezone.utc)
            self.db.commit()

            sample = analysis.sample
            if not sample:
                raise FileNotFoundError("Associated sample does not exist.")

            # 2. PLANNED
            # In Phase 3, this invokes the AI Orchestration Planner.
            # For Phase 2, generate structured baseline plan.
            update_status(analysis, self.db, AnalysisStatus.PLANNED)

            # 3. QUEUED
            update_status(analysis, self.db, AnalysisStatus.QUEUED)

            # 4. RUNNING
            update_status(analysis, self.db, AnalysisStatus.RUNNING)
            sample_quarantine_path = Path(sample.quarantine_path)
            
            # Select backend
            if analysis.backend_type == "replay":
                sandbox = ReplaySandboxBackend()
            else:
                from app.services.sandbox.cape import CapeSandboxBackend
                sandbox = CapeSandboxBackend()

            backend_task_id = sandbox.submit_sample(
                sample_path=sample_quarantine_path,
                profile=analysis.profile,
                timeout_seconds=analysis.timeout_seconds,
            )

            # 5. COLLECTING
            update_status(analysis, self.db, AnalysisStatus.COLLECTING)
            raw_results = sandbox.collect_results(backend_task_id)

            # Collect artifacts into analysis artifact folder
            artifacts_dir = settings.ARTIFACTS_DIR / analysis.id
            sandbox.generate_artifacts(backend_task_id, artifacts_dir)

            # 6. NORMALIZING
            update_status(analysis, self.db, AnalysisStatus.NORMALIZING)
            normalizer = TelemetryNormalizer(self.db)
            normalizer.normalize_sandbox_output(analysis.id, raw_results)

            # 7. CORRELATING
            update_status(analysis, self.db, AnalysisStatus.CORRELATING)
            # Correlation is evaluated dynamically by ProcessTree and Correlator queries

            # 8. SCORING
            update_status(analysis, self.db, AnalysisStatus.SCORING)
            detector = DetectionEngine(self.db)
            findings, risk_assessment = detector.evaluate_behavior(analysis.id)

            # 9. REPORTING
            update_status(analysis, self.db, AnalysisStatus.REPORTING)
            reporter = ReportGenerator(self.db)
            reporter.generate_report(analysis.id, risk_assessment)

            # 10. COMPLETED
            update_status(analysis, self.db, AnalysisStatus.COMPLETED)
            analysis.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(analysis)
            return analysis

        except Exception as e:
            self.db.rollback()
            analysis.status = AnalysisStatus.FAILED.value
            analysis.error_message = str(e)
            analysis.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(analysis)
            return analysis
