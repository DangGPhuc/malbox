from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import redact_sensitive_text
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.schemas.static_analysis import (
    StaticAnalysisProvenance,
    StaticAnalysisResult,
    StaticAnalysisTruncation,
)
from app.services.static_analysis.ghidra_adapter import GhidraStaticAnalyzer


class StaticAnalysisBusyError(RuntimeError):
    """Raised when the single-worker Ghidra queue is already executing a static analysis job."""


class StaticAnalysisWorkerManager:
    """
    Dedicated, optional, single-concurrency background worker for Ghidra Headless static analysis.
    Strictly decoupled from Replay/CAPE dynamic pipeline execution and limited to 1 active JVM job
    to protect Kali VM memory and CPU resources.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_job_id: Optional[str] = None
        self._cancel_event: Optional[threading.Event] = None

    def _get_executor(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="malbox-ghidra",
            )
        return self._executor

    def is_busy(self) -> bool:
        with self._lock:
            return self._active_job_id is not None

    def active_job_id(self) -> Optional[str]:
        with self._lock:
            return self._active_job_id

    def recover_stale_jobs(self, db: Session) -> int:
        stale = (
            db.query(StaticAnalysisRecord)
            .filter(StaticAnalysisRecord.status.in_(["QUEUED", "RUNNING"]))
            .all()
        )
        count = 0
        for row in stale:
            row.status = "FAILED"
            row.error_message = "Static analysis job interrupted by server shutdown/restart."
            row.completed_at = datetime.now(timezone.utc)
            count += 1
        if count > 0:
            db.commit()
        return count

    def submit_job(
        self,
        db: Session,
        sample: Sample,
        analysis_id: Optional[str] = None,
        analyzer: Optional[GhidraStaticAnalyzer] = None,
    ) -> StaticAnalysisRecord:
        with self._lock:
            if self._active_job_id is not None:
                raise StaticAnalysisBusyError(
                    f"Single-concurrency Ghidra worker is busy with job '{self._active_job_id}'. Try again after completion."
                )

            # Check DB persistence guard as well for an active job record
            existing_active = (
                db.query(StaticAnalysisRecord)
                .filter(StaticAnalysisRecord.status.in_(["QUEUED", "RUNNING"]))
                .first()
            )
            if existing_active is not None:
                raise StaticAnalysisBusyError(
                    f"Another static analysis job ('{existing_active.id}') is currently active."
                )

            now_dt = datetime.now(timezone.utc)
            placeholder_res = StaticAnalysisResult(
                status="QUEUED",
                provenance=StaticAnalysisProvenance(
                    analysis_id=analysis_id,
                    sample_id=sample.id,
                    sample_sha256=sample.sha256,
                    started_at=now_dt.isoformat(),
                    os_sandbox="bwrap",
                ),
                truncation=StaticAnalysisTruncation(),
            )

            record = StaticAnalysisRecord(
                sample_id=sample.id,
                analysis_id=analysis_id,
                sample_sha256=sample.sha256,
                status="QUEUED",
                result_json=placeholder_res.model_dump(mode="json"),
                created_at=now_dt,
            )
            db.add(record)
            db.commit()
            db.refresh(record)

            cancel_ev = threading.Event()
            self._active_job_id = record.id
            self._cancel_event = cancel_ev
            executor = self._get_executor()

        effective_analyzer = analyzer or GhidraStaticAnalyzer()
        executor.submit(
            self._execute_background_job,
            record.id,
            sample.id,
            sample.quarantine_path,
            sample.sha256,
            analysis_id,
            cancel_ev,
            effective_analyzer,
        )
        return record

    def _execute_background_job(
        self,
        record_id: str,
        sample_id: str,
        quarantine_path: str,
        expected_sha256: str,
        analysis_id: Optional[str],
        cancel_event: threading.Event,
        analyzer: GhidraStaticAnalyzer,
    ) -> None:
        db = SessionLocal()
        try:
            row = db.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == record_id).first()
            if not row:
                return
            row.status = "RUNNING"
            row.started_at = datetime.now(timezone.utc)
            db.commit()

            result = analyzer.analyze_sample(
                sample_id=sample_id,
                sample_path=Path(quarantine_path),
                expected_sha256=expected_sha256,
                analysis_id=analysis_id,
                job_id=record_id,
                cancel_event=cancel_event,
            )

            db.expire(row)
            row = db.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == record_id).first()
            if row:
                row.status = result.status
                row.ghidra_version = result.provenance.ghidra_version
                row.is_partial = result.is_partial
                row.error_message = "; ".join(result.errors)[:1000] if result.errors else None
                row.result_json = result.model_dump(mode="json")
                row.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception as exc:
            try:
                db.rollback()
                row = db.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == record_id).first()
                if row:
                    safe_err = redact_sensitive_text(f"{type(exc).__name__}: {exc}", max_chars=240)
                    row.status = "FAILED"
                    row.error_message = safe_err
                    row.completed_at = datetime.now(timezone.utc)
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()
            with self._lock:
                if self._active_job_id == record_id:
                    self._active_job_id = None
                    self._cancel_event = None

    def cancel_active(self) -> bool:
        with self._lock:
            if self._cancel_event is not None:
                self._cancel_event.set()
                return True
            return False


static_worker_manager = StaticAnalysisWorkerManager()

