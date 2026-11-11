from __future__ import annotations

import json
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
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


class StaticAnalysisSubmissionError(RuntimeError):
    """Raised when submitting a static analysis job to the worker executor fails."""


def prepare_result_for_persistence(
    result: StaticAnalysisResult,
    max_persisted_bytes: Optional[int] = None,
) -> StaticAnalysisResult:
    """
    Validates schema strictly and bounds serialized JSON size prior to database persistence.
    Never allows unvalidated or oversized JSON blobs into SQLite.
    """
    limit = max(16384, int(max_persisted_bytes or settings.GHIDRA_MAX_PERSISTED_RESULT_BYTES))
    validated = StaticAnalysisResult.model_validate(result)
    encoded_size = len(json.dumps(validated.model_dump(mode="json")).encode("utf-8"))
    if encoded_size <= limit:
        return validated

    # Gracefully shed bulky pseudocode & xrefs first while keeping schema & core metadata intact
    trimmed_decomp = [
        d.model_copy(
            update={
                "pseudocode": "",
                "pseudocode_bytes": 0,
                "truncated": True,
                "decompile_status": "SKIPPED_CAP",
                "error_message": "Omitted to stay within DB persistence byte cap.",
            }
        )
        for d in validated.decompiled_functions
    ]
    next_status = "PARTIAL" if validated.status == "COMPLETED" else validated.status
    candidate = validated.model_copy(
        update={
            "status": next_status,
            "is_partial": True if next_status == "PARTIAL" else validated.is_partial,
            "decompiled_functions": trimmed_decomp,
            "warnings": [*validated.warnings, "Decompiled pseudocode dropped to fit DB persistence ceiling."],
            "truncation": validated.truncation.model_copy(
                update={
                    "truncated": True,
                    "decompiled_included": 0,
                    "decompiled_omitted_cap": len(validated.decompiled_functions),
                }
            ),
        }
    )
    if len(json.dumps(candidate.model_dump(mode="json")).encode("utf-8")) <= limit:
        return StaticAnalysisResult.model_validate(candidate)

    # Second fallback: shed large cross-reference and call-graph edge arrays cleanly
    candidate_small = candidate.model_copy(
        update={
            "cross_references": [],
            "call_graph": candidate.call_graph[:200],
            "strings": candidate.strings[:50],
            "warnings": [*candidate.warnings, "Large edge/string tables trimmed to fit DB persistence ceiling."],
        }
    )
    if len(json.dumps(candidate_small.model_dump(mode="json")).encode("utf-8")) <= limit:
        return StaticAnalysisResult.model_validate(candidate_small)

    return StaticAnalysisResult(
        status="FAILED",
        provenance=validated.provenance,
        truncation=validated.truncation.model_copy(update={"truncated": True}),
        errors=[
            f"Static analysis payload exceeded maximum persistence size ({encoded_size} > {limit} bytes)."
        ],
        warnings=validated.warnings[:5],
        is_partial=False,
    )


class StaticAnalysisWorkerManager:
    """
    Dedicated, optional, single-concurrency background worker for Ghidra Headless static analysis.
    Strictly decoupled from Replay/CAPE dynamic pipeline execution and limited to 1 active JVM job
    to protect Kali VM memory and CPU resources.

    Deployment note: In-process thread coordination and SQLite DB guards assume a single Uvicorn
    worker (`--workers 1`). An inter-process advisory file lock in `GHIDRA_WORKSPACE_ROOT` also
    blocks concurrent Ghidra JVMs across multiple workers sharing the same host workspace.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_job_id: Optional[str] = None
        self._cancel_event: Optional[threading.Event] = None
        self._active_future: Optional[Future] = None
        self._shutting_down: bool = False

    def _get_executor(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="malbox-ghidra",
            )
        return self._executor

    def start(self) -> None:
        """Enables worker submissions cleanly at application startup."""
        with self._lock:
            self._shutting_down = False

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
            if isinstance(row.result_json, dict):
                try:
                    parsed = StaticAnalysisResult.model_validate(row.result_json)
                    updated = parsed.model_copy(
                        update={
                            "status": "FAILED",
                            "errors": [*parsed.errors, row.error_message],
                            "is_partial": False,
                        }
                    )
                    row.result_json = updated.model_dump(mode="json")
                except Exception:
                    pass
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
        effective_analyzer = analyzer or GhidraStaticAnalyzer()
        with self._lock:
            if self._shutting_down:
                raise StaticAnalysisSubmissionError(
                    "Static analysis worker is shutting down and cannot accept new jobs."
                )

            if self._active_job_id is not None:
                raise StaticAnalysisBusyError(
                    f"Single-concurrency Ghidra worker is busy with job '{self._active_job_id}'. Try again after completion."
                )

            # Guard against active jobs persisted by another process or unrecovered worker
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
            try:
                executor = self._get_executor()
                fut = executor.submit(
                    self._execute_background_job,
                    record.id,
                    sample.id,
                    sample.quarantine_path,
                    sample.sha256,
                    analysis_id,
                    cancel_ev,
                    effective_analyzer,
                )
                self._active_future = fut
            except Exception as exc:
                self._active_job_id = None
                self._cancel_event = None
                self._active_future = None
                safe_err = redact_sensitive_text(
                    f"Static analysis submission failed ({type(exc).__name__}): {exc}",
                    max_chars=240,
                )
                try:
                    failed_res = placeholder_res.model_copy(
                        update={"status": "FAILED", "errors": [safe_err], "is_partial": False}
                    )
                    record.status = "FAILED"
                    record.error_message = safe_err
                    record.completed_at = datetime.now(timezone.utc)
                    record.result_json = failed_res.model_dump(mode="json")
                    db.commit()
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass
                raise StaticAnalysisSubmissionError(safe_err) from exc

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

            if cancel_event.is_set():
                fail_res = StaticAnalysisResult(
                    status="FAILED",
                    provenance=StaticAnalysisProvenance(
                        analysis_id=analysis_id,
                        sample_id=sample_id,
                        sample_sha256=expected_sha256.lower(),
                        started_at=datetime.now(timezone.utc).isoformat(),
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        os_sandbox="none",
                    ),
                    truncation=StaticAnalysisTruncation(),
                    errors=["Static analysis job cancelled prior to execution."],
                )
                row.status = "FAILED"
                row.error_message = "Static analysis job cancelled prior to execution."
                row.result_json = fail_res.model_dump(mode="json")
                row.completed_at = datetime.now(timezone.utc)
                db.commit()
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

            bounded_result = prepare_result_for_persistence(result)

            db.expire(row)
            row = db.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == record_id).first()
            if row:
                row.status = bounded_result.status
                row.ghidra_version = bounded_result.provenance.ghidra_version
                row.is_partial = bounded_result.is_partial
                row.error_message = "; ".join(bounded_result.errors)[:1000] if bounded_result.errors else None
                row.result_json = bounded_result.model_dump(mode="json")
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
                    self._active_future = None

    def cancel_active(self) -> bool:
        with self._lock:
            if self._cancel_event is not None:
                self._cancel_event.set()
                return True
            return False

    def stop(self, wait_seconds: float = 5.0) -> int:
        """
        Propagates shutdown cancellation to any active Ghidra job, waits briefly for clean PGID
        termination and DB finalization, and marks any lingering QUEUED/RUNNING jobs FAILED.
        """
        with self._lock:
            self._shutting_down = True
            active_id = self._active_job_id
            active_fut = self._active_future
            cancel_ev = self._cancel_event
            executor = self._executor
            if cancel_ev is not None:
                cancel_ev.set()

        cancelled_count = 1 if active_id else 0

        if active_fut is not None:
            try:
                active_fut.result(timeout=max(0.2, float(wait_seconds)))
            except Exception:
                pass

        if executor is not None:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

        # Clean up lingering DB state if worker thread did not finish within shutdown window
        db = SessionLocal()
        try:
            recovered = self.recover_stale_jobs(db)
            cancelled_count = max(cancelled_count, recovered)
        except Exception:
            pass
        finally:
            db.close()

        with self._lock:
            self._executor = None
            if self._active_job_id == active_id:
                self._active_job_id = None
                self._cancel_event = None
                self._active_future = None

        return cancelled_count


static_worker_manager = StaticAnalysisWorkerManager()
