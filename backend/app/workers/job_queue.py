import time
import threading
from datetime import datetime, timezone
from typing import Optional, Dict
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.analysis import Analysis, AnalysisStatus, TERMINAL_STATES
from app.workers.pipeline_worker import PipelineWorker

class JobQueueManager:
    """
    In-process bounded sequential job queue manager.
    Enforces WORKER_CONCURRENCY=1 by default and coordinates safe task execution,
    lifecycle state transitions, cancellation signals, and crash recovery.
    Cannot be bypassed by public run_sync execution.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._worker_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._active_job_id: Optional[str] = None
        self._cancellation_events: Dict[str, threading.Event] = {}

    def start(self) -> None:
        """Starts the background sequential job consumer thread."""
        with self._lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="MalboxPipelineWorkerThread",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signals the worker thread to terminate and waits for completion."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return self._worker_thread is not None and self._worker_thread.is_alive()

    def get_active_job_id(self) -> Optional[str]:
        with self._lock:
            return self._active_job_id

    def execute_sync(self, analysis_id: str, db: Session, timeout: float = 60.0) -> Analysis:
        """
        Executes an analysis job synchronously while strictly enforcing WORKER_CONCURRENCY=1.
        Blocks until the worker concurrency lock is acquired.
        Guarantees that public run_sync=true requests cannot bypass execution limits.
        """
        acquired = self._worker_lock.acquire(timeout=timeout)
        if not acquired:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Worker concurrency limit (1) exceeded. Another analysis task is currently executing."
            )

        cancel_event = threading.Event()
        with self._lock:
            self._active_job_id = analysis_id
            self._cancellation_events[analysis_id] = cancel_event

        try:
            worker = PipelineWorker(db, cancel_event=cancel_event)
            return worker.execute_pipeline(analysis_id)
        finally:
            with self._lock:
                self._cancellation_events.pop(analysis_id, None)
                if self._active_job_id == analysis_id:
                    self._active_job_id = None
            self._worker_lock.release()

    def recover_stale_jobs(self, db: Session) -> int:
        """
        Recovers jobs left in intermediate non-terminal states during an abrupt crash or restart.
        Marks them FAILED so they do not remain indefinitely stuck in RUNNING.
        """
        active_non_terminal = [
            AnalysisStatus.PREFLIGHT.value,
            AnalysisStatus.PLANNED.value,
            AnalysisStatus.RUNNING.value,
            AnalysisStatus.COLLECTING.value,
            AnalysisStatus.NORMALIZING.value,
            AnalysisStatus.CORRELATING.value,
            AnalysisStatus.SCORING.value,
            AnalysisStatus.REPORTING.value,
        ]

        stale_jobs = (
            db.query(Analysis)
            .filter(Analysis.status.in_(active_non_terminal))
            .all()
        )

        recovered_count = 0
        for job in stale_jobs:
            job.status = AnalysisStatus.FAILED.value
            job.error_message = "Analysis interrupted by process shutdown or worker restart. Recovered safely."
            job.completed_at = datetime.now(timezone.utc)
            recovered_count += 1

        if recovered_count > 0:
            db.commit()

        return recovered_count

    def request_cancellation(self, analysis_id: str, db: Session) -> bool:
        """
        Cancels a queued or currently executing analysis task.
        Propagates cancellation event to worker and updates persistent state.
        Guarantees race-free state transitions against concurrent job completion.
        """
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return False

        current_status = AnalysisStatus(analysis.status)
        if current_status in TERMINAL_STATES:
            # Cannot cancel an already terminal state
            return False

        with self._lock:
            # 1. If currently running, signal cancellation event immediately
            if analysis_id in self._cancellation_events:
                self._cancellation_events[analysis_id].set()

            # 2. Re-verify database status under lock
            db.refresh(analysis)
            if AnalysisStatus(analysis.status) in TERMINAL_STATES:
                return False

            analysis.status = AnalysisStatus.CANCELLED.value
            analysis.completed_at = datetime.now(timezone.utc)
            if not analysis.error_message:
                analysis.error_message = "Task cancelled by analyst."
            db.commit()
            db.refresh(analysis)
            return True

    def _worker_loop(self) -> None:
        """Continuous consumer loop polling for QUEUED analyses while enforcing WORKER_CONCURRENCY=1."""
        while not self._stop_event.is_set():
            job_id_to_run = None
            db = SessionLocal()
            try:
                # Find oldest queued job
                queued_job = (
                    db.query(Analysis)
                    .filter(Analysis.status == AnalysisStatus.QUEUED.value)
                    .order_by(Analysis.created_at.asc())
                    .first()
                )

                if queued_job:
                    job_id_to_run = queued_job.id
            except Exception:
                pass
            finally:
                db.close()

            if not job_id_to_run:
                # Idle backoff
                time.sleep(settings.JOB_POLL_INTERVAL_SECONDS)
                continue

            # Acquire worker concurrency lock
            if not self._worker_lock.acquire(blocking=False):
                # Worker slot busy (e.g., executing synchronous task), back off
                time.sleep(settings.JOB_POLL_INTERVAL_SECONDS)
                continue

            try:
                # Verify job is still queued before starting
                check_db = SessionLocal()
                try:
                    target_job = check_db.query(Analysis).filter(Analysis.id == job_id_to_run).first()
                    if not target_job or target_job.status != AnalysisStatus.QUEUED.value:
                        continue
                finally:
                    check_db.close()

                cancel_event = threading.Event()
                with self._lock:
                    self._active_job_id = job_id_to_run
                    self._cancellation_events[job_id_to_run] = cancel_event

                worker_db = SessionLocal()
                try:
                    pipeline_worker = PipelineWorker(worker_db, cancel_event=cancel_event)
                    pipeline_worker.execute_pipeline(job_id_to_run)
                except Exception:
                    pass
                finally:
                    worker_db.close()
                    with self._lock:
                        self._cancellation_events.pop(job_id_to_run, None)
                        if self._active_job_id == job_id_to_run:
                            self._active_job_id = None
            finally:
                self._worker_lock.release()

job_queue_manager = JobQueueManager()
