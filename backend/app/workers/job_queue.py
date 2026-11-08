import threading
import time
from datetime import datetime, timezone
from typing import Optional, Dict
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.analysis import Analysis, AnalysisStatus, TERMINAL_STATES, VALID_STATE_TRANSITIONS
from app.workers.pipeline_worker import PipelineWorker

class JobQueueManager:
    """
    Persistent, bounded background job queue manager.
    Enforces WORKER_CONCURRENCY=1 by default and coordinates safe task execution,
    lifecycle state transitions, cancellation signals, and crash recovery.
    """

    def __init__(self):
        self._lock = threading.Lock()
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
        now = datetime.now(timezone.utc)
        for job in stale_jobs:
            job.status = AnalysisStatus.FAILED.value
            job.error_message = "Analysis interrupted by process shutdown or worker restart. Recovered safely."
            job.completed_at = now
            recovered_count += 1

        if recovered_count > 0:
            db.commit()

        return recovered_count

    def request_cancellation(self, analysis_id: str, db: Session) -> bool:
        """
        Cancels a queued or currently executing analysis task.
        Propagates cancellation event to worker and updates persistent state.
        """
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return False

        current_status = AnalysisStatus(analysis.status)
        if current_status in TERMINAL_STATES:
            # Cannot cancel an already terminal state
            return False

        with self._lock:
            # 1. If currently running, signal cancellation event
            if analysis_id in self._cancellation_events:
                self._cancellation_events[analysis_id].set()

            # 2. Update persistent status to CANCELLED
            analysis.status = AnalysisStatus.CANCELLED.value
            analysis.completed_at = datetime.now(timezone.utc)
            if not analysis.error_message:
                analysis.error_message = "Task cancelled by analyst."
            db.commit()
            db.refresh(analysis)
            return True

    def _worker_loop(self) -> None:
        """Continuous consumer loop polling for QUEUED analyses."""
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

            # Process job with concurrency=1
            cancel_event = threading.Event()
            with self._lock:
                self._active_job_id = job_id_to_run
                self._cancellation_events[job_id_to_run] = cancel_event

            worker_db = SessionLocal()
            try:
                pipeline_worker = PipelineWorker(worker_db, cancel_event=cancel_event)
                pipeline_worker.execute_pipeline(job_id_to_run)
            except Exception as e:
                pass
            finally:
                worker_db.close()
                with self._lock:
                    self._cancellation_events.pop(job_id_to_run, None)
                    if self._active_job_id == job_id_to_run:
                        self._active_job_id = None

job_queue_manager = JobQueueManager()
