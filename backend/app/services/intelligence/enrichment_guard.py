import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Callable, Deque, Iterator, Optional, Set, TypeVar

from app.core.config import settings

T = TypeVar("T")


class RateLimitExceededError(Exception):
    def __init__(self, message: str, retry_after: int = 1) -> None:
        super().__init__(message)
        self.retry_after = max(1, retry_after)


class ConcurrencyLimitError(Exception):
    pass


class AnalysisEnrichmentConflictError(Exception):
    pass


class EnrichmentTimeoutError(TimeoutError):
    pass


class EnrichmentCoordinator:
    """
    Thread-safe, bounded, cancellable execution coordinator for reporting enrichment.

    Scope Note: Rate-limit counters, active job slots, per-analysis mutual exclusion, and
    the bounded ThreadPoolExecutor live in-process inside this Python worker. Under a
    single Uvicorn worker (`--workers 1`), these limits apply globally to all enrichment
    requests; under multi-worker deployments (`workers > 1`), limits apply per worker process
    rather than globally across workers.

    Invariant: A concurrency slot and per-analysis lock are held for the true lifetime of the
    executing worker job (until the worker callable exits its `finally` block), NOT released
    early if the waiting HTTP handler times out. Timed-out jobs receive `cancel_event.set()`
    so subprocess trees terminate immediately and stale writes cannot occur.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._idle_cond = threading.Condition(self._lock)
        self._request_timestamps: Deque[float] = deque()
        self._active_analyses: Set[str] = set()
        self._active_count: int = 0
        self._executor: Optional[ThreadPoolExecutor] = None
        self._executor_max_workers: int = 0
        self._executor_creations: int = 0

    def active_count(self) -> int:
        with self._lock:
            return self._active_count

    def is_analysis_active(self, analysis_id: str) -> bool:
        with self._lock:
            return analysis_id in self._active_analyses

    def executor_creation_count(self) -> int:
        with self._lock:
            return self._executor_creations

    def wait_idle(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._idle_cond:
            while self._active_count > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._idle_cond.wait(timeout=remaining)
            return True

    def reset(self, wait_timeout: float = 3.0) -> None:
        """Waits briefly for active jobs to wind down and resets counters (for tests)."""
        self.wait_idle(timeout=wait_timeout)
        with self._lock:
            self._request_timestamps.clear()
            if self._active_count == 0:
                self._active_analyses.clear()

    def _get_shared_executor(self, max_concurrent: int) -> ThreadPoolExecutor:
        # Caller holds self._lock
        if self._executor is None or (
            self._executor_max_workers != max_concurrent and self._active_count == 0
        ):
            if self._executor is not None:
                self._executor.shutdown(wait=False)
            self._executor = ThreadPoolExecutor(
                max_workers=max_concurrent,
                thread_name_prefix="malbox-enrich",
            )
            self._executor_max_workers = max_concurrent
            self._executor_creations += 1
        return self._executor

    def _reserve_slot_locked(self, analysis_id: str) -> int:
        # Caller holds self._lock
        now = time.monotonic()
        max_requests = max(1, int(settings.REPORTING_RATE_LIMIT_REQUESTS))
        window_seconds = max(1, int(settings.REPORTING_RATE_LIMIT_WINDOW_SECONDS))
        max_concurrent = max(1, int(settings.REPORTING_MAX_CONCURRENT_JOBS))

        cutoff = now - window_seconds
        while self._request_timestamps and self._request_timestamps[0] <= cutoff:
            self._request_timestamps.popleft()

        if len(self._request_timestamps) >= max_requests:
            oldest = self._request_timestamps[0]
            retry_after = max(1, int(window_seconds - (now - oldest)) + 1)
            raise RateLimitExceededError(
                "Reporting intelligence rate limit exceeded. Please retry later.",
                retry_after=retry_after,
            )

        if analysis_id in self._active_analyses:
            raise AnalysisEnrichmentConflictError(
                "An intelligence enrichment job is already active for this analysis."
            )

        if self._active_count >= max_concurrent:
            raise ConcurrencyLimitError(
                "Maximum concurrent reporting enrichment capacity reached. Please retry shortly."
            )

        self._request_timestamps.append(now)
        self._active_analyses.add(analysis_id)
        self._active_count += 1
        return max_concurrent

    def acquire_slot(self, analysis_id: str) -> None:
        with self._lock:
            self._reserve_slot_locked(analysis_id)

    def release_slot(self, analysis_id: str) -> None:
        with self._idle_cond:
            self._active_analyses.discard(analysis_id)
            self._active_count = max(0, self._active_count - 1)
            if self._active_count == 0:
                self._idle_cond.notify_all()

    @contextmanager
    def acquire(self, analysis_id: str) -> Iterator[None]:
        self.acquire_slot(analysis_id)
        try:
            yield
        finally:
            self.release_slot(analysis_id)

    def execute_cancellable(
        self,
        analysis_id: str,
        timeout_seconds: float,
        fn: Callable[[threading.Event], T],
    ) -> T:
        """
        Reserves a bounded slot, executes `fn(cancel_event)` on the shared bounded executor,
        waits up to `timeout_seconds`, and triggers active cancellation on timeout.
        The slot stays held until `fn` finishes running, preventing unbounded job pileup.
        """
        with self._lock:
            max_concurrent = self._reserve_slot_locked(analysis_id)
            executor = self._get_shared_executor(max_concurrent)

        cancel_event = threading.Event()
        done_event = threading.Event()
        outcome: dict = {"result": None, "error": None}

        def _worker() -> None:
            try:
                outcome["result"] = fn(cancel_event)
            except BaseException as exc:
                outcome["error"] = exc
            finally:
                self.release_slot(analysis_id)
                done_event.set()

        try:
            executor.submit(_worker)
        except Exception:
            self.release_slot(analysis_id)
            raise

        finished = done_event.wait(timeout=max(0.1, float(timeout_seconds)))
        if not finished:
            cancel_event.set()
            # Brief grace period for responsive subprocess killpg teardown
            done_event.wait(timeout=0.35)
            raise EnrichmentTimeoutError(
                f"Reporting enrichment timed out after {float(timeout_seconds):.1f}s."
            )

        if outcome["error"] is not None:
            raise outcome["error"]

        return outcome["result"]


enrichment_coordinator = EnrichmentCoordinator()
