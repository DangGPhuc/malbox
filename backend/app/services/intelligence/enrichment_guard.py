import time
import threading
from collections import deque
from contextlib import contextmanager
from typing import Deque, Iterator, Set

from app.core.config import settings


class RateLimitExceededError(Exception):
    def __init__(self, message: str, retry_after: int = 1) -> None:
        super().__init__(message)
        self.retry_after = max(1, retry_after)


class ConcurrencyLimitError(Exception):
    pass


class AnalysisEnrichmentConflictError(Exception):
    pass


class EnrichmentCoordinator:
    """
    Thread-safe coordinator enforcing rate limits, global concurrent enrichment budget,
    and per-analysis mutual exclusion to protect reporting state from overlapping writes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._request_timestamps: Deque[float] = deque()
        self._active_analyses: Set[str] = set()
        self._active_count: int = 0

    def reset(self) -> None:
        """Clears runtime counters (intended for isolated test teardown)."""
        with self._lock:
            self._request_timestamps.clear()
            self._active_analyses.clear()
            self._active_count = 0

    def acquire_slot(self, analysis_id: str) -> None:
        now = time.monotonic()
        max_requests = max(1, int(settings.REPORTING_RATE_LIMIT_REQUESTS))
        window_seconds = max(1, int(settings.REPORTING_RATE_LIMIT_WINDOW_SECONDS))
        max_concurrent = max(1, int(settings.REPORTING_MAX_CONCURRENT_JOBS))

        with self._lock:
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

    def release_slot(self, analysis_id: str) -> None:
        with self._lock:
            self._active_analyses.discard(analysis_id)
            self._active_count = max(0, self._active_count - 1)

    @contextmanager
    def acquire(self, analysis_id: str) -> Iterator[None]:
        self.acquire_slot(analysis_id)
        try:
            yield
        finally:
            self.release_slot(analysis_id)


enrichment_coordinator = EnrichmentCoordinator()
