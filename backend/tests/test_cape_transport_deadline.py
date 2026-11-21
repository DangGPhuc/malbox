import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock
import httpx

from app.services.sandbox.cape import CapeSandboxBackend, MAX_REPORT_BYTES, MAX_ARTIFACT_BYTES


def test_monotonic_deadline_never_silently_extended():
    """Verify that when time budget has expired or is very small, no minimum 5s timeout is injected."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    # Pass max_timeout=0.0 -> deadline already passed
    with pytest.raises(TimeoutError, match="Monotonic deadline exceeded"):
        backend.collect_results("task_99", max_timeout=0.0)


def test_oversized_streaming_report_rejected(monkeypatch):
    """
    Independently of Content-Length headers, a response whose streamed chunks
    exceed MAX_REPORT_BYTES must immediately raise ValueError and terminate.
    """
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockStreamResponse:
        status_code = 200
        headers = {}  # No Content-Length header

        def iter_bytes(self, chunk_size=65536):
            # Yield chunks that will exceed MAX_REPORT_BYTES (50 MiB)
            oversized_chunk = b"A" * (1024 * 1024)  # 1 MiB
            for _ in range(55):  # 55 MiB total > 50 MiB limit
                yield oversized_chunk

    class MockStreamContext:
        def __enter__(self):
            return MockStreamResponse()
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(httpx.Client, "stream", lambda *args, **kwargs: MockStreamContext())

    with pytest.raises(ValueError, match="stream exceeded maximum allowed size"):
        backend.collect_results("task_big", max_timeout=10.0)


def test_oversized_fallback_body_rejected(monkeypatch):
    """When falling back to buffered client.get(), body exceeding MAX_REPORT_BYTES must be rejected."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockGetResponse:
        status_code = 200
        headers = {}
        content = b"X" * (MAX_REPORT_BYTES + 1024)
        def iter_bytes(self, *args, **kwargs):
            return iter([])
        def json(self):
            return {}

    monkeypatch.setattr(httpx.Client, "stream", MagicMock(side_effect=TypeError("No streaming")))
    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockGetResponse())

    with pytest.raises(ValueError, match="exceeded maximum allowed size"):
        backend.collect_results("task_buffered_big", max_timeout=10.0)


def test_interrupted_artifact_transfer_cleans_partial_tmp_files(monkeypatch, tmp_path):
    """
    When artifact downloading is interrupted by a timeout or exception,
    all temporary .tmp files must be completely removed.
    """
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    dest_dir = tmp_path / "artifacts_test"
    dest_dir.mkdir()

    class InterruptedStreamResponse:
        status_code = 200
        headers = {}

        def iter_bytes(self, chunk_size=65536):
            # Yield one chunk, then simulate network disconnection / timeout
            yield b"PK\x03\x04" + b"DATA" * 100
            raise httpx.ReadTimeout("Connection dropped mid-stream")

    class MockStreamContext:
        def __enter__(self):
            return InterruptedStreamResponse()
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(httpx.Client, "stream", lambda *args, **kwargs: MockStreamContext())

    artifacts = backend.generate_artifacts("task_interrupted", dest_dir, max_timeout=10.0)

    # Must return empty artifacts and NO lingering .tmp files
    assert len(artifacts) == 0
    tmp_files = list(dest_dir.glob("*.tmp"))
    assert len(tmp_files) == 0


def test_artifact_generation_respects_deadline(monkeypatch, tmp_path):
    """If the monotonic deadline has already expired, no network request is initiated."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    dest_dir = tmp_path / "artifacts_deadline"

    request_started = False
    def mock_stream(*args, **kwargs):
        nonlocal request_started
        request_started = True
        raise AssertionError("Network request should NOT have started after deadline expired!")

    monkeypatch.setattr(httpx.Client, "stream", mock_stream)

    # Pass an expired deadline
    expired_deadline = time.monotonic() - 1.0
    artifacts = backend.generate_artifacts("task_expired", dest_dir, deadline=expired_deadline)

    assert artifacts == []
    assert request_started is False


def test_insufficient_disk_space_skips_artifact_write(monkeypatch, tmp_path):
    """When disk space is less than 200MB, generate_artifacts must cleanly abort without writing."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    dest_dir = tmp_path / "low_disk"

    import shutil
    from collections import namedtuple
    DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
    # 50 MB free < 200 MB required
    monkeypatch.setattr(shutil, "disk_usage", lambda path: DiskUsage(1000 * 1024 * 1024, 950 * 1024 * 1024, 50 * 1024 * 1024))

    request_started = False
    def mock_stream(*args, **kwargs):
        nonlocal request_started
        request_started = True

    monkeypatch.setattr(httpx.Client, "stream", mock_stream)

    artifacts = backend.generate_artifacts("task_low_disk", dest_dir)
    assert artifacts == []
    assert request_started is False
