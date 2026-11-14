from pathlib import Path
import httpx
from app.services.sandbox.cape import CapeSandboxBackend

def test_cape_readiness_failure(monkeypatch):
    """Verifies that CAPE reports not ready when service is unreachable without throwing unhandled exceptions."""
    backend = CapeSandboxBackend(api_url="http://127.0.0.1:9999")
    res = backend.check_readiness()
    assert res["backend"] == "cape"
    assert res["ready"] is False
    assert "Failed to connect to CAPE API" in res["error"]
    assert len(res["prerequisites_missing"]) > 0

def test_cape_readiness_mocked(monkeypatch):
    """Verifies CAPE readiness parsing when API responds with 200."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0-CAPE",
                    "tasks": {"total": 150, "completed": 140, "running": 2}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponse())
    res = backend.check_readiness()
    assert res["ready"] is True
    assert res["version"] == "2.4.0-CAPE"
    assert res["tasks_summary"]["total"] == 150

def test_cape_submission_and_report_transform(monkeypatch, tmp_path):
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    # Create dummy sample file
    dummy_file = tmp_path / "test.exe"
    dummy_file.write_bytes(b"MZ_DUMMY_BINARY")

    # 1. Mock Submission
    class MockSubmitResponse:
        status_code = 200
        def json(self):
            return {"error": False, "data": {"task_ids": [7788]}}

    monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: MockSubmitResponse())
    task_id = backend.submit_sample(dummy_file, profile="ransomware_focus", timeout_seconds=60)
    assert task_id == "7788"

    # 2. Mock Status View
    class MockStatusResponse:
        status_code = 200
        def json(self):
            return {"error": False, "data": {"task": {"id": 7788, "status": "reported"}}}

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockStatusResponse())
    task_status = backend.get_task_status("7788")
    assert task_status["status"] == "completed"

    # 3. Mock Report Fetch & Transformation
    cape_report_fixture = {
        "info": {"id": 7788, "duration": 45},
        "behavior": {
            "processes": [
                {
                    "process_id": 1122,
                    "parent_id": 400,
                    "process_name": "malware.exe",
                    "command_line": "malware.exe -run",
                    "first_seen": "2026-11-08T10:00:00Z"
                }
            ],
            "generic": [
                {
                    "category": "registry",
                    "pid": 1122,
                    "process_name": "malware.exe",
                    "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Payload",
                    "status": "write",
                    "time": "2026-11-08T10:00:05Z"
                }
            ]
        },
        "network": {
            "dns": [
                {
                    "request": "c2-domain.com",
                    "type": "A",
                    "answers": [{"data": "1.2.3.4"}]
                }
            ],
            "tcp": [{"dst": "1.2.3.4", "dport": 8080}]
        }
    }

    class MockReportResponse:
        status_code = 200
        def json(self):
            return cape_report_fixture

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockReportResponse())
    transformed = backend.collect_results("7788")

    assert len(transformed["processes"]) == 1
    assert transformed["processes"][0]["pid"] == 1122
    assert len(transformed["registry"]) == 1
    assert transformed["registry"][0]["persistence"] is True
    assert len(transformed["network"]["dns"]) == 1
    assert transformed["network"]["dns"][0]["query"] == "c2-domain.com"


def test_cape_get_task_status_flat_and_wrapped_formats(monkeypatch):
    """Verifies parsing of both flat (real CAPE v2) and wrapped (legacy/mock) task statuses."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResp:
        def __init__(self, data, status_code=200):
            self._data = data
            self.status_code = status_code
        def json(self):
            return self._data

    # 1. Flat running (real CAPEv2)
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": False, "data": {"id": 101, "status": "running"}}))
    s1 = backend.get_task_status("101")
    assert s1["status"] == "running"
    assert s1["cape_status"] == "running"
    assert s1["is_ready_for_report"] is False

    # 2. Flat reported (ready for report)
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": False, "data": {"id": 101, "status": "reported"}}))
    s2 = backend.get_task_status("101")
    assert s2["status"] == "completed"
    assert s2["cape_status"] == "reported"
    assert s2["is_ready_for_report"] is True

    # 3. Flat completed (VM halted, still processing report)
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": False, "data": {"id": 101, "status": "completed"}}))
    s3 = backend.get_task_status("101")
    assert s3["status"] == "collecting"
    assert s3["cape_status"] == "completed"
    assert s3["is_ready_for_report"] is False

    # 4. Wrapped pending (mock / legacy format)
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": False, "data": {"task": {"id": 102, "status": "pending"}}}))
    s4 = backend.get_task_status("102")
    assert s4["status"] == "queued"
    assert s4["cape_status"] == "pending"

    # 5. Wrapped reported
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": False, "data": {"task": {"id": 102, "status": "reported"}}}))
    s5 = backend.get_task_status("102")
    assert s5["status"] == "completed"
    assert s5["is_ready_for_report"] is True


def test_cape_submission_options_and_tag_validation(monkeypatch, tmp_path):
    """Verifies strict option allowlist and graceful machine tag mapping."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ_DUMMY")

    # 1. Disallowed option rejected
    import pytest
    with pytest.raises(ValueError, match="Disallowed CAPE submission option: unapproved_key"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"unapproved_key": "val"})

    # 2. Invalid tag format rejected
    with pytest.raises(ValueError, match="Invalid CAPE machine tag format"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"tags": "invalid;rm -rf /"})

    # 3. Standard profile does not inject machine tags by default
    posted_data = {}
    class MockSubmitResp:
        status_code = 200
        def json(self):
            return {"error": False, "data": {"task_ids": [9901]}}

    def mock_post(*args, **kwargs):
        nonlocal posted_data
        posted_data = kwargs.get("data") or {}
        return MockSubmitResp()

    monkeypatch.setattr(httpx.Client, "post", mock_post)
    tid = backend.submit_sample(sample, profile="standard", timeout_seconds=60)
    assert tid == "9901"
    assert "tags" not in posted_data

    # 4. Valid explicit tag forwarded
    backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"tags": "win10_x64,clean"})
    assert posted_data.get("tags") == "win10_x64,clean"


def test_cape_report_error_envelope_with_http_200_raises(monkeypatch):
    """Verifies that CAPE returning HTTP 200 with error envelope is not swallowed as empty clean report."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockErrorResp:
        status_code = 200
        def json(self):
            return {"error": True, "error_value": "Report has not been generated yet or failed"}

    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockErrorResp())
    monkeypatch.setattr("time.sleep", lambda s: None)

    import pytest
    with pytest.raises(RuntimeError, match="CAPE report unavailable for task"):
        backend.collect_results("9999", max_retries=2, retry_delay_seconds=0.01)


def test_cape_completed_before_reported_race_retry(monkeypatch):
    """Verifies that race condition between VM completed and report.json generation retries with backoff."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    attempts = {"count": 0}

    class MockResp:
        def __init__(self, data, status_code=200):
            self._data = data
            self.status_code = status_code
        def json(self):
            return self._data

    def mock_get(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] < 3:
            # First 2 attempts return error envelope
            return MockResp({"error": True, "error_value": "No reports created for this task yet"})
        # 3rd attempt returns valid report
        return MockResp({
            "info": {"id": 5555, "duration": 20},
            "behavior": {
                "processes": [{"process_id": 1, "process_name": "proc.exe", "command_line": "proc.exe", "first_seen": "now"}],
                "generic": []
            },
            "network": {}
        })

    monkeypatch.setattr(httpx.Client, "get", mock_get)
    monkeypatch.setattr("time.sleep", lambda s: None)

    res = backend.collect_results("5555", max_retries=4, retry_delay_seconds=0.01)
    assert attempts["count"] == 3
    assert len(res["processes"]) == 1
    assert res["metadata"]["cape_id"] == 5555


def test_cape_analyzer_crash_detection(monkeypatch):
    """Verifies that guest analyzer crash is detected and marks telemetry INCOMPLETE."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    report_with_crash = {
        "info": {"id": 8888, "duration": 4},
        "debug": {
            "errors": [
                "CRITICAL: Guest analyzer syntax error in analyzer.py line 45 (Python 3.5 unsupported f-strings)"
            ]
        },
        "behavior": {"processes": [], "generic": []},
        "network": {}
    }

    class MockResp:
        status_code = 200
        def json(self):
            return report_with_crash

    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp())
    res = backend.collect_results("8888", max_retries=1)

    assert res["telemetry_completeness"] == "INCOMPLETE"
    assert res["metadata"]["analyzer_crashed"] is True
    assert any("crash or syntax failure" in note for note in res["telemetry_notes"])


def test_cape_extended_telemetry_extraction(monkeypatch):
    """Verifies extraction of monitored API calls, dropped files, and memory payloads."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    extended_report = {
        "info": {"id": 9999, "duration": 40},
        "behavior": {
            "processes": [
                {
                    "process_id": 2020,
                    "process_name": "loader.exe",
                    "command_line": "loader.exe",
                    "first_seen": "2026-11-08T12:00:00Z",
                    "calls": [
                        {
                            "api": "VirtualAllocEx",
                            "status": 1,
                            "arguments": {"flProtect": "0x00000040", "flAllocationType": "0x00001000"},
                            "timestamp": "2026-11-08T12:00:01Z"
                        },
                        {
                            "api": "WriteProcessMemory",
                            "status": 1,
                            "arguments": {"nSize": 4096},
                            "timestamp": "2026-11-08T12:00:02Z"
                        },
                        {
                            "api": "CreateRemoteThread",
                            "status": 1,
                            "arguments": {"hProcess": "0x1234"},
                            "timestamp": "2026-11-08T12:00:03Z"
                        }
                    ]
                }
            ],
            "generic": [],
            "summary": {
                "write_files": ["C:\\Users\\Admin\\AppData\\Local\\Temp\\dropped_payload.exe"]
            }
        },
        "dropped": [
            {
                "name": "extracted_miner.exe",
                "path": "C:\\Windows\\Temp\\extracted_miner.exe",
                "size": 1048576,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        ],
        "payloads": [
            {
                "name": "unpacked_core.dll",
                "size": 524288,
                "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        ],
        "network": {
            "dns": [{"request": "command.control.net", "type": "A", "answers": [{"data": "5.6.7.8"}]}]
        }
    }

    class MockResp:
        status_code = 200
        def json(self):
            return extended_report

    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp())
    res = backend.collect_results("9999", max_retries=1)

    # API calls extracted
    assert len(res["api_calls"]) == 3
    assert res["api_calls"][0]["api"] == "VirtualAllocEx"
    assert res["api_calls"][2]["api"] == "CreateRemoteThread"

    # Dropped binaries flagged
    dropped_bins = [f for f in res["filesystem"] if f.get("is_dropped_binary")]
    assert len(dropped_bins) == 3
    paths = [d["path"] for d in dropped_bins]
    assert any("dropped_payload.exe" in p for p in paths)
    assert any("extracted_miner.exe" in p for p in paths)
    assert any("unpacked_core.dll" in p for p in paths)

    # Telemetry completeness contract
    assert res["telemetry_completeness"] == "COMPLETE"


