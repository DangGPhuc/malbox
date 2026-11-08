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

