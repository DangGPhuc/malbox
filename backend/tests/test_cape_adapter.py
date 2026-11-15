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

    # Dropped binaries flagged in filesystem
    dropped_bins = [f for f in res["filesystem"] if f.get("is_dropped_binary")]
    assert len(dropped_bins) == 2
    paths = [d["path"] for d in dropped_bins]
    assert any("dropped_payload.exe" in p for p in paths)
    assert any("extracted_miner.exe" in p for p in paths)

    # In-memory extracted payloads preserved as artifacts (not forged filesystem writes, B2)
    memory_payloads = [a for a in res["artifacts"] if a.get("is_extracted_memory_payload")]
    assert len(memory_payloads) == 1
    assert memory_payloads[0]["name"] == "unpacked_core.dll"

    # Telemetry completeness contract
    assert res["telemetry_completeness"] == "COMPLETE"


def test_cape_planning_fields_rejected_as_options(tmp_path):
    """Verifies that internal orchestration planning fields cannot be injected as CAPE transport options (A1)."""
    import pytest
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ_DUMMY")

    with pytest.raises(ValueError, match="Disallowed CAPE submission option: requested_artifacts"):
        backend.submit_sample(
            sample,
            profile="standard",
            timeout_seconds=60,
            options={"requested_artifacts": ["pcap", "memory_dump"]},
        )

    with pytest.raises(ValueError, match="Disallowed CAPE submission option: telemetry_focus"):
        backend.submit_sample(
            sample,
            profile="standard",
            timeout_seconds=60,
            options={"telemetry_focus": ["process", "network"]},
        )


def test_cape_submission_options_value_validation(tmp_path):
    """Verifies strict value validation on all allowed submission options (A1)."""
    import pytest
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ_DUMMY")

    # Invalid timeout values
    with pytest.raises(ValueError, match="Invalid timeout option value"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"timeout": -5})
    with pytest.raises(ValueError, match="Invalid timeout option value"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"timeout": 5000})

    # Invalid enforce_timeout
    with pytest.raises(ValueError, match="Invalid enforce_timeout option value"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"enforce_timeout": "maybe"})

    # Invalid machine / package identifier
    with pytest.raises(ValueError, match="Invalid CAPE machine identifier"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"machine": "win10; reboot"})

    # Invalid priority
    with pytest.raises(ValueError, match="Invalid priority option value"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"priority": 5})

    # Invalid options string
    with pytest.raises(ValueError, match="Invalid CAPE options parameter string"):
        backend.submit_sample(sample, profile="standard", timeout_seconds=60, options={"options": "route=none\nmalicious_param=1"})


def test_cape_profile_tag_mapping_empty_by_default(monkeypatch, tmp_path):
    """Verifies that no implicit machine tags are injected for any profile by default (A2)."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ_DUMMY")

    posted_data = {}
    class MockSubmitResp:
        status_code = 200
        def json(self):
            return {"error": False, "data": {"task_ids": [1001]}}

    def mock_post(*args, **kwargs):
        nonlocal posted_data
        posted_data = kwargs.get("data") or {}
        return MockSubmitResp()

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    # 1. Default backend instance has empty profile_tag_map
    backend_default = CapeSandboxBackend(api_url="http://mock-cape.local")
    assert backend_default.profile_tag_map == {}

    # 2. Submitting ransomware_focus with default mapping sends NO tags
    backend_default.submit_sample(sample, profile="ransomware_focus", timeout_seconds=60)
    assert "tags" not in posted_data
    assert posted_data.get("enforce_timeout") == "1"

    # 3. Explicit operator mapping is respected
    backend_custom = CapeSandboxBackend(
        api_url="http://mock-cape.local",
        profile_tag_map={"ransomware_focus": "win10_isolated"}
    )
    backend_custom.submit_sample(sample, profile="ransomware_focus", timeout_seconds=60)
    assert posted_data.get("tags") == "win10_isolated"


def test_cape_task_id_and_sha256_mismatch_rejection(monkeypatch):
    """Verifies that mismatched task ID or sample SHA-256 in CAPE report raises ValueError (A3)."""
    import pytest
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResp:
        def __init__(self, data):
            self.status_code = 200
            self._data = data
        def json(self):
            return self._data

    # 1. Task ID mismatch: requested task 100, report is for task 200
    report_task_200 = {
        "info": {"id": 200, "duration": 15},
        "target": {"file": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
        "behavior": {"processes": [], "generic": []},
        "network": {}
    }
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp(report_task_200))
    with pytest.raises(ValueError, match="CAPE report task ID mismatch: requested task 100 but report returned task 200"):
        backend.collect_results("100")

    # 2. SHA-256 mismatch: expected sha aaa, report target has sha bbb
    report_matching_task_wrong_sha = {
        "info": {"id": 100, "duration": 15},
        "target": {"file": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
        "behavior": {"processes": [], "generic": []},
        "network": {}
    }
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp(report_matching_task_wrong_sha))
    with pytest.raises(ValueError, match="CAPE report sample SHA-256 mismatch"):
        backend.collect_results("100", expected_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_cape_missing_report_identity_marked_unverified(monkeypatch):
    """Verifies that missing report identity is marked unverified rather than substituting requested ID (A3)."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    report_without_id = {
        "info": {"duration": 20},  # No "id"
        "target": {},
        "behavior": {"processes": [], "generic": []},
        "network": {}
    }

    class MockResp:
        status_code = 200
        def json(self):
            return report_without_id

    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp())
    res = backend.collect_results("7777")
    assert res["metadata"]["cape_id"] is None
    assert res["metadata"]["cape_id_verified"] is False


def test_cape_readiness_rejects_malformed_and_error_envelope(monkeypatch):
    """Verifies that CAPE check_readiness rejects error envelopes and malformed JSON with HTTP 200 (A4)."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResp:
        def __init__(self, data):
            self.status_code = 200
            self._data = data
        def json(self):
            return self._data

    # Error envelope with HTTP 200
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp({"error": True, "error_value": "Database connection offline"}))
    r1 = backend.check_readiness()
    assert r1["ready"] is False
    assert r1["status"] == "error"
    assert "Database connection offline" in r1["error"]

    # Non-dict data
    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: MockResp(["not", "a", "dict"]))
    r2 = backend.check_readiness()
    assert r2["ready"] is False
    assert r2["status"] == "malformed"


def test_cape_collect_results_does_not_retry_auth_failure(monkeypatch):
    """Verifies that collect_results fails immediately on 401/403 without retrying (A4)."""
    import pytest
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")
    attempts = {"count": 0}

    class MockAuthFail:
        status_code = 401
        text = "Unauthorized"
        def json(self):
            return {"error": True}

    def mock_get(*args, **kwargs):
        attempts["count"] += 1
        return MockAuthFail()

    monkeypatch.setattr(httpx.Client, "get", mock_get)

    with pytest.raises(PermissionError, match="authentication failed"):
        backend.collect_results("5001", max_retries=4)

    # Must fail on the first attempt without retrying
    assert attempts["count"] == 1


def test_cape_pipeline_worker_e2e_regression_mocked_http(client, monkeypatch, tmp_path):
    """
    Mandatory Regression Test (A1):
    Executes actual PipelineWorker through full API request lifecycle with real CapeSandboxBackend
    and mocked HTTP transport.
    Verifies:
    API analysis request -> planner -> worker -> readiness -> CAPE submission ->
    status polling -> report retrieval -> normalization -> detection -> report persistence -> COMPLETED.
    Ensures internal planning fields (requested_artifacts, telemetry_focus) are NEVER forwarded to CAPE.
    """
    import io
    from app.core.config import settings
    from app.core.database import SessionLocal
    from app.models.analysis import Analysis, AnalysisStatus
    from app.models.audit import OrchestrationRecord

    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "e2e-op-token-secret")

    # 1. Upload benign test sample
    sample_bytes = b"MZ_SYNTHETIC_BENIGN_PE_FOR_E2E"
    res_upload = client.post("/api/v1/samples", files={"file": ("e2e_sample.exe", io.BytesIO(sample_bytes))})
    assert res_upload.status_code == 201
    sample_data = res_upload.json()
    sample_id = sample_data["id"]
    sample_sha256 = sample_data["sha256"]

    # Track requests sent to mock HTTP transport
    cape_posts: list = []
    cape_gets: list = []

    class MockHttpResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data
            self.text = "OK" if status_code == 200 else "Error"
            self.content = b""

        def json(self):
            return self._json

    orig_get = httpx.Client.get
    orig_post = httpx.Client.post

    def mock_post(self_client, url, *args, **kwargs):
        url_str = str(url)
        if "apiv2" in url_str:
            cape_posts.append({
                "url": url_str,
                "data": kwargs.get("data", {}),
                "files": kwargs.get("files", {}),
            })
            if "tasks/create/file" in url_str:
                return MockHttpResponse(200, {"error": False, "data": {"task_ids": [4455]}})
            return MockHttpResponse(400, {"error": True})
        return orig_post(self_client, url, *args, **kwargs)

    poll_count = {"count": 0}

    def mock_get(self_client, url, *args, **kwargs):
        url_str = str(url)
        if "apiv2" in url_str:
            cape_gets.append(url_str)
            if "cuckoo/status" in url_str:
                return MockHttpResponse(200, {
                    "error": False,
                    "data": {
                        "version": "2.4.0",
                        "machines": {"total": 2, "available": 2},
                        "tasks": {"total": 10}
                    }
                })
            elif "tasks/view/4455" in url_str:
                poll_count["count"] += 1
                return MockHttpResponse(200, {
                    "error": False,
                    "data": {"id": 4455, "status": "reported"}
                })
            elif "tasks/get/report/4455" in url_str:
                return MockHttpResponse(200, {
                    "info": {"id": 4455, "duration": 25},
                    "target": {"file": {"sha256": sample_sha256}},
                    "behavior": {
                        "processes": [
                            {
                                "process_id": 3001,
                                "parent_id": 4,
                                "process_name": "e2e_sample.exe",
                                "command_line": "e2e_sample.exe",
                                "first_seen": "2026-11-15T00:00:00Z"
                            }
                        ],
                        "generic": [
                            {
                                "category": "file",
                                "path": "C:\\Windows\\Temp\\benign.log",
                                "status": "write",
                                "time": "2026-11-15T00:00:01Z",
                                "pid": 3001,
                                "process_name": "e2e_sample.exe"
                            }
                        ]
                    },
                    "network": {"dns": []},
                    "debug": {"errors": []}
                })
            elif "tasks/get/pcap/4455" in url_str:
                return MockHttpResponse(200, {})
            return MockHttpResponse(404, {"error": True})
        return orig_get(self_client, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "post", mock_post)
    monkeypatch.setattr(httpx.Client, "get", mock_get)

    # 2. Trigger synchronous analysis creation through API
    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "profile": "standard",
        "timeout_seconds": 60,
        "live_mode": True,
        "approved_by_user": True,
    }

    res_analysis = client.post(
        "/api/v1/analyses?run_sync=true",
        json=payload,
        headers={"X-Operator-Token": "e2e-op-token-secret"},
    )
    assert res_analysis.status_code == 201
    analysis_id = res_analysis.json()["id"]

    # 3. Verify CAPE transport request correctness
    assert len(cape_posts) == 1
    post_data = cape_posts[0]["data"]

    # MANDATORY ASSERTION (A1): Internal planning fields must NEVER be sent to CAPE
    assert "requested_artifacts" not in post_data
    assert "telemetry_focus" not in post_data
    assert post_data.get("timeout") == "60"

    # 4. Verify Analysis in Database reached COMPLETED
    db = SessionLocal()
    try:
        db_analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        assert db_analysis is not None
        assert db_analysis.status == AnalysisStatus.COMPLETED.value
        assert db_analysis.external_task_id == "4455"
        assert db_analysis.error_message is None

        # Verify Report was generated and persisted
        assert db_analysis.report is not None
        assert db_analysis.report.risk_score is not None

        # Verify planning metadata was safely stored in OrchestrationRecord
        records = db.query(OrchestrationRecord).filter(OrchestrationRecord.analysis_id == analysis_id).all()
        assert len(records) >= 1
        preflight_record = [r for r in records if r.stage == "preflight_planning"]
        assert len(preflight_record) == 1
        final_action = preflight_record[0].final_action
        assert "requested_artifacts" in final_action
        assert "telemetry_focus" in final_action
    finally:
        db.close()



