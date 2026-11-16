import io
import pytest
from app.core.config import settings
from app.models.analysis import AnalysisStatus


def test_upload_sample_deduplication(client):
    file_content = b"MZ" + b"\x90" * 200 + b"FAKE_PE_HEADER_PAYLOAD"
    file_tuple = ("test_sample.exe", io.BytesIO(file_content), "application/octet-stream")

    # First upload
    res1 = client.post("/api/v1/samples", files={"file": file_tuple})
    assert res1.status_code == 201
    sample1 = res1.json()
    assert sample1["sha256"] is not None
    assert sample1["file_name"] == "test_sample.exe"

    # Second upload with same content -> should deduplicate
    file_tuple2 = ("test_sample_copy.exe", io.BytesIO(file_content), "application/octet-stream")
    res2 = client.post("/api/v1/samples", files={"file": file_tuple2})
    assert res2.status_code == 201
    sample2 = res2.json()
    assert sample2["id"] == sample1["id"]
    assert sample2["sha256"] == sample1["sha256"]


def test_live_mode_safety_gate_explicit_server_disable(client, monkeypatch):
    """When LIVE_MODE_ENABLED=False, live execution must be rejected with HTTP 403."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", False)

    file_content = b"MZ_TEST_SAMPLE"
    res = client.post("/api/v1/samples", files={"file": ("malware.exe", io.BytesIO(file_content))})
    sample = res.json()

    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
    }
    res_analysis = client.post("/api/v1/analyses", json=analysis_payload)
    assert res_analysis.status_code == 403
    assert "disabled by server security policy" in res_analysis.json()["detail"]


def test_live_mode_safety_gate_missing_user_approval(client, monkeypatch):
    """When approved_by_user=False (or omitted), live execution must be blocked with HTTP 400."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "valid-test-operator-token-32chars")

    file_content = b"MZ_TEST_SAMPLE_APPROVAL"
    res = client.post("/api/v1/samples", files={"file": ("malware2.exe", io.BytesIO(file_content))})
    sample = res.json()

    # Omit approved_by_user (defaults to False in schema)
    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": False,
    }
    res_analysis = client.post(
        "/api/v1/analyses",
        json=analysis_payload,
        headers={"X-Operator-Token": "valid-test-operator-token-32chars"}
    )
    assert res_analysis.status_code == 400
    assert "Live detonation requires explicit analyst approval." in res_analysis.json()["detail"]


def test_live_mode_safety_gate_unconfigured_operator_token(client, monkeypatch):
    """When MALBOX_OPERATOR_TOKEN is empty on server, live execution fails closed with HTTP 403."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "")

    file_content = b"MZ_TEST_SAMPLE_TOKEN"
    res = client.post("/api/v1/samples", files={"file": ("malware3.exe", io.BytesIO(file_content))})
    sample = res.json()

    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
    }
    res_analysis = client.post("/api/v1/analyses", json=analysis_payload)
    assert res_analysis.status_code == 403
    assert "Server operator security token is unconfigured (fail closed)" in res_analysis.json()["detail"]


def test_live_mode_safety_gate_missing_or_invalid_operator_token(client, monkeypatch):
    """When operator token is missing or mismatched in request headers, reject with HTTP 401."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "valid-test-operator-token-32chars")

    file_content = b"MZ_TEST_SAMPLE_AUTH"
    res = client.post("/api/v1/samples", files={"file": ("malware4.exe", io.BytesIO(file_content))})
    sample = res.json()

    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
    }

    # 1. Missing header
    res_missing = client.post("/api/v1/analyses", json=analysis_payload)
    assert res_missing.status_code == 401
    assert "Valid operator token required" in res_missing.json()["detail"]

    # 2. Invalid header
    res_invalid = client.post(
        "/api/v1/analyses",
        json=analysis_payload,
        headers={"X-Operator-Token": "invalid-wrong-token"}
    )
    assert res_invalid.status_code == 401
    assert "Valid operator token required" in res_invalid.json()["detail"]


def test_live_mode_authorized_submission(client, monkeypatch):
    """When authorized with valid token and approval, live CAPE analysis queues successfully (HTTP 201)."""
    token = "valid-test-operator-token-32chars"
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", token)

    file_content = b"MZ_SAMPLE_AUTHORIZED"
    res = client.post("/api/v1/samples", files={"file": ("authorized_sample.exe", io.BytesIO(file_content))})
    sample = res.json()

    analysis_payload = {
        "sample_id": sample["id"],
        "backend_type": "cape",
        "profile": "standard",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }
    res_analysis = client.post(
        "/api/v1/analyses",
        json=analysis_payload,
        headers={"X-Operator-Token": token}
    )
    assert res_analysis.status_code == 201
    analysis = res_analysis.json()
    assert analysis["status"] in [AnalysisStatus.QUEUED.value, AnalysisStatus.PREFLIGHT.value]
    assert analysis["backend_type"] == "cape"
    assert analysis["live_mode"] is True
    assert analysis["approved_by_user"] is True

    # Retrieve analysis by ID
    get_res = client.get(f"/api/v1/analyses/{analysis['id']}")
    assert get_res.status_code == 200
    detail = get_res.json()
    assert detail["id"] == analysis["id"]
    assert detail["sample_id"] == sample["id"]
    assert detail["sample_file_name"] == "authorized_sample.exe"
