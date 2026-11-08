import io
import time
from unittest.mock import MagicMock, patch
import pytest

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.schemas.analysis import AnalysisCreate
from app.workers.job_queue import job_queue_manager
from app.workers.pipeline_worker import safe_update_status
from app.services.sandbox.cape import CapeSandboxBackend


def test_safety_gate_cape_live_mode_false(client):
    """CAPE + live_mode=false must be rejected as invalid configuration."""
    res_sample = client.post("/api/v1/samples", files={"file": ("test1.exe", io.BytesIO(b"MZ123_1"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": False,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    assert res.status_code == 422
    assert "Inconsistent configuration: CAPE backend requires live_mode=true." in res.text


def test_safety_gate_cape_missing_approval(client):
    """CAPE + missing user approval must be rejected."""
    res_sample = client.post("/api/v1/samples", files={"file": ("test2.exe", io.BytesIO(b"MZ123_2"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": False,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    assert res.status_code == 422
    assert "Live execution requires explicit analyst authorization" in res.text


def test_safety_gate_invalid_backend(client):
    """Invalid backend enum value must be rejected."""
    res_sample = client.post("/api/v1/samples", files={"file": ("test3.exe", io.BytesIO(b"MZ123_3"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "invalid_backend_string",
        "live_mode": False,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    assert res.status_code == 422


def test_safety_gate_replay_live_mode_true(client):
    """Replay backend with live_mode=True must be rejected as inconsistent."""
    res_sample = client.post("/api/v1/samples", files={"file": ("test4.exe", io.BytesIO(b"MZ123_4"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    assert res.status_code == 422
    assert "Replay backend cannot run in live mode" in res.text


def test_safety_gate_live_disabled_by_policy(client, monkeypatch):
    """When LIVE_MODE_ENABLED=False, CAPE requests return HTTP 403."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", False)
    res_sample = client.post("/api/v1/samples", files={"file": ("test5.exe", io.BytesIO(b"MZ123_5"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    assert res.status_code == 403
    assert "disabled by server security policy" in res.json()["detail"]


def test_safety_gate_operator_token_required(client, monkeypatch):
    """When live analysis is enabled, requests require valid X-Operator-Token."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "secure-token-123")

    res_sample = client.post("/api/v1/samples", files={"file": ("test6.exe", io.BytesIO(b"MZ123_6"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }

    # Request without token -> 401
    res_no_token = client.post("/api/v1/analyses", json=payload)
    assert res_no_token.status_code == 401

    # Request with invalid token -> 401
    res_bad_token = client.post("/api/v1/analyses", json=payload, headers={"X-Operator-Token": "wrong"})
    assert res_bad_token.status_code == 401


def test_terminal_state_protection(db_session):
    """Ensure safe_update_status forbids transitions from terminal states or invalid orders."""
    sample = Sample(
        sha256="0" * 64,
        md5="0" * 32,
        sha1="0" * 40,
        file_size=100,
        file_name="test.exe",
        quarantine_path="/tmp/test.exe",
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        profile="standard",
        status=AnalysisStatus.PREFLIGHT.value,
        live_mode=False,
    )
    db_session.add(analysis)
    db_session.commit()

    # Valid transition PREFLIGHT -> PLANNED
    assert safe_update_status(analysis, db_session, AnalysisStatus.PLANNED) is True
    assert analysis.status == AnalysisStatus.PLANNED.value

    # Invalid direct transition PLANNED -> REPORTING (skipping steps) raises ValueError
    with pytest.raises(ValueError):
        safe_update_status(analysis, db_session, AnalysisStatus.REPORTING)
    assert analysis.status == AnalysisStatus.PLANNED.value

    # Transition to FAILED (terminal)
    analysis.error_message = "test error"
    assert safe_update_status(analysis, db_session, AnalysisStatus.FAILED) is True
    assert analysis.status == AnalysisStatus.FAILED.value

    # Attempt transition from terminal state FAILED -> RUNNING must return False
    assert safe_update_status(analysis, db_session, AnalysisStatus.RUNNING) is False
    assert analysis.status == AnalysisStatus.FAILED.value


def test_job_queue_recover_stale_jobs(db_session):
    """Stale running/in-progress jobs on restart must be transitioned to FAILED."""
    sample = Sample(
        sha256="1" * 64,
        md5="1" * 32,
        sha1="1" * 40,
        file_size=200,
        file_name="stale.exe",
        quarantine_path="/tmp/stale.exe",
    )
    db_session.add(sample)
    db_session.commit()

    stale_analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        profile="standard",
        status=AnalysisStatus.RUNNING.value,
        live_mode=False,
    )
    completed_analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        profile="standard",
        status=AnalysisStatus.COMPLETED.value,
        live_mode=False,
    )
    db_session.add_all([stale_analysis, completed_analysis])
    db_session.commit()

    # Run recovery
    job_queue_manager.recover_stale_jobs(db_session)

    db_session.refresh(stale_analysis)
    db_session.refresh(completed_analysis)

    assert stale_analysis.status == AnalysisStatus.FAILED.value
    assert "interrupted by process shutdown or worker restart" in stale_analysis.error_message
    # Terminal completed state remains unchanged
    assert completed_analysis.status == AnalysisStatus.COMPLETED.value


def test_cancellation_flow(client, db_session):
    """Ensure cancellation request updates status and aborts in-progress tasks."""
    res_sample = client.post("/api/v1/samples", files={"file": ("cancel_test.exe", io.BytesIO(b"MZ_CANCEL"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "profile": "standard",
        "live_mode": False,
        "timeout_seconds": 60,
    }
    res = client.post("/api/v1/analyses", json=payload)
    analysis_id = res.json()["id"]

    # Cancel the analysis
    cancel_res = client.post(f"/api/v1/analyses/{analysis_id}/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == AnalysisStatus.CANCELLED.value

    # Status in database should be CANCELLED
    status_res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert status_res.json()["status"] == AnalysisStatus.CANCELLED.value


def test_cape_polling_lifecycle_mocked(monkeypatch):
    """CAPE polling loop properly handles queued -> running -> reported, and collects results."""
    cape = CapeSandboxBackend(api_url="http://127.0.0.1:8008")

    call_count = {"count": 0}

    def mock_get(endpoint, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        if "cuckoo/status" in endpoint:
            mock_resp.json.return_value = {"data": {"version": "2.2", "tasks": {}}}
        elif "tasks/view" in endpoint:
            call_count["count"] += 1
            if call_count["count"] == 1:
                mock_resp.json.return_value = {"data": {"task": {"status": "pending"}}}
            elif call_count["count"] == 2:
                mock_resp.json.return_value = {"data": {"task": {"status": "running"}}}
            else:
                mock_resp.json.return_value = {"data": {"task": {"status": "reported"}}}
        elif "tasks/get/report" in endpoint:
            mock_resp.json.return_value = {
                "info": {"id": 1, "duration": 30},
                "behavior": {"processes": [], "generic": []},
                "network": {},
            }
        return mock_resp

    with patch("httpx.Client.get", side_effect=mock_get):
        status1 = cape.get_task_status("123")
        assert status1["status"] == "queued"

        status2 = cape.get_task_status("123")
        assert status2["status"] == "running"

        status3 = cape.get_task_status("123")
        assert status3["status"] == "completed"

        report = cape.collect_results("123")
        assert "metadata" in report
        assert report["metadata"]["cape_id"] == 1


def test_operator_token_fail_closed_when_empty(client, monkeypatch):
    """When OPERATOR_TOKEN is empty string (default), live mode is blocked (fail-closed HTTP 403)."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "")

    res_sample = client.post("/api/v1/samples", files={"file": ("op_test.exe", io.BytesIO(b"MZ_OP_TEST"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }
    # Even if client passes a token, server must fail closed if OPERATOR_TOKEN is empty
    res = client.post("/api/v1/analyses", json=payload, headers={"X-Operator-Token": "some_token"})
    assert res.status_code == 403
    assert "Live detonation is blocked: Server operator security token is unconfigured" in res.json()["detail"]


def test_operator_token_auth_flow(client, monkeypatch):
    """When OPERATOR_TOKEN is configured, verify 401 on missing/wrong token and 200 on valid token."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "valid-super-secret-token-12345")

    res_sample = client.post("/api/v1/samples", files={"file": ("op_auth.exe", io.BytesIO(b"MZ_OP_AUTH"))})
    sample_id = res_sample.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "cape",
        "live_mode": True,
        "approved_by_user": True,
        "timeout_seconds": 60,
    }

    # Missing header -> 401
    res_missing = client.post("/api/v1/analyses", json=payload)
    assert res_missing.status_code == 401

    # Wrong header -> 401
    res_wrong = client.post("/api/v1/analyses", json=payload, headers={"X-Operator-Token": "wrong-token"})
    assert res_wrong.status_code == 401

    # Valid header -> 201 (created)
    res_valid = client.post("/api/v1/analyses", json=payload, headers={"X-Operator-Token": "valid-super-secret-token-12345"})
    assert res_valid.status_code == 201


def test_replay_scenario_validation_strict(client):
    """Replay scenario validation rejects path traversal and unknown scenario IDs."""
    res_sample = client.post("/api/v1/samples", files={"file": ("scen_test.exe", io.BytesIO(b"MZ_SCEN_TEST"))})
    sample_id = res_sample.json()["id"]

    # 1. Path traversal rejected
    payload_traversal = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "live_mode": False,
        "replay_scenario_id": "../../etc/passwd",
        "timeout_seconds": 60,
    }
    res_trav = client.post("/api/v1/analyses", json=payload_traversal)
    assert res_trav.status_code == 400
    assert "path traversal" in res_trav.json()["detail"]

    # 2. Unknown scenario ID rejected
    payload_unknown = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "live_mode": False,
        "replay_scenario_id": "malicious_unregistered_scenario",
        "timeout_seconds": 60,
    }
    res_unk = client.post("/api/v1/analyses", json=payload_unknown)
    assert res_unk.status_code == 400
    assert "Unknown replay scenario identifier" in res_unk.json()["detail"]

    # 3. Registered scenario accepted
    payload_valid = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "live_mode": False,
        "replay_scenario_id": "ransomware_wannacry_mock",
        "timeout_seconds": 60,
    }
    res_ok = client.post("/api/v1/analyses", json=payload_valid)
    assert res_ok.status_code == 201
    assert res_ok.json()["replay_scenario_id"] == "ransomware_wannacry_mock"


def test_live_analysis_cancellation_requires_operator_token(client, db_session, monkeypatch):
    """Cancelling a live analysis requires a valid operator token."""
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "cancel-secret-token")

    res_sample = client.post("/api/v1/samples", files={"file": ("cancel_live.exe", io.BytesIO(b"MZ_LIVE_CANCEL"))})
    sample_id = res_sample.json()["id"]

    # Insert a live analysis directly
    live_analysis = Analysis(
        sample_id=sample_id,
        backend_type=SandboxBackendType.CAPE.value,
        status=AnalysisStatus.RUNNING.value,
        live_mode=True,
        approved_by_user=True,
    )
    db_session.add(live_analysis)
    db_session.commit()

    # Cancel without token -> 401
    res_no_tok = client.post(f"/api/v1/analyses/{live_analysis.id}/cancel")
    assert res_no_tok.status_code == 401

    # Cancel with valid token -> 200
    res_auth = client.post(
        f"/api/v1/analyses/{live_analysis.id}/cancel",
        headers={"X-Operator-Token": "cancel-secret-token"}
    )
    assert res_auth.status_code == 200
    assert res_auth.json()["status"] == AnalysisStatus.CANCELLED.value

