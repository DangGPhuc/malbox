import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.sandbox.cape import CapeSandboxBackend
from app.services.sandbox.readiness import check_system_readiness
from app.services.sandbox.confinement import (
    create_isolation_attestation,
    verify_cape_confinement,
    get_attestation_path,
)
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.workers.pipeline_worker import PipelineWorker

client = TestClient(app)


def test_missing_machine_metadata_fails_closed(monkeypatch, tmp_path):
    """Missing CAPE machines information must NOT imply guest readiness (fails closed)."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0",
                    # 'machines' key explicitly omitted
                    "tasks": {"total": 10}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponse())
    att_file = tmp_path / "test_att.json"
    create_isolation_attestation("*", "drop", attestation_path=att_file)
    monkeypatch.setattr("app.services.sandbox.confinement.get_attestation_path", lambda: att_file)

    res = backend.check_readiness()
    assert res["ready"] is False
    assert res["status"] == "missing_machine_metadata"
    assert res["guest_vm_ready"] is False
    assert "machine metadata" in res["error"]


def test_zero_available_guests_fails_closed(monkeypatch, tmp_path):
    """When CAPE reports 0 total or 0 available guests, readiness must fail closed."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResponseZeroTotal:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0",
                    "machines": {"total": 0, "available": 0},
                    "tasks": {"total": 0}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponseZeroTotal())
    att_file = tmp_path / "test_att.json"
    create_isolation_attestation("*", "drop", attestation_path=att_file)
    monkeypatch.setattr("app.services.sandbox.confinement.get_attestation_path", lambda: att_file)

    r1 = backend.check_readiness()
    assert r1["ready"] is False
    assert r1["status"] == "no_guests_configured"
    assert r1["guest_vm_ready"] is False

    class MockResponseZeroAvail:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0",
                    "machines": {"total": 3, "available": 0},
                    "tasks": {"total": 5}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponseZeroAvail())
    r2 = backend.check_readiness()
    assert r2["ready"] is False
    assert r2["status"] == "no_guests_available"
    assert r2["guest_vm_ready"] is False


def test_missing_isolation_evidence_fails_closed(monkeypatch, tmp_path):
    """When isolation attestation file is missing, readiness must fail closed even if CAPE API is 200 OK."""
    backend = CapeSandboxBackend(api_url="http://mock-cape.local")

    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0",
                    "machines": {"total": 2, "available": 2},
                    "tasks": {"total": 5}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponse())
    non_existent = tmp_path / "does_not_exist.json"
    monkeypatch.setattr("app.services.sandbox.confinement.get_attestation_path", lambda: non_existent)

    res = backend.check_readiness()
    assert res["ready"] is False
    assert res["status"] == "unverified_confinement"
    assert res["confinement_verified"] is False
    assert res["confinement_status"] == "missing_isolation_evidence"


def test_mismatched_guest_and_route_fails_closed(monkeypatch, tmp_path):
    """Attestation for machine 'win10_clean' must reject submission targeting 'win7_legacy'."""
    att_file = tmp_path / "att_mismatch.json"
    create_isolation_attestation(
        verified_machine="win10_clean",
        verified_route="drop",
        attestation_path=att_file,
    )

    # 1. Matching machine succeeds
    m_ok = verify_cape_confinement(target_machine="win10_clean", target_route="drop", attestation_path=att_file)
    assert m_ok.is_verified is True

    # 2. Mismatched machine fails
    m_fail = verify_cape_confinement(target_machine="win7_legacy", target_route="drop", attestation_path=att_file)
    assert m_fail.is_verified is False
    assert m_fail.status == "machine_mismatch"
    assert "does not match attested machine" in m_fail.error

    # 3. Mismatched route fails
    r_fail = verify_cape_confinement(target_machine="win10_clean", target_route="none", attestation_path=att_file)
    assert r_fail.is_verified is False
    assert r_fail.status == "route_mismatch"

    # 4. Unconfined internet route fails creation
    with pytest.raises(ValueError, match="Cannot attest unconfined route"):
        create_isolation_attestation(verified_machine="win10", verified_route="internet", attestation_path=tmp_path / "bad.json")


def test_expired_stale_readiness_evidence_fails_closed(tmp_path):
    """An expired attestation timestamp must be rejected as stale readiness evidence."""
    att_file = tmp_path / "expired_att.json"
    create_isolation_attestation(
        verified_machine="*",
        verified_route="drop",
        validity_seconds=1,
        attestation_path=att_file,
    )

    # Manually backdate expiration to ensure it is in the past
    import json
    data = json.loads(att_file.read_text(encoding="utf-8"))
    data["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    att_file.write_text(json.dumps(data), encoding="utf-8")

    res = verify_cape_confinement(target_machine="cape1", target_route="drop", attestation_path=att_file)
    assert res.is_verified is False
    assert res.status == "expired_attestation"
    assert "stale readiness evidence" in res.error


def test_api_healthy_but_execution_unsafe(monkeypatch, tmp_path):
    """Distinguishes between API healthy and actual execution safety."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "a" * 32)
    monkeypatch.setattr(settings, "CAPE_API_URL", "http://mock-cape.local")

    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "error": False,
                "data": {
                    "version": "2.4.0",
                    "machines": {"total": 5, "available": 5},
                    "tasks": {"total": 100}
                }
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: MockResponse())

    # Case A: Attestation missing -> healthy API but execution unsafe
    missing_file = tmp_path / "missing.json"
    monkeypatch.setattr("app.services.sandbox.confinement.get_attestation_path", lambda: missing_file)

    readiness = check_system_readiness(check_cape=True)
    assert readiness["cape_reachable"] is True
    assert readiness["cape_authenticated"] is True
    assert readiness["guest_vm_ready"] is True
    assert readiness["network_isolation_verified"] is False
    assert readiness["ready_for_analysis"] is False
    assert readiness["status"] == "unverified_confinement"

    # Case B: Attestation verified -> execution safe
    valid_file = tmp_path / "valid.json"
    create_isolation_attestation("*", "drop", attestation_path=valid_file)
    monkeypatch.setattr("app.services.sandbox.confinement.get_attestation_path", lambda: valid_file)

    readiness_ok = check_system_readiness(check_cape=True)
    assert readiness_ok["network_isolation_verified"] is True
    assert readiness_ok["ready_for_analysis"] is True
    assert readiness_ok["status"] == "ready"


def test_pipeline_worker_blocks_execution_when_confinement_unverified(db_session, monkeypatch, tmp_path):
    """PipelineWorker must reject detonation and transition to FAILED when confinement is unverified."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)

    import hashlib
    raw_bytes = b"MZ" + b"\x00" * 1022
    exe_path = tmp_path / "suspicious.exe"
    exe_path.write_bytes(raw_bytes)
    sha_val = hashlib.sha256(raw_bytes).hexdigest()

    sample = Sample(
        file_name="suspicious.exe",
        file_size=len(raw_bytes),
        sha256=sha_val,
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        md5=hashlib.md5(raw_bytes).hexdigest(),
        is_pe=True,
        quarantine_path=str(exe_path),
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.CAPE.value,
        status=AnalysisStatus.QUEUED.value,
        profile="standard",
        live_mode=True,
        approved_by_user=True,
    )
    db_session.add(analysis)
    db_session.commit()

    # Mock CAPE with reachable API but missing confinement
    class MockUnconfinedCape:
        def check_readiness(self, *args, **kwargs):
            return {
                "ready": False,
                "confinement_verified": False,
                "error": "Guest network isolation attestation missing.",
            }

    monkeypatch.setattr("app.services.sandbox.cape.CapeSandboxBackend", MockUnconfinedCape)

    worker = PipelineWorker(db_session)
    result = worker.execute_pipeline(analysis.id)

    assert result.status == AnalysisStatus.FAILED.value
    assert "confinement or readiness check failed" in (result.error_message or "")
    # Triage report preserved safely
    assert result.report is not None


def test_public_health_endpoints_never_leak_secrets(monkeypatch, tmp_path):
    """Health endpoints (/api/v1/health and /api/v1/readiness) must never expose operator tokens or API secrets."""
    secret_token = "super-sensitive-operator-secret-token-12345"
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", secret_token)
    monkeypatch.setattr(settings, "CAPE_API_TOKEN", "cape-internal-secret-token-999")

    # 1. /api/v1/health
    r_health = client.get("/api/v1/health")
    assert r_health.status_code == 200
    health_text = r_health.text
    assert secret_token not in health_text
    assert "cape-internal-secret-token-999" not in health_text

    # 2. /api/v1/readiness
    r_ready = client.get("/api/v1/readiness")
    assert r_ready.status_code == 200
    ready_text = r_ready.text
    assert secret_token not in ready_text
    assert "cape-internal-secret-token-999" not in ready_text
