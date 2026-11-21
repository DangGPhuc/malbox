import io
import uuid
import pytest
from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.models.sample import Sample
from app.workers.job_queue import job_queue_manager


def _create_sample(db_session):
    s = Sample(
        id=str(uuid.uuid4()),
        file_name="recovery_test.exe",
        file_size=1024,
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        sha1=uuid.uuid4().hex[:40],
        md5=uuid.uuid4().hex[:32],
        mime_type="application/x-dosexec",
        is_pe=True,
        quarantine_path="/tmp/fake_quarantine.bin",
    )
    db_session.add(s)
    db_session.commit()
    return s


def test_orphaned_job_recovery_marks_failed_with_audit_message(db_session):
    """Orphaned jobs in non-terminal states are recovered safely, distinguishing queued from active."""
    sample = _create_sample(db_session)

    # 1. Active jobs interrupted mid-execution
    job1 = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        status=AnalysisStatus.RUNNING.value,
        backend_type="replay",
        live_mode=False,
    )
    job2 = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        status=AnalysisStatus.COLLECTING.value,
        backend_type="replay",
        live_mode=False,
    )
    # 2. Never-started queued job
    job3 = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        status=AnalysisStatus.QUEUED.value,
        backend_type="replay",
        live_mode=False,
        started_at=None,
    )
    db_session.add_all([job1, job2, job3])
    db_session.commit()

    recovered = job_queue_manager.recover_stale_jobs(db_session)
    assert recovered >= 3

    db_session.refresh(job1)
    db_session.refresh(job2)
    db_session.refresh(job3)

    assert job1.status == AnalysisStatus.FAILED.value
    assert "interrupted during active stage 'RUNNING'" in job1.error_message
    assert job1.completed_at is not None

    assert job2.status == AnalysisStatus.FAILED.value
    assert "interrupted during active stage 'COLLECTING'" in job2.error_message
    assert job2.completed_at is not None

    assert job3.status == AnalysisStatus.FAILED.value
    assert "never started: abandoned in QUEUED state" in job3.error_message
    assert job3.completed_at is not None


def _upload_sample(client):
    sample_bytes = b"MZ" + b"\x90" * 128 + uuid.uuid4().hex.encode("ascii")
    res_up = client.post(
        "/api/v1/samples",
        files={"file": ("retry_test.exe", io.BytesIO(sample_bytes), "application/octet-stream")},
    )
    assert res_up.status_code == 201
    return res_up.json()


def test_retry_nonexistent_analysis_returns_404(client):
    """POST /analyses/{id}/retry returns 404 if analysis ID does not exist."""
    res = client.post(f"/api/v1/analyses/{uuid.uuid4()}/retry")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_retry_active_or_completed_analysis_returns_400(client, db_session):
    """Retrying an analysis that is COMPLETED returns 400 Bad Request."""
    sample = _upload_sample(client)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample["id"],
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        live_mode=False,
    )
    db_session.add(analysis)
    db_session.commit()

    res = client.post(f"/api/v1/analyses/{analysis.id}/retry")
    assert res.status_code == 400
    assert "Cannot retry analysis in status 'COMPLETED'" in res.json()["detail"]


def test_retry_failed_analysis_resets_status(client, db_session):
    """Retrying a failed analysis resets status to QUEUED and clears transient error message."""
    sample = _upload_sample(client)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample["id"],
        status=AnalysisStatus.FAILED.value,
        error_message="Previous transient error",
        backend_type="replay",
        live_mode=False,
    )
    db_session.add(analysis)
    db_session.commit()

    # Retry without run_sync (asynchronous queue mode)
    res = client.post(f"/api/v1/analyses/{analysis.id}/retry")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == AnalysisStatus.QUEUED.value
    assert data["error_message"] is None


def test_retry_live_mode_requires_valid_operator_token(client, db_session, monkeypatch, tmp_path):
    """Retrying a live mode analysis requires valid X-Operator-Token and verified confinement."""
    from app.services.sandbox.confinement import create_isolation_attestation, STANDARD_VALID_ASSERTIONS
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "secure-op-token-999")

    # Set up valid isolation attestation
    att_file = tmp_path / "retry_att.json"
    create_isolation_attestation(
        verified_machine="win10_analyst",
        verified_route="drop",
        attestation_path=att_file,
        operator_assertions=STANDARD_VALID_ASSERTIONS,
        evidence_references=["iptables:drop_rules", "pcap:zero_egress"],
    )
    monkeypatch.setattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", str(att_file))
    monkeypatch.setattr(settings, "CAPE_DEFAULT_MACHINE", "win10_analyst")
    monkeypatch.setattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", "drop")

    sample = _upload_sample(client)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample["id"],
        status=AnalysisStatus.FAILED.value,
        backend_type="cape",
        live_mode=True,
    )
    db_session.add(analysis)
    db_session.commit()

    # 1. Without token -> 401
    res_no_tok = client.post(f"/api/v1/analyses/{analysis.id}/retry")
    assert res_no_tok.status_code == 401

    # 2. With wrong token -> 401
    res_bad_tok = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "wrong-token"},
    )
    assert res_bad_tok.status_code == 401

    # 3. With correct token but unverified confinement -> 412
    monkeypatch.setattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", str(tmp_path / "nonexistent.json"))
    res_unconf = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "secure-op-token-999"},
    )
    assert res_unconf.status_code == 412
    assert "confinement" in res_unconf.json()["detail"].lower()

    # 4. With correct token and verified confinement -> 200
    monkeypatch.setattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", str(att_file))
    res_ok = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "secure-op-token-999"},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["status"] == AnalysisStatus.QUEUED.value


def test_retry_live_reconciles_remote_cape_task(client, db_session, monkeypatch, tmp_path):
    """Retrying live analysis reconciles existing remote CAPE task state, preventing duplicates."""
    from app.services.sandbox.confinement import create_isolation_attestation, STANDARD_VALID_ASSERTIONS
    from app.services.sandbox.cape import cape_adapter

    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "secure-op-token-999")
    att_file = tmp_path / "retry_att.json"
    create_isolation_attestation(
        verified_machine="win10_analyst",
        verified_route="drop",
        attestation_path=att_file,
        operator_assertions=STANDARD_VALID_ASSERTIONS,
        evidence_references=["iptables:drop_rules", "pcap:zero_egress"],
    )
    monkeypatch.setattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", str(att_file))
    monkeypatch.setattr(settings, "CAPE_DEFAULT_MACHINE", "win10_analyst")
    monkeypatch.setattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", "drop")

    sample = _upload_sample(client)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample["id"],
        status=AnalysisStatus.FAILED.value,
        backend_type="cape",
        live_mode=True,
        external_task_id="cape_task_444",
    )
    db_session.add(analysis)
    db_session.commit()

    # Case A: Remote task is actively running -> 409 Conflict
    monkeypatch.setattr(cape_adapter, "get_task_status", lambda tid: {"status": "ok", "cape_status": "running"})
    res_running = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "secure-op-token-999"},
    )
    assert res_running.status_code == 409
    assert "still active" in res_running.json()["detail"].lower()

    # Case B: Remote task was completed/reported/failed -> 200 QUEUED with cleared external_task_id
    monkeypatch.setattr(cape_adapter, "get_task_status", lambda tid: {"status": "ok", "cape_status": "completed"})
    res_ok = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "secure-op-token-999"},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["status"] == AnalysisStatus.QUEUED.value

    db_session.refresh(analysis)
    assert analysis.external_task_id is None
    assert analysis.sample_id == sample["id"]  # Sample identity strictly preserved
