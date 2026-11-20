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
    """Orphaned jobs in non-terminal states are recovered safely upon worker restart."""
    sample = _create_sample(db_session)

    # Create stale jobs in intermediate states
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
    db_session.add_all([job1, job2])
    db_session.commit()

    recovered = job_queue_manager.recover_stale_jobs(db_session)
    assert recovered >= 2

    db_session.refresh(job1)
    db_session.refresh(job2)

    assert job1.status == AnalysisStatus.FAILED.value
    assert job1.error_message == "Analysis interrupted by process shutdown or worker restart; static triage preserved."
    assert job1.completed_at is not None

    assert job2.status == AnalysisStatus.FAILED.value
    assert job2.error_message == "Analysis interrupted by process shutdown or worker restart; static triage preserved."
    assert job2.completed_at is not None


def test_retry_nonexistent_analysis_returns_404(client):
    """POST /analyses/{id}/retry returns 404 if analysis ID does not exist."""
    res = client.post(f"/api/v1/analyses/{uuid.uuid4()}/retry")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_retry_active_or_completed_analysis_returns_400(client, db_session):
    """Retrying an analysis that is COMPLETED returns 400 Bad Request."""
    sample = _create_sample(db_session)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
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
    sample = _create_sample(db_session)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
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


def test_retry_live_mode_requires_valid_operator_token(client, db_session, monkeypatch):
    """Retrying a live mode analysis requires valid X-Operator-Token."""
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "secure-op-token-999")
    sample = _create_sample(db_session)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
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

    # 3. With correct token -> 200
    res_ok = client.post(
        f"/api/v1/analyses/{analysis.id}/retry",
        headers={"X-Operator-Token": "secure-op-token-999"},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["status"] == AnalysisStatus.QUEUED.value
