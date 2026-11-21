import time
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.services.static_analysis.worker import StaticAnalysisWorkerManager
from app.workers.pipeline_worker import PipelineWorker


def test_mocked_ghidra_worker_refusing_cancellation_blocks_cape(db_session, monkeypatch, tmp_path):
    """
    If a Ghidra static analysis job times out and refuses immediate cancellation
    (process remains active), CAPE MUST NOT BE DISPATCHED to protect host resources
    and maintain strict execution isolation.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_HOME", "/dummy/ghidra")
    monkeypatch.setattr(settings, "GHIDRA_TIMEOUT_SECONDS", 0.05)

    import hashlib
    raw_bytes = b"MZ" + b"\x00" * 2046
    q_file = tmp_path / "heavy_sample.exe"
    q_file.write_bytes(raw_bytes)
    sha_val = hashlib.sha256(raw_bytes).hexdigest()

    sample = Sample(
        file_name="heavy_sample.exe",
        file_size=len(raw_bytes),
        sha256=sha_val,
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        md5=hashlib.md5(raw_bytes).hexdigest(),
        is_pe=True,
        quarantine_path=str(q_file),
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.CAPE.value,
        status=AnalysisStatus.QUEUED.value,
        profile="standard",
        timeout_seconds=60,
        live_mode=True,
        approved_by_user=True,
    )
    db_session.add(analysis)
    db_session.commit()

    cape_dispatched = False

    class MockCapeSandbox:
        def check_readiness(self, *args, **kwargs):
            return {"ready": True, "confinement_verified": True}

        def submit_sample(self, *args, **kwargs):
            nonlocal cape_dispatched
            cape_dispatched = True
            return "cape_task_123"

    monkeypatch.setattr("app.services.sandbox.cape.CapeSandboxBackend", MockCapeSandbox)

    # Stub worker manager to simulate a stubborn process that remains active
    from concurrent.futures import Future

    stub_future = Future()
    stub_future.cancel = MagicMock(return_value=False)

    class StubWorkerManager:
        def __init__(self):
            self._active_future = stub_future
            self._process_active = True

        def submit_job(self, db, sample, analysis_id):
            now_dt = datetime.now(timezone.utc)
            rec = StaticAnalysisRecord(
                sample_id=sample.id,
                analysis_id=analysis_id,
                sample_sha256=sample.sha256,
                status="RUNNING",
                created_at=now_dt,
            )
            db.add(rec)
            db.commit()
            return rec

        def cancel_active(self, wait_seconds=2.0):
            # Stubbornly refuses to terminate
            self._process_active = True
            return False

        def wait_for_completion(self, timeout=5.0):
            # Stubbornly reports still running
            return False

        def is_process_active(self):
            return True

    stub_mgr = StubWorkerManager()
    monkeypatch.setattr("app.services.static_analysis.worker.static_worker_manager", stub_mgr)

    worker = PipelineWorker(db_session)
    result = worker.execute_pipeline(analysis.id)

    # Must transition to FAILED without dispatching CAPE!
    assert result.status == AnalysisStatus.FAILED.value
    assert "background worker process remained active" in (result.error_message or "")
    assert cape_dispatched is False


def test_ghidra_timeout_records_timed_out_status_accurately(db_session, monkeypatch, tmp_path):
    """When Ghidra times out and cancels cleanly, the static analysis record must be marked TIMED_OUT."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_HOME", "/dummy/ghidra")
    monkeypatch.setattr(settings, "GHIDRA_TIMEOUT_SECONDS", 0.05)

    import hashlib
    raw_bytes = b"MZ" + b"\x00" * 1022
    q_file = tmp_path / "timeout_sample.exe"
    q_file.write_bytes(raw_bytes)
    sha_val = hashlib.sha256(raw_bytes).hexdigest()

    sample = Sample(
        file_name="timeout_sample.exe",
        file_size=len(raw_bytes),
        sha256=sha_val,
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        md5=hashlib.md5(raw_bytes).hexdigest(),
        is_pe=True,
        quarantine_path=str(q_file),
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.CAPE.value,
        status=AnalysisStatus.QUEUED.value,
        profile="standard",
        timeout_seconds=60,
        live_mode=True,
        approved_by_user=True,
    )
    db_session.add(analysis)
    db_session.commit()

    from concurrent.futures import Future
    stub_future = Future()  # never completed -> TimeoutError

    class CleanCancelWorkerManager:
        def __init__(self):
            self._active_future = stub_future
            self.job_id = None

        def submit_job(self, db, sample, analysis_id):
            now_dt = datetime.now(timezone.utc)
            rec = StaticAnalysisRecord(
                sample_id=sample.id,
                analysis_id=analysis_id,
                sample_sha256=sample.sha256,
                status="RUNNING",
                created_at=now_dt,
            )
            db.add(rec)
            db.commit()
            self.job_id = rec.id
            return rec

        def cancel_active(self, wait_seconds=2.0):
            return True

        def wait_for_completion(self, timeout=5.0):
            return True

        def is_process_active(self):
            return False

    clean_mgr = CleanCancelWorkerManager()
    monkeypatch.setattr("app.services.static_analysis.worker.static_worker_manager", clean_mgr)

    # CAPE returns quickly
    class MockCapeSandbox:
        def check_readiness(self, *args, **kwargs):
            return {"ready": True, "confinement_verified": True}

        def submit_sample(self, *args, **kwargs):
            return "cape_task_clean"

        def get_task_status(self, *args, **kwargs):
            return {"status": "reported", "is_ready_for_report": True}

        def collect_results(self, *args, **kwargs):
            return {"telemetry_completeness": "COMPLETE", "metadata": {}}

        def generate_artifacts(self, *args, **kwargs):
            return []

    monkeypatch.setattr("app.services.sandbox.cape.CapeSandboxBackend", MockCapeSandbox)
    from app.services.sandbox.confinement import create_isolation_attestation, STANDARD_VALID_ASSERTIONS
    create_isolation_attestation(
        "win10_analyst",
        "drop",
        operator_assertions=STANDARD_VALID_ASSERTIONS,
        evidence_references=["iptables:drop_rules", "pcap:zero_egress"],
    )

    worker = PipelineWorker(db_session)
    result = worker.execute_pipeline(analysis.id)

    # Static record must be marked TIMED_OUT
    static_rec = db_session.query(StaticAnalysisRecord).filter(
        StaticAnalysisRecord.id == clean_mgr.job_id
    ).first()
    assert static_rec is not None
    assert static_rec.status == "TIMED_OUT"
    assert "timeout" in static_rec.error_message.lower()


def test_correlation_failure_does_not_break_pipeline(db_session, monkeypatch, tmp_path):
    """Evidence correlation exceptions are caught, logged, and appended as notes without failing the pipeline."""
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)

    import hashlib
    raw_bytes = b"MZ" + b"\x00" * 1022
    q_file = tmp_path / "correl_sample.exe"
    q_file.write_bytes(raw_bytes)
    sha_val = hashlib.sha256(raw_bytes).hexdigest()

    sample = Sample(
        file_name="correl_sample.exe",
        file_size=len(raw_bytes),
        sha256=sha_val,
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        md5=hashlib.md5(raw_bytes).hexdigest(),
        is_pe=True,
        quarantine_path=str(q_file),
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.CAPE.value,
        status=AnalysisStatus.QUEUED.value,
        profile="standard",
        timeout_seconds=60,
        live_mode=True,
        approved_by_user=True,
    )
    db_session.add(analysis)
    db_session.commit()

    class MockCapeSandbox:
        def check_readiness(self, *args, **kwargs):
            return {"ready": True, "confinement_verified": True}

        def submit_sample(self, *args, **kwargs):
            return "cape_task_correl"

        def get_task_status(self, *args, **kwargs):
            return {"status": "reported", "is_ready_for_report": True}

        def collect_results(self, *args, **kwargs):
            return {"telemetry_completeness": "COMPLETE", "metadata": {}}

        def generate_artifacts(self, *args, **kwargs):
            return []

    monkeypatch.setattr("app.services.sandbox.cape.CapeSandboxBackend", MockCapeSandbox)
    from app.services.sandbox.confinement import create_isolation_attestation, STANDARD_VALID_ASSERTIONS
    create_isolation_attestation(
        "win10_analyst",
        "drop",
        operator_assertions=STANDARD_VALID_ASSERTIONS,
        evidence_references=["iptables:drop_rules", "pcap:zero_egress"],
    )

    # Mock correlation service to throw an error
    class BrokenCorrelationService:
        def __init__(self, db):
            pass
        def compute_and_persist(self, *args, **kwargs):
            raise RuntimeError("Database locked during correlation calculation")

    monkeypatch.setattr("app.services.evidence_correlation.service.EvidenceCorrelationService", BrokenCorrelationService)

    worker = PipelineWorker(db_session)
    result = worker.execute_pipeline(analysis.id)

    assert result.status == AnalysisStatus.COMPLETED.value
    assert result.report is not None
    # Environment notes must capture the correlation warning
    report_json = result.report.full_report_json or {}
    notes = report_json.get("analysis_environment", {}).get("telemetry_notes", []) or report_json.get("confidence_and_limitations", {}).get("telemetry_notes", [])
    assert any("Correlation computation warning" in n or "Correlation computation failed" in n or "Correlation computation note" in n for n in notes)
