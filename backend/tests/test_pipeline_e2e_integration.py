import io
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import httpx

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.workers.pipeline_worker import PipelineWorker
from app.services.sandbox.confinement import create_isolation_attestation


@pytest.fixture(autouse=True)
def setup_test_isolation_attestation(tmp_path, monkeypatch):
    att_file = tmp_path / "test_attestation.json"
    monkeypatch.setattr(settings, "CAPE_ISOLATION_ATTESTATION_PATH", str(att_file))
    create_isolation_attestation(
        verified_machine="win10_analyst",
        verified_route="drop",
        attestation_path=att_file,
    )
    yield


def create_test_pe_sample(db_session, tmp_path, name="sample.exe") -> Sample:
    """Helper to create and persist a valid test PE sample."""
    import hashlib
    content = b"MZ" + b"\x90" * 100 + b"TEST_PAYLOAD"
    sha = hashlib.sha256(content).hexdigest()
    fpath = tmp_path / name
    fpath.write_bytes(content)

    sample = Sample(
        sha256=sha,
        md5=hashlib.md5(content).hexdigest(),
        sha1=hashlib.sha1(content).hexdigest(),
        file_name=name,
        file_size=len(content),
        quarantine_path=str(fpath),
        is_pe=True,
        pe_metadata={"is_valid_pe": True, "subsystem": "WINDOWS_GUI"},
    )
    db_session.add(sample)
    db_session.commit()
    db_session.refresh(sample)
    return sample


def test_pipeline_strict_stage_ordering_and_upstream_evidence_in_report(db_session, monkeypatch, tmp_path):
    """
    Verifies that PipelineWorker executes stages strictly in sequential order:
    Intake -> Triage/Plan -> Ghidra -> CAPE -> Normalize -> Detection -> Correlation -> Classification -> Report.
    Also verifies that correlation and classification findings are available in the final intelligence report.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", False)  # Records UNAVAILABLE cleanly

    sample = create_test_pe_sample(db_session, tmp_path, "pipeline_order_sample.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=30,
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()
    db_session.refresh(analysis)

    execution_order = []

    # 1. Spy Triage/Planner
    from app.services.orchestration.planner import AnalysisPlanner
    orig_plan = AnalysisPlanner.create_and_validate_plan
    def mock_plan(self, a):
        execution_order.append("triage")
        return orig_plan(self, a)
    monkeypatch.setattr(AnalysisPlanner, "create_and_validate_plan", mock_plan)

    # 2. Mock CAPE backend methods
    from app.services.sandbox.cape import CapeSandboxBackend
    def mock_check_readiness(self, timeout=2.0):
        return {"ready": True, "confinement_verified": True, "error": None}

    def mock_submit_sample(self, sample_path, profile="standard", timeout_seconds=120, options=None):
        execution_order.append("cape_submit")
        return "9001"

    def mock_get_task_status(self, backend_task_id):
        return {"status": "reported", "is_ready_for_report": True}

    def mock_collect_results(self, backend_task_id, expected_sha256=None, max_timeout=60.0, is_cancelled_fn=None):
        execution_order.append("cape_collect")
        return {
            "metadata": {
                "cape_id": 9001,
                "cape_id_verified": True,
                "target_sha256": sample.sha256,
                "target_sha256_verified": True,
                "duration_seconds": 15,
                "environment": {"guest_os": "Windows 10 x64"},
                "telemetry_completeness": "COMPLETE",
                "telemetry_notes": [],
            },
            "telemetry_completeness": "COMPLETE",
            "telemetry_notes": [],
            "processes": [{"pid": 1111, "ppid": 4, "name": "pipeline_order_sample.exe", "command_line": "pipeline_order_sample.exe"}],
            "api_calls": [],
            "filesystem": [{"action": "write", "pid": 1111, "path": "C:\\temp\\out.txt", "size_bytes": 10}],
            "registry": [{"action": "reg_write", "pid": 1111, "key": "HKCU\\Software\\Test", "value_name": "x", "data": "1"}],
            "network": {"dns": [], "connections": [], "http": []},
            "artifacts": [],
        }

    monkeypatch.setattr(CapeSandboxBackend, "check_readiness", mock_check_readiness)
    monkeypatch.setattr(CapeSandboxBackend, "submit_sample", mock_submit_sample)
    monkeypatch.setattr(CapeSandboxBackend, "get_task_status", mock_get_task_status)
    monkeypatch.setattr(CapeSandboxBackend, "collect_results", mock_collect_results)
    monkeypatch.setattr(CapeSandboxBackend, "generate_artifacts", lambda *a, **k: [])

    # 3. Spy Detection Engine
    from app.services.detection.engine import DetectionEngine
    orig_eval = DetectionEngine.evaluate_behavior
    def mock_eval(self, aid, **kwargs):
        execution_order.append("detection")
        return orig_eval(self, aid, **kwargs)
    monkeypatch.setattr(DetectionEngine, "evaluate_behavior", mock_eval)

    # 4. Spy Evidence Correlation Service
    from app.services.evidence_correlation.service import EvidenceCorrelationService
    orig_corr = EvidenceCorrelationService.compute_and_persist
    def mock_corr(self, analysis_id, triggered_automatically=False):
        execution_order.append("correlation")
        return orig_corr(self, analysis_id=analysis_id, triggered_automatically=triggered_automatically)
    monkeypatch.setattr(EvidenceCorrelationService, "compute_and_persist", mock_corr)

    # 5. Spy Malware Classification
    from app.services.classification.engine import MalwareClassificationEngine
    orig_classify = MalwareClassificationEngine.classify
    def mock_classify(self, **kwargs):
        execution_order.append("classification")
        return orig_classify(self, **kwargs)
    monkeypatch.setattr(MalwareClassificationEngine, "classify", mock_classify)

    # 6. Spy Report Generator
    from app.services.reporting.generator import ReportGenerator
    orig_report = ReportGenerator.generate_report
    def mock_report(self, *args, **kwargs):
        execution_order.append("reporting")
        return orig_report(self, *args, **kwargs)
    monkeypatch.setattr(ReportGenerator, "generate_report", mock_report)

    # Execute pipeline
    worker = PipelineWorker(db_session)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.COMPLETED.value
    assert execution_order == [
        "triage",
        "cape_submit",
        "cape_collect",
        "detection",
        "correlation",
        "classification",
        "reporting",
    ]

    # Verify upstream evidence is available to the report
    report_record = res.report
    assert report_record is not None
    rep_json = report_record.full_report_json or {}
    assert "malware_classification" in rep_json
    assert "intelligence_report" in rep_json
    assert "classification_status" in rep_json["malware_classification"]


def test_pipeline_error_path_ghidra_disabled(db_session, monkeypatch, tmp_path):
    """
    When Ghidra is disabled or not configured, PipelineWorker records an UNAVAILABLE
    static analysis record and continues cleanly to dynamic analysis.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", False)

    sample = create_test_pe_sample(db_session, tmp_path, "ghidra_off.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=30,
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()

    from app.services.sandbox.cape import CapeSandboxBackend
    monkeypatch.setattr(CapeSandboxBackend, "check_readiness", lambda self, timeout=2.0: {"ready": True, "confinement_verified": True, "error": None})
    monkeypatch.setattr(CapeSandboxBackend, "submit_sample", lambda *a, **k: "9002")
    monkeypatch.setattr(CapeSandboxBackend, "get_task_status", lambda *a, **k: {"status": "reported", "is_ready_for_report": True})
    monkeypatch.setattr(CapeSandboxBackend, "collect_results", lambda *a, **k: {
        "metadata": {"telemetry_completeness": "COMPLETE", "environment": {}},
        "telemetry_completeness": "COMPLETE",
        "processes": [{"pid": 12, "name": "ghidra_off.exe"}],
        "api_calls": [], "filesystem": [], "registry": [], "network": {"dns": [], "connections": [], "http": []},
        "artifacts": []
    })
    monkeypatch.setattr(CapeSandboxBackend, "generate_artifacts", lambda *a, **k: [])

    worker = PipelineWorker(db_session)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.COMPLETED.value
    static_rec = db_session.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.analysis_id == analysis.id).first()
    assert static_rec is not None
    assert static_rec.status == "UNAVAILABLE"


def test_pipeline_error_path_cape_unavailable(db_session, monkeypatch, tmp_path):
    """
    When CAPE is unreachable or reports not ready, PipelineWorker fails closed,
    sets status to FAILED with descriptive error, and preserves static/triage findings.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)

    sample = create_test_pe_sample(db_session, tmp_path, "cape_down.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=30,
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()

    from app.services.sandbox.cape import CapeSandboxBackend
    monkeypatch.setattr(
        CapeSandboxBackend,
        "check_readiness",
        lambda self, timeout=2.0: {"ready": False, "error": "Connection refused to CAPE API on 127.0.0.1:8000"}
    )

    worker = PipelineWorker(db_session)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.FAILED.value
    assert "Connection refused" in (res.error_message or "")


def test_pipeline_error_path_report_retrieval_failure(db_session, monkeypatch, tmp_path):
    """
    When CAPE submission succeeds but report retrieval fails, PipelineWorker
    transitions to FAILED with a descriptive error.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)

    sample = create_test_pe_sample(db_session, tmp_path, "report_fail.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=30,
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()

    from app.services.sandbox.cape import CapeSandboxBackend
    monkeypatch.setattr(CapeSandboxBackend, "check_readiness", lambda self, timeout=2.0: {"ready": True, "confinement_verified": True, "error": None})
    monkeypatch.setattr(CapeSandboxBackend, "submit_sample", lambda *a, **k: "9003")
    monkeypatch.setattr(CapeSandboxBackend, "get_task_status", lambda *a, **k: {"status": "reported", "is_ready_for_report": True})

    def mock_collect_fail(*a, **k):
        raise RuntimeError("CAPE report endpoint returned HTTP 500: Database lock failed")

    monkeypatch.setattr(CapeSandboxBackend, "collect_results", mock_collect_fail)

    worker = PipelineWorker(db_session)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.FAILED.value
    assert "Database lock failed" in (res.error_message or "")


def test_pipeline_error_path_deadline_timeout(db_session, monkeypatch, tmp_path):
    """
    When the overall monotonic deadline expires before the sandbox task completes,
    PipelineWorker cancels the task and transitions to TIMED_OUT.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)
    monkeypatch.setattr(settings, "CAPE_POLL_INTERVAL_SECONDS", 0.01)

    sample = create_test_pe_sample(db_session, tmp_path, "timeout_sample.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=0.05,  # Very short deadline
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()

    cancelled_tasks = []
    from app.services.orchestration.planner import AnalysisPlanner
    from app.services.sandbox.cape import CapeSandboxBackend

    orig_plan_fn = AnalysisPlanner.create_and_validate_plan
    def mock_short_plan(self, a):
        p, v = orig_plan_fn(self, a)
        p.execution_timeout_seconds = 0.05
        a.timeout_seconds = 0.05
        return p, v

    monkeypatch.setattr(AnalysisPlanner, "create_and_validate_plan", mock_short_plan)
    monkeypatch.setattr(CapeSandboxBackend, "check_readiness", lambda self, timeout=2.0: {"ready": True, "confinement_verified": True, "error": None})
    monkeypatch.setattr(CapeSandboxBackend, "submit_sample", lambda *a, **k: "9004")
    # Always report still running until timeout
    monkeypatch.setattr(CapeSandboxBackend, "get_task_status", lambda *a, **k: {"status": "running", "is_ready_for_report": False})
    monkeypatch.setattr(CapeSandboxBackend, "cancel_task", lambda self, tid: cancelled_tasks.append(tid))

    worker = PipelineWorker(db_session)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.TIMED_OUT.value
    assert "timed out waiting for CAPE" in (res.error_message or "")
    assert "9004" in cancelled_tasks


def test_pipeline_error_path_cancellation(db_session, monkeypatch, tmp_path):
    """
    When a cancellation event is flagged, PipelineWorker halts execution and
    transitions to CANCELLED cleanly.
    """
    monkeypatch.setattr(settings, "LIVE_MODE_ENABLED", True)

    sample = create_test_pe_sample(db_session, tmp_path, "cancelled_sample.exe")
    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        profile="standard",
        timeout_seconds=30,
        live_mode=True,
        approved_by_user=True,
        status=AnalysisStatus.QUEUED.value,
    )
    db_session.add(analysis)
    db_session.commit()

    cancel_event = threading.Event()
    cancel_event.set()  # Pre-cancelled

    worker = PipelineWorker(db_session, cancel_event=cancel_event)
    res = worker.execute_pipeline(analysis.id)

    assert res.status == AnalysisStatus.CANCELLED.value
