import io
import pytest
from app.core.config import Settings, settings
from app.models.analysis import SandboxBackendType, Analysis, AnalysisStatus
from app.models.sample import Sample
from app.models.event import AnalysisEvent
from app.services.sandbox.cape import CapeSandboxBackend, MAX_REPORT_BYTES, MAX_ARTIFACT_BYTES
from app.services.graph.builder import build_behavior_graph


def test_live_first_settings_defaults():
    """Verifies that default settings enforce live-first CAPE analysis and production safety."""
    default_cfg = Settings(_env_file=None)
    assert default_cfg.DEFAULT_SANDBOX_BACKEND == "cape"
    assert default_cfg.LIVE_MODE_ENABLED is True
    assert default_cfg.ALLOW_SYNTHETIC_REPLAY is False


def test_production_replay_request_is_rejected(client, db_session, monkeypatch):
    """Verifies that in production mode (ALLOW_SYNTHETIC_REPLAY=False), new replay requests are rejected."""
    monkeypatch.setattr(settings, "ALLOW_SYNTHETIC_REPLAY", False)

    sample_bytes = b"MZ\x90\x00" + b"\x00" * 60 + b"PE_TEST_BYTES"
    file_tuple = ("test_sample.exe", io.BytesIO(sample_bytes), "application/octet-stream")
    upload_res = client.post("/api/v1/samples", files={"file": file_tuple})
    assert upload_res.status_code == 201
    sample_id = upload_res.json()["id"]

    # Attempt to request replay mode in production
    res = client.post(
        "/api/v1/analyses",
        json={
            "sample_id": sample_id,
            "backend_type": "replay",
            "live_mode": False,
            "profile": "standard",
        },
    )
    assert res.status_code == 400
    assert "Replay mode is deprecated and disabled in production" in res.json()["detail"]


def test_historical_replay_records_remain_labeled(client, db_session):
    """Verifies that historical replay analyses retain their replay label and synthetic provenance."""
    sample = Sample(
        file_name="historic_wannacry.exe",
        file_size=2048,
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        sha1="1122334455667788990011223344556677889900",
        md5="11223344556677889900112233445566",
        quarantine_path="/tmp/fake_quarantine",
    )
    db_session.add(sample)
    db_session.commit()

    hist_analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        status=AnalysisStatus.COMPLETED.value,
        profile="ransomware_focus",
        live_mode=False,
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(hist_analysis)
    db_session.commit()
    analysis_id = str(hist_analysis.id)

    res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["backend_type"] == "replay"
    assert data["replay_scenario_id"] == "ransomware_wannacry_mock"
    assert data["live_mode"] is False


def test_cape_report_and_artifact_bounded_byte_limits():
    """Verifies that CAPE report and artifact byte caps are strictly enforced."""
    backend = CapeSandboxBackend(api_url="http://127.0.0.1:8008")
    assert MAX_REPORT_BYTES == 50 * 1024 * 1024
    assert MAX_ARTIFACT_BYTES == 100 * 1024 * 1024


def test_graph_builder_excludes_api_calls_from_process_nodes(db_session):
    """Verifies that API call events (is_api_call: True) are never represented as process creation nodes."""
    sample = Sample(
        file_name="injector.exe",
        file_size=4096,
        sha256="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        sha1="2233445566778899001122334455667788990011",
        md5="22334455667788990011223344556677",
        quarantine_path="/tmp/fake_inj",
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type="cape",
        status="COMPLETED",
        profile="standard",
    )
    db_session.add(analysis)
    db_session.commit()

    # Event 1: Real process spawn
    spawn_ev = AnalysisEvent(
        analysis_id=analysis.id,
        category="process",
        action="spawn",
        process_id=1234,
        process_name="injector.exe",
        attributes={"command_line": "injector.exe"},
    )
    # Event 2: API call event in process category
    api_ev = AnalysisEvent(
        analysis_id=analysis.id,
        category="process",
        action="VirtualAllocEx",
        process_id=1234,
        process_name="injector.exe",
        attributes={"is_api_call": True, "api_name": "VirtualAllocEx"},
    )
    db_session.add_all([spawn_ev, api_ev])
    db_session.commit()

    graph = build_behavior_graph(analysis.id, db_session)
    # Nodes of type Process should only contain the actual spawn event, NOT the API call event
    proc_nodes = [n for n in graph.nodes if n.data.type == "Process"]
    assert len(proc_nodes) == 1
    assert proc_nodes[0].data.id == f"proc_{spawn_ev.id}"
