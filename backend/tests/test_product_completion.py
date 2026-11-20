import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from malbox_cli.checks import (
    check_cape_confinement_attestation,
    check_optional_integrations,
    check_os,
    run_all_checks,
)
from malbox_cli.cli import main as cli_main
from malbox_cli.models import CheckStatus
from malbox_cli.setup import (
    setup_ai,
    setup_cape,
    setup_check,
    setup_ghidra,
    setup_plan,
    setup_verify,
)

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus, Base
from app.workers.job_queue import job_queue_manager
from app.ai.llm_client import RealLLMProvider, get_llm_provider, get_reporting_llm_provider
from app.ai.intelligence_helper import (
    build_deterministic_proposed_intelligence,
    run_bounded_llm_intelligence,
)
from app.schemas.intelligence import VerifiedEvidenceBundle, SampleIdentityEvidence, BundleProvenance


@pytest.fixture
def isolated_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "test_malbox"
    ws.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / ".env.example", ws / ".env.example")
    shutil.copyfile(REPO_ROOT / ".env.example", ws / ".env")
    (ws / "backend").mkdir()
    shutil.copyfile(REPO_ROOT / "backend" / "pyproject.toml", ws / "backend" / "pyproject.toml")
    (ws / "frontend").mkdir()
    shutil.copyfile(REPO_ROOT / "frontend" / "package.json", ws / "frontend" / "package.json")
    (ws / "data").mkdir()
    fixtures_dst = ws / "fixtures" / "replay"
    fixtures_dst.mkdir(parents=True)
    for f in (REPO_ROOT / "fixtures" / "replay").glob("*.json"):
        shutil.copyfile(f, fixtures_dst / f.name)
    return ws


# ==============================================================================
# 1. CAPE Confinement Attestation Check Tests
# ==============================================================================

def test_cape_confinement_attestation_disabled_live(isolated_workspace: Path):
    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "false"},
    )
    assert res.status == CheckStatus.SKIP
    assert res.readiness_tier == "CONFIGURED"


def test_cape_confinement_attestation_missing(isolated_workspace: Path):
    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true"},
    )
    assert res.status == CheckStatus.WARN
    assert res.readiness_tier == "BLOCKED"
    assert "missing" in res.summary.lower()


def test_cape_confinement_attestation_insecure_permissions(isolated_workspace: Path):
    if os.name != "posix":
        pytest.skip("POSIX permission checks only apply on POSIX")
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    att_file.write_text("{}", encoding="utf-8")
    att_file.chmod(0o666)  # world/group writable

    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true"},
    )
    assert res.status == CheckStatus.FAIL
    assert res.readiness_tier == "BLOCKED"
    assert "insecure" in res.summary.lower()


def test_cape_confinement_attestation_mismatched_target(isolated_workspace: Path):
    from app.services.sandbox.confinement import create_isolation_attestation
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    create_isolation_attestation(
        verified_machine="other_machine",
        verified_route="drop",
        verifier="test_op",
        attestation_path=att_file,
        evidence_references=["pcap:test_evidence"],
    )

    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true", "MALBOX_CAPE_DEFAULT_MACHINE": "win10_analyst", "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": "drop"},
    )
    assert res.status == CheckStatus.FAIL
    assert res.readiness_tier == "BLOCKED"
    assert "mismatch" in res.summary.lower() or "rejected" in res.summary.lower()


def test_cape_confinement_attestation_expired(isolated_workspace: Path):
    from app.services.sandbox.confinement import create_isolation_attestation
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    create_isolation_attestation(
        verified_machine="win10_analyst",
        verified_route="drop",
        verifier="test_op",
        validity_seconds=-10,  # Expired immediately
        attestation_path=att_file,
        evidence_references=["pcap:test_evidence"],
    )

    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true", "MALBOX_CAPE_DEFAULT_MACHINE": "win10_analyst", "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": "drop"},
    )
    assert res.status == CheckStatus.FAIL
    assert res.readiness_tier == "BLOCKED"
    assert "expired" in res.summary.lower()


def test_cape_confinement_attestation_unverified_assertions(isolated_workspace: Path):
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    now_iso = datetime.now(timezone.utc).isoformat()
    future_iso = datetime.fromtimestamp(time.time() + 3600, tz=timezone.utc).isoformat()
    payload = {
        "schema_version": "1.0",
        "attestation_type": "manual_operator_assertion",
        "status": "verified",
        "verified_machine": "win10_analyst",
        "verified_route": "drop",
        "verifier": "test_op",
        "verified_at": now_iso,
        "expires_at": future_iso,
        "evidence_references": ["pcap:test_evidence"],
        "operator_assertions": {
            "host_only_networking_verified": True,
            "routing_isolation_verified": False,  # Missing!
            "firewall_rules_verified": True,
            "guest_snapshot_clean_verified": True,
        },
    }
    att_file.write_text(json.dumps(payload), encoding="utf-8")
    att_file.chmod(0o600)

    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true", "MALBOX_CAPE_DEFAULT_MACHINE": "win10_analyst", "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": "drop"},
    )
    assert res.status == CheckStatus.FAIL
    assert res.readiness_tier == "BLOCKED"
    assert "missing" in res.summary.lower() or "rejected" in res.summary.lower()


def test_cape_confinement_attestation_verified(isolated_workspace: Path):
    from app.services.sandbox.confinement import create_isolation_attestation, verify_cape_confinement
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    create_isolation_attestation(
        verified_machine="win10_analyst",
        verified_route="drop",
        verifier="test_operator",
        attestation_path=att_file,
        evidence_references=["pcap:zero_egress_test", "iptables:drop_rule_checked"],
    )

    res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true", "MALBOX_CAPE_DEFAULT_MACHINE": "win10_analyst", "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": "drop"},
    )
    assert res.status == CheckStatus.PASS
    assert res.readiness_tier == "VERIFIED"
    assert "verified" in res.summary.lower()

    # Verify runtime verifier agrees identically
    runtime_res = verify_cape_confinement(
        target_machine="win10_analyst",
        target_route="drop",
        attestation_path=att_file,
    )
    assert runtime_res.is_verified is True
    assert runtime_res.status == "verified"


def test_unsupported_host_only_route_rejected(isolated_workspace: Path):
    """Host-only is an adapter name, not a valid CAPE execution routing policy."""
    from app.services.sandbox.confinement import verify_cape_confinement
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    now_iso = datetime.now(timezone.utc).isoformat()
    future_iso = datetime.fromtimestamp(time.time() + 3600, tz=timezone.utc).isoformat()
    payload = {
        "schema_version": "1.0",
        "attestation_type": "manual_operator_assertion",
        "status": "verified",
        "verified_machine": "win10_analyst",
        "verified_route": "host-only",  # Invalid route!
        "verifier": "test_op",
        "verified_at": now_iso,
        "expires_at": future_iso,
        "evidence_references": ["pcap:test"],
        "operator_assertions": {
            "host_only_networking_verified": True,
            "routing_isolation_verified": True,
            "firewall_rules_verified": True,
            "guest_snapshot_clean_verified": True,
        },
    }
    att_file.write_text(json.dumps(payload), encoding="utf-8")
    att_file.chmod(0o600)

    # Doctor must reject
    doc_res = check_cape_confinement_attestation(
        isolated_workspace,
        environ={"MALBOX_LIVE_MODE_ENABLED": "true", "MALBOX_CAPE_DEFAULT_MACHINE": "win10_analyst", "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": "host-only"},
    )
    assert doc_res.status == CheckStatus.FAIL
    assert doc_res.readiness_tier == "BLOCKED"

    # Runtime must reject identically
    rt_res = verify_cape_confinement(
        target_machine="win10_analyst",
        target_route="host-only",
        attestation_path=att_file,
    )
    assert rt_res.is_verified is False
    assert rt_res.status == "unconfined_route"


def test_setup_cape_default_never_creates_attestation(isolated_workspace: Path):
    """setup_cape() must never automatically generate an isolation attestation."""
    res = setup_cape(
        isolated_workspace,
        api_url="http://127.0.0.1:8008",
        machine="win10_analyst",
        route="drop",
        generate_attestation=False,  # Default
    )
    assert res["success"] is True
    assert res["attestation"] is None
    att_file = isolated_workspace / "data" / "cape_isolation_attestation.json"
    assert not att_file.exists()


def test_setup_attest_isolation_requires_operator_and_evidence(isolated_workspace: Path):
    """Explicit operator isolation workflow requires operator name and evidence references."""
    from malbox_cli.setup import setup_attest_isolation

    # Missing operator
    bad_op = setup_attest_isolation(isolated_workspace, operator="", evidence_refs=["pcap:test"])
    assert bad_op["success"] is False
    assert "operator" in bad_op["error"].lower()

    # Missing evidence references
    bad_refs = setup_attest_isolation(isolated_workspace, operator="analyst", evidence_refs=[])
    assert bad_refs["success"] is False
    assert "evidence" in bad_refs["error"].lower()

    # Valid attestation workflow
    ok_att = setup_attest_isolation(
        isolated_workspace,
        operator="lead_analyst",
        machine="win10_analyst",
        route="drop",
        evidence_refs=["iptables:drop_rules_verified", "wireshark:zero_egress_test"],
        notes="Verified in lab VLAN",
    )
    assert ok_att["success"] is True
    assert ok_att["verified"] is True
    assert Path(ok_att["attestation_path"]).is_file()


# ==============================================================================
# 2. Setup Assistant CLI Tests
# ==============================================================================

def test_setup_plan_logic(isolated_workspace: Path):
    plan = setup_plan(isolated_workspace)
    assert "recommended_profile" in plan
    assert "profiles" in plan
    assert "profile_a_single_host" in plan["profiles"]
    assert "profile_b_distributed" in plan["profiles"]
    assert plan["profiles"]["profile_b_distributed"]["supported_on_current_host"] is True


def test_setup_ghidra_and_cape_and_ai(isolated_workspace: Path):
    # Ghidra setup
    g_res = setup_ghidra(isolated_workspace, ghidra_home="/opt/ghidra", enable=True)
    assert g_res["success"] is True
    env_content = (isolated_workspace / ".env").read_text(encoding="utf-8")
    assert "MALBOX_GHIDRA_ENABLED=true" in env_content
    assert "MALBOX_GHIDRA_HOME=/opt/ghidra" in env_content

    # CAPE setup (does not auto-generate attestation)
    c_res = setup_cape(
        isolated_workspace,
        api_url="http://127.0.0.1:8008",
        api_token="test_cape_token",
        machine="win10_test",
        route="drop",
    )
    assert c_res["success"] is True
    assert c_res["attestation"] is None

    # Separate operator isolation attestation workflow
    from malbox_cli.setup import setup_attest_isolation
    att_res = setup_attest_isolation(
        isolated_workspace,
        operator="lead_analyst",
        machine="win10_test",
        route="drop",
        evidence_refs=["pcap:zero_leak"],
    )
    assert att_res["success"] is True
    assert Path(att_res["attestation_path"]).is_file()

    # AI setup (local/ollama)
    ai_res = setup_ai(
        isolated_workspace,
        provider="local",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3",
    )
    assert ai_res["success"] is True
    env_content = (isolated_workspace / ".env").read_text(encoding="utf-8")
    assert "MALBOX_AI_PROVIDER=local" in env_content
    assert "MALBOX_AI_MODEL=llama3" in env_content

    # Setup verify
    v_res = setup_verify(isolated_workspace)
    assert "overall_status" in v_res
    assert "readiness" in v_res
    assert "APPLICATION_READY" in v_res
    assert "DETONATION_READY" in v_res
    assert "CONFINEMENT_VERIFIED" in v_res
    assert v_res["readiness"]["CONFINEMENT_VERIFIED"] is True


def test_setup_verify_distinguishes_app_from_detonation_readiness():
    """Missing CAPE/confinement must allow APPLICATION_READY but block DETONATION_READY on clean repo."""
    v_res = setup_verify(REPO_ROOT)
    assert v_res["APPLICATION_READY"] is True
    assert v_res["DETONATION_READY"] is False
    assert v_res["overall_status"] == "APPLICATION_READY_DETONATION_BLOCKED"
    assert len(v_res["detonation_blockers"]) > 0


def test_setup_ghidra_distinguishes_configuration_from_operational(isolated_workspace: Path):
    """Configuring GHIDRA_ENABLED=true without valid binary must NOT report operational readiness."""
    res = setup_ghidra(isolated_workspace, ghidra_home="/nonexistent/ghidra/path", enable=True)
    assert res["success"] is True
    assert res["ghidra_operational"] is False
    assert res["status"] == "CONFIGURED_NOT_OPERATIONAL"
    assert len(res["prerequisites_missing"]) > 0


def test_setup_dry_run_does_not_modify_env(isolated_workspace: Path):
    original_env = (isolated_workspace / ".env").read_text(encoding="utf-8")
    res = setup_cape(
        isolated_workspace,
        api_url="http://99.99.99.99:8008",
        dry_run=True,
    )
    assert res["success"] is True
    assert res["dry_run"] is True
    assert (isolated_workspace / ".env").read_text(encoding="utf-8") == original_env


def test_cli_setup_and_logs(isolated_workspace: Path, capsys):
    ret = cli_main(["setup", "--plan"], root_dir=isolated_workspace)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Hardware & Deployment Planning" in captured.out

    ret_logs = cli_main(["logs", "-n", "10"], root_dir=isolated_workspace)
    assert ret_logs == 0


# ==============================================================================
# 3. AI Unavailable Fallback Tests (P0 Defect Resolution)
# ==============================================================================

def test_real_llm_provider_plan_unavailable_on_failure():
    provider = RealLLMProvider(api_key="invalid", model="test-model", base_url="http://127.0.0.1:9999")
    with patch.object(provider, "_call_chat_completions", side_effect=RuntimeError("Connection refused")):
        plan = provider.generate_plan({"file_name": "test.exe", "file_size": 100})
        assert provider.last_call_meta["provider"] == "mock_fallback"
        assert provider.last_call_meta["fallback"] is True
        assert "[AI PLANNER UNAVAILABLE:" in plan["rationale"]


def test_real_llm_provider_evaluation_unavailable_on_failure():
    provider = RealLLMProvider(api_key="invalid", model="test-model", base_url="http://127.0.0.1:9999")
    with patch.object(provider, "_call_chat_completions", side_effect=RuntimeError("Timeout")):
        rec = provider.evaluate_observations({"file_name": "test.exe"}, {})
        assert provider.last_call_meta["provider"] == "mock_fallback"
        assert provider.last_call_meta["fallback"] is True
        assert "[AI EVALUATOR UNAVAILABLE:" in rec["rationale"]


def test_real_llm_provider_summary_unavailable_on_failure():
    provider = RealLLMProvider(api_key="invalid", model="test-model", base_url="http://127.0.0.1:9999")
    with patch.object(provider, "_call_chat_completions", side_effect=RuntimeError("Bad Gateway")):
        summary = provider.generate_executive_summary({}, {}, [])
        assert provider.last_call_meta["provider"] == "mock_fallback"
        assert "[AI SUMMARY UNAVAILABLE:" in summary


def test_run_bounded_llm_intelligence_unavailable_on_failure():
    bundle = VerifiedEvidenceBundle(
        analysis_id="test-analysis-1",
        sample_identity=SampleIdentityEvidence(
            evidence_id="sample:123",
            sample_id="samp-1",
            file_name="sample.exe",
            file_size=1024,
            sha256="abc1234567890123456789012345678901234567890123456789012345678901",
        ),
        provenance=BundleProvenance(
            analysis_id="test-analysis-1",
            backend_type="cape",
            is_replay=False,
            provenance_statement="Live CAPE",
        ),
        deterministic_risk_score=75,
        deterministic_risk_level="Malicious",
        valid_evidence_ids=["sample:123"],
    )

    with patch("httpx.Client.post", side_effect=RuntimeError("Network unreachable")):
        report, meta = run_bounded_llm_intelligence(
            bundle=bundle,
            api_key="sk-test",
            model="gpt-4o",
            base_url="http://127.0.0.1:9999",
            timeout=1.0,
        )
        assert meta["provider"] == "mock_fallback"
        assert report.provider_metadata.mode == "mock_fallback"
        assert report.provider_metadata.provider == "mock_fallback"
        assert report.provider_metadata.fallback_used is True
        assert "[AI ANALYSIS UNAVAILABLE:" in report.executive_assessment
        # Deterministic findings and score are preserved
        assert report.deterministic_risk_score == 75
        assert report.deterministic_risk_level == "Malicious"


# ==============================================================================
# 4. Local AI Factory & Orphaned Job Recovery Tests
# ==============================================================================

def test_local_ai_provider_factory(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "local")
    monkeypatch.setattr(settings, "AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)

    p1 = get_llm_provider()
    assert isinstance(p1, RealLLMProvider)
    assert p1.base_url == "http://127.0.0.1:11434/v1"

    p2 = get_reporting_llm_provider(requested_mode="local")
    assert isinstance(p2, RealLLMProvider)
    assert p2.base_url == "http://127.0.0.1:11434/v1"


def test_orphaned_analysis_recovery():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Create one queued and one running analysis
    a1 = Analysis(
        id="orphan-1",
        sample_id="samp-1",
        status=AnalysisStatus.QUEUED.value,
        backend_type="cape",
    )
    a2 = Analysis(
        id="orphan-2",
        sample_id="samp-2",
        status=AnalysisStatus.RUNNING.value,
        backend_type="cape",
    )
    a3 = Analysis(
        id="finished-1",
        sample_id="samp-3",
        status=AnalysisStatus.COMPLETED.value,
        backend_type="cape",
    )
    db.add_all([a1, a2, a3])
    db.commit()

    recovered = job_queue_manager.recover_stale_jobs(db)
    assert recovered == 2

    db.refresh(a1)
    db.refresh(a2)
    db.refresh(a3)

    assert a1.status == AnalysisStatus.FAILED.value
    assert a1.error_message == "Analysis interrupted by process shutdown or worker restart; static triage preserved."
    assert a2.status == AnalysisStatus.FAILED.value
    assert a2.error_message == "Analysis interrupted by process shutdown or worker restart; static triage preserved."
    assert a3.status == AnalysisStatus.COMPLETED.value

    db.close()
