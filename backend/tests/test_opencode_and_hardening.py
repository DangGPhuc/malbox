import io
import json
import os
import signal
import stat
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from app.ai.intelligence_helper import build_deterministic_proposed_intelligence
from app.ai.opencode_provider import OpenCodeReportProvider, TESTED_OPENCODE_VERSION
from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.models.sample import Sample
from app.schemas.intelligence import AIProviderMetadata
from app.schemas.report import FullReportSchema, RiskAssessment
from app.services.intelligence.bundle_builder import (
    BundleSizeLimitError,
    EvidenceBundleBuilder,
)
from app.services.intelligence.enrichment_guard import enrichment_coordinator
from app.services.intelligence.validator import EvidenceValidator


@pytest.fixture(autouse=True)
def _reset_guard():
    enrichment_coordinator.reset()
    yield
    enrichment_coordinator.reset()


def _run_sync_replay(client, scenario_id: str = "ransomware_wannacry_mock"):
    payload = b"MZ" + b"\x00" * 64 + b"RAW_SECRET_SAMPLE_" + uuid.uuid4().hex.encode("ascii")
    res = client.post(
        "/api/v1/samples",
        files={"file": (f"sample_{uuid.uuid4().hex[:6]}.exe", io.BytesIO(payload), "application/octet-stream")},
    )
    assert res.status_code == 201
    sample = res.json()
    run_res = client.post(
        "/api/v1/analyses?run_sync=true",
        json={
            "sample_id": sample["id"],
            "backend_type": "replay",
            "profile": "standard",
            "replay_scenario_id": scenario_id,
            "timeout_seconds": 60,
        },
    )
    assert run_res.status_code == 201
    return sample, run_res.json()


def test_enrichment_authorization_fail_closed_and_no_cape_privilege_reuse(client, monkeypatch):
    _, analysis = _run_sync_replay(client)
    aid = analysis["id"]

    # 1. Server token empty -> fail-closed 403
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "")
    r_unconf = client.post(f"/api/v1/analyses/{aid}/report/intelligence", json={"mode": "deterministic"})
    assert r_unconf.status_code == 403

    # 2. Server token configured: missing/wrong header -> 401
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "reporting-secret-abc")
    monkeypatch.setattr(settings, "OPERATOR_TOKEN", "cape-operator-secret-xyz")
    r_missing = client.post(f"/api/v1/analyses/{aid}/report/intelligence", json={"mode": "deterministic"})
    assert r_missing.status_code == 401

    r_wrong = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "wrong-token"},
        json={"mode": "deterministic"},
    )
    assert r_wrong.status_code == 401

    # 3. CAPE X-Operator-Token must NOT grant reporting privilege
    r_cape = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Operator-Token": "cape-operator-secret-xyz"},
        json={"mode": "deterministic"},
    )
    assert r_cape.status_code == 401

    # 4. Authorized deterministic enrichment succeeds cleanly
    r_ok = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "reporting-secret-abc"},
        json={"mode": "deterministic"},
    )
    assert r_ok.status_code == 200
    assert r_ok.json()["full_report"]["intelligence_report"]["provider_metadata"]["provider"] == "mock"


def test_external_consent_rate_limit_and_get_no_external_calls(client, monkeypatch):
    _, analysis = _run_sync_replay(client)
    aid = analysis["id"]

    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "rep-token-123")
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(settings, "AI_API_KEY", "sk-secret-key-999")
    monkeypatch.setattr(settings, "AI_REPORTING_MODE", "opt_in")
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)

    # GET requests NEVER trigger external LLM even if keys exist
    class ForbidHttpClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            raise AssertionError("GET /report must never invoke external HTTP LLM!")

    monkeypatch.setattr(httpx, "Client", ForbidHttpClient)
    assert client.get(f"/api/v1/analyses/{aid}/report").status_code == 200
    assert client.get(f"/api/v1/analyses/{aid}/report/html").status_code == 200

    # External LLM denied without server consent
    r_no_srv = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-123"},
        json={"mode": "llm", "external_transmission_consent": True},
    )
    assert r_no_srv.status_code == 403

    # External LLM denied without per-request consent
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", True)
    r_no_req = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-123"},
        json={"mode": "llm", "external_transmission_consent": False},
    )
    assert r_no_req.status_code == 403

    # OpenCode denied while disabled
    monkeypatch.setattr(settings, "OPENCODE_ENABLED", False)
    r_oc_dis = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-123"},
        json={"mode": "opencode", "external_transmission_consent": True},
    )
    assert r_oc_dis.status_code == 403

    # Rate limit enforcement
    monkeypatch.setattr(settings, "REPORTING_RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(settings, "REPORTING_RATE_LIMIT_WINDOW_SECONDS", 60)
    assert (
        client.post(
            f"/api/v1/analyses/{aid}/report/intelligence",
            headers={"X-Reporting-Token": "rep-token-123"},
            json={"mode": "deterministic"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/analyses/{aid}/report/intelligence",
            headers={"X-Reporting-Token": "rep-token-123"},
            json={"mode": "deterministic"},
        ).status_code
        == 200
    )
    r_limited = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-123"},
        json={"mode": "deterministic"},
    )
    assert r_limited.status_code == 429
    assert "Retry-After" in r_limited.headers


def test_concurrent_enrichment_conflict_and_capacity_limit(client, db_session, monkeypatch):
    _, a1 = _run_sync_replay(client, "ransomware_wannacry_mock")
    _, a2 = _run_sync_replay(client, "infostealer_redline_mock")

    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "rep-token-123")
    monkeypatch.setattr(settings, "REPORTING_MAX_CONCURRENT_JOBS", 1)
    monkeypatch.setattr(settings, "REPORTING_RATE_LIMIT_REQUESTS", 20)

    # Simulate an active enrichment holding analysis a1 lock
    with enrichment_coordinator.acquire(a1["id"]):
        # Same analysis -> 409 Conflict
        r_same = client.post(
            f"/api/v1/analyses/{a1['id']}/report/intelligence",
            headers={"X-Reporting-Token": "rep-token-123"},
            json={"mode": "deterministic"},
        )
        assert r_same.status_code == 409

        # Different analysis while global max=1 -> 429 Too Many Requests
        r_other = client.post(
            f"/api/v1/analyses/{a2['id']}/report/intelligence",
            headers={"X-Reporting-Token": "rep-token-123"},
            json={"mode": "deterministic"},
        )
        assert r_other.status_code == 429


def test_previous_report_preserved_on_failure_and_secrets_redacted(client, monkeypatch):
    _, analysis = _run_sync_replay(client)
    aid = analysis["id"]

    # Record baseline good report
    baseline_rep = client.get(f"/api/v1/analyses/{aid}/report").json()
    baseline_summary = baseline_rep["executive_summary"]
    baseline_provider = baseline_rep["full_report"]["intelligence_report"]["provider_metadata"]["provider"]
    assert baseline_provider == "mock"

    secret_val = "sk-supersecret-token-leak-998877"
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "rep-auth-555")
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", True)
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(settings, "AI_API_KEY", secret_val)

    # 1. Provider HTTP error containing sensitive secret + local filesystem path
    class LeakyErrorClient:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            raise RuntimeError(
                f"Upstream error with Bearer {secret_val} at /home/kali/malbox/secret.pem"
            )

    monkeypatch.setattr(httpx, "Client", LeakyErrorClient)
    r_fail = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-auth-555"},
        json={"mode": "llm", "external_transmission_consent": True},
    )
    assert r_fail.status_code == 502
    assert secret_val not in r_fail.text
    assert "/home/kali/" not in r_fail.text

    # Previous good report remained completely intact
    after_err = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert after_err["executive_summary"] == baseline_summary
    assert after_err["full_report"]["intelligence_report"]["provider_metadata"]["provider"] == "mock"

    # 2. Request-level timeout boundary preserves previous report too
    monkeypatch.setattr(settings, "REPORTING_ENRICHMENT_TIMEOUT_SECONDS", 1.0)

    class HungClient:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            time.sleep(2.5)
            return MagicMock()

    monkeypatch.setattr(httpx, "Client", HungClient)
    r_to = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-auth-555"},
        json={"mode": "llm", "external_transmission_consent": True},
    )
    assert r_to.status_code == 504
    after_to = client.get(f"/api/v1/analyses/{aid}/report").json()
    assert after_to["executive_summary"] == baseline_summary


def test_validator_rejects_semantically_false_claim_on_real_citation_and_enforces_hypothesis_uncertainty(
    client, db_session
):
    _, analysis = _run_sync_replay(client, "infostealer_redline_mock")
    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)

    dns_event = next(e for e in bundle.events if e.category == "dns")
    meta = AIProviderMetadata(
        mode="llm_enriched",
        provider="real",
        model="gpt-4o-mini",
        tokens_used=100,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    # Adversarial claims: real citation IDs attached to false semantics, overconfident hypothesis, and analyst inference
    raw = {
        "executive_assessment": "Replay scenario 'infostealer_redline_mock' telemetry inspected.",
        "behavioral_narrative": "Chronological scenario telemetry.",
        "timeline_interpretations": [],
        "technical_claims": [
            {
                "claim_id": "CLM-FALSE-FACT",
                "classification": "FACT",
                "claim_text": "Process vssadmin.exe (PID 9999) deleted shadow copies on host.",
                "supporting_evidence_ids": [dns_event.event_id],
                "confidence": 0.99,
                "caveats": [],
            },
            {
                "claim_id": "CLM-SAMPLE-BEHAVIOR-FALSE",
                "classification": "FACT",
                "claim_text": "Sample spawned process and encrypted files on host.",
                "supporting_evidence_ids": [bundle.sample_identity.evidence_id],
                "confidence": 0.95,
                "caveats": [],
            },
            {
                "claim_id": "CLM-CERTAIN-HYP",
                "classification": "HYPOTHESIS",
                "claim_text": "Confirmed fact: APT41 authored this stealer module.",
                "supporting_evidence_ids": [dns_event.event_id],
                "confidence": 0.9,
                "caveats": [],
            },
            {
                "claim_id": "CLM-INF",
                "classification": "INFERENCE",
                "claim_text": f"DNS resolution toward {dns_event.target_path} supports C2 staging workflow.",
                "supporting_evidence_ids": [dns_event.event_id],
                "confidence": 0.8,
                "caveats": [],
            },
        ],
        "ioc_interpretations": [],
        "confidence_assessment": {
            "overall_confidence": 0.65,
            "evidence_completeness": "medium",
            "rationale": "Replay scenario.",
        },
        "contradictions_or_gaps": [],
        "limitations": [],
        "recommended_follow_up_actions": [],
    }

    res = EvidenceValidator().validate_and_finalize(
        raw, bundle, meta, build_deterministic_proposed_intelligence
    )
    by_id = {c.claim_id: c for c in res.technical_claims}
    assert by_id["CLM-FALSE-FACT"].validation_status == "REJECTED"
    assert by_id["CLM-FALSE-FACT"].support_category == "UNSUPPORTED_OR_FABRICATED"
    assert by_id["CLM-SAMPLE-BEHAVIOR-FALSE"].validation_status == "REJECTED"
    assert by_id["CLM-CERTAIN-HYP"].validation_status != "VERIFIED"
    assert by_id["CLM-CERTAIN-HYP"].validation_status == "UNVERIFIED"
    assert by_id["CLM-CERTAIN-HYP"].support_category == "UNCERTAIN_HYPOTHESIS"
    assert len(by_id["CLM-CERTAIN-HYP"].caveats) >= 1
    assert by_id["CLM-INF"].validation_status == "UNVERIFIED"
    assert by_id["CLM-INF"].support_category == "ANALYST_INFERENCE"
    assert by_id["CLM-INF"].requires_human_review is True
    assert res.validation_summary.passed is False


def test_bounded_db_retrieval_and_hard_bundle_byte_cap(db_session, monkeypatch):
    sample = Sample(
        sha256="e" * 64,
        sha1="f" * 40,
        md5="a" * 32,
        file_name="large_scale.exe",
        file_size=8192,
        is_pe=True,
        quarantine_path="/tmp/none",
    )
    db_session.add(sample)
    db_session.flush()

    analysis = Analysis(
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(analysis)
    db_session.flush()

    # Insert 1,200 routine file events before 2 critical finding-linked events
    for idx in range(1200):
        db_session.add(
            AnalysisEvent(
                id=f"noise-{idx:04d}",
                analysis_id=analysis.id,
                category="file",
                action="read",
                timestamp=datetime(2026, 1, 1, 0, idx // 60, idx % 60, tzinfo=timezone.utc),
                process_id=101,
                process_name="explorer.exe",
                target_path=f"C:\\Windows\\noise_{idx:04d}.dll",
                attributes={"blob": "X" * 400},
            )
        )

    crit_ids = ["crit-large-1", "crit-large-2"]
    for cid in crit_ids:
        db_session.add(
            AnalysisEvent(
                id=cid,
                analysis_id=analysis.id,
                category="process",
                action="spawn",
                timestamp=datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
                process_id=888,
                process_name="vssadmin.exe",
                attributes={"command_line": "vssadmin delete shadows /all /quiet"},
            )
        )

    # Oversized finding + oversized IOC descriptions
    for f_idx in range(6):
        db_session.add(
            BehavioralFinding(
                id=f"big-find-{f_idx}",
                analysis_id=analysis.id,
                rule_id="RULE_SHADOW_COPY_DELETION",
                title="Volume Shadow Copy Deletion",
                description="O" * 2000,
                severity="Critical",
                confidence=0.95,
                mitre_attack_id="T1490",
                mitre_tactic="Impact",
                supporting_event_ids=crit_ids,
            )
        )
    db_session.commit()

    # Track SQL query row counts via builder bounded methods (zero unbounded .all() on full 1200 rows)
    from sqlalchemy.orm import Query

    max_rows_returned = 0
    orig_all = Query.all

    def guarded_all(self_q):
        rows = orig_all(self_q)
        nonlocal max_rows_returned
        if rows and isinstance(rows[0], AnalysisEvent):
            max_rows_returned = max(max_rows_returned, len(rows))
        return rows

    monkeypatch.setattr(Query, "all", guarded_all)

    builder = EvidenceBundleBuilder(
        db_session, max_events=12, max_timeline=12, max_field_chars=128, max_bundle_bytes=4096
    )
    bundle = builder.build(
        analysis.id, risk_assessment=RiskAssessment(score=95, level="Malicious")
    )

    assert max_rows_returned < 300  # Never materialized all 1,202 events
    assert bundle.truncation.total_events_available == 1202
    assert bundle.truncation.truncated is True
    assert len(bundle.model_dump_json().encode("utf-8")) <= 4096

    # Verify finding-linked prioritization when byte budget allows
    builder_roomy = EvidenceBundleBuilder(
        db_session, max_events=10, max_timeline=10, max_field_chars=128, max_bundle_bytes=32768
    )
    roomy_bundle = builder_roomy.build(
        analysis.id, risk_assessment=RiskAssessment(score=95, level="Malicious")
    )
    assert set(crit_ids).issubset({e.event_id for e in roomy_bundle.events})

    # Impossible byte cap fails closed with controlled BundleSizeLimitError
    tiny_builder = EvidenceBundleBuilder(
        db_session, max_events=10, max_timeline=10, max_field_chars=128, max_bundle_bytes=250
    )
    with pytest.raises(BundleSizeLimitError):
        tiny_builder.build(analysis.id, risk_assessment=RiskAssessment(score=95, level="Malicious"))


def test_opencode_agent_spec_and_disabled_or_missing_cli_fallbacks():
    spec_path = Path(__file__).resolve().parents[2] / ".opencode" / "agents" / "report-analyst.md"
    assert spec_path.is_file()
    content = spec_path.read_text(encoding="utf-8")
    assert TESTED_OPENCODE_VERSION in content
    assert "shell" in content and "deny" in content
    assert "edit" in content
    assert "external_directory" in content
    assert "webfetch" in content
    assert "subagent" in content

    # Disabled by default -> clean deterministic fallback, never claims external execution
    p_disabled = OpenCodeReportProvider(enabled=False, external_consent=True)
    assert p_disabled._resolve_binary("opencode-nonexistent-xyz") is None

    # Create tiny minimal bundle from helper
    from app.schemas.intelligence import (
        BundleProvenance,
        SampleIdentityEvidence,
        VerifiedEvidenceBundle,
    )

    bundle = VerifiedEvidenceBundle(
        analysis_id="an-1",
        sample_identity=SampleIdentityEvidence(
            evidence_id="sample:" + ("a" * 64),
            sample_id="s-1",
            file_name="test.exe",
            file_size=1234,
            sha256="a" * 64,
            is_pe=True,
        ),
        provenance=BundleProvenance(
            analysis_id="an-1",
            backend_type="replay",
            is_replay=True,
            replay_scenario_id="ransomware_wannacry_mock",
            provenance_statement="Synthetic replay scenario 'ransomware_wannacry_mock'; sample not executed.",
        ),
        deterministic_risk_score=85,
        deterministic_risk_level="Malicious",
        valid_evidence_ids=["sample:" + ("a" * 64)],
    )

    rep_dis = p_disabled.generate_intelligence_report(bundle)
    assert rep_dis.provider_metadata.provider == "mock_fallback"
    assert rep_dis.provider_metadata.mode == "mock_fallback"
    assert rep_dis.provider_metadata.fallback_used is True
    assert rep_dis.is_replay is True

    # Missing CLI binary -> clean fallback
    p_missing = OpenCodeReportProvider(
        enabled=True, external_consent=True, binary="opencode-nonexistent-xyz"
    )
    rep_miss = p_missing.generate_intelligence_report(bundle)
    assert rep_miss.provider_metadata.provider == "mock_fallback"
    assert rep_miss.provider_metadata.fallback_used is True


def test_opencode_isolation_env_permissions_and_jsonl_success(client, db_session, monkeypatch):
    _, analysis = _run_sync_replay(client, "ransomware_wannacry_mock")
    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)
    valid_proposal = build_deterministic_proposed_intelligence(bundle).model_dump()

    # Inject sensitive secrets into process environment
    monkeypatch.setenv("MALBOX_OPERATOR_TOKEN", "leak-op-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-aws-secret")
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "leak-rep-token")

    fake_bin = Path(settings.DATA_DIR) / "fake_opencode"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(fake_bin, 0o755)

    captured = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            captured["env"] = dict(kwargs.get("env") or {})
            cwd = Path(kwargs["cwd"])
            captured["cwd"] = cwd
            captured["cwd_mode"] = stat.S_IMODE(cwd.stat().st_mode)
            captured["bundle_exists"] = (cwd / "evidence_bundle.json").is_file()
            captured["bundle_text"] = (cwd / "evidence_bundle.json").read_text(encoding="utf-8")
            captured["oc_json"] = json.loads((cwd / "opencode.json").read_text(encoding="utf-8"))
            captured["agent_exists"] = (cwd / ".opencode" / "agents" / "report-analyst.md").is_file()
            self.pid = 999999
            self.returncode = 0
            jsonl = "\n".join(
                [
                    json.dumps({"type": "step_start", "part": {"type": "step-start"}}),
                    json.dumps(
                        {
                            "type": "tool_use",
                            "part": {"tool": "read", "input": {"filePath": "./evidence_bundle.json"}},
                        }
                    ),
                    json.dumps({"type": "text", "part": {"text": json.dumps(valid_proposal)}}),
                    json.dumps({"type": "step_finish", "part": {"tokens": {"total": 333}}}),
                ]
            ).encode("utf-8")
            self.stdout = io.BytesIO(jsonl)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", FakePopen)

    provider = OpenCodeReportProvider(
        enabled=True,
        external_consent=True,
        binary=str(fake_bin),
        model="openai/gpt-4o-mini",
    )
    res = provider.generate_intelligence_report(bundle)

    assert res.provider_metadata.provider == "opencode"
    assert res.provider_metadata.mode == "opencode_enriched"
    assert res.provider_metadata.tokens_used == 333
    assert res.provider_metadata.fallback_used is False
    assert res.is_replay is True
    assert res.validation_summary.passed is True

    # Verify strict isolation invariants
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["cwd"] != Path(settings.WORKSPACE_ROOT).resolve()
    assert captured["cwd"] != Path(settings.QUARANTINE_DIR).resolve()
    assert captured["cwd"] != Path.home().resolve()
    assert not captured["cwd"].exists()  # Temp workspace cleaned up afterward
    assert captured["cwd_mode"] == 0o700
    assert captured["bundle_exists"] is True
    assert "RAW_SECRET_SAMPLE_" not in captured["bundle_text"]
    assert captured["agent_exists"] is True

    # Verify opencode.json locked down all dangerous actions
    perms = {(p["action"], p["effect"]) for p in captured["oc_json"]["permissions"]}
    for forbidden_act in ("*", "shell", "bash", "edit", "external_directory", "webfetch", "subagent"):
        assert (forbidden_act, "deny") in perms

    # Verify zero sensitive env variable leakage
    assert "MALBOX_OPERATOR_TOKEN" not in captured["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in captured["env"]
    assert "REPORTING_AUTH_TOKEN" not in captured["env"]
    assert captured["env"]["HOME"] == str(captured["cwd"])

    # OS isolation check fails closed cleanly when unavailable
    monkeypatch.setattr(
        "app.ai.opencode_provider.check_posix_isolation_support",
        lambda: (False, "POSIX OS isolation primitives are unavailable."),
    )
    res_win = provider.generate_intelligence_report(bundle)
    assert res_win.provider_metadata.provider == "mock_fallback"
    assert res_win.provider_metadata.fallback_used is True


def test_opencode_malformed_jsonl_disallowed_tool_timeout_and_oversized_output(
    client, db_session, monkeypatch
):
    _, analysis = _run_sync_replay(client, "ransomware_wannacry_mock")
    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)

    fake_bin = Path(settings.DATA_DIR) / "fake_oc_err"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(fake_bin, 0o755)

    killed_pids = []
    monkeypatch.setattr("app.ai.opencode_provider.os.getpgid", lambda pid: pid)
    monkeypatch.setattr(
        "app.ai.opencode_provider.os.killpg",
        lambda pgid, sig: killed_pids.append((pgid, sig)),
    )

    # 1. Malformed JSONL -> deterministic fallback
    class MalformedPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 111
            self.returncode = 0
            self.stdout = io.BytesIO(b"not-json-at-all\n")
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", MalformedPopen)
    prov = OpenCodeReportProvider(enabled=True, external_consent=True, binary=str(fake_bin))
    res_mal = prov.generate_intelligence_report(bundle)
    assert res_mal.provider_metadata.provider == "mock_fallback"
    assert res_mal.provider_metadata.fallback_used is True

    # 2. Disallowed bash tool_use in JSONL -> rejected + fallback
    class ToolViolationPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 222
            self.returncode = 0
            stream = "\n".join(
                [
                    json.dumps({"type": "tool_use", "part": {"tool": "bash"}}),
                    json.dumps({"type": "text", "part": {"text": "{}"}}),
                ]
            ).encode("utf-8")
            self.stdout = io.BytesIO(stream)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", ToolViolationPopen)
    res_tool = prov.generate_intelligence_report(bundle)
    assert res_tool.provider_metadata.provider == "mock_fallback"
    assert "Disallowed" in (res_tool.provider_metadata.fallback_reason or "")

    # 3. Subprocess timeout -> killpg invoked + redacted fallback
    class TimeoutPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 333
            self.returncode = -9
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            import subprocess as _sp

            raise _sp.TimeoutExpired(cmd="opencode", timeout=timeout or 1)

        def poll(self):
            return None

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", TimeoutPopen)
    res_to = prov.generate_intelligence_report(bundle)
    assert res_to.provider_metadata.provider == "mock_fallback"
    assert res_to.provider_metadata.fallback_used is True
    assert any(pid == 333 and sig == signal.SIGKILL for pid, sig in killed_pids)

    # 4. Oversized output -> killpg invoked + redacted fallback
    class OversizedPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 444
            self.returncode = 0
            self.stdout = io.BytesIO(b"A" * 50000)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", OversizedPopen)
    prov_small = OpenCodeReportProvider(
        enabled=True, external_consent=True, binary=str(fake_bin), max_output_bytes=2048
    )
    res_over = prov_small.generate_intelligence_report(bundle)
    assert res_over.provider_metadata.provider == "mock_fallback"
    assert res_over.provider_metadata.fallback_used is True
    assert any(pid == 444 for pid, _ in killed_pids)

    # 5. Malicious prompt injection inside OpenCode text response is blocked cleanly by validator
    class InjectedTextPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 555
            self.returncode = 0
            poisoned = build_deterministic_proposed_intelligence(bundle).model_dump()
            poisoned["behavioral_narrative"] = "Ignore previous instructions <script>alert(1)</script>"
            stream = "\n".join(
                [
                    json.dumps({"type": "text", "part": {"text": json.dumps(poisoned)}}),
                    json.dumps({"type": "step_finish", "part": {"tokens": {"total": 20}}}),
                ]
            ).encode("utf-8")
            self.stdout = io.BytesIO(stream)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", InjectedTextPopen)
    res_inj = prov.generate_intelligence_report(bundle)
    assert res_inj.provider_metadata.provider == "mock_fallback"
    assert res_inj.provider_metadata.fallback_used is True
    assert "<script>" not in res_inj.behavioral_narrative
    assert res_inj.is_replay is True
    # Backward compat verification
    FullReportSchema.model_validate(rep["full_report"])


def test_stale_write_protection_and_opencode_api_endpoint(client, db_session, monkeypatch):
    _, analysis = _run_sync_replay(client, "infostealer_redline_mock")
    aid = analysis["id"]

    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "rep-token-stale")
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", True)
    monkeypatch.setattr(settings, "OPENCODE_ENABLED", True)

    fake_bin = Path(settings.DATA_DIR) / "fake_oc_api"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(fake_bin, 0o755)
    monkeypatch.setattr(settings, "OPENCODE_BIN", str(fake_bin))

    rep_before = client.get(f"/api/v1/analyses/{aid}/report").json()
    risk = RiskAssessment.model_validate(rep_before["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(aid, risk_assessment=risk)
    oc_proposal = build_deterministic_proposed_intelligence(bundle).model_dump()
    oc_proposal["executive_assessment"] = (
        "Synthetic Replay Scenario 'infostealer_redline_mock': OpenCode enriched assessment."
    )

    class SuccessApiPopen:
        def __init__(self, cmd, **kwargs):
            self.pid = 777
            self.returncode = 0
            stream = "\n".join(
                [
                    json.dumps({"type": "text", "part": {"text": json.dumps(oc_proposal)}}),
                    json.dumps({"type": "step_finish", "part": {"tokens": {"total": 180}}}),
                ]
            ).encode("utf-8")
            self.stdout = io.BytesIO(stream)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr("app.ai.opencode_provider.subprocess.Popen", SuccessApiPopen)
    ok_res = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-stale"},
        json={"mode": "opencode", "external_transmission_consent": True},
    )
    assert ok_res.status_code == 200
    assert ok_res.json()["full_report"]["intelligence_report"]["provider_metadata"]["provider"] == "opencode"
    assert "OpenCode enriched assessment" in ok_res.json()["executive_summary"]

    # Simulate stale-write race: DB row mutates while slow provider runs
    from app.models.report import AnalysisReport
    from app.ai.mock_provider import MockLLMProvider

    orig_gen = MockLLMProvider.generate_intelligence_report

    def mutating_gen(self_prov, b, rules_text=None):
        row = db_session.query(AnalysisReport).filter(AnalysisReport.analysis_id == aid).first()
        mutated = dict(row.full_report_json)
        mutated["executive_summary"] = "CONCURRENT_NEWER_WRITE"
        row.full_report_json = mutated
        row.executive_summary = "CONCURRENT_NEWER_WRITE"
        db_session.commit()
        return orig_gen(self_prov, b, rules_text=rules_text)

    monkeypatch.setattr(MockLLMProvider, "generate_intelligence_report", mutating_gen)
    stale_res = client.post(
        f"/api/v1/analyses/{aid}/report/intelligence",
        headers={"X-Reporting-Token": "rep-token-stale"},
        json={"mode": "deterministic"},
    )
    assert stale_res.status_code == 409
    assert "CONCURRENT_NEWER_WRITE" in client.get(f"/api/v1/analyses/{aid}/report").json()["executive_summary"]
