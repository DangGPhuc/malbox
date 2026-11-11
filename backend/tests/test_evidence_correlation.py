from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.models.correlation import StaticDynamicCorrelationRecord
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.models.report import AnalysisReport
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.schemas.intelligence import (
    AIProposedIntelligence,
    AIProviderMetadata,
    ConfidenceAssessment,
    IntelligenceReport,
    ProposedClaim,
    VerifiedEvidenceBundle,
)
from app.schemas.report import FullReportSchema, RiskAssessment
from app.schemas.static_analysis import (
    FunctionMetadata,
    ImportedSymbol,
    ProgramMetadata,
    StaticAnalysisProvenance,
    StaticAnalysisResult,
    StaticAnalysisTruncation,
    StaticStringEvidence,
    make_static_function_id,
    make_static_string_id,
)
from app.services.detection.engine import DetectionEngine
from app.services.evidence_correlation.engine import EvidenceCorrelationEngine
from app.services.evidence_correlation.schemas import (
    CorrelationBundleSection,
    CorrelationConfidence,
    CorrelationEvidenceReference,
    CorrelationFinding,
)
from app.services.evidence_correlation.service import EvidenceCorrelationService
from app.services.intelligence.bundle_builder import EvidenceBundleBuilder
from app.services.intelligence.validator import EvidenceValidator
from app.services.reporting.generator import ReportGenerator
from app.services.telemetry.normalizer import TelemetryNormalizer
from app.workers.job_queue import job_queue_manager


def _sample_sha(tag: str = "a") -> str:
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _create_sample_and_analysis(
    db_session,
    *,
    tag: str = "demo",
    backend_type: str = "cape",
    replay_scenario_id: str | None = None,
    pe_metadata: dict | None = None,
):
    sha = _sample_sha(tag)
    sample = Sample(
        id=str(uuid.uuid4()),
        sha256=sha,
        sha1="a" * 40,
        md5="b" * 32,
        file_name=f"{tag}.exe",
        file_size=16384,
        is_pe=True,
        pe_metadata=pe_metadata or {"overall_entropy": 5.4, "is_packed_heuristic": False},
        quarantine_path=f"/tmp/malbox_test_{tag}.bin",
    )
    db_session.add(sample)
    analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type=backend_type,
        replay_scenario_id=replay_scenario_id,
        profile="default",
        timeout_seconds=60,
        live_mode=(backend_type == "cape"),
        approved_by_user=(backend_type == "cape"),
    )
    db_session.add(analysis)
    db_session.commit()
    db_session.refresh(sample)
    db_session.refresh(analysis)
    return sample, analysis


def _create_static_record(
    db_session,
    sample: Sample,
    analysis_id: str | None,
    *,
    status: str = "COMPLETED",
    imports: List[tuple[str, str]] | None = None,
    string_values: List[str] | None = None,
    extra_funcs: List[FunctionMetadata] | None = None,
    is_partial: bool = False,
):
    sha = sample.sha256
    imports = imports if imports is not None else []
    string_values = string_values if string_values is not None else []

    imp_models = [ImportedSymbol(library=lib, name=name, address="0x402000") for lib, name in imports]
    api_names = [name for _, name in imports]
    fn_id = make_static_function_id(sha, "0x401000")
    funcs = [
        FunctionMetadata(
            function_id=fn_id,
            entry_address="0x401000",
            name="main_dispatch",
            size_bytes=220,
            basic_block_count=8,
            is_executed=False,
            imported_api_calls=api_names,
            rank_score=8.5,
        )
    ]
    if extra_funcs:
        funcs.extend(extra_funcs)

    strs = [
        StaticStringEvidence(
            string_id=make_static_string_id(sha, hex(0x403000 + i * 16)),
            address=hex(0x403000 + i * 16),
            value=val,
            length=len(val),
            section=".rdata",
            referencing_function_ids=[fn_id],
        )
        for i, val in enumerate(string_values)
    ]

    static_res = StaticAnalysisResult(
        status=status,  # type: ignore[arg-type]
        provenance=StaticAnalysisProvenance(
            analysis_id=analysis_id,
            sample_id=sample.id,
            sample_sha256=sha,
            ghidra_version="12.1.4",
            os_sandbox="bwrap",
        ),
        program_metadata=ProgramMetadata(
            program_name=sample.file_name,
            architecture="x86",
            address_size=32,
            total_functions_discovered=len(funcs),
            total_imports=len(imp_models),
            total_strings=len(strs),
        ),
        functions=funcs,
        imports=imp_models,
        strings=strs,
        truncation=StaticAnalysisTruncation(
            truncated=is_partial,
            functions_discovered=len(funcs),
            functions_included=len(funcs),
            strings_included=len(strs),
        ),
        is_partial=is_partial,
    )
    rec = StaticAnalysisRecord(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        analysis_id=analysis_id,
        sample_sha256=sha,
        status=status,
        ghidra_version="12.1.4",
        is_partial=is_partial,
        result_json=static_res.model_dump(mode="json"),
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(rec)
    db_session.commit()
    return rec, static_res


# ---------------------------------------------------------------------------
# 1 & 2. Sample SHA-256 Matching & Cross-Sample Contamination Rejection
# ---------------------------------------------------------------------------
def test_1_and_2_matching_sha_and_cross_sample_contamination_rejected(db_session):
    sample, analysis = _create_sample_and_analysis(db_session, tag="match_sha", backend_type="cape")
    _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("KERNEL32.dll", "CreateFileW"), ("KERNEL32.dll", "WriteFile")],
    )
    ev = AnalysisEvent(
        analysis_id=analysis.id,
        category="file",
        action="write",
        timestamp=datetime.now(timezone.utc),
        process_id=101,
        process_name="match_sha.exe",
        target_path="C:\\Temp\\out.bin",
        attributes={"is_dropped_binary": True},
        source_tool="sandbox-fsmon",
    )
    db_session.add(ev)
    db_session.commit()

    res = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    assert res.status == "COMPLETED"
    assert res.provenance.sample_identity_verified is True
    assert res.provenance.sample_sha256 == sample.sha256
    assert any(f.relationship == "CONSISTENT_WITH" for f in res.findings)

    # Cross-sample contamination: static result from a different SHA-256 MUST fail closed
    other_sample, _ = _create_sample_and_analysis(db_session, tag="other_sample", backend_type="cape")
    _, bad_static = _create_static_record(
        db_session,
        other_sample,
        analysis.id,
        imports=[("WININET.dll", "InternetOpenW")],
    )
    contaminated = EvidenceCorrelationEngine(db_session).correlate(analysis.id, static_override=bad_static)
    assert contaminated.status == "FAILED"
    assert contaminated.provenance.sample_identity_verified is False
    assert contaminated.findings == []
    assert any("Cross-sample static contamination rejected" in err for err in contaminated.errors)


# ---------------------------------------------------------------------------
# 3. Static API Presence Without Runtime Execution
# ---------------------------------------------------------------------------
def test_3_static_api_presence_without_runtime_execution_never_claims_execution(db_session):
    sample, analysis = _create_sample_and_analysis(db_session, tag="dormant_cap", backend_type="cape")
    _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[
            ("WININET.dll", "InternetOpenW"),
            ("WININET.dll", "HttpSendRequestW"),
            ("ADVAPI32.dll", "RegSetValueExW"),
        ],
    )
    # Zero network or registry runtime events occurred (only benign root process start)
    db_session.add(
        AnalysisEvent(
            analysis_id=analysis.id,
            category="process",
            action="spawn",
            process_id=500,
            process_name="dormant_cap.exe",
            source_tool="sandbox-monitor",
        )
    )
    db_session.commit()

    res = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    assert res.status in ("COMPLETED", "INSUFFICIENT_EVIDENCE")
    assert len(res.findings) >= 2
    for f in res.findings:
        assert f.relationship == "INSUFFICIENT_EVIDENCE"
        assert f.behavioral_execution_directly_observed is False
        assert f.dynamic_references == []


# ---------------------------------------------------------------------------
# 4. Valid Normalized API/Event Relationships & Direct Trace Invariants
# ---------------------------------------------------------------------------
def test_4_normalized_api_matching_and_execution_invariant(db_session):
    # Pydantic schema refuses directly_observed=True without DIRECTLY_OBSERVED + non-synthetic dynamic ref
    with pytest.raises(ValidationError):
        CorrelationFinding(
            correlation_id="corr:deadbeef1111",
            rule_id="RULE_TEST",
            analysis_id="ana_1",
            sample_sha256="a" * 64,
            static_references=[],
            dynamic_references=[],
            relationship="CONSISTENT_WITH",
            relationship_summary="bad",
            explanation="bad",
            confidence=CorrelationConfidence(score=0.5, level="medium", rationale="test"),
            behavioral_execution_directly_observed=True,
        )

    sample, analysis = _create_sample_and_analysis(db_session, tag="api_norm", backend_type="cape")
    _, static_res = _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("WININET.dll", "InternetOpenW")],
    )
    fn_id = static_res.functions[0].function_id

    ts = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)
    # Untraced runtime API call -> CONSISTENT_WITH (not DIRECTLY_OBSERVED)
    ev_api = AnalysisEvent(
        analysis_id=analysis.id,
        category="api",
        action="call",
        timestamp=ts,
        process_id=700,
        process_name="api_norm.exe",
        attributes={"api": "InternetOpenW"},
        source_tool="sandbox-apimon",
    )
    db_session.add(ev_api)
    db_session.commit()

    res1 = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    api_findings = [f for f in res1.findings if f.rule_id == "CORR_API_CAPABILITY_VS_RUNTIME_API"]
    assert len(api_findings) == 1
    assert api_findings[0].relationship == "CONSISTENT_WITH"
    assert api_findings[0].behavioral_execution_directly_observed is False
    assert api_findings[0].dynamic_references[0].timestamp is not None
    assert api_findings[0].dynamic_references[0].timestamp.startswith("2026-11-10T12:00:00")
    assert api_findings[0].dynamic_references[0].source_tool == "sandbox-apimon"

    # Trusted non-replay tracer binding verified function_id -> DIRECTLY_OBSERVED
    ev_traced = AnalysisEvent(
        analysis_id=analysis.id,
        category="api",
        action="call",
        timestamp=ts + timedelta(seconds=1),
        process_id=700,
        process_name="api_norm.exe",
        attributes={
            "api": "InternetOpenW",
            "trace_verified": True,
            "function_id": fn_id,
            "function_address": "0x401000",
        },
        source_tool="frida-tracer",
    )
    db_session.add(ev_traced)
    db_session.commit()

    res2 = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    direct = [f for f in res2.findings if f.relationship == "DIRECTLY_OBSERVED"]
    assert len(direct) == 1
    assert direct[0].behavioral_execution_directly_observed is True
    assert any(r.ref_id == fn_id for r in direct[0].static_references)


# ---------------------------------------------------------------------------
# 5, 6, 7. Missing Function IDs, Missing/Cross-Analysis Event IDs, Wrong Analysis ID
# ---------------------------------------------------------------------------
def test_5_6_7_missing_ids_and_wrong_analysis_id(client, db_session):
    # Prevent FastAPI lifespan's background job polling thread from sharing SQLite StaticPool
    job_queue_manager.stop()
    sample, analysis = _create_sample_and_analysis(db_session, tag="missing_ids", backend_type="cape")
    other_sample, other_analysis = _create_sample_and_analysis(db_session, tag="other_ana", backend_type="cape")

    bad_fn = FunctionMetadata(
        function_id=f"func:{other_sample.sha256[:16]}:0x409999",
        entry_address="0x409999",
        name="foreign_fn",
        imported_api_calls=["WinExec"],
    )
    _, static_res = _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("KERNEL32.dll", "CreateFileW")],
        extra_funcs=[bad_fn],
    )

    from app.services.evidence_correlation.verifier import validate_runtime_events, verify_correlation_inputs

    ctx = verify_correlation_inputs(db_session, analysis, static_override=static_res)
    assert bad_fn.function_id not in ctx.valid_function_ids
    assert any("Filtered unverified/cross-sample static function_id" in w for w in ctx.warnings)

    foreign_ev = AnalysisEvent(
        id="ev_foreign_1",
        analysis_id=other_analysis.id,
        category="file",
        action="write",
        source_tool="sandbox-fsmon",
    )
    verified_evs, valid_ev_ids, ev_warnings, _ = validate_runtime_events(
        [foreign_ev], analysis_id=analysis.id, is_replay=False
    )
    assert verified_evs == []
    assert "ev_foreign_1" not in valid_ev_ids
    assert any("Rejected cross-analysis event" in w for w in ev_warnings)

    # Wrong analysis ID returns 404 safely on API
    assert client.get("/api/v1/analyses/does-not-exist/correlation").status_code == 404


# ---------------------------------------------------------------------------
# 8. Sample-Level Static Result Reuse Detection
# ---------------------------------------------------------------------------
def test_8_sample_level_static_reuse_explicitly_recorded(db_session):
    sample, a1 = _create_sample_and_analysis(db_session, tag="reuse_bin", backend_type="cape")
    a2 = Analysis(
        id=str(uuid.uuid4()),
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="cape",
    )
    db_session.add(a2)
    db_session.commit()

    _create_static_record(
        db_session,
        sample,
        a1.id,
        imports=[("ADVAPI32.dll", "RegSetValueExW")],
    )
    db_session.add(
        AnalysisEvent(
            analysis_id=a2.id,
            category="registry",
            action="reg_write",
            target_path="HKCU\\Software\\Test",
            attributes={"persistence": True},
            source_tool="sandbox-regmon",
        )
    )
    db_session.commit()

    res = EvidenceCorrelationEngine(db_session).correlate(a2.id)
    assert res.provenance.static_reuse_detected is True
    assert res.provenance.static_analysis_id == a1.id
    assert res.provenance.static_provenance_scope == "sample_fallback"
    assert res.limitations.sample_level_static_reuse is True
    assert any(a1.id in item for item in res.limitations.items)


# ---------------------------------------------------------------------------
# 9. Replay Synthetic Provenance (WannaCry & RedLine) + Adversarial Bypass Block
# ---------------------------------------------------------------------------
def test_9_replay_wannacry_and_redline_strict_synthetic_provenance_and_adversarial_block(db_session):
    # Test A: WannaCry Replay scenario + static WannaCry-like capabilities
    wc_fixture = Path(settings.FIXTURES_DIR) / "ransomware_wannacry_mock.json"
    import json

    wc_raw = json.loads(wc_fixture.read_text(encoding="utf-8"))
    s_wc, a_wc = _create_sample_and_analysis(
        db_session,
        tag="wannacry_replay",
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    TelemetryNormalizer(db_session).normalize_sandbox_output(a_wc.id, wc_raw)
    _, wc_static = _create_static_record(
        db_session,
        s_wc,
        a_wc.id,
        imports=[
            ("KERNEL32.dll", "CreateFileW"),
            ("KERNEL32.dll", "WriteFile"),
            ("ADVAPI32.dll", "CryptEncrypt"),
            ("ADVAPI32.dll", "RegSetValueExW"),
            ("KERNEL32.dll", "CreateProcessW"),
            ("WS2_32.dll", "connect"),
        ],
        string_values=[
            "vssadmin.exe delete shadows /all /quiet",
            "CurrentVersion\\Run",
            "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        ],
    )
    # Inject adversarial fabricated trace event inside Replay mode attempting to spoof DIRECTLY_OBSERVED
    db_session.add(
        AnalysisEvent(
            analysis_id=a_wc.id,
            category="api",
            action="call",
            timestamp=datetime.now(timezone.utc),
            process_name="wannacry_variant_sample.exe",
            attributes={
                "api": "CryptEncrypt",
                "trace_verified": True,
                "is_synthetic": False,
                "function_id": wc_static.functions[0].function_id,
                "function_address": "0x401000",
            },
            source_tool="frida-tracer",
        )
    )
    db_session.commit()

    corr_wc = EvidenceCorrelationEngine(db_session).correlate(a_wc.id)
    assert corr_wc.provenance.is_replay is True
    assert corr_wc.summary.directly_observed_count == 0
    assert corr_wc.summary.synthetic_scenario_only_count >= 4
    for f in corr_wc.findings:
        assert f.behavioral_execution_directly_observed is False
        assert f.relationship != "DIRECTLY_OBSERVED"
        assert f.relationship == "SYNTHETIC_SCENARIO_ONLY"
        for d in f.dynamic_references:
            assert d.is_synthetic is True

    # Test B: RedLine Replay scenario + string/endpoint correlation
    rl_fixture = Path(settings.FIXTURES_DIR) / "infostealer_redline_mock.json"
    rl_raw = json.loads(rl_fixture.read_text(encoding="utf-8"))
    s_rl, a_rl = _create_sample_and_analysis(
        db_session,
        tag="redline_replay",
        backend_type="replay",
        replay_scenario_id="infostealer_redline_mock",
    )
    TelemetryNormalizer(db_session).normalize_sandbox_output(a_rl.id, rl_raw)
    _create_static_record(
        db_session,
        s_rl,
        a_rl.id,
        imports=[
            ("WININET.dll", "HttpSendRequestW"),
            ("ADVAPI32.dll", "RegQueryValueExW"),
            ("KERNEL32.dll", "CreateProcessW"),
        ],
        string_values=[
            "http://c2-collector-node9.xyz:8080/gate.php",
            "c2-collector-node9.xyz",
            "MachineGuid",
        ],
    )
    corr_rl = EvidenceCorrelationEngine(db_session).correlate(a_rl.id)
    assert corr_rl.summary.directly_observed_count == 0
    str_matches = [f for f in corr_rl.findings if f.rule_id == "CORR_STATIC_STRING_IOC_MATCH"]
    assert len(str_matches) == 1
    assert str_matches[0].relationship == "SYNTHETIC_SCENARIO_ONLY"
    assert str_matches[0].behavioral_execution_directly_observed is False


# ---------------------------------------------------------------------------
# 10, 11, 12, 13. No Correlation, Conflicting, Packed/Partial, Malformed
# ---------------------------------------------------------------------------
def test_10_11_12_13_no_correlation_conflict_packed_partial_and_malformed_telemetry(db_session):
    # 10. Legitimate no-correlation (benign static without monitored APIs + 0 events)
    s_clean, a_clean = _create_sample_and_analysis(db_session, tag="clean_empty", backend_type="cape")
    _create_static_record(db_session, s_clean, a_clean.id, imports=[("KERNEL32.dll", "GetTickCount")])
    res_empty = EvidenceCorrelationEngine(db_session).correlate(a_clean.id)
    assert res_empty.status == "INSUFFICIENT_EVIDENCE"
    assert res_empty.findings == []

    # 11 & 12. Packed + PARTIAL Ghidra output vs rich dynamic behavior -> CONTRADICTORY + PARTIAL
    s_pack, a_pack = _create_sample_and_analysis(
        db_session,
        tag="packed_upx",
        backend_type="cape",
        pe_metadata={"overall_entropy": 7.65, "is_packed_heuristic": True},
    )
    _create_static_record(
        db_session,
        s_pack,
        a_pack.id,
        status="PARTIAL",
        imports=[("KERNEL32.dll", "LoadLibraryA"), ("KERNEL32.dll", "GetProcAddress")],
        string_values=["http", "windows"],  # Ambiguous noise strings suppressed safely
        is_partial=True,
    )
    # Malformed + multi-domain dynamic events
    db_session.add_all(
        [
            AnalysisEvent(
                analysis_id=a_pack.id,
                category="network",
                action="connect",
                target_path="198.51.100.42:443",
                attributes={"dest_ip": "198.51.100.42", "dest_port": 443},
                source_tool="sandbox-netmon",
            ),
            AnalysisEvent(
                analysis_id=a_pack.id,
                category="registry",
                action="reg_write",
                target_path="HKCU\\Run\\Evil",
                attributes="corrupted-string-attributes",  # type: ignore[arg-type]
                source_tool="sandbox-regmon",
            ),
            AnalysisEvent(
                analysis_id=a_pack.id,
                category="process",
                action="spawn",
                process_name="cmd.exe",
                attributes={"command_line": "cmd.exe /c whoami"},
                source_tool="sandbox-monitor",
            ),
            AnalysisEvent(
                analysis_id=a_pack.id,
                category="",
                action="",
                source_tool="broken-sensor",
            ),
        ]
    )
    db_session.commit()

    res_pack = EvidenceCorrelationEngine(db_session).correlate(a_pack.id)
    assert res_pack.status == "PARTIAL"
    assert res_pack.limitations.partial_static_coverage is True
    assert res_pack.limitations.suppressed_ambiguous_count >= 2
    assert any("non-dict attributes" in w for w in res_pack.warnings)
    assert any("missing category/action" in w for w in res_pack.warnings)
    conflicts = [f for f in res_pack.findings if f.relationship == "CONTRADICTORY"]
    assert len(conflicts) == 1
    assert "high-entropy/packed" in conflicts[0].explanation


# ---------------------------------------------------------------------------
# 14 & 15. Large 10,000+ Event Scale, Byte Caps, Deterministic Idempotency & Auth API
# ---------------------------------------------------------------------------
def test_14_15_and_19_and_20_scale_caps_idempotency_api_auth_no_spawns_and_preserve_on_failure(
    client, db_session, monkeypatch
):
    job_queue_manager.stop()
    sample, analysis = _create_sample_and_analysis(db_session, tag="scale_test", backend_type="cape")
    _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[
            ("KERNEL32.dll", "WriteFile"),
            ("WININET.dll", "InternetOpenW"),
            ("ADVAPI32.dll", "RegSetValueExW"),
            ("KERNEL32.dll", "CreateProcessW"),
        ],
    )

    # Bulk insert 10,050 events (must run quickly & enforce bounded scan + truncation)
    base_ts = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
    bulk = [
        AnalysisEvent(
            id=f"ev_bulk_{i:05d}",
            analysis_id=analysis.id,
            category="network" if i == 5 else "file",
            action="connect" if i == 5 else "read",
            timestamp=base_ts + timedelta(milliseconds=i),
            target_path="198.51.100.77:8080" if i == 5 else f"C:\\noise\\f_{i}.txt",
            attributes={"dest_ip": "198.51.100.77"} if i == 5 else {},
            source_tool="sandbox-netmon" if i == 5 else "sandbox-fsmon",
        )
        for i in range(10050)
    ]
    db_session.bulk_save_objects(bulk)
    db_session.commit()

    # Never invoke Ghidra, CAPE, or OpenCode during correlation!
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.GhidraStaticAnalyzer.analyze_sample",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("Ghidra must NEVER run during correlation!")),
    )
    monkeypatch.setattr(
        "app.services.sandbox.cape.CapeSandboxBackend.submit_sample",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("CAPE must NEVER run during correlation!")),
    )
    monkeypatch.setattr(
        "app.ai.opencode_provider.OpenCodeReportProvider.generate_intelligence_report",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("OpenCode must NEVER run during correlation!")),
    )

    t0 = time.monotonic()
    res_a = EvidenceCorrelationEngine(db_session, max_events=250, max_bytes=16384).correlate(analysis.id)
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0
    assert res_a.truncation.total_events_in_analysis == 10050
    assert res_a.truncation.events_scanned == 250
    assert res_a.truncation.events_omitted == 9800
    assert res_a.truncation.truncated is True
    assert res_a.truncation.serialized_bytes <= 16384

    # Tight byte cap test enforces truncation cleanly (engine minimum ceiling is 8192 bytes)
    res_tight = EvidenceCorrelationEngine(db_session, max_events=250, max_bytes=8192).correlate(analysis.id)
    assert res_tight.truncation.serialized_bytes <= 8192
    assert res_tight.truncation.findings_omitted >= 1

    # Deterministic repeatability
    res_b = EvidenceCorrelationEngine(db_session, max_events=250, max_bytes=16384).correlate(analysis.id)
    assert [f.correlation_id for f in res_a.findings] == [f.correlation_id for f in res_b.findings]
    assert [f.rule_id for f in res_a.findings] == [f.rule_id for f in res_b.findings]

    # Auth enforcement on POST /correlation + GET read-only + idempotent reuse + preserve on failure
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "")
    assert client.post(f"/api/v1/analyses/{analysis.id}/correlation").status_code == 403

    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "corr-secret-token")
    assert (
        client.post(
            f"/api/v1/analyses/{analysis.id}/correlation",
            headers={"X-Reporting-Token": "wrong"},
        ).status_code
        == 401
    )

    uncomputed_get = client.get(f"/api/v1/analyses/{analysis.id}/correlation")
    assert uncomputed_get.status_code == 200
    assert uncomputed_get.json()["provenance"]["source_fingerprint"] == "uncomputed"

    post1 = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "corr-secret-token"},
    )
    assert post1.status_code == 200
    good_body = post1.json()
    assert len(good_body["findings"]) >= 1

    # Second POST without evidence change returns idempotently without creating duplicate DB rows
    post2 = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "corr-secret-token"},
    )
    assert post2.status_code == 200
    assert post2.json()["provenance"]["source_fingerprint"] == good_body["provenance"]["source_fingerprint"]
    row_count = (
        db_session.query(StaticDynamicCorrelationRecord)
        .filter(StaticDynamicCorrelationRecord.analysis_id == analysis.id)
        .count()
    )
    assert row_count == 1

    # Forced failure preserves previous good result cleanly!
    monkeypatch.setattr(
        "app.services.evidence_correlation.engine.EvidenceCorrelationEngine.correlate",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("synthetic engine crash")),
    )
    post_fail = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        json={"force": True},
        headers={"X-Reporting-Token": "corr-secret-token"},
    )
    assert post_fail.status_code == 200
    preserved_body = post_fail.json()
    assert len(preserved_body["findings"]) == len(good_body["findings"])
    assert any("preserved previous usable result" in w for w in preserved_body["warnings"])

    get_after_fail = client.get(f"/api/v1/analyses/{analysis.id}/correlation")
    assert get_after_fail.status_code == 200
    assert len(get_after_fail.json()["findings"]) == len(good_body["findings"])


# ---------------------------------------------------------------------------
# 16, 17, 18. AI Hallucinations, Execution Upgrades, Score Invariance, Backward Compat
# ---------------------------------------------------------------------------
def test_16_17_18_intelligence_validator_score_invariance_and_backward_compat(db_session):
    sample, analysis = _create_sample_and_analysis(
        db_session,
        tag="intel_corr",
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("ADVAPI32.dll", "CryptEncrypt")],
    )
    ev = AnalysisEvent(
        id="ev_intel_1",
        analysis_id=analysis.id,
        category="file",
        action="write",
        target_path="C:\\Users\\Victim\\doc.wnry",
        attributes={"is_encrypted_target": True},
        source_tool="sandbox-fsmon",
    )
    finding = BehavioralFinding(
        id="find_intel_1",
        analysis_id=analysis.id,
        rule_id="RULE_MASS_FILE_ENCRYPTION",
        title="High-Entropy File Encryption & Ransom Note Creation",
        description="Observed synthetic encryption.",
        severity="Critical",
        confidence=0.95,
        mitre_attack_id="T1486",
        mitre_tactic="Impact",
        supporting_event_ids=[ev.id],
    )
    db_session.add_all([ev, finding])
    db_session.commit()

    findings, risk = DetectionEngine(db_session).evaluate_behavior(analysis.id)
    bundle = EvidenceBundleBuilder(db_session).build(analysis.id, risk_assessment=risk)
    assert bundle.correlation_summary is not None
    assert len(bundle.correlation_summary.findings) >= 1
    valid_corr_id = bundle.correlation_summary.findings[0]["correlation_id"]
    assert valid_corr_id in bundle.valid_evidence_ids

    # Generate full report and verify risk score invariance
    rep = ReportGenerator(db_session).generate_report(analysis.id, risk_assessment=risk)
    assert rep.risk_score == risk.score
    assert rep.full_report_json["risk_assessment"]["score"] == risk.score
    assert rep.full_report_json["intelligence_report"]["deterministic_risk_score"] == risk.score
    assert rep.full_report_json["intelligence_report"]["correlation_summary"] is not None

    # Adversarial validator checks:
    provider_meta = AIProviderMetadata(
        mode="llm_enriched",
        provider="mock",
        model="test",
        rules_version="2.0",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    from app.ai.intelligence_helper import build_deterministic_proposed_intelligence

    base_prop = build_deterministic_proposed_intelligence(bundle)

    # 16a: AI hallucinated correlation ID & attempted weak correlation upgrade to proven execution
    bad_claims = [
        ProposedClaim(
            claim_id="CLM-BAD-ID",
            classification="FACT",
            claim_text="Correlation corr:0000deadbeef directly aligns.",
            supporting_evidence_ids=["corr:0000deadbeef"],
            confidence=0.9,
        ),
        ProposedClaim(
            claim_id="CLM-UPGRADE",
            classification="FACT",
            claim_text=f"Correlation {valid_corr_id} is directly observed proven execution of main_dispatch.",
            supporting_evidence_ids=[valid_corr_id],
            confidence=0.95,
        ),
    ]
    bad_prop = base_prop.model_copy(update={"technical_claims": bad_claims})
    validated_rep = EvidenceValidator().validate_and_finalize(
        raw_output=bad_prop,
        bundle=bundle,
        provider_meta=provider_meta,
        fallback_fn=build_deterministic_proposed_intelligence,
    )
    by_id = {c.claim_id: c for c in validated_rep.technical_claims}
    assert by_id["CLM-BAD-ID"].validation_status == "REJECTED"
    assert by_id["CLM-UPGRADE"].validation_status == "REJECTED"
    assert "corr:0000deadbeef" in validated_rep.validation_summary.removed_invalid_evidence_ids

    # 16b: Injected fake correlation entry citing nonexistent func & event ID inside bundle.correlation_summary
    corrupted_corr_section = CorrelationBundleSection(
        status="COMPLETED",
        is_replay=True,
        summary={"total_findings": 1},
        findings=[
            {
                "correlation_id": "corr:fakeinjected",
                "rule_id": "CORR_FAKE",
                "relationship": "DIRECTLY_OBSERVED",
                "relationship_summary": "Injected fake execution claim",
                "explanation": "Injected",
                "confidence_score": 0.99,
                "confidence_level": "high",
                "behavioral_execution_directly_observed": True,
                "static_ref_ids": ["func:deadbeefdeadbeef:0x999999"],
                "dynamic_ref_ids": ["ev-nonexistent-999"],
                "known_limitations": [],
            }
        ],
    )
    corrupted_bundle = bundle.model_copy(
        update={
            "correlation_summary": corrupted_corr_section,
            "valid_evidence_ids": [*bundle.valid_evidence_ids, "corr:fakeinjected"],
        }
    )
    res_corrupt = EvidenceValidator().validate_and_finalize(
        raw_output=build_deterministic_proposed_intelligence(bundle),
        bundle=corrupted_bundle,
        provider_meta=provider_meta,
        fallback_fn=build_deterministic_proposed_intelligence,
    )
    assert res_corrupt.correlation_summary is not None
    assert res_corrupt.correlation_summary.findings == []
    assert "corr:fakeinjected" in res_corrupt.validation_summary.removed_invalid_evidence_ids

    # 18. Backward compatibility with old IntelligenceReport JSON lacking correlation_summary
    legacy_intel_dict = validated_rep.model_dump(mode="json")
    legacy_intel_dict.pop("correlation_summary", None)
    parsed_legacy = IntelligenceReport.model_validate(legacy_intel_dict)
    assert parsed_legacy.correlation_summary is None

    legacy_full_dict = dict(rep.full_report_json)
    legacy_full_dict["intelligence_report"] = legacy_intel_dict
    parsed_full_legacy = FullReportSchema.model_validate(legacy_full_dict)
    assert parsed_full_legacy.intelligence_report is not None
    assert parsed_full_legacy.intelligence_report.correlation_summary is None
