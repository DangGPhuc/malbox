from __future__ import annotations

import hashlib
import json
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
    StaticAnalysisPlaceholder,
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
    CorrelationLimitations,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationTruncation,
)
from app.services.evidence_correlation.service import EvidenceCorrelationService
from app.services.evidence_correlation.verifier import (
    compute_authenticated_trace_proof,
    validate_runtime_events,
    verify_correlation_inputs,
)
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
    image_base: str | None = "0x400000",
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
            image_base=image_base,
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

    # Spoofed non-replay tracer without backend trace_auth -> downgraded to CONSISTENT_WITH!
    ev_spoofed = AnalysisEvent(
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
    db_session.add(ev_spoofed)
    db_session.commit()

    res2 = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    assert [f for f in res2.findings if f.relationship == "DIRECTLY_OBSERVED"] == []
    assert any("Unauthenticated trace metadata" in w for w in res2.warnings)

    # Backend-authenticated HMAC trace provenance with valid module, ASLR base, IP range, and matching API -> DIRECTLY_OBSERVED
    trace_proof = compute_authenticated_trace_proof(
        analysis_id=analysis.id,
        sample_sha256=sample.sha256,
        trace_session_id="sess-trace-001",
        source_tool="backend-callstack-verifier",
        module_name=sample.file_name,
        module_base="0x10000000",
        instruction_pointer="0x10001028",  # maps to static 0x401028 inside [0x401000, 0x4010dc)
        function_id=fn_id,
        function_address="0x401000",
        api_name="InternetOpenW",
    )
    ev_traced = AnalysisEvent(
        analysis_id=analysis.id,
        category="api",
        action="call",
        timestamp=ts + timedelta(seconds=2),
        process_id=700,
        process_name="api_norm.exe",
        attributes={
            "api": "InternetOpenW",
            "trace_auth": trace_proof,
        },
        source_tool="backend-callstack-verifier",
    )
    db_session.add(ev_traced)
    db_session.commit()

    res3 = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    direct = [f for f in res3.findings if f.relationship == "DIRECTLY_OBSERVED"]
    assert len(direct) == 1
    assert direct[0].behavioral_execution_directly_observed is True
    assert direct[0].dynamic_references[0].trace_verified is True
    assert res3.limitations.has_runtime_function_trace is True
    assert res3.provenance.trace_verification_mode == "authenticated_runtime_trace_verified"
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


# ===========================================================================
# PHASE 4A.1 REGRESSION SUITE (TASKS 1 - 6 HARDENING VERIFICATION)
# ===========================================================================


def test_21_forged_tracer_names_and_unauthenticated_trace_flags_rejected(db_session):
    """Tasks 1/R1/R2/R6: Forged source_tool names and raw trace_verified=True never emit DIRECTLY_OBSERVED."""
    sample, analysis = _create_sample_and_analysis(db_session, tag="forged_tracers", backend_type="cape")
    _, static_res = _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("WININET.dll", "InternetOpenW")],
    )
    fn_id = static_res.functions[0].function_id
    ts = datetime(2026, 11, 10, 14, 0, 0, tzinfo=timezone.utc)

    for idx, forged_tool in enumerate(("frida-tracer", "cape-tracer", "etw-callstack", "pin-tracer")):
        db_session.add(
            AnalysisEvent(
                id=f"ev_forged_{idx}",
                analysis_id=analysis.id,
                category="api",
                action="call",
                timestamp=ts + timedelta(seconds=idx),
                process_id=100 + idx,
                process_name="forged_tracers.exe",
                attributes={
                    "api": "InternetOpenW",
                    "trace_verified": True,
                    "function_id": fn_id,
                    "function_address": "0x401000",
                },
                source_tool=forged_tool,
            )
        )
    db_session.commit()

    res = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    assert res.status == "COMPLETED"
    assert [f for f in res.findings if f.relationship == "DIRECTLY_OBSERVED"] == []
    assert all(not f.behavioral_execution_directly_observed for f in res.findings)
    assert any(f.relationship == "CONSISTENT_WITH" for f in res.findings)
    assert res.limitations.has_runtime_function_trace is False
    assert res.provenance.trace_verification_mode == "unauthenticated_or_mismatched_trace_rejected"

    # Also enforce CorrelationFinding Pydantic schema invariant when static_references or trace_verified missing
    with pytest.raises(ValidationError):
        CorrelationFinding(
            correlation_id="corr:deadbeef2222",
            rule_id="RULE_TEST",
            analysis_id=analysis.id,
            sample_sha256=sample.sha256,
            static_references=[],
            dynamic_references=[
                CorrelationEvidenceReference(
                    ref_id="ev_forged_0",
                    evidence_kind="dynamic_event",
                    source_tool="frida-tracer",
                    summary="missing trace_verified",
                    is_synthetic=False,
                    trace_verified=True,
                )
            ],
            relationship="DIRECTLY_OBSERVED",
            relationship_summary="bad",
            explanation="bad",
            confidence=CorrelationConfidence(score=0.9, level="high", rationale="bad"),
            behavioral_execution_directly_observed=True,
        )
    with pytest.raises(ValidationError):
        CorrelationFinding(
            correlation_id="corr:deadbeef3333",
            rule_id="RULE_TEST",
            analysis_id=analysis.id,
            sample_sha256=sample.sha256,
            static_references=[
                CorrelationEvidenceReference(
                    ref_id=fn_id,
                    evidence_kind="static_function",
                    source_tool="ghidra_headless",
                    summary="fn",
                )
            ],
            dynamic_references=[
                CorrelationEvidenceReference(
                    ref_id="ev_forged_0",
                    evidence_kind="dynamic_event",
                    source_tool="sandbox-apimon",
                    summary="unverified dynamic",
                    is_synthetic=False,
                    trace_verified=False,
                )
            ],
            relationship="DIRECTLY_OBSERVED",
            relationship_summary="bad",
            explanation="bad",
            confidence=CorrelationConfidence(score=0.9, level="high", rationale="bad"),
            behavioral_execution_directly_observed=True,
        )


def test_22_trace_provenance_mismatches_and_replay_override_blocked(db_session):
    """Tasks 1/R3/R4/R5: Unrelated API, wrong module/base/IP/SHA, and Replay never yield DIRECTLY_OBSERVED."""
    sample, analysis = _create_sample_and_analysis(db_session, tag="trace_mismatch", backend_type="cape")
    other_sample, other_analysis = _create_sample_and_analysis(db_session, tag="other_sample", backend_type="cape")
    # Static function imports InternetOpenW only (NOT RegSetValueExW)
    _, static_res = _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("WININET.dll", "InternetOpenW"), ("ADVAPI32.dll", "RegSetValueExW")],
        extra_funcs=[
            FunctionMetadata(
                function_id=make_static_function_id(sample.sha256, "0x402500"),
                entry_address="0x402500",
                name="internet_only_fn",
                size_bytes=96,
                is_executed=False,
                imported_api_calls=["InternetOpenW"],
            )
        ],
    )
    internet_fn_id = make_static_function_id(sample.sha256, "0x402500")
    ts = datetime(2026, 11, 10, 14, 15, 0, tzinfo=timezone.utc)

    common = dict(
        analysis_id=analysis.id,
        sample_sha256=sample.sha256,
        trace_session_id="sess-bad-cases",
        source_tool="backend-callstack-verifier",
        module_name=sample.file_name,
        module_base="0x400000",
        instruction_pointer="0x402520",
        function_id=internet_fn_id,
        function_address="0x402500",
        api_name="InternetOpenW",
    )

    bad_cases = [
        # (event_api, override dict)
        ("RegSetValueExW", {**common, "api_name": "RegSetValueExW"}),  # R3: valid fn_id paired with API not imported by fn
        ("InternetOpenW", {**common, "module_name": "ntdll.dll"}),  # R4: wrong module
        ("InternetOpenW", {**common, "module_base": "0x77000000"}),  # R4: wrong loaded module_base
        ("InternetOpenW", {**common, "instruction_pointer": "0x402999"}),  # R4: IP outside [0x402500, 0x402560)
        ("InternetOpenW", {**common, "sample_sha256": other_sample.sha256}),  # R4: wrong SHA-256
        ("InternetOpenW", {**common, "analysis_id": other_analysis.id}),  # R4: wrong analysis_id
        (
            "InternetOpenW",
            {**common, "hmac_sha256_tamper": True},
        ),
    ]

    for idx, (ev_api, cfg) in enumerate(bad_cases):
        tamper = cfg.pop("hmac_sha256_tamper", False)
        proof = compute_authenticated_trace_proof(**cfg)
        if tamper:
            proof["hmac_sha256"] = "f" * 64
        db_session.add(
            AnalysisEvent(
                id=f"ev_bad_trace_{idx}",
                analysis_id=analysis.id,
                category="api",
                action="call",
                timestamp=ts + timedelta(seconds=idx),
                process_id=500 + idx,
                process_name=sample.file_name,
                attributes={"api": ev_api, "trace_auth": proof},
                source_tool="backend-callstack-verifier",
            )
        )
    db_session.commit()

    res = EvidenceCorrelationEngine(db_session).correlate(analysis.id)
    assert [f for f in res.findings if f.relationship == "DIRECTLY_OBSERVED"] == []
    assert res.limitations.has_runtime_function_trace is False
    assert all(not f.behavioral_execution_directly_observed for f in res.findings)

    # R5: Replay mode with validly signed backend trace_auth STILL forbids DIRECTLY_OBSERVED
    rep_sample, rep_analysis = _create_sample_and_analysis(
        db_session,
        tag="replay_signed",
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    _, rep_static = _create_static_record(
        db_session, rep_sample, rep_analysis.id, imports=[("WININET.dll", "InternetOpenW")]
    )
    rep_fn_id = rep_static.functions[0].function_id
    rep_proof = compute_authenticated_trace_proof(
        analysis_id=rep_analysis.id,
        sample_sha256=rep_sample.sha256,
        trace_session_id="sess-replay-spoof",
        source_tool="backend-callstack-verifier",
        module_name=rep_sample.file_name,
        module_base="0x400000",
        instruction_pointer="0x401010",
        function_id=rep_fn_id,
        function_address="0x401000",
        api_name="InternetOpenW",
    )
    db_session.add(
        AnalysisEvent(
            id="ev_replay_signed_1",
            analysis_id=rep_analysis.id,
            category="api",
            action="call",
            timestamp=ts,
            process_name=rep_sample.file_name,
            attributes={"api": "InternetOpenW", "trace_auth": rep_proof},
            source_tool="backend-callstack-verifier",
        )
    )
    db_session.commit()

    rep_res = EvidenceCorrelationEngine(db_session).correlate(rep_analysis.id)
    assert [f for f in rep_res.findings if f.relationship == "DIRECTLY_OBSERVED"] == []
    assert rep_res.provenance.trace_verification_mode == "replay_synthetic_disallowed"
    assert all(f.relationship in ("SYNTHETIC_SCENARIO_ONLY", "INSUFFICIENT_EVIDENCE") for f in rep_res.findings)


def test_23_content_sensitive_streaming_fingerprint_invalidation_and_staleness(client, db_session, monkeypatch):
    """Tasks 2/R7/R8/R9: Middle-event & static result_json edits invalidate fingerprints; unchanged stays idempotent."""
    job_queue_manager.stop()
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "fp-test-token")
    sample, analysis = _create_sample_and_analysis(db_session, tag="fp_drift", backend_type="cape")
    static_rec, static_res = _create_static_record(
        db_session,
        sample,
        analysis.id,
        imports=[("KERNEL32.dll", "WriteFile")],
    )
    base_ts = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)
    evs = [
        AnalysisEvent(
            id=f"ev_fp_{i:02d}",
            analysis_id=analysis.id,
            category="file",
            action="write" if i == 1 else "read",
            timestamp=base_ts + timedelta(seconds=i),
            target_path=f"C:\\work\\file_{i}.dat",
            attributes={"seq": i},
            source_tool="sandbox-fsmon",
        )
        for i in range(5)
    ]
    db_session.add_all(evs)
    db_session.commit()

    post1 = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "fp-test-token"},
    )
    assert post1.status_code == 200
    fp1 = post1.json()["provenance"]["source_fingerprint"]
    assert post1.json()["provenance"]["is_stale"] is False

    # R9: Re-POST with unchanged evidence is strictly idempotent
    post_same = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "fp-test-token"},
    )
    assert post_same.status_code == 200
    assert post_same.json()["provenance"]["source_fingerprint"] == fp1
    assert (
        db_session.query(StaticDynamicCorrelationRecord)
        .filter(StaticDynamicCorrelationRecord.analysis_id == analysis.id)
        .count()
        == 1
    )

    # R7: Mutate middle event (#2 of 0..4) keeping count, first_id, last_id IDENTICAL!
    mid_ev = db_session.query(AnalysisEvent).filter(AnalysisEvent.id == "ev_fp_02").first()
    assert mid_ev is not None
    mid_ev.attributes = {"seq": 2, "tampered": "middle_event_change"}
    mid_ev.target_path = "C:\\Windows\\System32\\evil.dll"
    db_session.commit()

    # GET read-only immediately marks stale rather than serving drifted cache silently
    get_stale = client.get(f"/api/v1/analyses/{analysis.id}/correlation")
    assert get_stale.status_code == 200
    assert get_stale.json()["provenance"]["is_stale"] is True
    assert any("changed since correlation was stored" in w for w in get_stale.json()["warnings"])

    # POST detects drift without force=True and computes updated fingerprint
    post2 = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "fp-test-token"},
    )
    assert post2.status_code == 200
    fp2 = post2.json()["provenance"]["source_fingerprint"]
    assert fp2 != fp1
    assert post2.json()["provenance"]["is_stale"] is False

    # R7b: Middle event deletion + reinsertion changes fingerprint cleanly too
    mid_ev_b = db_session.query(AnalysisEvent).filter(AnalysisEvent.id == "ev_fp_03").first()
    db_session.delete(mid_ev_b)
    db_session.commit()
    fp2_del = EvidenceCorrelationEngine(db_session).preview_source_fingerprint(analysis.id)
    assert fp2_del != fp2

    # R8: In-place mutation of static result_json under the SAME static_record_id invalidates fingerprint
    updated_static = static_res.model_copy(
        update={
            "imports": [
                *static_res.imports,
                ImportedSymbol(library="WININET.dll", name="InternetOpenW", address="0x402010"),
            ]
        }
    )
    static_rec.result_json = updated_static.model_dump(mode="json")
    db_session.commit()

    fp3 = EvidenceCorrelationEngine(db_session).preview_source_fingerprint(analysis.id)
    assert fp3 is not None and fp3 not in (fp1, fp2, fp2_del)
    post3 = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "fp-test-token"},
    )
    assert post3.status_code == 200
    assert post3.json()["provenance"]["source_fingerprint"] == fp3
    assert post3.json()["provenance"]["is_stale"] is False


def test_24_raw_event_orm_immutability_and_malformed_attributes(client, db_session, monkeypatch):
    """Tasks 3/R10/R11: Malformed/normal raw AnalysisEvent rows are never mutated in DB; DTO is frozen."""
    job_queue_manager.stop()
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "immut-token")
    sample, analysis = _create_sample_and_analysis(db_session, tag="raw_immut", backend_type="cape")
    _create_static_record(db_session, sample, analysis.id, imports=[("KERNEL32.dll", "WriteFile")])

    ev_malformed = AnalysisEvent(
        id="ev_malformed_raw",
        analysis_id=analysis.id,
        category="file",
        action="write",
        target_path="C:\\Temp\\note.txt",
        attributes="not-a-dict-raw-forensic-payload",  # type: ignore[arg-type]
        source_tool="sandbox-fsmon",
    )
    ev_normal = AnalysisEvent(
        id="ev_normal_raw",
        analysis_id=analysis.id,
        category="api",
        action="call",
        attributes={"api": "WriteFile", "nested": {"k": "v"}},
        source_tool="sandbox-apimon",
    )
    db_session.add_all([ev_malformed, ev_normal])
    db_session.commit()

    def _snapshot() -> str:
        rows = (
            db_session.query(AnalysisEvent)
            .filter(AnalysisEvent.analysis_id == analysis.id)
            .order_by(AnalysisEvent.id.asc())
            .all()
        )
        return json.dumps(
            [
                {
                    "id": r.id,
                    "category": r.category,
                    "action": r.action,
                    "target_path": r.target_path,
                    "source_tool": r.source_tool,
                    "attributes": r.attributes,
                }
                for r in rows
            ],
            sort_keys=True,
        )

    before_json = _snapshot()

    verified_evs, valid_ids, warnings, _ = validate_runtime_events(
        [ev_malformed, ev_normal],
        analysis_id=analysis.id,
        is_replay=False,
        sample_sha256=sample.sha256,
    )
    assert valid_ids == {"ev_malformed_raw", "ev_normal_raw"}
    assert any("non-dict attributes" in w for w in warnings)
    assert len(db_session.dirty) == 0

    # DTO attributes are strictly immutable MappingProxyType
    with pytest.raises(TypeError):
        verified_evs[1].attributes["injected"] = "mutate"  # type: ignore[index]

    post = client.post(
        f"/api/v1/analyses/{analysis.id}/correlation",
        headers={"X-Reporting-Token": "immut-token"},
    )
    assert post.status_code == 200
    after_json = _snapshot()
    assert after_json == before_json
    db_session.refresh(ev_malformed)
    assert ev_malformed.attributes == "not-a-dict-raw-forensic-payload"


def test_25_hard_serialized_byte_cap_across_all_statuses_and_empty_findings(db_session):
    """Tasks 4/R12/R13/R14: Hard max_bytes enforced across COMPLETED/PARTIAL/INSUFFICIENT_EVIDENCE/UNSUPPORTED/FAILED even with findings=[]."""
    sample, analysis = _create_sample_and_analysis(db_session, tag="caps_all", backend_type="cape")
    engine = EvidenceCorrelationEngine(db_session, max_bytes=4096)

    huge_warnings = [f"Warn-{i}-" + ("W" * 600) for i in range(40)]
    huge_errors = [f"Err-{i}-" + ("E" * 600) for i in range(40)]
    huge_limits = [f"Lim-{i}-" + ("L" * 600) for i in range(40)]

    for status_name in ("COMPLETED", "PARTIAL", "INSUFFICIENT_EVIDENCE", "UNSUPPORTED", "FAILED"):
        prov = CorrelationProvenance(
            analysis_id=analysis.id,
            sample_id=sample.id,
            sample_sha256=sample.sha256,
            dynamic_backend="cape",
            is_replay=False,
            sample_identity_verified=True,
            computed_at=datetime.now(timezone.utc).isoformat(),
            source_fingerprint="f" * 64,
        )
        raw_res = CorrelationResult(
            status=status_name,  # type: ignore[arg-type]
            provenance=prov,
            findings=[],
            limitations=CorrelationLimitations(items=list(huge_limits)),
            truncation=CorrelationTruncation(max_serialized_bytes=4096),
            warnings=list(huge_warnings),
            errors=list(huge_errors),
        )
        bounded = engine.enforce_serialized_limit(raw_res)
        encoded = json.dumps(bounded.model_dump(mode="json")).encode("utf-8")
        assert len(encoded) <= 4096
        assert bounded.truncation.serialized_bytes == len(encoded)
        assert bounded.truncation.truncated is True

    # Also test real engine correlate() FAILED & UNSUPPORTED paths with massive warnings/errors from malformed events
    for i in range(60):
        db_session.add(
            AnalysisEvent(
                id=f"ev_warn_{i:02d}",
                analysis_id=analysis.id,
                category="file",
                action="write",
                attributes="corrupted-attr-" + ("X" * 300),  # type: ignore[arg-type]
                source_tool="sandbox-fsmon",
            )
        )
    db_session.commit()
    res_unsupported = EvidenceCorrelationEngine(db_session, max_bytes=4096).correlate(analysis.id)
    assert res_unsupported.status == "UNSUPPORTED"
    assert len(json.dumps(res_unsupported.model_dump(mode="json")).encode("utf-8")) <= 4096

    bad_analysis = Analysis(
        id=str(uuid.uuid4()),
        sample_id="missing-sample-id",
        status=AnalysisStatus.COMPLETED.value,
        backend_type="cape",
        profile="default",
        timeout_seconds=60,
    )
    db_session.add(bad_analysis)
    db_session.commit()
    res_failed = EvidenceCorrelationEngine(db_session, max_bytes=4096).correlate(bad_analysis.id)
    assert res_failed.status == "FAILED"
    assert len(json.dumps(res_failed.model_dump(mode="json")).encode("utf-8")) <= 4096


def test_26_bundle_builder_injected_static_analysis_paths_and_byte_caps(db_session):
    """Tasks 5/R15/R16: Injected build(static_analysis=...) never UnboundLocalErrors, preserves provenance, no fake IDs."""
    sample, analysis = _create_sample_and_analysis(db_session, tag="bundle_inj", backend_type="cape")
    fn_id = make_static_function_id(sample.sha256, "0x401000")
    db_session.add(
        AnalysisEvent(
            id="ev_bundle_inj_1",
            analysis_id=analysis.id,
            category="api",
            action="call",
            target_path="C:\\Windows\\System32\\cmd.exe",
            attributes={"api": "CreateProcessW"},
            source_tool="sandbox-apimon",
        )
    )
    db_session.commit()

    # Path A: injected placeholder with status="not_available"
    placeholder_na = StaticAnalysisPlaceholder(status="not_available", notes="Custom injected note.")
    bundle_na = EvidenceBundleBuilder(db_session).build(analysis.id, static_analysis=placeholder_na)
    assert bundle_na.static_analysis.status == "not_available"
    assert bundle_na.static_analysis.notes == "Custom injected note."
    assert bundle_na.correlation_summary is None

    # Path B: injected placeholder with valid matching SHA-256 & function metadata
    placeholder_ok = StaticAnalysisPlaceholder(
        status="available",
        analysis_id=analysis.id,
        sample_sha256=sample.sha256,
        ghidra_version="12.1.4",
        notes="Injected verified static context.",
        functions=[
            {
                "function_id": fn_id,
                "entry_address": "0x401000",
                "name": "proc_launcher",
                "size_bytes": 160,
                "imported_api_calls": ["CreateProcessW"],
            }
        ],
    )
    bundle_ok = EvidenceBundleBuilder(db_session, max_bundle_bytes=16384).build(
        analysis.id, static_analysis=placeholder_ok
    )
    assert bundle_ok.static_analysis.notes == "Injected verified static context."
    assert bundle_ok.correlation_summary is not None
    assert len(bundle_ok.correlation_summary.findings) >= 1
    assert fn_id in bundle_ok.valid_evidence_ids
    assert len(json.dumps(bundle_ok.model_dump(mode="json")).encode("utf-8")) <= 16384

    # Path C: injected placeholder with mismatched SHA-256 refuses correlation & does not invent IDs
    placeholder_bad_sha = StaticAnalysisPlaceholder(
        status="available",
        sample_sha256="d" * 64,
        functions=[
            {
                "function_id": "func:dddddddddddddddd:0x401000",
                "entry_address": "0x401000",
                "name": "foreign_fn",
                "imported_api_calls": ["CreateProcessW"],
            }
        ],
    )
    bundle_bad = EvidenceBundleBuilder(db_session).build(analysis.id, static_analysis=placeholder_bad_sha)
    assert bundle_bad.correlation_summary is None
    assert "func:dddddddddddddddd:0x401000" not in bundle_bad.valid_evidence_ids
    assert any("lacked matching sample_sha256" in lim for lim in bundle_bad.known_limitations)

    # Path D: Default DB-loaded static path works unchanged and honors tight max_bundle_bytes
    _create_static_record(db_session, sample, analysis.id, imports=[("KERNEL32.dll", "CreateProcessW")])
    bundle_db_tight = EvidenceBundleBuilder(db_session, max_bundle_bytes=16384).build(analysis.id)
    assert bundle_db_tight.static_analysis.status == "available"
    assert bundle_db_tight.correlation_summary is not None
    assert len(json.dumps(bundle_db_tight.model_dump(mode="json")).encode("utf-8")) <= 16384


def test_27_bounded_history_retrieval_across_large_history_and_replay_invariance(db_session, monkeypatch):
    """Tasks 6/R17/R18/R19/R20: Large 60-row correlation history uses LIMIT 1 queries without loading history."""
    from sqlalchemy import event

    sample, analysis = _create_sample_and_analysis(db_session, tag="large_hist", backend_type="replay", replay_scenario_id="ransomware_wannacry_mock")
    _create_static_record(db_session, sample, analysis.id, imports=[("ADVAPI32.dll", "CryptEncrypt")])
    db_session.add(
        AnalysisEvent(
            id="ev_hist_1",
            analysis_id=analysis.id,
            category="file",
            action="write",
            target_path="C:\\Users\\Victim\\file.wnry",
            attributes={"is_encrypted_target": True},
            source_tool="sandbox-fsmon",
        )
    )
    db_session.commit()

    svc = EvidenceCorrelationService(db_session)
    res_good = svc.compute_and_persist(analysis.id)
    assert res_good.status == "COMPLETED"
    good_fp = res_good.provenance.source_fingerprint

    # Insert 55 older/historical FAILED and stale COMPLETED rows plus 1 newer FAILED attempt
    base_dt = datetime(2026, 11, 10, 1, 0, 0, tzinfo=timezone.utc)
    hist_rows = []
    for idx in range(55):
        st = "FAILED" if idx % 3 == 0 else "COMPLETED"
        hist_rows.append(
            StaticDynamicCorrelationRecord(
                id=f"hist_{idx:03d}",
                analysis_id=analysis.id,
                sample_id=sample.id,
                sample_sha256=sample.sha256,
                status=st,
                source_fingerprint=good_fp,
                is_replay=True,
                findings_count=1 if st == "COMPLETED" else 0,
                result_json=res_good.model_dump(mode="json") if st == "COMPLETED" else {"status": "FAILED"},
                created_at=base_dt + timedelta(seconds=idx),
                updated_at=base_dt + timedelta(seconds=idx),
            )
        )
    # Add latest failure AFTER the usable record (must be preserved gracefully!)
    hist_rows.append(
        StaticDynamicCorrelationRecord(
            id="hist_latest_failed",
            analysis_id=analysis.id,
            sample_id=sample.id,
            sample_sha256=sample.sha256,
            status="FAILED",
            source_fingerprint=good_fp,
            is_replay=True,
            error_message="simulated prior crash",
            result_json=res_good.model_copy(update={"status": "FAILED"}).model_dump(mode="json"),
            created_at=datetime(2026, 11, 11, 23, 0, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 11, 11, 23, 0, 0, tzinfo=timezone.utc),
        )
    )
    db_session.bulk_save_objects(hist_rows)
    db_session.commit()

    # Spy on actual SQL emitted against static_dynamic_correlations
    corr_queries: List[str] = []

    def _capture_sql(conn, cursor, statement, parameters, context, executemany):
        if "evidence_correlations" in statement.lower() and statement.lstrip().upper().startswith("SELECT"):
            corr_queries.append(statement)

    event.listen(db_session.bind, "before_cursor_execute", _capture_sql)
    try:
        latest_rec, usable_rec = svc._select_records(analysis.id, sample_sha256=sample.sha256)
        assert latest_rec is not None and latest_rec.id == "hist_latest_failed"
        assert usable_rec is not None and usable_rec.status in ("COMPLETED", "PARTIAL")
        assert len(corr_queries) == 2
        assert all("LIMIT ?" in q.upper() or "LIMIT 1" in q.upper() for q in corr_queries)

        ro = svc.get_correlation_readonly(analysis.id)
        assert ro.status == "COMPLETED"
        assert len(ro.findings) == len(res_good.findings)
        assert any("preserved previous usable result" in w for w in ro.warnings)
    finally:
        event.remove(db_session.bind, "before_cursor_execute", _capture_sql)

