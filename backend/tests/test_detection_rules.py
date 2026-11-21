from datetime import datetime, timezone
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.models.event import AnalysisEvent
from app.services.detection.engine import DetectionEngine


def test_detection_engine_no_suspicious_behavior(db_session):
    """When zero suspicious behaviors are observed, score is 0 and level is NOT labeled as 'Clean'."""
    sample = Sample(
        sha256="b" * 64, md5="b" * 32, sha1="b" * 40,
        file_name="benign.exe", file_size=50, quarantine_path="/tmp/b.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    # Ingest only ordinary benign events
    ev_proc = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=datetime.now(timezone.utc), process_id=100, process_name="benign.exe",
        attributes={"command_line": "benign.exe"}
    )
    ev_file = AnalysisEvent(
        analysis_id=analysis.id, category="file", action="read",
        timestamp=datetime.now(timezone.utc), process_id=100, target_path="C:\\Windows\\system32\\kernel32.dll",
        attributes={}
    )
    db_session.add_all([ev_proc, ev_file])
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, assessment = engine.evaluate_behavior(analysis.id)

    assert len(findings) == 0
    assert assessment.score == 0
    assert assessment.level == "No Suspicious Behavior Observed"
    assert "Clean" not in assessment.level


def test_detection_engine_ransomware_contextual_threshold(db_session):
    """RULE_MASS_FILE_ENCRYPTION requires multiple encrypted files or encrypted target + ransom note."""
    sample = Sample(
        sha256="r" * 64, md5="r" * 32, sha1="r" * 40,
        file_name="ransom.exe", file_size=50, quarantine_path="/tmp/r.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="ransomware_focus", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    # Ingest 2 encrypted file writes
    ev_enc1 = AnalysisEvent(
        analysis_id=analysis.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=200, target_path="C:\\Users\\test\\doc1.pdf.wnry",
        attributes={"is_encrypted_target": True}
    )
    ev_enc2 = AnalysisEvent(
        analysis_id=analysis.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=200, target_path="C:\\Users\\test\\doc2.xlsx.wnry",
        attributes={"is_encrypted_target": True}
    )
    db_session.add_all([ev_enc1, ev_enc2])
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, assessment = engine.evaluate_behavior(analysis.id)

    matched_rules = [f.rule_id for f in findings]
    assert "RULE_MASS_FILE_ENCRYPTION" in matched_rules
    assert any(f.mitre_attack_id == "T1486" for f in findings)
    assert assessment.score >= 45


def test_detection_engine_shadow_copy_deletion(db_session):
    """RULE_SHADOW_COPY_DELETION matches vssadmin delete shadows commands."""
    sample = Sample(
        sha256="s" * 64, md5="s" * 32, sha1="s" * 40,
        file_name="vss.exe", file_size=50, quarantine_path="/tmp/s.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    ev_cmd = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=datetime.now(timezone.utc), process_id=300, process_name="cmd.exe",
        attributes={"command_line": "vssadmin.exe Delete Shadows /All /Quiet"}
    )
    db_session.add(ev_cmd)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, assessment = engine.evaluate_behavior(analysis.id)

    assert any(f.rule_id == "RULE_SHADOW_COPY_DELETION" for f in findings)
    assert any(f.mitre_attack_id == "T1490" for f in findings)


def test_detection_engine_c2_contextual_threshold(db_session):
    """RULE_C2_HTTP_EXFILTRATION requires POST with gate/exfiltration parameters."""
    sample = Sample(
        sha256="c2" + "0" * 62, md5="c" * 32, sha1="c" * 40,
        file_name="c2.exe", file_size=50, quarantine_path="/tmp/c2.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="infostealer_focus", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    # Normal GET must not trigger C2 exfiltration
    ev_get = AnalysisEvent(
        analysis_id=analysis.id, category="http", action="get",
        timestamp=datetime.now(timezone.utc), process_id=400, target_path="http://api.ipify.org",
        attributes={"method": "GET", "status_code": 200}
    )
    db_session.add(ev_get)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, _ = engine.evaluate_behavior(analysis.id)
    assert not any(f.rule_id == "RULE_C2_HTTP_EXFILTRATION" for f in findings)

    # Suspicious POST to gate triggers C2
    ev_post = AnalysisEvent(
        analysis_id=analysis.id, category="http", action="post",
        timestamp=datetime.now(timezone.utc), process_id=400, target_path="http://91.240.118.172/gate.php",
        attributes={"method": "POST", "status_code": 200}
    )
    db_session.add(ev_post)
    db_session.commit()

    findings_post, assessment = engine.evaluate_behavior(analysis.id)
    assert any(f.rule_id == "RULE_C2_HTTP_EXFILTRATION" for f in findings_post)


def test_lone_ransom_note_without_encrypted_files_not_mass_encryption(db_session):
    """A lone ransom note must NOT trigger RULE_MASS_FILE_ENCRYPTION without encrypted file evidence."""
    sample = Sample(
        sha256="lone" + "0" * 60, md5="l" * 32, sha1="l" * 40,
        file_name="note_only.exe", file_size=50, quarantine_path="/tmp/l.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    # Single ransom note, zero encrypted files
    ev_note = AnalysisEvent(
        analysis_id=analysis.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=500,
        target_path="C:\\Users\\test\\Desktop\\how_to_decrypt.txt",
        attributes={"is_ransom_note": True}
    )
    db_session.add(ev_note)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, assessment = engine.evaluate_behavior(analysis.id)

    # Must NOT trigger mass file encryption
    matched_rules = [f.rule_id for f in findings]
    assert "RULE_MASS_FILE_ENCRYPTION" not in matched_rules


def test_normal_http_post_not_c2_exfiltration(db_session):
    """A normal HTTP POST (even with HTTP 200) must NOT automatically trigger RULE_C2_HTTP_EXFILTRATION."""
    sample = Sample(
        sha256="post" + "0" * 60, md5="p" * 32, sha1="p" * 40,
        file_name="post_benign.exe", file_size=50, quarantine_path="/tmp/p.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    # Benign telemetry API call with HTTP 200
    ev_normal_post = AnalysisEvent(
        analysis_id=analysis.id, category="http", action="post",
        timestamp=datetime.now(timezone.utc), process_id=600,
        target_path="https://telemetry.microsoft.com/v10/events",
        attributes={"method": "POST", "status_code": 200}
    )
    db_session.add(ev_normal_post)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, _ = engine.evaluate_behavior(analysis.id)

    matched_rules = [f.rule_id for f in findings]
    assert "RULE_C2_HTTP_EXFILTRATION" not in matched_rules


def test_dropped_executable_rule_positive_and_negative(db_session):
    """RULE_DROPPED_EXECUTABLE_PAYLOAD triggers on binary dropped files, but ignores benign text/log writes."""
    sample = Sample(
        sha256="drop" + "1" * 60, md5="d" * 32, sha1="d" * 40,
        file_name="dropper.exe", file_size=50, quarantine_path="/tmp/d.exe"
    )
    db_session.add(sample)
    db_session.commit()

    # 1. Negative test: benign text file write
    analysis_benign = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis_benign)
    db_session.commit()

    ev_txt = AnalysisEvent(
        analysis_id=analysis_benign.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=701,
        target_path="C:\\Users\\User\\AppData\\Local\\Temp\\log.txt",
        attributes={"is_dropped_binary": False}
    )
    db_session.add(ev_txt)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings_neg, assessment_neg = engine.evaluate_behavior(analysis_benign.id)
    matched_neg = [f.rule_id for f in findings_neg]
    assert "RULE_DROPPED_EXECUTABLE_PAYLOAD" not in matched_neg

    # 2. Positive test: dropped .exe or explicit is_dropped_binary payload
    analysis_mal = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis_mal)
    db_session.commit()

    ev_exe = AnalysisEvent(
        analysis_id=analysis_mal.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=702,
        target_path="C:\\Users\\User\\AppData\\Local\\Temp\\secondary_payload.exe",
        attributes={"is_dropped_binary": True}
    )
    db_session.add(ev_exe)
    db_session.commit()

    findings_pos, assessment_pos = engine.evaluate_behavior(analysis_mal.id)
    matched_pos = [f.rule_id for f in findings_pos]
    assert "RULE_DROPPED_EXECUTABLE_PAYLOAD" in matched_pos
    assert assessment_pos.score >= 30


def test_process_injection_rule_positive_and_negative(db_session):
    """RULE_PROCESS_INJECTION_TECHNIQUE requires executable allocation paired with remote thread or cross-PID write."""
    sample = Sample(
        sha256="inj" + "2" * 61, md5="i" * 32, sha1="i" * 40,
        file_name="injector.exe", file_size=50, quarantine_path="/tmp/i.exe"
    )
    db_session.add(sample)
    db_session.commit()

    # 1. Negative test: lone local VirtualAlloc without thread execution or cross-PID
    analysis_lone = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis_lone)
    db_session.commit()

    ev_alloc_lone = AnalysisEvent(
        analysis_id=analysis_lone.id, category="process", action="virtualalloc",
        timestamp=datetime.now(timezone.utc), process_id=801,
        target_path=None,
        attributes={"arguments": {"protect": "PAGE_READWRITE", "flAllocationType": "0x1000"}}
    )
    db_session.add(ev_alloc_lone)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings_lone, _ = engine.evaluate_behavior(analysis_lone.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in findings_lone]

    # 2. Positive test: VirtualAllocEx (PAGE_EXECUTE_READWRITE) + CreateRemoteThread on same target PID
    analysis_inj = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis_inj)
    db_session.commit()

    now = datetime.now(timezone.utc)
    ev_alloc_exec = AnalysisEvent(
        analysis_id=analysis_inj.id, category="process", action="virtualallocex",
        timestamp=now, process_id=802,
        target_path=None,
        attributes={"target_pid": 999, "arguments": {"protect": "PAGE_EXECUTE_READWRITE", "flProtect": "0x40", "target_pid": 999}}
    )
    ev_thread = AnalysisEvent(
        analysis_id=analysis_inj.id, category="process", action="createremotethread",
        timestamp=now, process_id=802,
        target_path=None,
        attributes={"target_pid": 999, "arguments": {"hProcess": "0x444", "target_pid": 999}, "remote_thread": True}
    )
    db_session.add_all([ev_alloc_exec, ev_thread])
    db_session.commit()

    findings_inj, assessment_inj = engine.evaluate_behavior(analysis_inj.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" in [f.rule_id for f in findings_inj]
    assert assessment_inj.score >= 40


def test_remote_alloc_and_write_without_thread_is_staging_not_injection(db_session):
    """Remote memory allocation and write alone without remote thread creation is memory staging, NOT confirmed injection execution."""
    sample = Sample(
        sha256="inj" + "3" * 61, md5="j" * 32, sha1="j" * 40,
        file_name="stager.exe", file_size=50, quarantine_path="/tmp/j.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    now = datetime.now(timezone.utc)
    ev_alloc_remote = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="virtualallocex",
        timestamp=now, process_id=803,
        target_path=None,
        attributes={"target_pid": 1001, "arguments": {"protect": "PAGE_EXECUTE_READWRITE", "flProtect": "0x40", "target_pid": 1001}}
    )
    ev_write_remote = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="writeprocessmemory",
        timestamp=now, process_id=803,
        target_path=None,
        attributes={"target_pid": 1001, "arguments": {"nSize": 4096, "target_pid": 1001}}
    )
    db_session.add_all([ev_alloc_remote, ev_write_remote])
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, _ = engine.evaluate_behavior(analysis.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in findings]


def test_incomplete_telemetry_quality_contract_prevents_false_clean(db_session):
    """When telemetry is INCOMPLETE (e.g. analyzer crashed), assessment level must NOT be Clean or No Suspicious Behavior."""
    sample = Sample(
        sha256="inc" + "3" * 61, md5="c" * 32, sha1="c" * 40,
        file_name="crashed.exe", file_size=50, quarantine_path="/tmp/c.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.CAPE.value,
        profile="standard", status=AnalysisStatus.SCORING.value
    )
    db_session.add(analysis)
    db_session.commit()

    engine = DetectionEngine(db_session)
    findings, assessment = engine.evaluate_behavior(analysis.id, telemetry_completeness="INCOMPLETE")

    assert len(findings) == 0
    assert assessment.score == 0
    assert assessment.level == "Analysis Incomplete — Inconclusive"
    assert "Clean" not in assessment.level
    assert "No Suspicious Behavior" not in assessment.level
    assert assessment.confidence <= 0.50


def test_process_injection_contextual_negatives_suite(db_session):
    """
    Comprehensive Negative Matrix for Process Memory Injection (B1):
    1. Unrelated processes using different APIs
    2. Local allocation and normal thread creation
    3. Failed API calls
    4. Non-executable memory protection
    5. Missing target process identity
    6. Out-of-order events (thread before alloc)
    7. Distant events (> 60s apart)
    """
    from datetime import timedelta
    engine = DetectionEngine(db_session)
    now = datetime.now(timezone.utc)

    # Helper to generate isolated analysis
    def make_analysis(name):
        s = Sample(sha256="neg" + name.ljust(61, "0")[:61], md5="a"*32, sha1="a"*40, file_name=f"{name}.exe", file_size=100, quarantine_path="/tmp/q")
        db_session.add(s)
        db_session.commit()
        a = Analysis(sample_id=s.id, backend_type="replay", status="SCORING")
        db_session.add(a)
        db_session.commit()
        return a

    # 1. Unrelated processes using different APIs (Proc 100 allocs in 500, Proc 200 threads in 600)
    a1 = make_analysis("unrelated")
    db_session.add_all([
        AnalysisEvent(analysis_id=a1.id, category="process", action="virtualallocex", timestamp=now, process_id=100,
                      attributes={"target_pid": 500, "arguments": {"flProtect": "0x40", "target_pid": 500}}),
        AnalysisEvent(analysis_id=a1.id, category="process", action="createremotethread", timestamp=now, process_id=200,
                      attributes={"target_pid": 600, "arguments": {"target_pid": 600}}),
    ])
    db_session.commit()
    f1, _ = engine.evaluate_behavior(a1.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f1]

    # 2. Local allocation and thread creation (source == target == 300)
    a2 = make_analysis("local")
    db_session.add_all([
        AnalysisEvent(analysis_id=a2.id, category="process", action="virtualalloc", timestamp=now, process_id=300,
                      attributes={"target_pid": 300, "arguments": {"flProtect": "0x40", "target_pid": 300}}),
        AnalysisEvent(analysis_id=a2.id, category="process", action="createremotethread", timestamp=now, process_id=300,
                      attributes={"target_pid": 300, "arguments": {"target_pid": 300}}),
    ])
    db_session.commit()
    f2, _ = engine.evaluate_behavior(a2.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f2]

    # 3. Failed API calls (status=0 and return_value=0)
    a3 = make_analysis("failed_api")
    db_session.add_all([
        AnalysisEvent(analysis_id=a3.id, category="process", action="virtualallocex", timestamp=now, process_id=400,
                      attributes={"target_pid": 777, "status": 0, "return_value": "0x0", "arguments": {"flProtect": "0x40", "target_pid": 777}}),
        AnalysisEvent(analysis_id=a3.id, category="process", action="createremotethread", timestamp=now, process_id=400,
                      attributes={"target_pid": 777, "status": 0, "return_value": "0x0", "arguments": {"target_pid": 777}}),
    ])
    db_session.commit()
    f3, _ = engine.evaluate_behavior(a3.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f3]

    # 4. Non-executable memory protection (flProtect: 0x04 PAGE_READWRITE)
    a4 = make_analysis("non_exec")
    db_session.add_all([
        AnalysisEvent(analysis_id=a4.id, category="process", action="virtualallocex", timestamp=now, process_id=500,
                      attributes={"target_pid": 888, "arguments": {"flProtect": "PAGE_READWRITE", "target_pid": 888}}),
        AnalysisEvent(analysis_id=a4.id, category="process", action="createremotethread", timestamp=now, process_id=500,
                      attributes={"target_pid": 888, "arguments": {"target_pid": 888}}),
    ])
    db_session.commit()
    f4, _ = engine.evaluate_behavior(a4.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f4]

    # 5. Missing target process identity
    a5 = make_analysis("missing_target")
    db_session.add_all([
        AnalysisEvent(analysis_id=a5.id, category="process", action="virtualallocex", timestamp=now, process_id=600,
                      attributes={"arguments": {"flProtect": "0x40"}}),
        AnalysisEvent(analysis_id=a5.id, category="process", action="createremotethread", timestamp=now, process_id=600,
                      attributes={"arguments": {}}),
    ])
    db_session.commit()
    f5, _ = engine.evaluate_behavior(a5.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f5]

    # 6. Out-of-order events (thread created BEFORE memory was allocated)
    a6 = make_analysis("out_of_order")
    db_session.add_all([
        AnalysisEvent(analysis_id=a6.id, category="process", action="createremotethread", timestamp=now, process_id=700,
                      attributes={"target_pid": 999, "arguments": {"target_pid": 999}}),
        AnalysisEvent(analysis_id=a6.id, category="process", action="virtualallocex", timestamp=now + timedelta(seconds=10), process_id=700,
                      attributes={"target_pid": 999, "arguments": {"flProtect": "0x40", "target_pid": 999}}),
    ])
    db_session.commit()
    f6, _ = engine.evaluate_behavior(a6.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f6]

    # 7. Distant events (> 60 seconds apart - likely PID reuse)
    a7 = make_analysis("distant_events")
    db_session.add_all([
        AnalysisEvent(analysis_id=a7.id, category="process", action="virtualallocex", timestamp=now, process_id=800,
                      attributes={"target_pid": 999, "arguments": {"flProtect": "0x40", "target_pid": 999}}),
        AnalysisEvent(analysis_id=a7.id, category="process", action="createremotethread", timestamp=now + timedelta(seconds=120), process_id=800,
                      attributes={"target_pid": 999, "arguments": {"target_pid": 999}}),
    ])
    db_session.commit()
    f7, _ = engine.evaluate_behavior(a7.id)
    assert "RULE_PROCESS_INJECTION_TECHNIQUE" not in [f.rule_id for f in f7]


def test_dropped_executable_negative_reads_and_arbitrary_bin(db_session):
    """
    Dropped Executable Semantics (B2):
    1. Legitimate executable reads/accesses do NOT trigger
    2. Arbitrary .bin files without verified PE indicators do NOT trigger
    3. Benign text/log writes do NOT trigger
    4. Verified executable write triggers
    """
    engine = DetectionEngine(db_session)
    now = datetime.now(timezone.utc)

    s = Sample(sha256="bin" + "0"*61, md5="b"*32, sha1="b"*40, file_name="bin_test.exe", file_size=100, quarantine_path="/tmp/q")
    db_session.add(s)
    db_session.commit()
    a = Analysis(sample_id=s.id, backend_type="replay", status="SCORING")
    db_session.add(a)
    db_session.commit()

    # 1. Reading notepad.exe
    ev_read = AnalysisEvent(
        analysis_id=a.id, category="file", action="read", timestamp=now, process_id=10,
        target_path="C:\\Windows\\System32\\notepad.exe",
        attributes={"is_dropped_binary": False}
    )
    # 2. Accessing calc.exe
    ev_access = AnalysisEvent(
        analysis_id=a.id, category="file", action="access", timestamp=now, process_id=10,
        target_path="C:\\Windows\\System32\\calc.exe",
        attributes={"is_dropped_binary": False}
    )
    # 3. Arbitrary firmware.bin write without PE metadata
    ev_bin = AnalysisEvent(
        analysis_id=a.id, category="file", action="write", timestamp=now, process_id=10,
        target_path="C:\\Temp\\firmware_chunk.bin",
        attributes={"is_dropped_binary": False, "file_type": "data"}
    )
    # 4. Benign install.log write
    ev_log = AnalysisEvent(
        analysis_id=a.id, category="file", action="write", timestamp=now, process_id=10,
        target_path="C:\\Temp\\install.log",
        attributes={"is_dropped_binary": False}
    )
    db_session.add_all([ev_read, ev_access, ev_bin, ev_log])
    db_session.commit()

    findings_neg, assessment_neg = engine.evaluate_behavior(a.id)
    assert "RULE_DROPPED_EXECUTABLE_PAYLOAD" not in [f.rule_id for f in findings_neg]
    assert assessment_neg.score == 0

    # 5. Observed writing actual payload.dll triggers
    ev_dll = AnalysisEvent(
        analysis_id=a.id, category="file", action="write", timestamp=now, process_id=10,
        target_path="C:\\Users\\User\\AppData\\Local\\Temp\\malicious.dll",
        attributes={"is_dropped_binary": True}
    )
    db_session.add(ev_dll)
    db_session.commit()

    findings_pos, assessment_pos = engine.evaluate_behavior(a.id)
    assert "RULE_DROPPED_EXECUTABLE_PAYLOAD" in [f.rule_id for f in findings_pos]
    assert assessment_pos.score >= 30



