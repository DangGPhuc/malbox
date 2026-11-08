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
