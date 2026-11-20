import pytest
from app.models.finding import BehavioralFinding
from app.models.event import AnalysisEvent
from app.models.sample import Sample
from app.models.analysis import Analysis
from app.schemas.classification import CategoryAssessment
from app.services.classification.engine import MalwareClassificationEngine
from app.services.reporting.export_html import generate_html_report


def test_cross_analysis_and_synthetic_evidence_ids_rejected(db_session):
    """
    Adversarial negative test: An assessment attempting to reference an event ID
    belonging to ANOTHER analysis (or a synthetic ID like EVENT:foo or PE:bar)
    must have that evidence rejected and downgraded to SUSPECTED.
    """
    engine = MalwareClassificationEngine(db=db_session)

    # 1. Create two separate analyses in DB
    s1 = Sample(file_name="target.exe", file_size=100, sha256="aa" * 32, sha1="a" * 40, md5="a" * 32, is_pe=True, quarantine_path="/tmp/fake1")
    s2 = Sample(file_name="other.exe", file_size=100, sha256="bb" * 32, sha1="b" * 40, md5="b" * 32, is_pe=True, quarantine_path="/tmp/fake2")
    db_session.add_all([s1, s2])
    db_session.commit()

    a1 = Analysis(id="target_analysis", sample_id=s1.id, backend_type="cape", status="COMPLETED")
    a2 = Analysis(id="victim_analysis", sample_id=s2.id, backend_type="cape", status="COMPLETED")
    db_session.add_all([a1, a2])
    db_session.commit()

    # Event belonging to victim_analysis (NOT target_analysis)
    foreign_event = AnalysisEvent(
        id=9999,
        analysis_id=a2.id,
        category="process",
        action="createremotethread",
        attributes={"remote_thread": True},
    )
    db_session.add(foreign_event)
    db_session.commit()

    # Now attempt to classify target_analysis passing foreign event ID
    assessments = [
        CategoryAssessment(
            category_id="injector",
            category_name="Injector",
            category_type="behavior",
            classification_status="CONFIRMED",
            confidence=0.90,
            evidence_ids=["9999", "EVENT:remote_thread_creation", "PE:section_entropy"],
            explanation="Malicious attempt to cross-contaminate findings.",
        )
    ]
    limitations = []

    engine._validate_and_filter_evidence(
        analysis_id=a1.id,
        sample_sha256=s1.sha256,
        assessments=assessments,
        input_findings=[],
        input_events=[],
        limitations=limitations,
    )

    # All foreign & synthetic IDs must be purged
    assert "9999" not in assessments[0].evidence_ids
    assert "EVENT:remote_thread_creation" not in assessments[0].evidence_ids
    assert "PE:section_entropy" not in assessments[0].evidence_ids
    assert len(assessments[0].evidence_ids) == 0

    # Assessment must be downgraded from CONFIRMED to SUSPECTED
    assert assessments[0].classification_status == "SUSPECTED"
    assert assessments[0].confidence <= 0.50
    assert any("downgraded to SUSPECTED" in lim for lim in limitations)


def test_injector_requires_verified_remote_thread_not_just_api_name():
    """Merely seeing an API string without verified remote thread execution is NOT confirmed Injector."""
    engine = MalwareClassificationEngine()

    # Only VirtualAllocEx (memory allocation only)
    events = [
        AnalysisEvent(
            id=10,
            analysis_id="a_api_only",
            category="process",
            action="virtualallocex",
            attributes={"target_pid": 1234},
        )
    ]

    res = engine.classify(
        analysis_id="a_api_only",
        sample_sha256="55" * 32,
        findings=[],
        events=events,
        is_pe=True,
    )
    inj = next((f for f in res.classification_findings if f.category_id == "injector"), None)
    assert inj is not None
    assert inj.classification_status == "SUSPECTED"
    assert res.primary_category != "Injector"


def test_downloader_requires_linked_transfer_and_saved_binary():
    """Unrelated network GET and unrelated file write must NOT be confirmed Downloader."""
    engine = MalwareClassificationEngine()

    # Generic GET without executable extension + standard text file write
    events = [
        AnalysisEvent(
            id=21,
            analysis_id="a_unlinked",
            category="http",
            action="get",
            target_path="http://example.com/logo.png",
            attributes={"method": "GET"},
        ),
        AnalysisEvent(
            id=22,
            analysis_id="a_unlinked",
            category="file",
            action="write",
            target_path="C:\\Users\\victim\\Documents\\notes.txt",
            attributes={"is_dropped_binary": False},
        ),
    ]

    res = engine.classify(
        analysis_id="a_unlinked",
        sample_sha256="66" * 32,
        findings=[],
        events=events,
        is_pe=True,
    )
    dl = next((f for f in res.classification_findings if f.category_id == "downloader"), None)
    if dl is not None:
        assert dl.classification_status != "CONFIRMED"
    assert res.primary_category != "Downloader"


def test_launcher_rejects_benign_admin_tools():
    """Common Windows utilities (cmd.exe, powershell.exe) without evasive flags are ABSENT."""
    engine = MalwareClassificationEngine()

    events = [
        AnalysisEvent(
            id=31,
            analysis_id="a_admin",
            category="process",
            action="spawn",
            process_id=400,
            process_name="cmd.exe",
            attributes={"command_line": "cmd.exe /c echo Hello"},
        ),
        AnalysisEvent(
            id=32,
            analysis_id="a_admin",
            category="process",
            action="spawn",
            process_id=401,
            process_name="powershell.exe",
            attributes={"command_line": "powershell.exe Write-Host Test"},
        ),
    ]

    res = engine.classify(
        analysis_id="a_admin",
        sample_sha256="77" * 32,
        findings=[],
        events=events,
        is_pe=True,
    )
    launcher = next(f for f in res.classification_findings if f.category_id == "launcher")
    assert launcher.classification_status == "ABSENT"
    assert res.primary_category != "Launcher"


def test_confidence_constrained_under_partial_telemetry():
    """When telemetry completeness is PARTIAL, confidence scores are capped and scaled down."""
    engine = MalwareClassificationEngine()

    findings = [
        BehavioralFinding(
            id="f1",
            analysis_id="a_part",
            rule_id="RULE_SHADOW_COPY_DELETION",
            title="Shadow Copy Deletion",
            severity="Critical",
            confidence=0.95,
        ),
        BehavioralFinding(
            id="f2",
            analysis_id="a_part",
            rule_id="RULE_MASS_FILE_ENCRYPTION",
            title="Mass File Encryption",
            severity="Critical",
            confidence=0.95,
        ),
    ]

    res = engine.classify(
        analysis_id="a_part",
        sample_sha256="88" * 32,
        findings=findings,
        events=[],
        telemetry_completeness="PARTIAL",
        is_pe=True,
    )

    rw = next(f for f in res.classification_findings if f.category_id == "ransomware")
    # Confidence constrained under partial telemetry: capped at <= 0.65
    assert rw.confidence <= 0.65
    assert any("Telemetry completeness is PARTIAL" in lim for lim in res.limitations)


def test_classification_rendered_in_html_report():
    """Verifies that classification sections, badges, and grounding evidence render safely in HTML export."""
    classification_dict = {
        "primary_category": "Ransomware",
        "secondary_categories": ["Obfuscation", "Kernel Driver"],
        "classification_status": "CLASSIFIED",
        "taxonomy_version": "1.0",
        "classifier_version": "1.0.0",
        "classification_findings": [
            {
                "category_id": "ransomware",
                "category_name": "Ransomware",
                "category_type": "behavior",
                "classification_status": "CONFIRMED",
                "confidence": 0.95,
                "evidence_ids": ["f_ransom_1"],
                "explanation": "Mass file encryption and shadow copy deletion.",
            },
            {
                "category_id": "obfuscation",
                "category_name": "Obfuscation",
                "category_type": "characteristic",
                "classification_status": "CONFIRMED",
                "confidence": 0.85,
                "evidence_ids": ["sample_sha"],
                "explanation": "High entropy packed sections.",
            },
        ],
        "unsupported_categories": ["phishing", "android_rat"],
    }

    report_data = {
        "analysis_id": "test_analysis_html",
        "generated_at": "2026-11-19T00:00:00Z",
        "risk_assessment": {"score": 90, "level": "Critical", "confidence": 0.95},
        "malware_classification": classification_dict,
        "environment": {"is_replay": False},
    }

    html = generate_html_report(report_data)
    assert "Malware Category Classification" in html
    assert "Ransomware" in html
    assert "pill-critical" in html
    assert "Obfuscation" in html
    assert "Mass file encryption and shadow copy deletion" in html
    assert "unsupported for Windows PE" in html
