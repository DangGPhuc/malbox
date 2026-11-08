import io
from app.models.analysis import AnalysisStatus

def test_full_replay_analysis_pipeline(client):
    # 1. Upload a simulated ransomware sample
    sample_bytes = b"MZ" + b"\x00" * 80 + b"WannaCry_Variant_Executable_Bytes"
    file_tuple = ("wannacry_sample.exe", io.BytesIO(sample_bytes), "application/octet-stream")
    upload_res = client.post("/api/v1/samples", files={"file": file_tuple})
    assert upload_res.status_code == 201
    sample = upload_res.json()
    sample_id = sample["id"]
    assert sample["file_name"] == "wannacry_sample.exe"

    # 2. Trigger analysis with synchronous execution
    analysis_payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "profile": "ransomware_focus",
        "timeout_seconds": 60,
    }
    create_res = client.post("/api/v1/analyses?run_sync=true", json=analysis_payload)
    assert create_res.status_code == 201
    analysis = create_res.json()
    analysis_id = analysis["id"]
    assert analysis["status"] == AnalysisStatus.COMPLETED.value

    # 3. Verify Normalized Events
    events_res = client.get(f"/api/v1/analyses/{analysis_id}/events")
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert events_data["total"] > 5
    categories = {e["category"] for e in events_data["items"]}
    assert "process" in categories
    assert "file" in categories
    assert "registry" in categories
    assert "network" in categories
    assert "dns" in categories

    # 4. Verify Process Tree
    tree_res = client.get(f"/api/v1/analyses/{analysis_id}/process-tree")
    assert tree_res.status_code == 200
    tree_data = tree_res.json()
    assert tree_data["total_processes"] >= 3
    assert len(tree_data["root_nodes"]) >= 1
    root = tree_data["root_nodes"][0]
    assert "wannacry" in root["name"].lower() or "sample" in root["name"].lower()
    assert len(root["children"]) >= 1

    # 5. Verify Behavioral Findings and MITRE ATT&CK Mappings
    findings_res = client.get(f"/api/v1/analyses/{analysis_id}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) >= 2
    mitre_ids = [f["mitre_attack_id"] for f in findings if f["mitre_attack_id"]]
    assert "T1490" in mitre_ids  # Volume Shadow Copy Deletion
    assert "T1486" in mitre_ids or "T1547.001" in mitre_ids  # Encryption or Persistence

    # 6. Verify Behavior Graph
    graph_res = client.get(f"/api/v1/analyses/{analysis_id}/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()
    assert graph["total_nodes"] > 5
    assert graph["total_edges"] > 5
    node_types = {n["data"]["type"] for n in graph["nodes"]}
    assert "Sample" in node_types
    assert "Process" in node_types
    assert "File" in node_types

    # 7. Verify Structured Report
    report_res = client.get(f"/api/v1/analyses/{analysis_id}/report")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["risk_score"] >= 80
    assert report["risk_level"] == "Malicious"
    assert "wannacry" in report["executive_summary"].lower() or "threat" in report["executive_summary"].lower()
    assert len(report["full_report"]["extracted_iocs"]["domains"]) >= 1

    # 8. Verify HTML Report Export
    html_res = client.get(f"/api/v1/analyses/{analysis_id}/report/html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "malbox-ai // Forensic Intelligence" in html_res.text
    assert "Volume Shadow Copy Deletion" in html_res.text

    # 9. Verify Artifact Collection
    art_res = client.get(f"/api/v1/analyses/{analysis_id}/artifacts")
    assert art_res.status_code == 200
    artifacts = art_res.json()
    assert len(artifacts) >= 2
    art_names = [a["file_name"] for a in artifacts]
    assert any("pcap" in n for n in art_names)


def test_replay_scenario_wannacry_independent_of_profile(client):
    """Explicit replay_scenario_id='ransomware_wannacry_mock' takes precedence over profile."""
    sample_bytes = b"MZ" + b"\x00" * 80 + b"WannaCry_Explicit_Test"
    upload_res = client.post("/api/v1/samples", files={"file": ("wannacry_explicit.exe", io.BytesIO(sample_bytes))})
    assert upload_res.status_code == 201
    sample_id = upload_res.json()["id"]

    # Use a non-ransomware profile ('infostealer_focus') to verify scenario_id takes precedence
    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "profile": "infostealer_focus",
        "replay_scenario_id": "ransomware_wannacry_mock",
        "timeout_seconds": 60,
    }
    create_res = client.post("/api/v1/analyses?run_sync=true", json=payload)
    assert create_res.status_code == 201
    analysis = create_res.json()
    assert analysis["replay_scenario_id"] == "ransomware_wannacry_mock"

    # Verify report displays correct scenario ID and provenance
    report_res = client.get(f"/api/v1/analyses/{analysis['id']}/report")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["replay_scenario_id"] == "ransomware_wannacry_mock"
    assert report["is_replay"] is True
    assert "REPLAY DATA PROVENANCE" in report["full_report"]["provenance_disclaimer"]
    assert report["full_report"]["analysis_environment"]["replay_scenario_id"] == "ransomware_wannacry_mock"

    # Verify WannaCry behavioral indicators occurred
    findings_res = client.get(f"/api/v1/analyses/{analysis['id']}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert any(f["rule_id"] in ["RULE_SHADOW_COPY_DELETION", "RULE_MASS_FILE_ENCRYPTION"] for f in findings)


def test_replay_scenario_redline_independent_of_profile(client):
    """Explicit replay_scenario_id='infostealer_redline_mock' takes precedence over profile."""
    sample_bytes = b"MZ" + b"\x00" * 80 + b"RedLine_Explicit_Test"
    upload_res = client.post("/api/v1/samples", files={"file": ("redline_explicit.exe", io.BytesIO(sample_bytes))})
    assert upload_res.status_code == 201
    sample_id = upload_res.json()["id"]

    # Use 'ransomware_focus' profile but explicit RedLine scenario
    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "profile": "ransomware_focus",
        "replay_scenario_id": "infostealer_redline_mock",
        "timeout_seconds": 60,
    }
    create_res = client.post("/api/v1/analyses?run_sync=true", json=payload)
    assert create_res.status_code == 201
    analysis = create_res.json()
    assert analysis["replay_scenario_id"] == "infostealer_redline_mock"

    # Verify report displays correct scenario ID and provenance
    report_res = client.get(f"/api/v1/analyses/{analysis['id']}/report")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["replay_scenario_id"] == "infostealer_redline_mock"
    assert report["is_replay"] is True
    assert "REPLAY DATA PROVENANCE" in report["full_report"]["provenance_disclaimer"]

    # Verify RedLine infostealer findings (credential access / C2)
    findings_res = client.get(f"/api/v1/analyses/{analysis['id']}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert any(f["rule_id"] in ["RULE_CREDENTIAL_VAULT_ACCESS", "RULE_C2_HTTP_EXFILTRATION"] for f in findings)


def test_replay_scenario_alias_compatibility(client):
    """Sending scenario_id as alias in create payload maps to replay_scenario_id."""
    sample_bytes = b"MZ" + b"\x00" * 80 + b"Alias_Test"
    upload_res = client.post("/api/v1/samples", files={"file": ("alias_test.exe", io.BytesIO(sample_bytes))})
    sample_id = upload_res.json()["id"]

    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "scenario_id": "infostealer_redline_mock",  # using frontend legacy alias
        "timeout_seconds": 60,
    }
    create_res = client.post("/api/v1/analyses?run_sync=true", json=payload)
    assert create_res.status_code == 201
    analysis = create_res.json()
    assert analysis["replay_scenario_id"] == "infostealer_redline_mock"


def test_replay_invalid_scenario_id_does_not_silently_fallback(client):
    """Supplying an unknown or invalid explicit scenario ID fails closed with HTTP 400 (no silent fallback)."""
    sample_bytes = b"MZ" + b"\x00" * 80 + b"Invalid_Scen_Test"
    upload_res = client.post("/api/v1/samples", files={"file": ("invalid_scen.exe", io.BytesIO(sample_bytes))})
    sample_id = upload_res.json()["id"]

    # 1. Unknown scenario name
    payload_fake = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "replay_scenario_id": "nonexistent_mock_scenario",
        "timeout_seconds": 60,
    }
    res_fake = client.post("/api/v1/analyses", json=payload_fake)
    assert res_fake.status_code == 400
    assert "Unknown replay scenario identifier" in res_fake.json()["detail"]

    # 2. Path traversal
    payload_trav = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "replay_scenario_id": "../../../etc/passwd",
        "timeout_seconds": 60,
    }
    res_trav = client.post("/api/v1/analyses", json=payload_trav)
    assert res_trav.status_code == 400
    assert "path traversal" in res_trav.json()["detail"]

