import io
from app.services.orchestration.policy import PolicyValidator

def test_policy_validator_allowlist():
    # Valid plan
    valid_plan = {
        "profile": "ransomware_focus",
        "execution_timeout_seconds": 90,
        "requested_artifacts": ["pcap", "screenshots"],
        "telemetry_focus": ["file", "registry"],
        "rationale": "High entropy sample requiring ransomware profile",
    }
    res = PolicyValidator.validate_analysis_plan(valid_plan)
    assert res.is_allowed is True
    assert res.status == "ALLOWED"

def test_policy_validator_reject_host_command_injection():
    # Malicious injection attempt
    injected_plan = {
        "profile": "standard",
        "execution_timeout_seconds": 60,
        "host_command": "rm -rf /",
        "requested_artifacts": ["pcap"],
    }
    res = PolicyValidator.validate_analysis_plan(injected_plan)
    assert res.is_allowed is False
    assert res.status == "REJECTED"
    assert "Security Policy Violation" in res.reason

def test_policy_validator_reject_unapproved_profile():
    # Unapproved profile
    bad_profile_plan = {
        "profile": "unrestricted_root_privilege",
        "execution_timeout_seconds": 60,
    }
    res = PolicyValidator.validate_analysis_plan(bad_profile_plan)
    assert res.is_allowed is False
    assert res.status == "REJECTED"
    assert "not in the approved sandbox profile allowlist" in res.reason

def test_policy_validator_clamp_excessive_timeout():
    # Excessive timeout (>300s)
    over_timeout_plan = {
        "profile": "standard",
        "execution_timeout_seconds": 9999,
        "requested_artifacts": ["pcap", "arbitrary_host_dump"],
    }
    res = PolicyValidator.validate_analysis_plan(over_timeout_plan)
    assert res.is_allowed is True
    assert res.status == "MODIFIED"
    assert res.modified_parameters["execution_timeout_seconds"] == 300
    assert "arbitrary_host_dump" not in res.modified_parameters["requested_artifacts"]

def test_ai_orchestration_audit_trail_recorded(client):
    # Upload sample and execute pipeline
    sample_bytes = b"MZ" + b"\x90" * 150 + b"WannaCry_AI_Orchestration_Test"
    res_upload = client.post("/api/v1/samples", files={"file": ("wannacry_ai.exe", io.BytesIO(sample_bytes))})
    sample = res_upload.json()

    res_analysis = client.post(
        "/api/v1/analyses?run_sync=true",
        json={"sample_id": sample["id"], "backend_type": "replay", "profile": "standard", "timeout_seconds": 60}
    )
    analysis = res_analysis.json()
    analysis_id = analysis["id"]

    # Verify audit records in /api/v1/analyses/{id}/orchestration
    res_audit = client.get(f"/api/v1/analyses/{analysis_id}/orchestration")
    assert res_audit.status_code == 200
    audit_records = res_audit.json()
    assert len(audit_records) >= 2

    stages = [r["stage"] for r in audit_records]
    assert "preflight_planning" in stages
    assert "observation_evaluation" in stages

    for r in audit_records:
        assert r["validation_result"] in ["ALLOWED", "MODIFIED"]
        assert "proposed_action" in r
        assert "supporting_evidence" in r
        assert "final_action" in r

