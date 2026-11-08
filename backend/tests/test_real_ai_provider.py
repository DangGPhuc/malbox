import io
import json
from unittest.mock import MagicMock, patch
import httpx
import pytest

from app.ai.llm_client import RealLLMProvider
from app.services.orchestration.policy import PolicyValidator


def test_real_llm_provider_generate_plan_success():
    """RealLLMProvider successfully queries HTTP endpoint, parses JSON, and returns plan."""
    provider = RealLLMProvider(api_key="test-key", model="gpt-4o-mini", base_url="http://fake-llm.test/v1")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "profile": "ransomware_focus",
                    "execution_timeout_seconds": 120,
                    "requested_artifacts": ["pcap", "screenshots"],
                    "telemetry_focus": ["file", "registry"],
                    "rationale": "High entropy indicates potential encryption payload.",
                    "confidence": 0.95,
                    "limitations": ["Anti-sandbox triggers may delay execution."],
                })
            }
        }],
        "usage": {"total_tokens": 150},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        plan = provider.generate_plan({"overall_entropy": 7.5, "file_name": "sample.exe"})
        assert plan["profile"] == "ransomware_focus"
        assert plan["execution_timeout_seconds"] == 120
        assert provider.last_call_meta["provider"] == "real"
        assert provider.last_call_meta["fallback"] is False
        assert provider.last_call_meta["tokens_used"] == 150


def test_real_llm_provider_network_failure_fallback():
    """Network connection failure falls back gracefully to MockLLMProvider with audit info."""
    provider = RealLLMProvider(api_key="test-key", model="gpt-4o-mini", base_url="http://unreachable-llm.test/v1")

    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Network unreachable")):
        plan = provider.generate_plan({"overall_entropy": 5.0, "file_name": "sample.exe"})
        assert plan["profile"] in ["standard", "ransomware_focus", "infostealer_focus"]
        assert provider.last_call_meta["provider"] == "mock_fallback"
        assert provider.last_call_meta["fallback"] is True
        assert "Network unreachable" in provider.last_call_meta["fallback_reason"]


def test_real_llm_provider_invalid_schema_fallback():
    """Malformed or invalid JSON from LLM triggers fallback to MockLLMProvider."""
    provider = RealLLMProvider(api_key="test-key", model="gpt-4o-mini", base_url="http://fake-llm.test/v1")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "This is plain text, not valid JSON."}}],
        "usage": {"total_tokens": 50},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        plan = provider.generate_plan({"overall_entropy": 5.0, "file_name": "sample.exe"})
        assert plan["profile"] == "standard"
        assert provider.last_call_meta["provider"] == "mock_fallback"
        assert provider.last_call_meta["fallback"] is True


def test_real_llm_provider_evaluate_observations_success():
    """RealLLMProvider successfully evaluates observations via HTTP."""
    provider = RealLLMProvider(api_key="test-key", model="gpt-4o-mini", base_url="http://fake-llm.test/v1")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "needs_second_pass": True,
                    "recommended_profile": "evasion_focus",
                    "telemetry_gaps_identified": ["Network traffic silenced."],
                    "prioritized_events": ["reg_key_create"],
                    "rationale": "Sample went dormant after initial registry modification.",
                    "confidence": 0.85,
                    "stop_recommendation": False,
                    "stop_reason": None,
                })
            }
        }],
        "usage": {"total_tokens": 120},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        obs = provider.evaluate_observations({}, {"total_events": 5})
        assert obs["needs_second_pass"] is True
        assert obs["recommended_profile"] == "evasion_focus"
        assert provider.last_call_meta["provider"] == "real"
        assert provider.last_call_meta["tokens_used"] == 120


def test_policy_validator_positive_allowlist_unknown_keys():
    """Unknown keys not in positive schema allowlist must be rejected."""
    plan_with_extra = {
        "profile": "standard",
        "execution_timeout_seconds": 60,
        "unexpected_control_key": "some_value",
    }
    res = PolicyValidator.validate_analysis_plan(plan_with_extra)
    assert res.is_allowed is False
    assert res.status == "REJECTED"
    assert "Security Policy Violation" in res.reason


def test_orchestration_audit_includes_llm_metadata(client):
    """Orchestration audit trail preserves provider, model, and token metadata."""
    sample_bytes = b"MZ" + b"\x90" * 150 + b"Metadata_Audit_Test"
    res_upload = client.post("/api/v1/samples", files={"file": ("meta_test.exe", io.BytesIO(sample_bytes))})
    sample = res_upload.json()

    res_analysis = client.post(
        "/api/v1/analyses?run_sync=true",
        json={"sample_id": sample["id"], "backend_type": "replay", "profile": "standard", "timeout_seconds": 60}
    )
    analysis_id = res_analysis.json()["id"]

    res_audit = client.get(f"/api/v1/analyses/{analysis_id}/orchestration")
    assert res_audit.status_code == 200
    records = res_audit.json()
    assert len(records) >= 2

    for rec in records:
        evidence = rec["supporting_evidence"]
        assert "llm_metadata" in evidence
        assert "provider" in evidence["llm_metadata"]
        assert "model" in evidence["llm_metadata"]

