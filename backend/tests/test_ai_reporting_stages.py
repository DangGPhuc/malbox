import io
import json
import uuid
from unittest.mock import MagicMock
import httpx
import pytest

from app.core.config import settings
from app.ai.llm_client import get_reporting_llm_provider, RealLLMProvider, MockLLMProvider
from app.ai.intelligence_helper import (
    build_deterministic_proposed_intelligence,
    build_analyst_stages_execution,
    run_bounded_llm_intelligence,
)
from app.services.intelligence.bundle_builder import EvidenceBundleBuilder
from app.services.intelligence.enrichment_guard import enrichment_coordinator
from app.schemas.report import RiskAssessment


@pytest.fixture(autouse=True)
def _setup_test_env(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SYNTHETIC_REPLAY", True)
    enrichment_coordinator.reset()
    yield
    enrichment_coordinator.reset()


def _upload_and_analyze(client, filename="test_sample.exe"):
    sample_bytes = b"MZ" + b"\x90" * 128 + uuid.uuid4().hex.encode("ascii")
    res_up = client.post(
        "/api/v1/samples",
        files={"file": (filename, io.BytesIO(sample_bytes), "application/octet-stream")},
    )
    assert res_up.status_code == 201
    sample = res_up.json()

    res_an = client.post(
        "/api/v1/analyses?run_sync=true",
        json={
            "sample_id": sample["id"],
            "backend_type": "replay",
            "live_mode": False,
            "replay_scenario_id": "ransomware_wannacry_mock",
            "profile": "standard",
            "timeout_seconds": 60,
        },
    )
    assert res_an.status_code == 201, res_an.text
    analysis = res_an.json()
    return sample, analysis


def test_local_ai_mode_resolution_and_no_cloud_consent():
    """Verify that local AI mode resolves to RealLLMProvider targeting local endpoint without needing cloud consent."""
    # When local AI is configured:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(settings, "AI_REPORTING_MODE", "local")
        mp.setattr(settings, "AI_PROVIDER", "local")
        mp.setattr(settings, "AI_BASE_URL", "http://localhost:11434/v1")
        mp.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)

        # get_reporting_llm_provider in 'auto' mode should resolve to local provider
        provider = get_reporting_llm_provider(requested_mode="auto")
        assert isinstance(provider, RealLLMProvider)
        assert provider.base_url == "http://localhost:11434/v1"

        # Explicit 'local' mode also resolves to RealLLMProvider without consent
        provider_local = get_reporting_llm_provider(requested_mode="local")
        assert isinstance(provider_local, RealLLMProvider)


def test_analyst_stages_execution_structure(db_session, client):
    """Verify that 4 distinct inspectable analyst stages are generated with valid summaries."""
    _, analysis = _upload_and_analyze(client, "stages_test.exe")
    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)

    proposed = build_deterministic_proposed_intelligence(bundle)
    stages = build_analyst_stages_execution(bundle=bundle, proposed_intel=proposed, is_fallback=False, tokens_used=100)

    assert len(stages) == 4
    stage_ids = [s["stage_id"] for s in stages]
    assert stage_ids == [
        "stage_1_static_code_analyst",
        "stage_2_dynamic_behavior_analyst",
        "stage_3_threat_classification_analyst",
        "stage_4_report_composer",
    ]

    for s in stages:
        assert "valid" in s["validation_status"] or "verified" in s["validation_status"]
        assert s["error"] is None
        assert "inputs_summary" in s
        assert "output_summary" in s
        assert isinstance(s["tokens_used"], int)
        assert s["tokens_used"] == 0  # Fabricated per-stage token counts eliminated
        assert s["inference_mode"] == "consolidated_single_pass"
        assert s["execution_nature"] == "consolidated_single_pass_section"

    # Check stage 1 details
    assert "file_name" in stages[0]["inputs_summary"]
    assert "sha256" in stages[0]["inputs_summary"]
    # Check stage 2 details
    assert "matched_rules_count" in stages[1]["inputs_summary"]
    # Check stage 3 details
    assert "deterministic_risk_score" in stages[2]["inputs_summary"]
    # Check stage 4 details
    assert stages[3]["output_summary"]["deterministic_score_preserved"] is True


def test_local_ai_enrichment_mock_http_endpoint(client, db_session, monkeypatch):
    """Test full intelligence enrichment flow using mock local OpenAI-compatible endpoint."""
    _, analysis = _upload_and_analyze(client, "local_ai_sample.exe")
    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)

    proposal = build_deterministic_proposed_intelligence(bundle).model_dump()
    proposal["executive_assessment"] = "Local Ollama model evaluated sample: Benign demonstration executable."

    mock_http_called = False

    class MockLocalAIClient:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            nonlocal mock_http_called
            mock_http_called = True
            assert "chat/completions" in url
            resp = MagicMock()
            resp.raise_for_status = lambda: None
            resp.json = lambda: {
                "choices": [{"message": {"content": __import__("json").dumps(proposal)}}],
                "usage": {"total_tokens": 180},
            }
            return resp

    monkeypatch.setattr(settings, "AI_REPORTING_MODE", "local")
    monkeypatch.setattr(settings, "AI_PROVIDER", "local")
    monkeypatch.setattr(settings, "AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "test-reporting-token-abc")
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)  # Note: NO cloud consent!
    monkeypatch.setattr(httpx, "Client", MockLocalAIClient)

    # 1. Test POST /report/intelligence with mode='local' (without external_transmission_consent)
    res = client.post(
        f"/api/v1/analyses/{analysis['id']}/report/intelligence",
        headers={"X-Reporting-Token": "test-reporting-token-abc"},
        json={"mode": "local", "external_transmission_consent": False},
    )
    assert res.status_code == 200, res.text
    assert mock_http_called is True

    enriched = res.json()
    intel = enriched["full_report"]["intelligence_report"]
    assert intel["provider_metadata"]["provider"] == "real"
    assert intel["provider_metadata"]["fallback_used"] is False
    assert "Local Ollama model evaluated" in enriched["executive_summary"]

    # Verify 4 analyst stages in provider metadata
    stages = intel["provider_metadata"].get("analyst_stages")
    assert stages is not None
    assert len(stages) == 4
    assert stages[0]["stage_id"] == "stage_1_static_code_analyst"
    assert stages[3]["stage_id"] == "stage_4_report_composer"
    for st in stages:
        assert "valid" in st["validation_status"] or "verified" in st["validation_status"]
        assert st["tokens_used"] == 0
        assert st["inference_mode"] == "consolidated_single_pass"


def test_local_ai_enrichment_failure_preserves_previous_report(client, db_session, monkeypatch):
    """When the local AI endpoint fails during explicit enrichment, previous report is preserved and 502/503 returned."""
    _, analysis = _upload_and_analyze(client, "fallback_sample.exe")
    rep_initial = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    initial_summary = rep_initial["executive_summary"]
    initial_full = rep_initial["full_report"]

    class FailingClient:
        def __init__(self, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            raise httpx.ConnectError("Connection refused on http://127.0.0.1:11434")

    monkeypatch.setattr(settings, "AI_REPORTING_MODE", "local")
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "test-token")
    monkeypatch.setattr(httpx, "Client", FailingClient)

    # Explicit AI enrichment request fails
    res = client.post(
        f"/api/v1/analyses/{analysis['id']}/report/intelligence",
        headers={"X-Reporting-Token": "test-token"},
        json={"mode": "local"},
    )
    assert res.status_code in (502, 503)
    assert "previous known-good report preserved" in res.json()["detail"].lower()

    # Verify previous report is untouched in database
    rep_after = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    assert rep_after["executive_summary"] == initial_summary
    assert rep_after["full_report"] == initial_full


def test_untrusted_local_ai_endpoint_rejected(monkeypatch):
    """Untrusted external hosts are strictly rejected for local AI mode."""
    from app.ai.llm_client import validate_local_ai_endpoint

    # 1. Loopback hosts are permitted
    validate_local_ai_endpoint("http://127.0.0.1:11434/v1")
    validate_local_ai_endpoint("http://localhost:11434/v1")
    validate_local_ai_endpoint("http://[::1]:11434/v1")

    # 2. External public domains and IPs are rejected
    with pytest.raises(ValueError, match="Untrusted local AI endpoint host"):
        validate_local_ai_endpoint("http://api.openai.com/v1")

    with pytest.raises(ValueError, match="Untrusted local AI endpoint host"):
        validate_local_ai_endpoint("http://8.8.8.8:11434/v1")

    # 3. Approved private host via TRUSTED_LOCAL_AI_HOSTS succeeds
    monkeypatch.setattr(settings, "TRUSTED_LOCAL_AI_HOSTS", "192.168.1.100,lab-ai.internal")
    validate_local_ai_endpoint("http://192.168.1.100:11434/v1")
    validate_local_ai_endpoint("http://lab-ai.internal:11434/v1")

    # 4. Other host still rejected
    with pytest.raises(ValueError, match="Untrusted local AI endpoint host"):
        validate_local_ai_endpoint("http://192.168.1.101:11434/v1")


def test_cloud_consent_required_for_external_llm(monkeypatch):
    """External LLM provider strictly requires explicit cloud consent."""
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(settings, "AI_API_KEY", "sk-test-key-12345")
    monkeypatch.setattr(settings, "AI_BASE_URL", "https://api.openai.com/v1")

    # Without consent -> MockLLMProvider (no external transmission)
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)
    prov_no_consent = get_reporting_llm_provider(force_external=True, requested_mode="llm")
    assert isinstance(prov_no_consent, MockLLMProvider)

    # With consent -> RealLLMProvider
    monkeypatch.setattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", True)
    prov_with_consent = get_reporting_llm_provider(force_external=True, requested_mode="llm")
    assert isinstance(prov_with_consent, RealLLMProvider)
