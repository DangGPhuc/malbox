import json
import logging
from typing import Dict, Any, Optional
import httpx

from app.core.config import settings
from app.ai.provider import LLMProvider
from app.ai.mock_provider import MockLLMProvider
from app.core.security import sanitize_untrusted_input_for_ai
from app.schemas.orchestration import AnalysisPlan, FollowUpRecommendation

logger = logging.getLogger(__name__)

class RealLLMProvider(LLMProvider):
    """
    Live OpenAI / Ollama / OpenAI-compatible LLM provider with strict schema validation
    and deterministic fallback to MockLLMProvider on failure or timeout.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or settings.AI_BASE_URL).rstrip("/")
        self.timeout = timeout or settings.AI_TIMEOUT_SECONDS
        self.provider_name = "real"
        self.last_call_meta: Dict[str, Any] = {
            "provider": "real",
            "model": self.model,
            "tokens_used": 0,
            "fallback": False,
            "fallback_reason": None,
        }

    def _call_chat_completions(self, system_prompt: str, user_prompt: str, response_json: bool = True) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": settings.AI_TEMPERATURE,
            "max_tokens": settings.AI_MAX_TOKENS,
        }
        if response_json:
            payload["response_format"] = {"type": "json_object"}

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(endpoint, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"LLM API returned HTTP {resp.status_code}: {resp.text[:300]}")
            return resp.json()

    def generate_plan(self, sample_metadata: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = (
            "You are an AI Malware Analysis Orchestrator. Output ONLY valid JSON adhering to the AnalysisPlan schema:\n"
            "{\n"
            '  "profile": "standard" | "ransomware_focus" | "infostealer_focus" | "evasion_focus" | "dropper_focus" | "network_focus",\n'
            '  "execution_timeout_seconds": integer between 30 and 300,\n'
            '  "requested_artifacts": list from ["pcap", "screenshots", "memory_strings", "dropped_files", "network_traffic"],\n'
            '  "telemetry_focus": list from ["process", "file", "registry", "network", "memory"],\n'
            '  "rationale": "detailed reason based on static PE triage",\n'
            '  "confidence": float 0.0 to 1.0,\n'
            '  "limitations": list of strings\n'
            "}"
        )
        safe_meta = {
            "file_name": sanitize_untrusted_input_for_ai(sample_metadata.get("file_name", "unknown.exe")),
            "file_size": sample_metadata.get("file_size", 0),
            "entropy": sample_metadata.get("overall_entropy", 0.0),
            "is_packed": sample_metadata.get("is_packed_heuristic", False),
            "sections": [s.get("name") for s in sample_metadata.get("sections", []) if isinstance(s, dict)],
            "imports_count": len(sample_metadata.get("imports", [])),
        }
        user_prompt = f"Analyze the following static PE metadata and propose a bounded dynamic execution plan:\n{json.dumps(safe_meta)}"

        try:
            result = self._call_chat_completions(system_prompt, user_prompt, response_json=True)
            content = result["choices"][0]["message"]["content"]
            plan_dict = json.loads(content)
            # Schema validation
            validated = AnalysisPlan.model_validate(plan_dict)
            tokens = result.get("usage", {}).get("total_tokens", 0)
            self.last_call_meta = {
                "provider": "real",
                "model": self.model,
                "tokens_used": tokens,
                "fallback": False,
                "fallback_reason": None,
            }
            return validated.model_dump()
        except Exception as e:
            logger.warning(f"Real LLM plan generation failed: {e}. Falling back to MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            return mock.generate_plan(sample_metadata)

    def evaluate_observations(
        self,
        sample_metadata: Dict[str, Any],
        telemetry_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        system_prompt = (
            "You are an AI Malware Analysis Evaluator. Output ONLY valid JSON adhering to FollowUpRecommendation schema:\n"
            "{\n"
            '  "needs_second_pass": boolean,\n'
            '  "recommended_profile": "standard" | "ransomware_focus" | "infostealer_focus" | "evasion_focus" | null,\n'
            '  "telemetry_gaps_identified": list of strings,\n'
            '  "prioritized_events": list of strings,\n'
            '  "rationale": "detailed reason based on observed telemetry",\n'
            '  "confidence": float 0.0 to 1.0,\n'
            '  "stop_recommendation": boolean,\n'
            '  "stop_reason": string or null\n'
            "}"
        )
        user_prompt = f"Evaluate observed sandbox telemetry:\nTelemetry Summary: {json.dumps(telemetry_summary)}"

        try:
            result = self._call_chat_completions(system_prompt, user_prompt, response_json=True)
            content = result["choices"][0]["message"]["content"]
            eval_dict = json.loads(content)
            validated = FollowUpRecommendation.model_validate(eval_dict)
            tokens = result.get("usage", {}).get("total_tokens", 0)
            self.last_call_meta = {
                "provider": "real",
                "model": self.model,
                "tokens_used": tokens,
                "fallback": False,
                "fallback_reason": None,
            }
            return validated.model_dump()
        except Exception as e:
            logger.warning(f"Real LLM observation evaluation failed: {e}. Falling back to MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            return mock.evaluate_observations(sample_metadata, telemetry_summary)

    def generate_executive_summary(
        self,
        sample_metadata: Dict[str, Any],
        findings_summary: Dict[str, Any],
        timeline: list
    ) -> str:
        system_prompt = (
            "You are an expert Malware Behavioral Intelligence Analyst. "
            "Write a concise executive summary grounded strictly in the provided forensic evidence."
        )
        user_prompt = f"Metadata: {json.dumps(sample_metadata)}\nFindings: {json.dumps(findings_summary)}"

        try:
            result = self._call_chat_completions(system_prompt, user_prompt, response_json=False)
            tokens = result.get("usage", {}).get("total_tokens", 0)
            self.last_call_meta = {
                "provider": "real",
                "model": self.model,
                "tokens_used": tokens,
                "fallback": False,
                "fallback_reason": None,
            }
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"Real LLM summary generation failed: {e}. Falling back to MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            return mock.generate_executive_summary(sample_metadata, findings_summary, timeline)


    def generate_intelligence_report(
        self,
        bundle: "VerifiedEvidenceBundle",
        rules_text: "Optional[str]" = None,
    ) -> "IntelligenceReport":
        from app.ai.intelligence_helper import run_bounded_llm_intelligence

        report, call_meta = run_bounded_llm_intelligence(
            bundle=bundle,
            api_key=self.api_key,
            model=self.model,
            base_url=self.base_url,
            timeout=self.timeout,
            rules_text=rules_text,
        )
        self.last_call_meta = call_meta
        return report


def get_llm_provider() -> LLMProvider:
    """Factory returns active AI provider based on configuration."""
    if settings.AI_PROVIDER != "mock" and settings.AI_API_KEY:
        return RealLLMProvider(
            api_key=settings.AI_API_KEY,
            model=settings.AI_MODEL,
            base_url=settings.AI_BASE_URL,
            timeout=settings.AI_TIMEOUT_SECONDS,
        )
    return MockLLMProvider()


def get_reporting_llm_provider(
    force_external: bool = False,
    requested_mode: "Optional[str]" = None,
) -> LLMProvider:
    """
    Returns reporting intelligence provider respecting AI_REPORTING_MODE and explicit
    external transmission consent. Defaults strictly to offline MockLLMProvider.
    """
    mode = (
        (requested_mode or getattr(settings, "AI_REPORTING_MODE", "opt_in") or "opt_in")
        .strip()
        .lower()
    )
    has_consent = bool(getattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False))

    if mode == "deterministic":
        return MockLLMProvider()

    if mode == "opencode" or (force_external and mode == "auto" and getattr(settings, "OPENCODE_ENABLED", False)):
        from app.ai.opencode_provider import OpenCodeReportProvider

        return OpenCodeReportProvider()

    if (
        (mode == "llm" or (force_external and mode == "auto"))
        and has_consent
        and settings.AI_PROVIDER != "mock"
        and settings.AI_API_KEY
    ):
        return RealLLMProvider(
            api_key=settings.AI_API_KEY,
            model=settings.AI_MODEL,
            base_url=settings.AI_BASE_URL,
            timeout=settings.AI_TIMEOUT_SECONDS,
        )
    return MockLLMProvider()
