import json
import logging
import os
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import httpx

from app.core.config import settings
from app.ai.provider import LLMProvider
from app.ai.mock_provider import MockLLMProvider
from app.core.security import sanitize_untrusted_input_for_ai
from app.schemas.orchestration import AnalysisPlan, FollowUpRecommendation

logger = logging.getLogger(__name__)

TRUSTED_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_local_ai_endpoint(base_url: str) -> None:
    """
    Enforces trusted local endpoint policy: base_url must point strictly to loopback
    (localhost, 127.0.0.1, ::1) or explicitly approved private inference hosts via
    TRUSTED_LOCAL_AI_HOSTS. External/unauthorized hosts are strictly rejected when provider='local'.
    """
    if not base_url:
        raise ValueError("Local AI base_url cannot be empty.")

    try:
        parsed = urlparse(base_url)
        host = (parsed.hostname or "").strip().lower()
    except Exception as exc:
        raise ValueError(f"Invalid local AI base_url '{base_url}': {str(exc)}") from exc

    if not host:
        raise ValueError(f"Invalid local AI base_url '{base_url}': missing hostname.")

    if host in TRUSTED_LOOPBACK_HOSTS:
        return

    # Check explicitly approved private inference hosts from configuration
    allowed_raw = getattr(settings, "TRUSTED_LOCAL_AI_HOSTS", None) or os.environ.get("MALBOX_TRUSTED_LOCAL_AI_HOSTS", "")
    allowed_list = (
        [h.strip().lower() for h in allowed_raw.split(",") if h.strip()]
        if isinstance(allowed_raw, str)
        else [str(h).strip().lower() for h in allowed_raw]
    )
    if host in allowed_list:
        return

    raise ValueError(
        f"Untrusted local AI endpoint host '{host}'. Local AI policy strictly requires loopback (localhost, 127.0.0.1, ::1) "
        f"or explicitly approved private hosts in TRUSTED_LOCAL_AI_HOSTS ({allowed_list}). External or remote hosts "
        f"cannot be accessed under local AI mode without cloud provider consent."
    )


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
        is_local: bool = False,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or settings.AI_BASE_URL).rstrip("/")
        self.timeout = timeout or settings.AI_TIMEOUT_SECONDS
        self.is_local = is_local
        if self.is_local:
            validate_local_ai_endpoint(self.base_url)
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
            logger.warning(f"Real LLM plan generation failed: {e}. Falling back to deterministic MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            plan = mock.generate_plan(sample_metadata)
            plan["rationale"] = f"[AI PLANNER UNAVAILABLE: {e}] Deterministic static triage plan applied. " + plan.get("rationale", "")
            return plan

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
            logger.warning(f"Real LLM observation evaluation failed: {e}. Falling back to deterministic MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            eval_res = mock.evaluate_observations(sample_metadata, telemetry_summary)
            eval_res["rationale"] = f"[AI EVALUATOR UNAVAILABLE: {e}] Deterministic follow-up rules applied. " + eval_res.get("rationale", "")
            return eval_res

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
            logger.warning(f"Real LLM summary generation failed: {e}. Falling back to deterministic MockLLMProvider.")
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": self.model,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": str(e),
            }
            mock = MockLLMProvider()
            summary = mock.generate_executive_summary(sample_metadata, findings_summary, timeline)
            return f"[AI SUMMARY UNAVAILABLE: {e}] Non-AI technical summary: " + summary


    def generate_intelligence_report(
        self,
        bundle: "VerifiedEvidenceBundle",
        rules_text: "Optional[str]" = None,
        cancel_event: "Optional[Any]" = None,
    ) -> "IntelligenceReport":
        from app.ai.intelligence_helper import run_bounded_llm_intelligence

        report, call_meta = run_bounded_llm_intelligence(
            bundle=bundle,
            api_key=self.api_key,
            model=self.model,
            base_url=self.base_url,
            timeout=self.timeout,
            rules_text=rules_text,
            cancel_event=cancel_event,
        )
        self.last_call_meta = call_meta
        return report


def get_local_ai_base_url() -> str:
    """Returns local AI endpoint URL, defaulting to loopback Ollama if unconfigured or default cloud URL."""
    url = getattr(settings, "AI_BASE_URL", "") or ""
    if not url or "api.openai.com" in url.lower():
        return "http://127.0.0.1:11434/v1"
    return url


def get_llm_provider() -> LLMProvider:
    """Factory returns active AI provider based on configuration."""
    if settings.AI_PROVIDER in ("local", "ollama"):
        url = get_local_ai_base_url()
        return RealLLMProvider(
            api_key=settings.AI_API_KEY or "ollama",
            model=settings.AI_MODEL or "llama3",
            base_url=url,
            timeout=settings.AI_TIMEOUT_SECONDS,
            is_local=True,
        )
    if settings.AI_PROVIDER != "mock" and settings.AI_API_KEY:
        return RealLLMProvider(
            api_key=settings.AI_API_KEY,
            model=settings.AI_MODEL,
            base_url=settings.AI_BASE_URL,
            timeout=settings.AI_TIMEOUT_SECONDS,
            is_local=False,
        )
    return MockLLMProvider()


def get_reporting_llm_provider(
    force_external: bool = False,
    requested_mode: "Optional[str]" = None,
) -> LLMProvider:
    """
    Returns reporting intelligence provider respecting AI_REPORTING_MODE and explicit
    external transmission consent. Defaults strictly to offline MockLLMProvider.
    Local AI models (e.g. Ollama) execute locally on the host and do not require external consent.
    """
    cfg_mode = (getattr(settings, "AI_REPORTING_MODE", "opt_in") or "opt_in").strip().lower()
    cfg_prov = (getattr(settings, "AI_PROVIDER", "mock") or "mock").strip().lower()

    req_mode = (requested_mode or "").strip().lower()
    if not req_mode or req_mode in ("auto", "opt_in"):
        if cfg_mode in ("local", "ollama") or cfg_prov in ("local", "ollama"):
            mode = "local"
        elif cfg_mode == "opt_in":
            if cfg_prov != "mock" and getattr(settings, "AI_API_KEY", ""):
                mode = "llm"
            else:
                mode = "deterministic"
        else:
            mode = cfg_mode
    else:
        mode = req_mode

    if mode == "deterministic":
        return MockLLMProvider()

    # Local AI provider (Ollama / Local OpenAI-compatible server on localhost)
    if mode in ("local", "ollama") or cfg_prov in ("local", "ollama"):
        url = get_local_ai_base_url()
        return RealLLMProvider(
            api_key=settings.AI_API_KEY or "ollama",
            model=settings.AI_MODEL or "llama3",
            base_url=url,
            timeout=settings.AI_TIMEOUT_SECONDS,
            is_local=True,
        )

    if mode == "opencode" or (force_external and mode == "auto" and getattr(settings, "OPENCODE_ENABLED", False)):
        from app.ai.opencode_provider import OpenCodeReportProvider

        return OpenCodeReportProvider()

    has_consent = bool(getattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False))
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
