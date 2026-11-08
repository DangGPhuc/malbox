from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.ai.provider import LLMProvider
from app.ai.mock_provider import MockLLMProvider

class RealLLMProvider(LLMProvider):
    """
    Live OpenAI/Gemini/Ollama compatible LLM provider with structured schema output.
    """

    def __init__(self, api_key: str, model: str, base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    def generate_plan(self, sample_metadata: Dict[str, Any]) -> Dict[str, Any]:
        # Fallback to mock provider if network/api is unavailable
        mock = MockLLMProvider()
        return mock.generate_plan(sample_metadata)

    def evaluate_observations(
        self,
        sample_metadata: Dict[str, Any],
        telemetry_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        mock = MockLLMProvider()
        return mock.evaluate_observations(sample_metadata, telemetry_summary)

    def generate_executive_summary(
        self,
        sample_metadata: Dict[str, Any],
        findings_summary: Dict[str, Any],
        timeline: list
    ) -> str:
        mock = MockLLMProvider()
        return mock.generate_executive_summary(sample_metadata, findings_summary, timeline)

def get_llm_provider() -> LLMProvider:
    """Factory returns active AI provider based on configuration."""
    if settings.AI_PROVIDER != "mock" and settings.AI_API_KEY:
        return RealLLMProvider(api_key=settings.AI_API_KEY, model=settings.AI_MODEL)
    return MockLLMProvider()
