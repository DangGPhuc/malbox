from abc import ABC, abstractmethod
from typing import Dict, Any

class LLMProvider(ABC):
    """Abstract interface for structured AI analysis providers."""

    @abstractmethod
    def generate_plan(self, sample_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Proposes dynamic execution plan based on preflight PE triage."""
        pass

    @abstractmethod
    def evaluate_observations(
        self,
        sample_metadata: Dict[str, Any],
        telemetry_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates telemetry for execution gaps and recommends follow-up actions."""
        pass

    @abstractmethod
    def generate_executive_summary(
        self,
        sample_metadata: Dict[str, Any],
        findings_summary: Dict[str, Any],
        timeline: list
    ) -> str:
        """Produces evidence-grounded analyst executive summary."""
        pass
