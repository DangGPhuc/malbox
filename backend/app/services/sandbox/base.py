from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional

class SandboxBackend(ABC):
    """Abstract interface defining the contract for dynamic execution backends."""

    @abstractmethod
    def check_readiness(self) -> Dict[str, Any]:
        """Validates that the sandbox infrastructure is accessible and ready to accept tasks."""
        pass

    @abstractmethod
    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None,
        scenario_id: Optional[str] = None
    ) -> str:
        """Submits an approved binary to the execution environment. Returns backend task ID."""
        pass

    @abstractmethod
    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        """Polls current task state. Returns dict with status (running, completed, failed, etc.)."""
        pass

    @abstractmethod
    def collect_results(self, backend_task_id: str) -> Dict[str, Any]:
        """Gathers raw execution telemetry and report data from the sandbox backend."""
        pass

    @abstractmethod
    def cancel_task(self, backend_task_id: str) -> bool:
        """Requests task cancellation when supported by backend."""
        pass

    @abstractmethod
    def generate_artifacts(self, backend_task_id: str, dest_dir: Path) -> List[Dict[str, Any]]:
        """Materializes safe mock or real forensic artifacts into the analysis artifacts folder."""
        pass
