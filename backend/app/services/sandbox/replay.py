import json
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

class ReplaySandboxBackend(SandboxBackend):
    """
    High-fidelity deterministic replay sandbox backend.
    Enables full end-to-end telemetry correlation, graph modeling, and reporting
    without executing dangerous code on host systems.
    """

    def __init__(self, fixtures_dir: Optional[Path] = None):
        self.fixtures_dir = fixtures_dir or settings.FIXTURES_DIR
        self._tasks: Dict[str, Dict[str, Any]] = {}

    def check_readiness(self) -> Dict[str, Any]:
        has_fixtures = any(self.fixtures_dir.glob("*.json"))
        return {
            "backend": "replay",
            "ready": True,
            "fixtures_available": has_fixtures,
            "fixtures_path": str(self.fixtures_dir),
            "mode": "deterministic_replay",
        }

    def _select_fixture_file(self, profile: str, sample_path: Path) -> Path:
        filename_lower = sample_path.name.lower()
        if "stealer" in profile or "redline" in filename_lower or "invoice" in filename_lower:
            stealer_path = self.fixtures_dir / "infostealer_redline_mock.json"
            if stealer_path.exists():
                return stealer_path

        # Default to ransomware fixture
        ransom_path = self.fixtures_dir / "ransomware_wannacry_mock.json"
        if ransom_path.exists():
            return ransom_path

        # Fallback to any json fixture
        all_fixtures = list(self.fixtures_dir.glob("*.json"))
        if all_fixtures:
            return all_fixtures[0]

        raise FileNotFoundError(f"No replay fixtures located in {self.fixtures_dir}")

    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        task_id = f"replay_{uuid.uuid4().hex[:12]}"
        fixture_file = self._select_fixture_file(profile, sample_path)
        
        with open(fixture_file, "r", encoding="utf-8") as f:
            fixture_data = json.load(f)

        self._tasks[task_id] = {
            "status": "completed",
            "profile": profile,
            "timeout_seconds": timeout_seconds,
            "sample_path": str(sample_path),
            "fixture_file": str(fixture_file),
            "data": fixture_data,
        }
        return task_id

    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(backend_task_id)
        if not task:
            return {"status": "not_found", "error": f"Unknown replay task {backend_task_id}"}
        return {
            "status": task["status"],
            "backend_task_id": backend_task_id,
            "progress_percent": 100,
        }

    def collect_results(self, backend_task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(backend_task_id)
        if not task:
            raise KeyError(f"Replay task {backend_task_id} not found.")
        return task["data"]

    def cancel_task(self, backend_task_id: str) -> bool:
        if backend_task_id in self._tasks:
            self._tasks[backend_task_id]["status"] = "cancelled"
            return True
        return False

    def generate_artifacts(self, backend_task_id: str, dest_dir: Path) -> List[Dict[str, Any]]:
        """Generates safe mock artifact files (PCAP, PNG screenshot, TXT) for the analysis."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        task = self._tasks.get(backend_task_id)
        if not task:
            return []

        fixture_data = task.get("data", {})
        artifacts_meta = fixture_data.get("artifacts", [])
        generated = []

        for item in artifacts_meta:
            name = item.get("name", "artifact.bin")
            art_type = item.get("type", "unknown")
            target_path = dest_dir / name

            if art_type == "pcap":
                # Standard pcap global header magic (little endian: d4 c3 b2 a1)
                pcap_hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
                with open(target_path, "wb") as f:
                    f.write(pcap_hdr)
            elif art_type == "screenshot":
                # Minimal valid 1x1 PNG bytes
                png_bytes = (
                    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
                    b"\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
                    b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
                )
                with open(target_path, "wb") as f:
                    f.write(png_bytes)
            else:
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(f"--- malbox-ai Forensic Artifact Mock: {name} ---\n{item.get('description', '')}\n")

            generated.append({
                "name": name,
                "type": art_type,
                "size_bytes": target_path.stat().st_size,
                "path": str(target_path),
            })

        return generated
