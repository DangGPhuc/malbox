import json
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

class ReplaySandboxBackend(SandboxBackend):
    """
    Deterministic replay sandbox backend.
    Enables full end-to-end telemetry correlation, graph modeling, and reporting
    without executing dangerous code on host systems. All outputs are explicitly
    tagged with synthetic provenance.
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
            "is_synthetic": True,
        }

    def _resolve_fixture(self, profile: str, scenario_id: Optional[str] = None) -> tuple[Path, str]:
        """Resolves explicit scenario ID or falls back to profile-based scenario with explicit ID."""
        if scenario_id:
            # Check direct match
            direct_file = self.fixtures_dir / f"{scenario_id}.json"
            if direct_file.exists():
                return direct_file, scenario_id

            # Check stem match
            for p in self.fixtures_dir.glob("*.json"):
                if scenario_id.lower() in p.stem.lower():
                    return p, p.stem

        if "stealer" in profile.lower() or "credential" in profile.lower():
            target = self.fixtures_dir / "infostealer_redline_mock.json"
            if target.exists():
                return target, "infostealer_redline_mock"

        # Default ransomware scenario
        target = self.fixtures_dir / "ransomware_wannacry_mock.json"
        if target.exists():
            return target, "ransomware_wannacry_mock"

        all_fixtures = list(self.fixtures_dir.glob("*.json"))
        if all_fixtures:
            return all_fixtures[0], all_fixtures[0].stem

        raise FileNotFoundError(f"No replay fixtures located in {self.fixtures_dir}")

    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None,
        scenario_id: Optional[str] = None
    ) -> str:
        task_id = f"replay_{uuid.uuid4().hex[:12]}"
        fixture_file, resolved_scenario_id = self._resolve_fixture(profile, scenario_id)

        with open(fixture_file, "r", encoding="utf-8") as f:
            fixture_data = json.load(f)

        # Inject explicit synthetic provenance metadata
        meta = fixture_data.setdefault("metadata", {})
        meta["is_synthetic_replay"] = True
        meta["replay_scenario_id"] = resolved_scenario_id
        meta["fixture_file"] = fixture_file.name
        meta["fixture_version"] = fixture_data.get("fixture_version", "1.0")
        meta["provenance_statement"] = (
            "SYNTHETIC REPLAY DATA: Telemetry derived from calibrated reference scenario. "
            "Uploaded binary was NOT executed on the host system."
        )

        self._tasks[task_id] = {
            "status": "completed",
            "profile": profile,
            "timeout_seconds": timeout_seconds,
            "sample_path": str(sample_path),
            "fixture_file": str(fixture_file),
            "scenario_id": resolved_scenario_id,
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
            "is_synthetic": True,
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
        """Generates safe mock artifact files labeled explicitly as synthetic."""
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
                    f.write(
                        f"--- malbox-ai SYNTHETIC Forensic Artifact Mock: {name} ---\n"
                        f"Notice: Synthetic artifact generated from reference fixture {task.get('scenario_id')}.\n"
                        f"{item.get('description', '')}\n"
                    )

            generated.append({
                "name": name,
                "type": art_type,
                "size_bytes": target_path.stat().st_size,
                "path": str(target_path),
                "is_synthetic": True,
            })

        return generated
