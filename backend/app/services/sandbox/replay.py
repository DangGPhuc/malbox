import json
import re
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

REGISTERED_REPLAY_SCENARIOS: Set[str] = {
    "ransomware_wannacry_mock",
    "infostealer_redline_mock",
}

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
            "registered_scenarios": sorted(list(REGISTERED_REPLAY_SCENARIOS)),
        }

    def _resolve_fixture(self, profile: str, scenario_id: Optional[str] = None) -> tuple[Path, str, str]:
        """
        Resolves explicit scenario ID with strict path validation and allowlist enforcement.
        Rejects unknown scenario IDs and path traversal attempts.
        Returns: (fixture_path, resolved_scenario_id, fixture_version)
        """
        resolved_id = None
        if scenario_id:
            # 1. Prevent path traversal and arbitrary file access
            if ".." in scenario_id or "/" in scenario_id or "\\" in scenario_id or "\x00" in scenario_id:
                raise ValueError(
                    f"Security Policy Violation: Invalid replay scenario identifier containing path traversal: '{scenario_id}'"
                )
            if not re.match(r"^[a-zA-Z0-9_\-]+$", scenario_id):
                raise ValueError(
                    f"Security Policy Violation: Replay scenario identifier contains invalid characters: '{scenario_id}'"
                )

            # 2. Reject unknown scenario identifiers strictly (no silent fallback)
            if scenario_id not in REGISTERED_REPLAY_SCENARIOS:
                raise ValueError(
                    f"Unknown replay scenario identifier: '{scenario_id}'. "
                    f"Allowed scenarios: {sorted(list(REGISTERED_REPLAY_SCENARIOS))}"
                )
            resolved_id = scenario_id
        else:
            # Deterministic mapping from approved profile
            if "stealer" in profile.lower() or "infostealer" in profile.lower() or "credential" in profile.lower():
                resolved_id = "infostealer_redline_mock"
            else:
                resolved_id = "ransomware_wannacry_mock"

        target_file = (self.fixtures_dir / f"{resolved_id}.json").resolve()
        fixtures_root = self.fixtures_dir.resolve()

        # Strict containment verification
        if not target_file.is_relative_to(fixtures_root):
            raise ValueError(f"Security Policy Violation: Resolved fixture path escaped fixture directory: '{target_file}'")

        if not target_file.exists():
            raise FileNotFoundError(f"Registered replay fixture file not found on disk: {target_file}")

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                fixture_version = str(data.get("fixture_version", "1.0"))
        except Exception as e:
            raise RuntimeError(f"Failed to read replay fixture '{target_file}': {e}")

        return target_file, resolved_id, fixture_version

    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None,
        scenario_id: Optional[str] = None
    ) -> str:
        task_id = f"replay_{uuid.uuid4().hex[:12]}"
        fixture_file, resolved_scenario_id, fixture_version = self._resolve_fixture(profile, scenario_id)

        with open(fixture_file, "r", encoding="utf-8") as f:
            fixture_data = json.load(f)

        # Inject explicit synthetic provenance metadata
        meta = fixture_data.setdefault("metadata", {})
        meta["is_synthetic_replay"] = True
        meta["replay_scenario_id"] = resolved_scenario_id
        meta["fixture_file"] = fixture_file.name
        meta["fixture_version"] = fixture_version
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
            "fixture_version": fixture_version,
            "data": fixture_data,
        }
        return task_id

    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(backend_task_id)
        if not task:
            return {"status": "not_found", "error": f"Unknown replay task {backend_task_id}"}
        return {
            "status": "completed",
            "backend_task_id": backend_task_id,
            "scenario_id": task["scenario_id"],
            "fixture_version": task.get("fixture_version", "1.0"),
            "is_synthetic": True,
        }

    def collect_results(self, backend_task_id: str) -> Dict[str, Any]:
        task = self._tasks.get(backend_task_id)
        if not task:
            raise KeyError(f"Task {backend_task_id} not found in replay storage")
        return task["data"]

    def cancel_task(self, backend_task_id: str) -> bool:
        if backend_task_id in self._tasks:
            self._tasks[backend_task_id]["status"] = "cancelled"
            return True
        return False

    def generate_artifacts(self, backend_task_id: str, dest_dir: Path) -> List[Dict[str, Any]]:
        """Generates safe mock artifact files labeled explicitly as synthetic with strict path validation."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_root = dest_dir.resolve()
        task = self._tasks.get(backend_task_id)
        if not task:
            return []

        fixture_data = task.get("data", {})
        artifacts_meta = fixture_data.get("artifacts", [])
        generated = []

        for item in artifacts_meta:
            raw_name = str(item.get("name", "artifact.bin"))
            # Validate artifact name: prevent path traversal
            if ".." in raw_name or "/" in raw_name or "\\" in raw_name or "\x00" in raw_name:
                safe_name = Path(raw_name).name
            else:
                safe_name = raw_name

            target_path = (dest_dir / safe_name).resolve()
            if not target_path.is_relative_to(dest_root):
                continue

            art_type = item.get("type", "unknown")

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
                        f"--- malbox-ai SYNTHETIC Forensic Artifact Mock: {safe_name} ---\n"
                        f"Notice: Synthetic artifact generated from reference fixture {task.get('scenario_id')}.\n"
                        f"{item.get('description', '')}\n"
                    )

            generated.append({
                "name": safe_name,
                "type": art_type,
                "size_bytes": target_path.stat().st_size,
                "path": str(target_path),
                "is_synthetic": True,
            })

        return generated
