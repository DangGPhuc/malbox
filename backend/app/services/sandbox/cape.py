import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

class CapeSandboxBackend(SandboxBackend):
    """
    Integration adapter for CAPE Sandbox v2 REST API.
    Provides strict schema compliance, network error recovery, and telemetry ingestion.
    Does not require live sandbox infrastructure for initialization or testing.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ):
        self.api_url = (api_url or settings.CAPE_API_URL).rstrip("/")
        self.api_token = api_token or settings.CAPE_API_TOKEN
        self.timeout = timeout_seconds or settings.CAPE_TIMEOUT_SECONDS

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"
        return headers

    def check_readiness(self) -> Dict[str, Any]:
        """
        Verifies connectivity and service health against the CAPE v2 REST API endpoint.
        """
        endpoint = f"{self.api_url}/apiv2/cuckoo/status/"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    cuckoo_data = data.get("data", {})
                    return {
                        "backend": "cape",
                        "ready": True,
                        "version": cuckoo_data.get("version", "2.x"),
                        "tasks_summary": cuckoo_data.get("tasks", {}),
                        "api_url": self.api_url,
                        "error": None,
                    }
                else:
                    return {
                        "backend": "cape",
                        "ready": False,
                        "api_url": self.api_url,
                        "error": f"CAPE API returned HTTP {resp.status_code}: {resp.text[:200]}",
                    }
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            return {
                "backend": "cape",
                "ready": False,
                "api_url": self.api_url,
                "error": f"Failed to connect to CAPE API: {str(e)}",
                "prerequisites_missing": [
                    "CAPE Sandbox instance is not reachable at the configured URL.",
                    "Verify CAPE API service is active (systemctl status cape-web).",
                    "Ensure network routing and token authentication are configured in MALBOX_CAPE_API_URL / TOKEN."
                ]
            }

    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None,
        scenario_id: Optional[str] = None,
    ) -> str:
        """
        Submits a quarantined sample to the CAPE Sandbox task queue.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/create/file/"
        if not sample_path.exists():
            raise FileNotFoundError(f"Quarantined sample file not found: {sample_path}")

        files = {"file": (sample_path.name, open(sample_path, "rb"), "application/octet-stream")}
        data = {
            "timeout": str(timeout_seconds),
            "enforce_timeout": "1" if profile == "ransomware_focus" else "0",
            "tags": profile,
        }
        if options:
            data.update({k: str(v) for k, v in options.items()})

        try:
            with httpx.Client(timeout=30.0, headers=self._get_headers()) as client:
                resp = client.post(endpoint, files=files, data=data)
                if resp.status_code != 200:
                    raise RuntimeError(f"CAPE submission failed (HTTP {resp.status_code}): {resp.text}")

                resp_data = resp.json()
                task_ids = resp_data.get("data", {}).get("task_ids", [])
                if not task_ids:
                    raise ValueError(f"CAPE API returned no task IDs: {resp_data}")
                return str(task_ids[0])
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"CAPE Sandbox unreachable during submission: {str(e)}")

    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        """
        Queries the current status of an active or queued CAPE analysis task.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/view/{backend_task_id}/"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code == 404:
                    return {"status": "not_found", "backend_task_id": backend_task_id}
                if resp.status_code != 200:
                    return {"status": "error", "error": f"HTTP {resp.status_code}"}

                task_info = resp.json().get("data", {}).get("task", {})
                cape_status = task_info.get("status", "unknown")

                # Map CAPE statuses (pending, running, completed, reported, failed_analysis)
                status_map = {
                    "pending": "queued",
                    "running": "running",
                    "completed": "collecting",
                    "reported": "completed",
                    "failed_analysis": "failed",
                    "failed_processing": "failed",
                }
                normalized_status = status_map.get(cape_status, cape_status)
                return {
                    "status": normalized_status,
                    "backend_task_id": backend_task_id,
                    "cape_status": cape_status,
                }
        except Exception as e:
            return {"status": "error", "error": str(e), "backend_task_id": backend_task_id}

    def collect_results(self, backend_task_id: str) -> Dict[str, Any]:
        """
        Retrieves and normalizes the full JSON report from CAPE Sandbox.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/get/report/{backend_task_id}/"
        try:
            with httpx.Client(timeout=60.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code != 200:
                    raise RuntimeError(f"Failed to fetch CAPE report (HTTP {resp.status_code}): {resp.text[:200]}")

                cape_report = resp.json()
                return self._transform_cape_report(cape_report)
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"CAPE report retrieval failed: {str(e)}")

    def cancel_task(self, backend_task_id: str) -> bool:
        endpoint = f"{self.api_url}/apiv2/tasks/delete/{backend_task_id}/"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                return resp.status_code == 200
        except Exception:
            return False

    def generate_artifacts(self, backend_task_id: str, dest_dir: Path) -> List[Dict[str, Any]]:
        """
        Fetches official forensic artifacts (PCAP) from CAPE and stores them in the analysis directory.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        artifacts = []
        pcap_endpoint = f"{self.api_url}/apiv2/tasks/get/pcap/{backend_task_id}/"

        try:
            with httpx.Client(timeout=30.0, headers=self._get_headers()) as client:
                resp = client.get(pcap_endpoint)
                if resp.status_code == 200 and resp.content:
                    pcap_file = dest_dir / "traffic.pcap"
                    with open(pcap_file, "wb") as f:
                        f.write(resp.content)
                    artifacts.append({
                        "name": "traffic.pcap",
                        "type": "pcap",
                        "size_bytes": len(resp.content),
                        "path": str(pcap_file),
                    })
        except Exception:
            pass

        return artifacts

    def _transform_cape_report(self, cape_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates native CAPE v2 JSON schema into malbox-ai raw telemetry format.
        """
        behavior = cape_json.get("behavior", {})
        processes_raw = behavior.get("processes", [])
        generic = behavior.get("generic", [])
        network = cape_json.get("network", {})
        info = cape_json.get("info", {})

        processes = []
        for p in processes_raw:
            processes.append({
                "pid": p.get("process_id"),
                "ppid": p.get("parent_id"),
                "name": p.get("process_name"),
                "command_line": p.get("command_line", ""),
                "start_time": p.get("first_seen"),
                "end_time": None,
            })

        filesystem = []
        registry = []
        for g in generic:
            category = g.get("category", "")
            if category == "file":
                filesystem.append({
                    "action": g.get("status", "access"),
                    "pid": g.get("pid"),
                    "process_name": g.get("process_name"),
                    "path": g.get("path"),
                    "timestamp": g.get("time"),
                    "size_bytes": 0,
                    "is_dropped_binary": False,
                })
            elif category == "registry":
                registry.append({
                    "action": "reg_write" if "write" in g.get("status", "") else "reg_query",
                    "pid": g.get("pid"),
                    "process_name": g.get("process_name"),
                    "key": g.get("path"),
                    "value_name": "",
                    "data": "",
                    "timestamp": g.get("time"),
                    "persistence": "run" in (g.get("path") or "").lower(),
                })

        dns_list = []
        for d in network.get("dns", []):
            dns_list.append({
                "query": d.get("request"),
                "record_type": d.get("type", "A"),
                "response": (d.get("answers", [{}])[0].get("data")) if d.get("answers") else None,
                "timestamp": None,
            })

        connections = []
        for tcp in network.get("tcp", []):
            connections.append({
                "protocol": "TCP",
                "dest_ip": tcp.get("dst"),
                "dest_port": tcp.get("dport"),
                "timestamp": None,
            })

        http_list = []
        for h in network.get("http", []):
            http_list.append({
                "method": h.get("method", "GET"),
                "url": h.get("uri"),
                "status_code": h.get("response", {}).get("status"),
                "user_agent": h.get("user-agent"),
                "timestamp": None,
            })

        # Extract real sandbox metadata from CAPE info, or explicitly mark as unknown
        machine_meta = info.get("machine", {}) if isinstance(info.get("machine"), dict) else {}
        guest_os = machine_meta.get("name") or machine_meta.get("label") or "Not reported by sandbox backend"
        duration = info.get("duration")

        return {
            "metadata": {
                "cape_id": info.get("id"),
                "duration_seconds": duration,
                "environment": {
                    "guest_os": guest_os,
                    "machine": machine_meta.get("name", "Unknown"),
                    "confinement_verified": False,
                },
            },
            "processes": processes,
            "filesystem": filesystem,
            "registry": registry,
            "network": {
                "dns": dns_list,
                "connections": connections,
                "http": http_list,
            },
            "artifacts": [
                {"name": "traffic.pcap", "type": "pcap", "description": "CAPE captured network traffic"}
            ],
        }

