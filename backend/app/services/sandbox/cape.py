import os
import re
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

ALLOWED_SUBMISSION_OPTIONS = {
    "timeout",
    "enforce_timeout",
    "tags",
    "machine",
    "package",
    "options",
    "priority",
    "custom",
    "clock",
}

SAFE_TAG_REGEX = re.compile(r"^[a-zA-Z0-9_,-]{1,128}$")

DEFAULT_PROFILE_TAG_MAP = {
    "ransomware_focus": "ransomware_focus",
    "infostealer_focus": "infostealer_focus",
    "evasion_focus": "evasion_focus",
}


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
        profile_tag_map: Optional[Dict[str, str]] = None,
    ):
        self.api_url = (api_url or settings.CAPE_API_URL).rstrip("/")
        self.api_token = api_token or settings.CAPE_API_TOKEN
        self.timeout = timeout_seconds or settings.CAPE_TIMEOUT_SECONDS
        self.profile_tag_map = profile_tag_map or DEFAULT_PROFILE_TAG_MAP

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
            with httpx.Client(timeout=5.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    cuckoo_data = data.get("data", {}) if isinstance(data, dict) else {}
                    return {
                        "backend": "cape",
                        "ready": True,
                        "status": "ready",
                        "version": cuckoo_data.get("version", "2.x"),
                        "tasks_summary": cuckoo_data.get("tasks", {}),
                        "api_url": self.api_url,
                        "error": None,
                    }
                elif resp.status_code in (401, 403):
                    return {
                        "backend": "cape",
                        "ready": False,
                        "status": "unauthorized",
                        "api_url": self.api_url,
                        "error": f"CAPE API authentication failed (HTTP {resp.status_code}). Check MALBOX_CAPE_API_TOKEN.",
                    }
                else:
                    return {
                        "backend": "cape",
                        "ready": False,
                        "status": "degraded",
                        "api_url": self.api_url,
                        "error": f"CAPE API returned HTTP {resp.status_code}: {resp.text[:200]}",
                    }
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            return {
                "backend": "cape",
                "ready": False,
                "status": "unreachable",
                "api_url": self.api_url,
                "error": f"Failed to connect to CAPE API: {str(e)}",
                "prerequisites_missing": [
                    "CAPE Sandbox instance is not reachable at the configured URL.",
                    "Verify CAPE API service is active (systemctl status cape-web or poetry run python manage.py runserver).",
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
        Enforces strict option allowlist and graceful machine tag mapping.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/create/file/"
        if not sample_path.exists():
            raise FileNotFoundError(f"Quarantined sample file not found: {sample_path}")

        # Validate options against strict allowlist
        validated_options: Dict[str, Any] = {}
        if options:
            for k, v in options.items():
                if k not in ALLOWED_SUBMISSION_OPTIONS:
                    raise ValueError(f"Disallowed CAPE submission option: {k}")
                validated_options[k] = v

        # Build form data
        data: Dict[str, str] = {
            "timeout": str(timeout_seconds),
            "enforce_timeout": "1" if profile == "ransomware_focus" else "0",
        }

        # Resolve machine tags gracefully (A2)
        # Standard profile should not require an explicit machine tag.
        explicit_tags = validated_options.get("tags")
        if explicit_tags:
            tag_str = str(explicit_tags).strip()
            if not SAFE_TAG_REGEX.match(tag_str):
                raise ValueError(f"Invalid CAPE machine tag format: {tag_str}")
            data["tags"] = tag_str
        elif profile and profile != "standard":
            mapped_tag = self.profile_tag_map.get(profile)
            if mapped_tag:
                if not SAFE_TAG_REGEX.match(mapped_tag):
                    raise ValueError(f"Invalid mapped CAPE machine tag format: {mapped_tag}")
                data["tags"] = mapped_tag

        # Forward other allowed options
        for k, v in validated_options.items():
            if k != "tags":
                data[k] = str(v)

        with open(sample_path, "rb") as f:
            file_bytes = f.read()

        files = {"file": (sample_path.name, file_bytes, "application/octet-stream")}

        try:
            with httpx.Client(timeout=30.0, headers=self._get_headers()) as client:
                resp = client.post(endpoint, files=files, data=data)
                if resp.status_code != 200:
                    raise RuntimeError(f"CAPE submission failed (HTTP {resp.status_code}): {resp.text[:200]}")

                try:
                    resp_data = resp.json()
                except Exception as e:
                    raise RuntimeError(f"Invalid JSON returned by CAPE submission endpoint: {str(e)}")

                if isinstance(resp_data, dict) and resp_data.get("error") is True:
                    err_msg = resp_data.get("error_value") or resp_data.get("errors") or "Unknown CAPE submission error"
                    raise RuntimeError(f"CAPE submission rejected: {err_msg}")

                data_block = resp_data.get("data", {}) if isinstance(resp_data, dict) else {}
                task_ids = data_block.get("task_ids", [])
                if not task_ids:
                    single_id = data_block.get("task_id") or data_block.get("id")
                    if single_id is not None:
                        task_ids = [single_id]

                if not task_ids:
                    raise ValueError(f"CAPE API returned no task IDs: {resp_data}")

                return str(task_ids[0])
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"CAPE Sandbox unreachable during submission: {str(e)}")

    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        """
        Queries the current status of an active or queued CAPE analysis task.
        Supports both flat (v2 native) and wrapped (legacy/mock) JSON response shapes.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/view/{backend_task_id}/"
        try:
            with httpx.Client(timeout=10.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code == 404:
                    return {
                        "status": "not_found",
                        "backend_task_id": backend_task_id,
                        "cape_status": "not_found",
                        "is_ready_for_report": False,
                        "error": "Task not found on CAPE server (HTTP 404)",
                    }
                if resp.status_code in (401, 403):
                    return {
                        "status": "unauthorized",
                        "backend_task_id": backend_task_id,
                        "cape_status": "unauthorized",
                        "is_ready_for_report": False,
                        "error": f"CAPE authentication failed (HTTP {resp.status_code})",
                    }
                if resp.status_code != 200:
                    return {
                        "status": "error",
                        "backend_task_id": backend_task_id,
                        "cape_status": "error",
                        "is_ready_for_report": False,
                        "error": f"HTTP {resp.status_code}: {resp.text[:150]}",
                    }

                try:
                    resp_json = resp.json()
                except Exception as e:
                    return {
                        "status": "error",
                        "backend_task_id": backend_task_id,
                        "cape_status": "error",
                        "is_ready_for_report": False,
                        "error": f"Invalid JSON response from CAPE: {str(e)}",
                    }

                if not isinstance(resp_json, dict):
                    return {
                        "status": "error",
                        "backend_task_id": backend_task_id,
                        "cape_status": "error",
                        "is_ready_for_report": False,
                        "error": f"Unexpected JSON response structure (expected dict, got {type(resp_json).__name__})",
                    }

                # Check error envelope
                if resp_json.get("error") is True:
                    err_val = resp_json.get("error_value") or "CAPE API error"
                    err_str = str(err_val)
                    if "not found" in err_str.lower() or "does not exist" in err_str.lower():
                        return {
                            "status": "not_found",
                            "backend_task_id": backend_task_id,
                            "cape_status": "not_found",
                            "is_ready_for_report": False,
                            "error": err_str,
                        }
                    return {
                        "status": "error",
                        "backend_task_id": backend_task_id,
                        "cape_status": "error",
                        "is_ready_for_report": False,
                        "error": err_str,
                    }

                # Handle both flat {"data": {"id": 1, "status": "running"}}
                # and wrapped {"data": {"task": {"id": 1, "status": "running"}}}
                data_obj = resp_json.get("data", {})
                if not isinstance(data_obj, dict):
                    return {
                        "status": "error",
                        "backend_task_id": backend_task_id,
                        "cape_status": "error",
                        "is_ready_for_report": False,
                        "error": f"Unexpected data payload in CAPE response: {type(data_obj).__name__}",
                    }

                task_info = data_obj.get("task") if isinstance(data_obj.get("task"), dict) else data_obj
                raw_status = task_info.get("status")
                if not raw_status or not isinstance(raw_status, str):
                    return {
                        "status": "unknown",
                        "backend_task_id": backend_task_id,
                        "cape_status": "unknown",
                        "is_ready_for_report": False,
                        "error": "Missing or non-string status field in task payload",
                    }

                cape_status = raw_status.strip().lower()

                # State transition mapping (A3)
                # "completed" in CAPE indicates guest VM halted; report post-processing is underway ("collecting").
                # "reported" in CAPE indicates report.json is fully compiled and ready ("completed").
                status_map = {
                    "pending": "queued",
                    "running": "running",
                    "completed": "collecting",
                    "processing": "collecting",
                    "reported": "completed",
                    "failed_analysis": "failed",
                    "failed_processing": "failed",
                    "deleted": "not_found",
                }
                normalized_status = status_map.get(cape_status, cape_status)

                return {
                    "status": normalized_status,
                    "backend_task_id": backend_task_id,
                    "cape_status": cape_status,
                    "is_ready_for_report": (cape_status == "reported"),
                    "error": None,
                }
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            return {
                "status": "network_unavailable",
                "backend_task_id": backend_task_id,
                "cape_status": "unreachable",
                "is_ready_for_report": False,
                "error": f"Network error contacting CAPE API: {str(e)}",
            }
        except Exception as e:
            return {
                "status": "error",
                "backend_task_id": backend_task_id,
                "cape_status": "error",
                "is_ready_for_report": False,
                "error": f"Unexpected error querying CAPE task status: {str(e)}",
            }

    def collect_results(
        self,
        backend_task_id: str,
        max_retries: int = 4,
        retry_delay_seconds: float = 2.0,
    ) -> Dict[str, Any]:
        """
        Retrieves and normalizes the full JSON report from CAPE Sandbox.
        Implements bounded retry for completed-before-reported race conditions.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/get/report/{backend_task_id}/"

        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=60.0, headers=self._get_headers()) as client:
                    resp = client.get(endpoint)
                    if resp.status_code == 200:
                        try:
                            cape_report = resp.json()
                        except Exception as e:
                            raise RuntimeError(f"CAPE report returned invalid JSON: {str(e)}")

                        # Reject API-level error envelopes even when HTTP status is 200 (A4)
                        if isinstance(cape_report, dict) and cape_report.get("error") is True:
                            err_val = cape_report.get("error_value") or cape_report.get("message") or "Unknown report error"
                            err_str = str(err_val).lower()
                            if ("no report" in err_str or "processing" in err_str or "not ready" in err_str) and attempt < max_retries - 1:
                                time.sleep(retry_delay_seconds)
                                continue
                            raise RuntimeError(f"CAPE report unavailable for task {backend_task_id}: {err_val}")

                        if not isinstance(cape_report, dict):
                            raise RuntimeError(f"CAPE report payload must be a JSON object, got {type(cape_report).__name__}")

                        return self._transform_cape_report(cape_report, backend_task_id=backend_task_id)

                    elif resp.status_code in (404, 500) and attempt < max_retries - 1:
                        # Report might still be rendering on disk
                        time.sleep(retry_delay_seconds)
                        continue
                    else:
                        raise RuntimeError(f"Failed to fetch CAPE report (HTTP {resp.status_code}): {resp.text[:200]}")
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay_seconds)
                    continue
                raise ConnectionError(f"CAPE report retrieval failed after retries: {str(e)}")

        raise RuntimeError(f"CAPE report retrieval timed out waiting for report generation for task {backend_task_id}")

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

    def _transform_cape_report(self, cape_json: Dict[str, Any], backend_task_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Translates native CAPE v2 JSON schema into malbox-ai raw telemetry format.
        Validates telemetry completeness, extracts payload dumps and API events conservatively.
        """
        behavior = cape_json.get("behavior", {}) if isinstance(cape_json.get("behavior"), dict) else {}
        processes_raw = behavior.get("processes", []) if isinstance(behavior.get("processes"), list) else []
        generic = behavior.get("generic", []) if isinstance(behavior.get("generic"), list) else []
        summary = behavior.get("summary", {}) if isinstance(behavior.get("summary"), dict) else {}
        network = cape_json.get("network", {}) if isinstance(cape_json.get("network"), dict) else {}
        info = cape_json.get("info", {}) if isinstance(cape_json.get("info"), dict) else {}
        debug = cape_json.get("debug", {}) if isinstance(cape_json.get("debug"), dict) else {}

        # 1. Process activity & monitored API calls
        processes = []
        all_monitored_calls: List[Dict[str, Any]] = []

        for p in processes_raw:
            pid = p.get("process_id")
            pname = p.get("process_name")
            processes.append({
                "pid": pid,
                "ppid": p.get("parent_id"),
                "name": pname,
                "command_line": p.get("command_line", ""),
                "start_time": p.get("first_seen"),
                "end_time": None,
            })

            # Bounded extraction of monitored API calls (A5)
            calls = p.get("calls", [])
            if isinstance(calls, list):
                for call in calls[:500]:  # Cap at 500 API calls per process
                    api_name = call.get("api")
                    if api_name:
                        all_monitored_calls.append({
                            "pid": pid,
                            "process_name": pname,
                            "api": api_name,
                            "status": call.get("status"),
                            "return_value": call.get("return_value"),
                            "arguments": call.get("arguments", {}),
                            "timestamp": call.get("timestamp"),
                        })

        # 2. Filesystem activity (combine generic + summary)
        filesystem: List[Dict[str, Any]] = []
        seen_file_paths = set()

        for g in generic:
            if g.get("category") == "file":
                path = g.get("path")
                if path:
                    seen_file_paths.add(path.lower())
                filesystem.append({
                    "action": g.get("status", "access"),
                    "pid": g.get("pid"),
                    "process_name": g.get("process_name"),
                    "path": path,
                    "timestamp": g.get("time"),
                    "size_bytes": 0,
                    "is_dropped_binary": False,
                })

        # Supplement with behavior.summary.write_files / delete_files if generic was sparse
        for w_file in summary.get("write_files", []):
            if isinstance(w_file, str) and w_file.lower() not in seen_file_paths:
                seen_file_paths.add(w_file.lower())
                is_bin = any(w_file.lower().endswith(ext) for ext in [".exe", ".dll", ".bin", ".sys", ".scr", ".bat", ".cmd"])
                filesystem.append({
                    "action": "write",
                    "pid": None,
                    "process_name": None,
                    "path": w_file,
                    "timestamp": None,
                    "size_bytes": 0,
                    "is_dropped_binary": is_bin,
                })

        # Supplement with dropped files section from CAPE report
        dropped_files = cape_json.get("dropped", [])
        if isinstance(dropped_files, list):
            for drop in dropped_files:
                if isinstance(drop, dict):
                    d_path = drop.get("path") or drop.get("name") or "dropped_file.bin"
                    if d_path.lower() not in seen_file_paths:
                        seen_file_paths.add(d_path.lower())
                        is_bin = any(d_path.lower().endswith(ext) for ext in [".exe", ".dll", ".bin", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".ps1"])
                        filesystem.append({
                            "action": "write",
                            "pid": drop.get("pid"),
                            "process_name": drop.get("process_name"),
                            "path": d_path,
                            "timestamp": None,
                            "size_bytes": drop.get("size", 0),
                            "sha256": drop.get("sha256"),
                            "is_dropped_binary": is_bin,
                        })

        for d_file in summary.get("delete_files", []):
            if isinstance(d_file, str) and d_file.lower() not in seen_file_paths:
                seen_file_paths.add(d_file.lower())
                filesystem.append({
                    "action": "delete",
                    "pid": None,
                    "process_name": None,
                    "path": d_file,
                    "timestamp": None,
                    "size_bytes": 0,
                    "is_dropped_binary": False,
                })

        # Ingest extracted in-memory / dumped payloads from CAPE (A5)
        payloads = cape_json.get("payloads", [])
        if not payloads and isinstance(cape_json.get("CAPE"), dict):
            payloads = cape_json.get("CAPE", {}).get("payloads", [])

        if isinstance(payloads, list):
            for payload in payloads:
                if isinstance(payload, dict):
                    p_name = payload.get("name") or payload.get("path") or "MEM_DUMP_PAYLOAD.bin"
                    filesystem.append({
                        "action": "write",
                        "pid": payload.get("pid"),
                        "process_name": payload.get("process_name"),
                        "path": p_name,
                        "timestamp": None,
                        "size_bytes": payload.get("size", 0),
                        "sha256": payload.get("sha256"),
                        "is_dropped_binary": True,
                    })

        # 3. Registry activity (combine generic + summary)
        registry: List[Dict[str, Any]] = []
        seen_reg_keys = set()

        for g in generic:
            if g.get("category") == "registry":
                key = g.get("path")
                if key:
                    seen_reg_keys.add(key.lower())
                registry.append({
                    "action": "reg_write" if "write" in g.get("status", "") else "reg_query",
                    "pid": g.get("pid"),
                    "process_name": g.get("process_name"),
                    "key": key,
                    "value_name": "",
                    "data": "",
                    "timestamp": g.get("time"),
                    "persistence": "run" in (key or "").lower(),
                })

        for w_key in summary.get("write_keys", []):
            if isinstance(w_key, str) and w_key.lower() not in seen_reg_keys:
                seen_reg_keys.add(w_key.lower())
                registry.append({
                    "action": "reg_write",
                    "pid": None,
                    "process_name": None,
                    "key": w_key,
                    "value_name": "",
                    "data": "",
                    "timestamp": None,
                    "persistence": "run" in w_key.lower(),
                })

        # 4. Network activity
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

        for udp in network.get("udp", []):
            connections.append({
                "protocol": "UDP",
                "dest_ip": udp.get("dst"),
                "dest_port": udp.get("dport"),
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

        # 5. Metadata and environment
        machine_meta = info.get("machine", {}) if isinstance(info.get("machine"), dict) else {}
        guest_os = machine_meta.get("name") or machine_meta.get("label") or "Not reported by sandbox backend"
        duration = info.get("duration")

        # 6. Evaluate analyzer health and telemetry completeness (A6)
        debug_errors = debug.get("errors", [])
        analyzer_crashed = False
        if isinstance(debug_errors, list):
            for err in debug_errors:
                err_str = str(err).lower()
                if "analyzer" in err_str or "syntaxerror" in err_str or "crash" in err_str:
                    analyzer_crashed = True
                    break

        telemetry_notes = []
        if analyzer_crashed:
            telemetry_completeness = "INCOMPLETE"
            telemetry_notes.append("Guest analyzer reported a crash or syntax failure during execution.")
        elif duration is not None and duration <= 5 and not processes:
            telemetry_completeness = "INCOMPLETE"
            telemetry_notes.append("Guest VM execution terminated prematurely (duration <= 5s) with zero monitored processes.")
        elif len(processes) > 0 and (len(filesystem) > 0 or len(registry) > 0 or len(network.get("dns", [])) > 0 or len(connections) > 0):
            telemetry_completeness = "COMPLETE"
        elif len(processes) > 0:
            telemetry_completeness = "PARTIAL"
            telemetry_notes.append("Process activity was recorded but secondary filesystem, registry, or network activity was empty.")
        else:
            telemetry_completeness = "UNVERIFIED"
            telemetry_notes.append("Zero processes or behaviors were recorded by the sandbox.")

        return {
            "metadata": {
                "cape_id": info.get("id") or backend_task_id,
                "duration_seconds": duration,
                "environment": {
                    "guest_os": guest_os,
                    "machine": machine_meta.get("name", "Unknown"),
                    "confinement_verified": False,
                },
                "telemetry_completeness": telemetry_completeness,
                "telemetry_notes": telemetry_notes,
                "analyzer_crashed": analyzer_crashed,
            },
            "telemetry_completeness": telemetry_completeness,
            "telemetry_notes": telemetry_notes,
            "processes": processes,
            "api_calls": all_monitored_calls,
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
