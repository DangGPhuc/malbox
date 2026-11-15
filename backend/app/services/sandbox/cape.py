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
SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
SAFE_OPTIONS_REGEX = re.compile(r"^[a-zA-Z0-9_=,.-]{1,512}$")
SAFE_CUSTOM_REGEX = re.compile(r"^[a-zA-Z0-9_., -]{1,256}$")

# Operator-configured profile-to-tag mapping defaults to empty (A2)
# No implicit machine tag for any analysis profile.
DEFAULT_PROFILE_TAG_MAP: Dict[str, str] = {}


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
        if profile_tag_map is not None:
            self.profile_tag_map = dict(profile_tag_map)
        else:
            self.profile_tag_map = dict(getattr(settings, "CAPE_PROFILE_TAG_MAP", {}) or {})

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"
        return headers

    def check_readiness(self) -> Dict[str, Any]:
        """
        Verifies connectivity and service health against the CAPE v2 REST API endpoint.
        Distinguishes API connectivity from actual guest availability and verified confinement.
        """
        endpoint = f"{self.api_url}/apiv2/cuckoo/status/"
        try:
            with httpx.Client(timeout=5.0, headers=self._get_headers()) as client:
                resp = client.get(endpoint)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception as e:
                        return {
                            "backend": "cape",
                            "ready": False,
                            "status": "malformed",
                            "api_url": self.api_url,
                            "error": f"Malformed JSON from CAPE status endpoint: {str(e)}",
                        }

                    if not isinstance(data, dict):
                        return {
                            "backend": "cape",
                            "ready": False,
                            "status": "malformed",
                            "api_url": self.api_url,
                            "error": f"Unexpected data type from CAPE status: {type(data).__name__}",
                        }

                    # Reject error=true envelopes even with HTTP 200
                    if data.get("error") is True:
                        err_val = data.get("error_value") or data.get("errors") or "CAPE status error"
                        return {
                            "backend": "cape",
                            "ready": False,
                            "status": "error",
                            "api_url": self.api_url,
                            "error": f"CAPE status reported error: {err_val}",
                        }

                    cuckoo_data = data.get("data", {}) if isinstance(data, dict) else {}
                    machines_info = cuckoo_data.get("machines", {}) if isinstance(cuckoo_data, dict) else {}
                    total_machines = machines_info.get("total", 0) if isinstance(machines_info, dict) else 0
                    avail_machines = machines_info.get("available", 0) if isinstance(machines_info, dict) else 0

                    return {
                        "backend": "cape",
                        "ready": True,
                        "status": "ready",
                        "version": cuckoo_data.get("version", "2.x") if isinstance(cuckoo_data, dict) else "2.x",
                        "tasks_summary": cuckoo_data.get("tasks", {}) if isinstance(cuckoo_data, dict) else {},
                        "guest_vms_total": total_machines,
                        "guest_vms_available": avail_machines,
                        "confinement_verified": False,  # API connectivity does not equal verified network confinement
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
        Enforces strict option allowlist, value validation, and graceful machine tag mapping.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/create/file/"
        if not sample_path.exists():
            raise FileNotFoundError(f"Quarantined sample file not found: {sample_path}")

        # Validate options and values against strict allowlist (A1)
        validated_options: Dict[str, Any] = {}
        if options:
            for k, v in options.items():
                if k not in ALLOWED_SUBMISSION_OPTIONS:
                    raise ValueError(f"Disallowed CAPE submission option: {k}")
                # Value validation
                if k == "timeout":
                    try:
                        val = int(v)
                        if val <= 0 or val > 3600:
                            raise ValueError()
                        validated_options[k] = str(val)
                    except Exception:
                        raise ValueError(f"Invalid timeout option value: {v}. Must be an integer between 1 and 3600.")
                elif k == "enforce_timeout":
                    if v in (1, "1", True, "true", "True"):
                        validated_options[k] = "1"
                    elif v in (0, "0", False, "false", "False"):
                        validated_options[k] = "0"
                    else:
                        raise ValueError(f"Invalid enforce_timeout option value: {v}. Must be 0 or 1.")
                elif k == "tags":
                    tag_str = str(v).strip()
                    if not SAFE_TAG_REGEX.match(tag_str):
                        raise ValueError(f"Invalid CAPE machine tag format: {tag_str}")
                    validated_options[k] = tag_str
                elif k in ("machine", "package"):
                    id_str = str(v).strip()
                    if not SAFE_IDENTIFIER_REGEX.match(id_str):
                        raise ValueError(f"Invalid CAPE {k} identifier: {id_str}")
                    validated_options[k] = id_str
                elif k == "priority":
                    try:
                        val = int(v)
                        if val < 1 or val > 3:
                            raise ValueError()
                        validated_options[k] = str(val)
                    except Exception:
                        raise ValueError(f"Invalid priority option value: {v}. Must be 1, 2, or 3.")
                elif k == "options":
                    opt_str = str(v).strip()
                    if not SAFE_OPTIONS_REGEX.match(opt_str):
                        raise ValueError(f"Invalid CAPE options parameter string: {opt_str}")
                    validated_options[k] = opt_str
                elif k == "custom":
                    cust_str = str(v).strip()
                    if not SAFE_CUSTOM_REGEX.match(cust_str):
                        raise ValueError(f"Invalid custom parameter string: {cust_str}")
                    validated_options[k] = cust_str
                elif k == "clock":
                    clock_str = str(v).strip()
                    if len(clock_str) > 64 or any(c in clock_str for c in "\r\n;$\\'\"`"):
                        raise ValueError(f"Invalid clock parameter string: {clock_str}")
                    validated_options[k] = clock_str
                else:
                    validated_options[k] = str(v)

        # Build form data
        data: Dict[str, str] = {
            "timeout": str(timeout_seconds),
            "enforce_timeout": "1" if profile == "ransomware_focus" else "0",
        }

        # Resolve machine tags gracefully (A2)
        # Default is NO tags unless explicitly mapped by operator or provided in options.
        explicit_tags = validated_options.get("tags")
        if explicit_tags:
            data["tags"] = explicit_tags
        elif profile:
            mapped_tag = self.profile_tag_map.get(profile)
            if mapped_tag:
                if not SAFE_TAG_REGEX.match(mapped_tag):
                    raise ValueError(f"Invalid mapped CAPE machine tag format: {mapped_tag}")
                data["tags"] = mapped_tag

        # Forward other allowed options (machine, package, options, etc.)
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

                if not task_ids or not isinstance(task_ids, list):
                    raise ValueError(f"CAPE API returned no valid task IDs: {resp_data}")

                valid_ids = []
                for tid in task_ids:
                    tid_str = str(tid).strip()
                    if tid_str and (tid_str.isdigit() or SAFE_IDENTIFIER_REGEX.match(tid_str)):
                        valid_ids.append(tid_str)

                if not valid_ids:
                    raise ValueError(f"CAPE API returned malformed task IDs: {task_ids}")

                return valid_ids[0]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            # Do NOT blindly retry ambiguous sample POST failures (prevents duplicate remote tasks)
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
        expected_sha256: Optional[str] = None,
        max_retries: int = 4,
        retry_delay_seconds: float = 2.0,
        max_timeout: Optional[float] = None,
        is_cancelled_fn: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves and normalizes the full JSON report from CAPE Sandbox.
        Implements bounded retry for completed-before-reported race conditions,
        strict task/report identity verification, and cancellation checks.
        """
        endpoint = f"{self.api_url}/apiv2/tasks/get/report/{backend_task_id}/"
        deadline = time.monotonic() + (max_timeout if max_timeout is not None else 60.0)

        for attempt in range(max_retries):
            if is_cancelled_fn and is_cancelled_fn():
                raise RuntimeError(f"Report collection cancelled for task {backend_task_id}")

            if time.monotonic() >= deadline:
                raise TimeoutError(f"Monotonic deadline exceeded waiting for CAPE report for task {backend_task_id}")

            timeout_per_request = min(30.0, max(5.0, deadline - time.monotonic()))

            try:
                with httpx.Client(timeout=timeout_per_request, headers=self._get_headers()) as client:
                    resp = client.get(endpoint)

                    # Do NOT retry authentication failures as if they were temporary processing failures
                    if resp.status_code in (401, 403):
                        raise PermissionError(
                            f"CAPE API authentication failed fetching report for task {backend_task_id} (HTTP {resp.status_code})"
                        )

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
                                if time.monotonic() + retry_delay_seconds < deadline:
                                    time.sleep(retry_delay_seconds)
                                    continue
                            raise RuntimeError(f"CAPE report unavailable for task {backend_task_id}: {err_val}")

                        if not isinstance(cape_report, dict):
                            raise RuntimeError(f"CAPE report payload must be a JSON object, got {type(cape_report).__name__}")

                        if is_cancelled_fn and is_cancelled_fn():
                            raise RuntimeError(f"Report collection cancelled for task {backend_task_id}")

                        return self._transform_cape_report(
                            cape_report,
                            backend_task_id=backend_task_id,
                            expected_sha256=expected_sha256,
                        )

                    elif resp.status_code in (404, 500) and attempt < max_retries - 1:
                        # Report might still be rendering on disk
                        if time.monotonic() + retry_delay_seconds < deadline:
                            time.sleep(retry_delay_seconds)
                            continue
                        else:
                            break
                    elif resp.status_code == 404:
                        raise LookupError(f"CAPE task {backend_task_id} not found on server (HTTP 404)")
                    else:
                        raise RuntimeError(f"Failed to fetch CAPE report (HTTP {resp.status_code}): {resp.text[:200]}")
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if attempt < max_retries - 1 and (time.monotonic() + retry_delay_seconds < deadline):
                    time.sleep(retry_delay_seconds)
                    continue
                raise ConnectionError(f"CAPE report retrieval failed after retries: {str(e)}")

        raise TimeoutError(f"CAPE report retrieval timed out waiting for report generation for task {backend_task_id}")

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

    def _transform_cape_report(
        self,
        cape_json: Dict[str, Any],
        backend_task_id: Optional[str] = None,
        expected_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Translates native CAPE v2 JSON schema into malbox-ai raw telemetry format.
        Validates telemetry completeness, extracts payload dumps and API events conservatively.
        Enforces task ID and sample SHA-256 integrity checks.
        """
        behavior = cape_json.get("behavior", {}) if isinstance(cape_json.get("behavior"), dict) else {}
        processes_raw = behavior.get("processes", []) if isinstance(behavior.get("processes"), list) else []
        generic = behavior.get("generic", []) if isinstance(behavior.get("generic"), list) else []
        summary = behavior.get("summary", {}) if isinstance(behavior.get("summary"), dict) else {}
        network = cape_json.get("network", {}) if isinstance(cape_json.get("network"), dict) else {}
        info = cape_json.get("info", {}) if isinstance(cape_json.get("info"), dict) else {}
        debug = cape_json.get("debug", {}) if isinstance(cape_json.get("debug"), dict) else {}
        target = cape_json.get("target", {}) if isinstance(cape_json.get("target"), dict) else {}

        # 0. Task identity and sample SHA-256 verification (A3)
        returned_id = info.get("id")
        if returned_id is not None and backend_task_id is not None:
            if str(returned_id) != str(backend_task_id):
                raise ValueError(
                    f"CAPE report task ID mismatch: requested task {backend_task_id} but report returned task {returned_id}. Possible cross-task contamination."
                )
            verified_task_id = returned_id
            cape_id_verified = True
        elif returned_id is not None:
            verified_task_id = returned_id
            cape_id_verified = True
        else:
            verified_task_id = None
            cape_id_verified = False

        target_file = target.get("file", {}) if isinstance(target.get("file"), dict) else {}
        report_sha256 = target_file.get("sha256") or target.get("sha256") or info.get("sha256")
        target_sha256_verified = False
        if expected_sha256 and report_sha256:
            if report_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f"CAPE report sample SHA-256 mismatch: expected {expected_sha256} but report target is {report_sha256}. Possible cross-sample contamination."
                )
            target_sha256_verified = True

        # 1. Process activity & monitored API calls (Bounded - B4)
        MAX_PROCESSES = 100
        MAX_CALLS_PER_PROC = 500
        MAX_TOTAL_API_CALLS = 2000
        MAX_FS_EVENTS = 500
        MAX_REG_EVENTS = 500
        MAX_NET_EVENTS = 200

        omitted_counts: Dict[str, int] = {}
        processes = []
        all_monitored_calls: List[Dict[str, Any]] = []

        if len(processes_raw) > MAX_PROCESSES:
            omitted_counts["processes"] = len(processes_raw) - MAX_PROCESSES

        for p in processes_raw[:MAX_PROCESSES]:
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

            calls = p.get("calls", [])
            if isinstance(calls, list):
                if len(calls) > MAX_CALLS_PER_PROC:
                    omitted_counts["api_calls_per_proc"] = omitted_counts.get("api_calls_per_proc", 0) + (len(calls) - MAX_CALLS_PER_PROC)
                for call in calls[:MAX_CALLS_PER_PROC]:
                    if len(all_monitored_calls) >= MAX_TOTAL_API_CALLS:
                        omitted_counts["api_calls_total"] = omitted_counts.get("api_calls_total", 0) + 1
                        continue
                    api_name = call.get("api")
                    if api_name:
                        all_monitored_calls.append({
                            "pid": pid,
                            "process_name": pname,
                            "api": api_name,
                            "status": call.get("status"),
                            "return_value": call.get("return_value"),
                            "arguments": call.get("arguments", {}) if isinstance(call.get("arguments"), dict) else {},
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

        for w_file in summary.get("write_files", []):
            if isinstance(w_file, str) and w_file.lower() not in seen_file_paths:
                seen_file_paths.add(w_file.lower())
                is_bin = any(w_file.lower().endswith(ext) for ext in [".exe", ".dll", ".sys", ".scr", ".bat", ".cmd"])
                filesystem.append({
                    "action": "write",
                    "pid": None,
                    "process_name": None,
                    "path": w_file,
                    "timestamp": None,
                    "size_bytes": 0,
                    "is_dropped_binary": is_bin,
                })

        dropped_files = cape_json.get("dropped", [])
        if isinstance(dropped_files, list):
            for drop in dropped_files:
                if isinstance(drop, dict):
                    d_path = drop.get("path") or drop.get("name") or "dropped_file.bin"
                    if d_path.lower() not in seen_file_paths:
                        seen_file_paths.add(d_path.lower())
                        drop_type = str(drop.get("type", "")).lower()
                        is_bin = any(d_path.lower().endswith(ext) for ext in [".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".ps1"]) or \
                                 ("pe" in drop_type or "executable" in drop_type)
                        filesystem.append({
                            "action": "write",
                            "pid": drop.get("pid"),
                            "process_name": drop.get("process_name"),
                            "path": d_path,
                            "timestamp": None,
                            "size_bytes": drop.get("size", 0),
                            "sha256": drop.get("sha256"),
                            "file_type": drop.get("type"),
                            "is_dropped_binary": is_bin,
                            "is_verified_pe": ("pe" in drop_type or "executable" in drop_type),
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

        # Forensic memory-dump payloads preserved as artifact evidence, NOT manufactured filesystem writes (B2)
        extracted_artifacts: List[Dict[str, Any]] = [
            {"name": "traffic.pcap", "type": "pcap", "description": "CAPE captured network traffic"}
        ]
        payloads = cape_json.get("payloads", [])
        if not payloads and isinstance(cape_json.get("CAPE"), dict):
            payloads = cape_json.get("CAPE", {}).get("payloads", [])

        if isinstance(payloads, list):
            for payload in payloads:
                if isinstance(payload, dict):
                    p_name = payload.get("name") or payload.get("path") or "MEM_DUMP_PAYLOAD.bin"
                    p_type = payload.get("type") or payload.get("cape_type") or "memory_dump"
                    extracted_artifacts.append({
                        "name": p_name,
                        "type": "memory_dump_payload",
                        "size_bytes": payload.get("size", 0),
                        "sha256": payload.get("sha256"),
                        "pid": payload.get("pid"),
                        "process_name": payload.get("process_name"),
                        "extraction_method": payload.get("extraction_type", "cape_yara_or_dump"),
                        "description": f"Forensic memory dump extracted by CAPE ({p_type})",
                        "is_extracted_memory_payload": True,
                    })

        # Cap filesystem events
        if len(filesystem) > MAX_FS_EVENTS:
            omitted_counts["filesystem"] = len(filesystem) - MAX_FS_EVENTS
            filesystem = filesystem[:MAX_FS_EVENTS]

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

        if len(registry) > MAX_REG_EVENTS:
            omitted_counts["registry"] = len(registry) - MAX_REG_EVENTS
            registry = registry[:MAX_REG_EVENTS]

        # 4. Network activity (Bounded)
        dns_list = []
        for d in network.get("dns", [])[:MAX_NET_EVENTS]:
            dns_list.append({
                "query": d.get("request"),
                "record_type": d.get("type", "A"),
                "response": (d.get("answers", [{}])[0].get("data")) if d.get("answers") else None,
                "timestamp": None,
            })

        connections = []
        for tcp in network.get("tcp", [])[:MAX_NET_EVENTS]:
            connections.append({
                "protocol": "TCP",
                "dest_ip": tcp.get("dst"),
                "dest_port": tcp.get("dport"),
                "timestamp": None,
            })

        for udp in network.get("udp", [])[:MAX_NET_EVENTS]:
            connections.append({
                "protocol": "UDP",
                "dest_ip": udp.get("dst"),
                "dest_port": udp.get("dport"),
                "timestamp": None,
            })

        http_list = []
        for h in network.get("http", [])[:MAX_NET_EVENTS]:
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

        if omitted_counts:
            telemetry_notes.append(f"Telemetry capped by safety limits: {omitted_counts}")

        return {
            "metadata": {
                "cape_id": verified_task_id,
                "cape_id_verified": cape_id_verified,
                "target_sha256": report_sha256,
                "target_sha256_verified": target_sha256_verified,
                "duration_seconds": duration,
                "environment": {
                    "guest_os": guest_os,
                    "machine": machine_meta.get("name", "Unknown"),
                    "confinement_verified": False,
                },
                "telemetry_completeness": telemetry_completeness,
                "telemetry_notes": telemetry_notes,
                "telemetry_truncated": bool(omitted_counts),
                "omitted_counts": omitted_counts,
                "analyzer_crashed": analyzer_crashed,
            },
            "telemetry_completeness": telemetry_completeness,
            "telemetry_notes": telemetry_notes,
            "telemetry_truncated": bool(omitted_counts),
            "omitted_counts": omitted_counts,
            "processes": processes,
            "api_calls": all_monitored_calls,
            "filesystem": filesystem,
            "registry": registry,
            "network": {
                "dns": dns_list,
                "connections": connections,
                "http": http_list,
            },
            "artifacts": extracted_artifacts,
        }
