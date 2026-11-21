from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.core.config import settings
from app.services.sandbox.base import SandboxBackend

# Maximum safe evidence bundle download size: 150 MB
MAX_EVIDENCE_BUNDLE_BYTES = 150_000_000


class RemnuxGatewayBackend(SandboxBackend):
    """
    Deterministic REMnux Gateway and REMWin VirtualBox Sandbox Backend.
    Integrates physical Kali host controller, REMnux network gateway, and REMWin guest.
    """

    def __init__(
        self,
        gateway_url: Optional[str] = None,
        gateway_token: Optional[str] = None,
        host_controller_url: Optional[str] = None,
        host_controller_secret: Optional[str] = None,
    ) -> None:
        self.gateway_url = (gateway_url or getattr(settings, "REMNUX_GATEWAY_URL", "http://192.168.56.10:8008")).rstrip("/")
        self.gateway_token = gateway_token or getattr(settings, "REMNUX_GATEWAY_TOKEN", "remnux-gateway-auth-token-xyz")
        self.host_controller_url = (host_controller_url or getattr(settings, "VBOX_CONTROLLER_URL", "http://127.0.0.1:8005")).rstrip("/")
        self.host_controller_secret = host_controller_secret or getattr(settings, "VBOX_CONTROLLER_SECRET", "malbox-vbox-host-secret-token")
        self._last_artifact_error: Optional[str] = None

    def _http_call(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        req_headers = dict(headers or {})
        if self.gateway_token and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {self.gateway_token}"
            req_headers["X-Malbox-Gateway-Token"] = self.gateway_token

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_bytes = resp.read()
                try:
                    return {"success": True, "status": resp.status, "data": json.loads(resp_bytes.decode("utf-8")), "bytes": resp_bytes}
                except Exception:
                    return {"success": True, "status": resp.status, "data": resp_bytes.decode("utf-8", errors="replace"), "bytes": resp_bytes}
        except urllib.error.HTTPError as e:
            err_b = e.read()
            try:
                err_data = json.loads(err_b.decode("utf-8"))
            except Exception:
                err_data = err_b.decode("utf-8", errors="replace")
            return {"success": False, "status": e.code, "error": err_data}
        except Exception as e:
            return {"success": False, "status": 500, "error": str(e)}

    def check_readiness(self, timeout: float = 2.0) -> Dict[str, Any]:
        """Validates that REMnux gateway and physical Kali host controller are ready and isolation is measured."""
        # 1. Fail closed if management credentials are not configured or too weak
        if (
            not self.gateway_token
            or len(self.gateway_token.strip()) < 16
            or not self.host_controller_secret
            or len(self.host_controller_secret.strip()) < 16
        ):
            return {
                "ready": False,
                "gateway_reachable": False,
                "gateway_authenticated": False,
                "host_controller_reachable": False,
                "confinement_verified": False,
                "guest_vm_ready": False,
                "guest_vms_available": 0,
                "guest_vms_total": 1,
                "error": "REMnux gateway token or VirtualBox host controller secret is unconfigured or fails minimum 16-character requirement.",
                "backend": "remnux_gateway",
            }

        gw_reachable = False
        gw_authenticated = False
        hc_reachable = False
        isolation_verified = False
        error_msg = None

        # 2. Probe REMnux Gateway
        res_gw = self._http_call(f"{self.gateway_url}/v1/health", timeout=timeout)
        if res_gw.get("success"):
            gw_reachable = True
            data = res_gw.get("data", {})
            if isinstance(data, dict):
                gw_authenticated = bool(data.get("authenticated", True))
        else:
            error_msg = f"REMnux Gateway unreachable at {self.gateway_url}: {res_gw.get('error')}"

        # 3. Probe Kali VirtualBox Host Controller
        res_hc = self._http_call(f"{self.host_controller_url}/health", timeout=timeout)
        if res_hc.get("success"):
            hc_reachable = True
            hc_data = res_hc.get("data", {})
            if isinstance(hc_data, dict) and hc_data.get("lockdown"):
                error_msg = f"VirtualBox Host Controller is in lockdown: {hc_data.get('lockdown_reason')}"
            else:
                # 4. Measure live hypervisor isolation (never infer from HTTP reachability alone)
                try:
                    from integrations.virtualbox_host_controller.security import generate_hmac_headers
                    target_vm = getattr(settings, "REMNUX_GUEST_VM_UUID", "REMWin")
                    hmac_headers = generate_hmac_headers(b"", self.host_controller_secret)
                    res_iso = self._http_call(
                        f"{self.host_controller_url}/isolation/verify?vm_target={target_vm}",
                        headers=hmac_headers,
                        timeout=timeout,
                    )
                    if res_iso.get("success"):
                        iso_data = res_iso.get("data", {})
                        if isinstance(iso_data, dict):
                            isolation_verified = bool(iso_data.get("isolation_verified", False))
                            if not isolation_verified and not error_msg:
                                violations = iso_data.get("violations", [])
                                error_msg = f"VirtualBox isolation verification failed: {', '.join(violations)}"
                    else:
                        if not error_msg:
                            error_msg = f"Host Controller isolation verification failed ({res_iso.get('status')}): {res_iso.get('error')}"
                except Exception as e:
                    if not error_msg:
                        error_msg = f"Failed to verify hypervisor isolation: {str(e)}"
        else:
            if not error_msg:
                error_msg = f"Host Controller unreachable at {self.host_controller_url}: {res_hc.get('error')}"

        ready = bool(gw_reachable and gw_authenticated and hc_reachable and isolation_verified)
        return {
            "ready": ready,
            "gateway_reachable": gw_reachable,
            "gateway_authenticated": gw_authenticated,
            "host_controller_reachable": hc_reachable,
            "confinement_verified": isolation_verified,
            "guest_vm_ready": ready,
            "guest_vms_available": 1 if ready else 0,
            "guest_vms_total": 1,
            "error": error_msg,
            "backend": "remnux_gateway",
        }

    def submit_sample(
        self,
        sample_path: Path,
        profile: str,
        timeout_seconds: int,
        options: Optional[Dict[str, Any]] = None,
        scenario_id: Optional[str] = None,
    ) -> str:
        """Submits an approved binary to the REMnux Gateway."""
        if not sample_path.is_file():
            raise FileNotFoundError(f"Sample file not found: {sample_path}")

        import hashlib
        sample_bytes = sample_path.read_bytes()
        sha256_hash = hashlib.sha256(sample_bytes).hexdigest()

        analysis_id = options.get("analysis_id", f"analysis_{int(time.time())}") if options else f"analysis_{int(time.time())}"
        filename = options.get("filename", sample_path.name) if options else sample_path.name

        payload = {
            "analysis_id": str(analysis_id),
            "sample_sha256": sha256_hash,
            "filename": filename,
            "payload_hex": sample_bytes.hex(),
            "timeout_seconds": min(timeout_seconds, 300),
            "approved_by_operator": True,
        }
        body_bytes = json.dumps(payload).encode("utf-8")

        res = self._http_call(
            f"{self.gateway_url}/v1/jobs",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=body_bytes,
            timeout=30.0,
        )

        if not res.get("success"):
            raise RuntimeError(f"REMnux Gateway submission failed ({res.get('status')}): {res.get('error')}")

        data = res.get("data", {})
        job_id = data.get("job_id") if isinstance(data, dict) else None
        if not job_id:
            raise RuntimeError(f"REMnux Gateway did not return a valid job_id: {res}")

        return job_id

    def get_task_status(self, backend_task_id: str) -> Dict[str, Any]:
        """Polls current job state on REMnux Gateway."""
        res = self._http_call(f"{self.gateway_url}/v1/jobs/{backend_task_id}", timeout=5.0)
        if not res.get("success"):
            return {
                "status": "failed",
                "is_ready_for_report": False,
                "error": f"Failed to poll REMnux Gateway ({res.get('status')}): {res.get('error')}",
            }

        data = res.get("data", {})
        if not isinstance(data, dict):
            return {"status": "failed", "is_ready_for_report": False, "error": "Malformed response"}

        raw_status = data.get("status", "SUBMITTED")
        is_ready = raw_status in ("EVIDENCE_READY", "COMPLETED")
        is_failed = raw_status in ("FAILED", "TIMED_OUT", "CLEANUP_FAILED")

        return {
            "status": "completed" if is_ready else ("failed" if is_failed else "running"),
            "raw_status": raw_status,
            "is_ready_for_report": is_ready,
            "elapsed_seconds": data.get("elapsed_seconds", 0.0),
            "execution_confirmed": data.get("execution_confirmed", False),
            "guest_pid": data.get("guest_pid"),
            "cleanup_status": data.get("cleanup_status"),
            "error": data.get("error"),
        }

    def collect_results(
        self,
        backend_task_id: str,
        expected_sha256: Optional[str] = None,
        max_timeout: Optional[float] = None,
        is_cancelled_fn: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Downloads the immutable evidence archive from REMnux, verifies manifest and hashes,
        extracts artifacts, and produces normalized dictionary for TelemetryNormalizer.
        """
        from integrations.remnux_gateway.collectors.packager import validate_and_extract_evidence_bundle

        # 1. Fetch manifest
        res_manifest = self._http_call(f"{self.gateway_url}/v1/jobs/{backend_task_id}/manifest", timeout=10.0)
        manifest_data = res_manifest.get("data", {}) if res_manifest.get("success") else {}

        # 2. Download evidence bundle stream
        evidence_url = f"{self.gateway_url}/v1/jobs/{backend_task_id}/evidence"
        req = urllib.request.Request(
            evidence_url,
            headers={
                "Authorization": f"Bearer {self.gateway_token}",
                "X-Malbox-Gateway-Token": self.gateway_token,
            },
        )

        with tempfile.TemporaryDirectory(prefix="malbox_evidence_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_file = tmp_path / f"evidence_{backend_task_id}.tar.gz"
            extract_dir = tmp_path / "extracted"

            try:
                with urllib.request.urlopen(req, timeout=30.0) as resp:
                    total_downloaded = 0
                    with open(archive_file, "wb") as f_out:
                        while chunk := resp.read(65536):
                            total_downloaded += len(chunk)
                            if total_downloaded > MAX_EVIDENCE_BUNDLE_BYTES:
                                raise ValueError(f"Evidence bundle exceeded maximum size of {MAX_EVIDENCE_BUNDLE_BYTES} bytes")
                            f_out.write(chunk)
            except Exception as e:
                raise RuntimeError(f"Failed to stream evidence bundle from REMnux Gateway: {str(e)}")

            # 3. Validate and extract safely
            val_ok, manifest, val_err = validate_and_extract_evidence_bundle(archive_file, extract_dir)
            if not val_ok:
                raise RuntimeError(f"Evidence bundle validation failed: {val_err}")

            if manifest:
                if expected_sha256 and manifest.sample_sha256.lower() != expected_sha256.lower():
                    raise RuntimeError(f"Evidence bundle hash mismatch: expected {expected_sha256}, got {manifest.sample_sha256}")
                if backend_task_id.startswith("gw_") and manifest.job_id != backend_task_id:
                    raise RuntimeError(f"Evidence bundle job_id mismatch: expected {backend_task_id}, got {manifest.job_id}")

            # 4. Read process events & network events
            proc_file = extract_dir / "dynamic" / "process_events.json"
            raw_guest_telemetry = {}
            if proc_file.is_file():
                try:
                    raw_guest_telemetry = json.loads(proc_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

            processes = raw_guest_telemetry.get("processes", [])
            network = raw_guest_telemetry.get("network", [])

            # Copy extracted files to permanent storage if artifacts dir exists
            self._extracted_staging_dir = Path(tempfile.mkdtemp(prefix="malbox_staged_"))
            shutil.copytree(extract_dir, self._extracted_staging_dir, dirs_exist_ok=True)

            confirmed = manifest.execution_confirmed if manifest else False
            completeness = "COMPLETE" if confirmed else "PARTIAL"

            return {
                "backend": "remnux_gateway",
                "job_id": backend_task_id,
                "analysis_id": manifest.analysis_id if manifest else None,
                "execution_confirmed": confirmed,
                "confirmation_source": manifest.confirmation_source if manifest else None,
                "telemetry_completeness": completeness,
                "telemetry_notes": [f"Evidence bundle verified and imported from REMnux Gateway ({total_downloaded} bytes)."],
                "processes": processes,
                "network": network,
                "api_calls": [],
                "filesystem": [],
                "registry": [],
                "artifacts": [a.model_dump() for a in (manifest.artifacts if manifest else [])],
            }

    def cancel_task(self, backend_task_id: str) -> bool:
        """Requests task cancellation on REMnux Gateway."""
        res = self._http_call(f"{self.gateway_url}/v1/jobs/{backend_task_id}/cancel", method="POST", timeout=5.0)
        return bool(res.get("success"))

    def generate_artifacts(
        self,
        backend_task_id: str,
        dest_dir: Path,
        deadline: Optional[float] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Materializes verified forensic artifacts into the analysis artifacts folder."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []

        staging = getattr(self, "_extracted_staging_dir", None)
        if staging and staging.is_dir():
            try:
                for p in staging.rglob("*"):
                    if p.is_file():
                        rel = p.relative_to(staging)
                        target = dest_dir / rel
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(p, target)

                        results.append({
                            "name": p.name,
                            "path": str(target),
                            "size_bytes": target.stat().st_size,
                            "category": "dynamic" if "dynamic" in str(rel) else "evidence",
                        })
                shutil.rmtree(staging, ignore_errors=True)
            except Exception as e:
                self._last_artifact_error = str(e)
        return results
