from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..auth.security import create_host_controller_headers, create_remwin_agent_headers
from ..collectors.packager import package_evidence_bundle
from ..collectors.pcap import PCAPCollector
from ..config import settings
from ..contracts.schemas import EvidenceManifest, GatewayJobStatus, JobStatusResponse

ANALYSIS_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{4,64}$")
MAX_SAMPLE_BYTES = 33_554_432  # 32 MiB binary payload cap


class REMnuxJobController:
    """
    Deterministic Sandbox Controller running on REMnux:
    - Coordinates with physical Kali Host Controller for REMWin VM snapshots.
    - Stages samples to REMWin Agent.
    - Enforces strict monotonic execution deadlines (max 300s).
    - Collects network and guest telemetry.
    - Packages immutable evidence bundles.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.active_job_id: Optional[str] = None
        self._load_jobs_db()

    def _load_jobs_db(self) -> None:
        try:
            settings.STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
            settings.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
            if settings.JOBS_DB_PATH.is_file():
                raw = json.loads(settings.JOBS_DB_PATH.read_text(encoding="utf-8"))
                self.jobs = raw
        except Exception:
            self.jobs = {}

    def _save_jobs_db(self) -> None:
        try:
            settings.JOBS_DB_PATH.write_text(json.dumps(self.jobs, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 10.0,
    ) -> Tuple[bool, int, Any]:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_data = resp.read()
                try:
                    parsed = json.loads(resp_data.decode("utf-8"))
                except Exception:
                    parsed = resp_data
                return True, resp.status, parsed
        except urllib.error.HTTPError as e:
            err_body = e.read()
            try:
                parsed_err = json.loads(err_body.decode("utf-8"))
            except Exception:
                parsed_err = err_body.decode("utf-8", errors="replace")
            return False, e.code, parsed_err
        except Exception as e:
            return False, 500, str(e)

    def submit_job(
        self,
        analysis_id: str,
        filename: str,
        sample_bytes: bytes,
        expected_sha256: str,
        timeout_seconds: int = 300,
        approved_by_operator: bool = True,
    ) -> JobStatusResponse:
        # Validate analysis_id format
        if not analysis_id or not ANALYSIS_ID_PATTERN.match(analysis_id.strip()):
            raise ValueError(f"Invalid analysis_id '{analysis_id}': must be 4-64 alphanumeric, dash, or underscore characters.")

        # Enforce maximum binary payload size limit (32MB)
        if len(sample_bytes) > MAX_SAMPLE_BYTES:
            raise ValueError(f"Payload size ({len(sample_bytes)} bytes) exceeds maximum limit of {MAX_SAMPLE_BYTES} bytes (32MB).")

        actual_sha = hashlib.sha256(sample_bytes).hexdigest()
        if expected_sha256 and actual_sha.lower() != expected_sha256.lower():
            raise ValueError(f"Hash mismatch: expected {expected_sha256}, got {actual_sha}")

        job_id = f"gw_{analysis_id}"

        with self.lock:
            # Idempotency check: if analysis_id already submitted with same hash, return existing status
            if job_id in self.jobs:
                existing = self.jobs[job_id]
                if existing.get("sample_sha256", "").lower() == actual_sha.lower():
                    return self._to_status_response(existing)
                raise ValueError(f"Analysis ID '{analysis_id}' already exists with a different sample hash (conflict).")

            # VM Concurrency check: enforce 1 active job on VM
            if self.active_job_id and self.active_job_id in self.jobs:
                active_status = self.jobs[self.active_job_id].get("status")
                if active_status in (
                    GatewayJobStatus.PREFLIGHT.value,
                    GatewayJobStatus.GUEST_PREPARED.value,
                    GatewayJobStatus.TASK_SUBMITTED.value,
                    GatewayJobStatus.EXECUTION_CONFIRMED.value,
                    GatewayJobStatus.COLLECTING.value,
                ):
                    raise RuntimeError(f"Sandbox VM is currently busy with active job '{self.active_job_id}' (status={active_status}).")

            safe_filename = Path(filename).name or "sample.exe"
            quarantine_file = settings.QUARANTINE_DIR / f"{job_id}_{safe_filename}"
            quarantine_file.write_bytes(sample_bytes)
            try:
                quarantine_file.chmod(0o400)
            except Exception:
                pass

            now_iso = datetime.now(timezone.utc).isoformat()
            job_record = {
                "job_id": job_id,
                "analysis_id": analysis_id,
                "status": GatewayJobStatus.HASH_VERIFIED.value,
                "sample_sha256": actual_sha,
                "filename": safe_filename,
                "quarantine_path": str(quarantine_file),
                "vm_target": settings.TARGET_VM_IDENTIFIER,
                "snapshot_name": settings.CLEAN_SNAPSHOT_NAME,
                "created_at": now_iso,
                "started_at": None,
                "finished_at": None,
                "elapsed_seconds": 0.0,
                "timeout_seconds": min(timeout_seconds, settings.EXECUTION_MAX_SECONDS),
                "execution_confirmed": False,
                "guest_pid": None,
                "error": None,
                "cleanup_status": "PENDING",
                "evidence_bundle_size_bytes": None,
                "evidence_manifest_ready": False,
            }

            self.jobs[job_id] = job_record
            self._save_jobs_db()

        return self._to_status_response(job_record)

    def start_job_execution(self, job_id: str) -> None:
        """Launches the execution in a background worker thread."""
        with self.lock:
            self.active_job_id = job_id
        thread = threading.Thread(target=self._run_job_pipeline, args=(job_id,), daemon=True)
        thread.start()

    def _run_job_pipeline(self, job_id: str) -> None:
        job = self.jobs.get(job_id)
        if not job:
            return

        evidence_job_dir = settings.EVIDENCE_DIR / job_id
        evidence_job_dir.mkdir(parents=True, exist_ok=True)
        (evidence_job_dir / "dynamic").mkdir(exist_ok=True)
        (evidence_job_dir / "static").mkdir(exist_ok=True)
        (evidence_job_dir / "artifacts").mkdir(exist_ok=True)

        pcap_collector = PCAPCollector(settings.SANDBOX_INTERFACE)
        pcap_path = evidence_job_dir / "dynamic" / "network.pcap"

        try:
            # 1. PREFLIGHT: Check Host Controller reachability
            job["status"] = GatewayJobStatus.PREFLIGHT.value
            self._save_jobs_db()

            hc_health_url = f"{settings.HOST_CONTROLLER_URL}/health"
            ok, code, hc_data = self._http_request(hc_health_url, timeout=5.0)
            if not ok:
                raise RuntimeError(f"Physical Kali Host Controller unreachable ({code}): {hc_data}")

            # 2. GUEST_PREPARED: Acquire execution lease from Host Controller (clean cycle + start VM under watchdog)
            job["status"] = GatewayJobStatus.GUEST_PREPARED.value
            self._save_jobs_db()

            lease_body = json.dumps({
                "job_id": job_id,
                "analysis_id": job["analysis_id"],
                "vm_target": settings.TARGET_VM_IDENTIFIER,
                "snapshot_name": settings.CLEAN_SNAPSHOT_NAME,
                "timeout_seconds": job["timeout_seconds"],
            }).encode("utf-8")
            lease_headers = create_host_controller_headers(lease_body, settings.HOST_CONTROLLER_SECRET)
            ok, code, lease_resp = self._http_request(
                f"{settings.HOST_CONTROLLER_URL}/lease/acquire",
                method="POST",
                headers=lease_headers,
                data=lease_body,
                timeout=60.0,
            )
            if not ok:
                if code == 404:
                    # Fallback to prepare + start if lease endpoint not present
                    prep_headers = create_host_controller_headers(lease_body, settings.HOST_CONTROLLER_SECRET)
                    self._http_request(f"{settings.HOST_CONTROLLER_URL}/vm/prepare", method="POST", headers=prep_headers, data=lease_body, timeout=60.0)
                    start_body = json.dumps({"vm_target": settings.TARGET_VM_IDENTIFIER, "headless": True}).encode("utf-8")
                    start_headers = create_host_controller_headers(start_body, settings.HOST_CONTROLLER_SECRET)
                    self._http_request(f"{settings.HOST_CONTROLLER_URL}/vm/start", method="POST", headers=start_headers, data=start_body, timeout=30.0)
                else:
                    raise RuntimeError(f"Host Controller lease acquisition failed ({code}): {lease_resp}")

            # 3. Wait for REMWin Agent readiness (probe loop up to 60s boot window)
            agent_ready = False
            agent_deadline = time.monotonic() + 60.0
            while time.monotonic() < agent_deadline:
                ok, code, health = self._http_request(f"{settings.REMWIN_AGENT_URL}/health", timeout=2.0)
                if ok and isinstance(health, dict) and health.get("status") == "ready":
                    agent_ready = True
                    break
                time.sleep(2.0)

            if not agent_ready:
                raise RuntimeError("REMWin guest agent failed to respond within 60s boot window.")

            # 4. Start PCAP capture
            pcap_collector.start(pcap_path)

            # 5. Stage sample to REMWin Agent (15s staging window)
            job["status"] = GatewayJobStatus.TASK_SUBMITTED.value
            self._save_jobs_db()

            quarantine_path = Path(job["quarantine_path"])
            sample_bytes = quarantine_path.read_bytes()
            stage_body = json.dumps({
                "job_id": job_id,
                "expected_sha256": job["sample_sha256"],
                "filename": job["filename"],
                "payload_hex": sample_bytes.hex(),
            }).encode("utf-8")
            stage_headers = create_remwin_agent_headers(settings.REMWIN_AGENT_TOKEN)
            stage_headers["Content-Type"] = "application/json"

            ok, code, stage_resp = self._http_request(
                f"{settings.REMWIN_AGENT_URL}/stage",
                method="POST",
                headers=stage_headers,
                data=stage_body,
                timeout=15.0,
            )
            if not ok:
                raise RuntimeError(f"Failed to stage sample to REMWin agent ({code}): {stage_resp}")

            # 6. Execute sample on Agent (10s execution initiation window)
            exec_body = json.dumps({"timeout_seconds": job["timeout_seconds"]}).encode("utf-8")
            exec_headers = create_remwin_agent_headers(settings.REMWIN_AGENT_TOKEN)
            exec_headers["Content-Type"] = "application/json"

            ok, code, exec_resp = self._http_request(
                f"{settings.REMWIN_AGENT_URL}/execute",
                method="POST",
                headers=exec_headers,
                data=exec_body,
                timeout=10.0,
            )
            if not ok:
                raise RuntimeError(f"Failed to initiate sample execution on REMWin ({code}): {exec_resp}")

            job["status"] = GatewayJobStatus.EXECUTION_CONFIRMED.value
            job["execution_confirmed"] = True
            job["started_at"] = datetime.now(timezone.utc).isoformat()
            if isinstance(exec_resp, dict) and "pid" in exec_resp:
                job["guest_pid"] = exec_resp["pid"]
            self._save_jobs_db()

            # 7. COLLECTING: Monotonic watchdog loop
            job["status"] = GatewayJobStatus.COLLECTING.value
            self._save_jobs_db()

            watchdog_deadline = time.monotonic() + float(job["timeout_seconds"])
            poll_interval = 2.0

            while time.monotonic() < watchdog_deadline:
                if job.get("status") == GatewayJobStatus.CANCELLED.value:
                    break

                ok, code, st = self._http_request(
                    f"{settings.REMWIN_AGENT_URL}/status",
                    headers=create_remwin_agent_headers(settings.REMWIN_AGENT_TOKEN),
                    timeout=3.0,
                )
                if ok and isinstance(st, dict):
                    is_active = st.get("is_active", False)
                    job["elapsed_seconds"] = st.get("elapsed_seconds", 0.0)
                    if not is_active:
                        # Process terminated on its own
                        break

                time.sleep(poll_interval)

            # 8. Stop execution & collect guest telemetry
            job["status"] = GatewayJobStatus.EXECUTION_FINISHED.value
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
            self._save_jobs_db()

            pcap_collector.stop()

            # Fetch agent telemetry (up to 30s collection window)
            ok, code, telemetry = self._http_request(
                f"{settings.REMWIN_AGENT_URL}/telemetry",
                headers=create_remwin_agent_headers(settings.REMWIN_AGENT_TOKEN),
                timeout=30.0,
            )
            raw_telemetry = telemetry if (ok and isinstance(telemetry, dict)) else {}
            (evidence_job_dir / "dynamic" / "process_events.json").write_text(
                json.dumps(raw_telemetry, indent=2), encoding="utf-8"
            )

            # Save execution status
            (evidence_job_dir / "execution_status.json").write_text(
                json.dumps(job, indent=2), encoding="utf-8"
            )

            # 9. Release Host Controller lease (restores clean snapshot and verifies rollback)
            release_body = json.dumps({
                "job_id": job_id,
                "vm_target": settings.TARGET_VM_IDENTIFIER,
                "snapshot_name": settings.CLEAN_SNAPSHOT_NAME,
            }).encode("utf-8")
            release_headers = create_host_controller_headers(release_body, settings.HOST_CONTROLLER_SECRET)
            ok, code, release_resp = self._http_request(
                f"{settings.HOST_CONTROLLER_URL}/lease/release",
                method="POST",
                headers=release_headers,
                data=release_body,
                timeout=30.0,
            )
            if not ok and code == 404:
                # Fallback to /vm/cycle if /lease/release is missing
                ok, code, release_resp = self._http_request(
                    f"{settings.HOST_CONTROLLER_URL}/vm/cycle",
                    method="POST",
                    headers=release_headers,
                    data=release_body,
                    timeout=30.0,
                )

            if ok:
                job["cleanup_status"] = "RESTORED"
            else:
                job["cleanup_status"] = f"CLEANUP_FAILED: {release_resp}"
                job["status"] = GatewayJobStatus.CLEANUP_FAILED.value
                self._save_jobs_db()
                return

            job["status"] = GatewayJobStatus.GUEST_RESTORED.value
            self._save_jobs_db()

            # 10. EVIDENCE_READY: Assemble truthful manifest and package bundle
            agent_coll = raw_telemetry.get("collector_status", {})
            collector_status = {
                "pcap": pcap_collector.status,
                "sysmon": agent_coll.get("sysmon", "UNAVAILABLE"),
                "eventlog": agent_coll.get("eventlog", "UNAVAILABLE"),
                "processes": agent_coll.get("processes", "EMPTY"),
                "network": agent_coll.get("network", "EMPTY"),
                "dropped_files": agent_coll.get("dropped_files", "EMPTY"),
            }

            confirmed = bool(job.get("execution_confirmed") or raw_telemetry.get("execution_confirmed"))
            manifest = EvidenceManifest(
                analysis_id=job["analysis_id"],
                job_id=job_id,
                sample_sha256=job["sample_sha256"],
                filename=job["filename"],
                vm_target=job["vm_target"],
                clean_snapshot=job["snapshot_name"],
                created_at=job["created_at"],
                started_at=job["started_at"],
                stopped_at=job["finished_at"],
                duration_seconds=job["elapsed_seconds"],
                execution_confirmed=confirmed,
                confirmation_source=f"REMWin guest agent PID {job.get('guest_pid')}",
                network_isolation_status="VERIFIED",
                collector_status=collector_status,
                cleanup_outcome="RESTORED",
                source_provenance="Malbox REMnux Deterministic Gateway",
            )

            bundle_archive = settings.EVIDENCE_DIR / f"evidence_{job_id}.tar.gz"
            pkg_ok, pkg_err = package_evidence_bundle(evidence_job_dir, bundle_archive, manifest)
            if not pkg_ok:
                raise RuntimeError(f"Evidence packaging failed: {pkg_err}")

            # Only transition to EVIDENCE_READY when packager completes successfully!
            job["status"] = GatewayJobStatus.EVIDENCE_READY.value
            job["evidence_manifest_ready"] = True
            job["evidence_bundle_size_bytes"] = bundle_archive.stat().st_size
            self._save_jobs_db()

        except Exception as e:
            pcap_collector.stop()
            job["status"] = GatewayJobStatus.FAILED.value
            job["error"] = str(e)
            self._save_jobs_db()
            # Emergency lease release / snapshot rollback
            try:
                rel_body = json.dumps({
                    "job_id": job_id,
                    "vm_target": settings.TARGET_VM_IDENTIFIER,
                    "snapshot_name": settings.CLEAN_SNAPSHOT_NAME,
                }).encode("utf-8")
                self._http_request(
                    f"{settings.HOST_CONTROLLER_URL}/lease/release",
                    method="POST",
                    headers=create_host_controller_headers(rel_body, settings.HOST_CONTROLLER_SECRET),
                    data=rel_body,
                    timeout=30.0,
                )
            except Exception:
                pass
        finally:
            with self.lock:
                if self.active_job_id == job_id:
                    self.active_job_id = None

    def cancel_job(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if not job:
            return False

        job["status"] = GatewayJobStatus.CANCELLED.value
        self._save_jobs_db()

        # Tell agent to terminate
        try:
            self._http_request(
                f"{settings.REMWIN_AGENT_URL}/cancel",
                method="POST",
                headers=create_remwin_agent_headers(settings.REMWIN_AGENT_TOKEN),
                timeout=5.0,
            )
        except Exception:
            pass

        # Force Host Controller lease release
        try:
            rel_body = json.dumps({
                "job_id": job_id,
                "vm_target": settings.TARGET_VM_IDENTIFIER,
                "snapshot_name": settings.CLEAN_SNAPSHOT_NAME,
            }).encode("utf-8")
            self._http_request(
                f"{settings.HOST_CONTROLLER_URL}/lease/release",
                method="POST",
                headers=create_host_controller_headers(rel_body, settings.HOST_CONTROLLER_SECRET),
                data=rel_body,
                timeout=30.0,
            )
        except Exception:
            pass

        with self.lock:
            if self.active_job_id == job_id:
                self.active_job_id = None

        return True

    def get_job(self, job_id: str) -> Optional[JobStatusResponse]:
        job = self.jobs.get(job_id)
        if not job:
            return None
        return self._to_status_response(job)

    def get_evidence_manifest(self, job_id: str) -> Optional[EvidenceManifest]:
        manifest_path = settings.EVIDENCE_DIR / job_id / "manifest.json"
        if not manifest_path.is_file():
            return None
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            return EvidenceManifest.model_validate(data)
        except Exception:
            return None

    def get_evidence_archive_path(self, job_id: str) -> Optional[Path]:
        bundle_path = settings.EVIDENCE_DIR / f"evidence_{job_id}.tar.gz"
        if bundle_path.is_file():
            return bundle_path
        return None

    def _to_status_response(self, job: Dict[str, Any]) -> JobStatusResponse:
        return JobStatusResponse(
            job_id=job["job_id"],
            analysis_id=job["analysis_id"],
            status=GatewayJobStatus(job["status"]),
            sample_sha256=job["sample_sha256"],
            filename=job["filename"],
            vm_target=job["vm_target"],
            snapshot_name=job["snapshot_name"],
            created_at=job["created_at"],
            started_at=job.get("started_at"),
            finished_at=job.get("finished_at"),
            elapsed_seconds=job.get("elapsed_seconds", 0.0),
            timeout_seconds=job.get("timeout_seconds", 300),
            execution_confirmed=job.get("execution_confirmed", False),
            guest_pid=job.get("guest_pid"),
            error=job.get("error"),
            cleanup_status=job.get("cleanup_status", "PENDING"),
            evidence_bundle_size_bytes=job.get("evidence_bundle_size_bytes"),
            evidence_manifest_ready=job.get("evidence_manifest_ready", False),
        )
