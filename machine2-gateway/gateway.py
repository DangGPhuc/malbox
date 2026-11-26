#!/usr/bin/env python3
"""MalBox Machine 2 Gateway (Application-Level HTTP Relay).

Relays sample submissions from Machine 1 (Internal Network 1) to Machine 3
(Internal Network 2) and streams evidence ZIP archives back to Machine 1.
Does not execute samples, inspect sample contents, or provide any remote shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import threading
import time
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from inetsim_diagnostics import collect_session_inetsim_evidence  # noqa: E402
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure concise terminal logging for Gateway operations."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger("malbox.gateway")


def _cfg_bool(config: dict[str, Any], key: str, default: bool) -> bool:
    val = config.get(key, default)
    if isinstance(val, bool):
        return val
    raise ValueError(f"Gateway config '{key}' must be a boolean (got {type(val).__name__}).")


def _cfg_int(
    config: dict[str, Any],
    key: str,
    default: int,
    min_val: int = 1,
    max_val: int | None = None,
) -> int:
    val = config.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Gateway config '{key}' must be an integer (got {type(val).__name__}).")
    if val < min_val or (max_val is not None and val > max_val):
        raise ValueError(f"Gateway config '{key}' out of range: {val}.")
    return val


def _cfg_float(config: dict[str, Any], key: str, default: float, min_val: float = 0.1) -> float:
    val = config.get(key, default)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"Gateway config '{key}' must be a finite number (got {type(val).__name__}).")
    fval = float(val)
    if fval != fval or fval in (float("inf"), float("-inf")) or fval < min_val:
        raise ValueError(f"Gateway config '{key}' must be finite and >= {min_val}.")
    return fval


def load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate Machine 2 Gateway configuration from JSON (UTF-8 with/without BOM)."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Gateway config root must be a JSON object (got {type(data).__name__}).")
    _cfg_int(data, "listen_port", 8000, min_val=1, max_val=65535)
    _cfg_int(data, "sandbox_port", 8001, min_val=1, max_val=65535)
    _cfg_bool(data, "retain_evidence_archives", True)
    _cfg_float(data, "connect_timeout_seconds", 5.0, min_val=0.1)
    _cfg_float(data, "request_timeout_seconds", 30.0, min_val=0.1)
    _cfg_float(data, "poll_interval_seconds", 3.0, min_val=0.1)
    _cfg_float(data, "analysis_timeout_seconds", 1800.0, min_val=1.0)
    _cfg_int(data, "chunk_size_bytes", 65536, min_val=1024)
    _cfg_float(data, "max_sample_size_mb", 200.0, min_val=1.0)
    _cfg_int(data, "max_evidence_archive_mb", 512, min_val=1)
    _cfg_int(data, "max_extracted_size_mb", 1024, min_val=1)
    _cfg_int(data, "max_single_file_mb", 256, min_val=1)
    _cfg_int(data, "max_archive_entries", 5000, min_val=10)
    _cfg_bool(data, "inetsim_diagnostics_enabled", False)
    _cfg_int(data, "max_inetsim_log_mb", 5, min_val=1)
    _cfg_int(data, "max_inetsim_events", 1000, min_val=10)
    return data


def resolve_dir(raw_path: str, base_dir: Path) -> Path:
    """Resolve relative directory paths against the config directory."""
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (base_dir / candidate).resolve()


def sanitize_filename(name: str) -> str:
    """Strip any directory components from an incoming filename."""
    cleaned = os.path.basename(name or "sample.bin").strip()
    cleaned = "".join(ch for ch in cleaned if ch.isalnum() or ch in (".", "-", "_"))
    return cleaned or "sample.bin"


def sanitize_job_id(job_id: str) -> str:
    """Validate and constrain job_id to safe filename characters."""
    cleaned = "".join(ch for ch in (job_id or "") if ch.isalnum() or ch in ("-", "_"))
    if not cleaned or cleaned != job_id:
        raise ValueError(f"Invalid job_id: {job_id!r}")
    return cleaned


def safe_unlink(path: Path | None) -> None:
    """Remove a temporary file if it exists without raising."""
    if path is None:
        return
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def validate_evidence_zip(
    zf: zipfile.ZipFile,
    max_entries: int,
    max_single_file_bytes: int,
    max_total_bytes: int,
) -> None:
    """Reject unsafe archive metadata before CRC checks or retention."""
    infos = zf.infolist()
    if len(infos) > max_entries:
        raise ValueError(f"Archive entry count ({len(infos)}) exceeds safety limit ({max_entries}).")
    seen: set[str] = set()
    total_bytes = 0
    for member in infos:
        name = member.filename
        if "\x00" in name:
            raise ValueError(f"Archive entry contains null byte: {name!r}")
        parts = name.rstrip("/").split("/")
        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or any(part in ("", ".", "..") or ":" in part for part in parts)
        ):
            raise ValueError(f"Unsafe archive entry path detected: {name}")
        normalized = "/".join(parts)
        if normalized in seen:
            raise ValueError(f"Duplicate archive entry: {name}")
        seen.add(normalized)
        mode = (member.external_attr >> 16) & 0o170000
        if mode not in (0, 0o040000, 0o100000):
            raise ValueError(f"Unsupported archive member type: {name}")
        if member.flag_bits & 1:
            raise ValueError(f"Encrypted evidence member is unsupported: {name}")
        if member.file_size < 0 or member.file_size > max_single_file_bytes:
            raise ValueError(f"Archive entry {name} exceeds max single file size limit.")
        total_bytes += member.file_size
        if total_bytes > max_total_bytes:
            raise ValueError("Total declared archive size exceeds safety expansion limit.")


class GatewayState:
    """Thread-safe single-job state holder for the Gateway relay."""

    def __init__(
        self,
        config: dict[str, Any],
        temp_dir: Path,
        archive_dir: Path,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.temp_dir = temp_dir
        self.archive_dir = archive_dir
        self.logger = logger
        self.lock = threading.Lock()
        self.active_job: dict[str, Any] | None = None

    @property
    def retain_evidence_archives(self) -> bool:
        return bool(self.config.get("retain_evidence_archives", True))

    @property
    def sandbox_base_url(self) -> str:
        host = self.config.get("sandbox_host", "10.10.20.30")
        port = int(self.config.get("sandbox_port", 8001))
        return f"http://{host}:{port}"

    @property
    def connect_timeout(self) -> float:
        return max(0.1, float(self.config.get("connect_timeout_seconds", 5)))

    @property
    def request_timeout(self) -> float:
        return max(0.1, float(self.config.get("request_timeout_seconds", 30)))

    @property
    def poll_interval(self) -> float:
        return max(0.1, float(self.config.get("poll_interval_seconds", 3)))

    @property
    def analysis_timeout(self) -> float:
        return max(1.0, float(self.config.get("analysis_timeout_seconds", 1800)))

    @property
    def chunk_size(self) -> int:
        return max(1024, int(self.config.get("chunk_size_bytes", 65536)))

    @property
    def max_sample_bytes(self) -> int:
        return max(1, int(float(self.config.get("max_sample_size_mb", 200)) * 1024 * 1024))

    @property
    def max_archive_bytes(self) -> int:
        return max(1, int(self.config.get("max_evidence_archive_mb", 512))) * 1024 * 1024

    @property
    def max_extracted_bytes(self) -> int:
        return max(1, int(self.config.get("max_extracted_size_mb", 1024))) * 1024 * 1024

    @property
    def max_single_file_bytes(self) -> int:
        return max(1, int(self.config.get("max_single_file_mb", 256))) * 1024 * 1024

    @property
    def max_archive_entries(self) -> int:
        return max(10, int(self.config.get("max_archive_entries", 5000)))


def create_app(config: dict[str, Any], config_dir: Path, logger: logging.Logger) -> Flask:
    """Create the Flask Gateway application."""
    temp_dir = resolve_dir(str(config.get("temp_dir", "./tmp")), config_dir)
    archive_dir = resolve_dir(str(config.get("evidence_archive_dir", "./retained_evidence")), config_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        for d in (temp_dir, archive_dir):
            try:
                os.chmod(d, 0o750)
            except OSError:
                pass

    state = GatewayState(config=config, temp_dir=temp_dir, archive_dir=archive_dir, logger=logger)
    app = Flask(__name__)

    def query_sandbox_status() -> tuple[int, dict[str, Any]]:
        try:
            resp = requests.get(
                f"{state.sandbox_base_url}/status",
                timeout=(state.connect_timeout, state.connect_timeout),
            )
            try:
                data = resp.json()
            except ValueError:
                data = {"raw": resp.text}
            return resp.status_code, data
        except requests.RequestException as exc:
            return 503, {"error": str(exc), "state": "UNAVAILABLE"}

    def monitor_and_fetch_evidence(job_id: str) -> None:
        try:
            _monitor_and_fetch_evidence_inner(job_id)
        except Exception as exc:
            logger.error("[ERROR] Unhandled Gateway relay error on job %s: %s", job_id, exc)
            with state.lock:
                if state.active_job and state.active_job.get("job_id") == job_id:
                    state.active_job["status"] = "FAILED"
                    state.active_job["error"] = f"Gateway relay error: {exc}"

    def _monitor_and_fetch_evidence_inner(job_id: str) -> None:
        deadline = time.monotonic() + state.analysis_timeout
        consecutive_errors = 0
        max_consecutive_errors = 5

        def _fail_job(err_msg: str, err_code: str) -> None:
            with state.lock:
                if state.active_job and state.active_job.get("job_id") == job_id:
                    state.active_job["status"] = "FAILED"
                    state.active_job["error"] = err_msg
                    state.active_job["error_code"] = err_code

        while time.monotonic() < deadline:
            try:
                resp = requests.get(
                    f"{state.sandbox_base_url}/jobs/{job_id}",
                    timeout=(state.connect_timeout, state.request_timeout),
                )
                consecutive_errors = 0
            except requests.Timeout as exc:
                consecutive_errors += 1
                logger.warning(
                    "[WARN] Sandbox status poll timeout (%d/%d): %s",
                    consecutive_errors,
                    max_consecutive_errors,
                    exc,
                )
                if consecutive_errors >= max_consecutive_errors:
                    _fail_job("Sandbox connection timed out repeatedly during analysis.", "connection_timeout")
                    logger.error("[ERROR] Sandbox became unreachable during job %s.", job_id)
                    return
                time.sleep(state.poll_interval)
                continue
            except requests.RequestException as exc:
                consecutive_errors += 1
                logger.warning(
                    "[WARN] Sandbox status poll failed (%d/%d): %s",
                    consecutive_errors,
                    max_consecutive_errors,
                    exc,
                )
                if consecutive_errors >= max_consecutive_errors:
                    _fail_job("Sandbox service unavailable during analysis.", "service_unavailable")
                    logger.error("[ERROR] Sandbox became unreachable during job %s.", job_id)
                    return
                time.sleep(state.poll_interval)
                continue

            if resp.status_code == 404:
                _fail_job("Sandbox job interrupted or no longer present (HTTP 404).", "interrupted_job")
                logger.error("[ERROR] Sandbox job interrupted or unknown (HTTP 404).")
                return

            if resp.status_code != 200:
                _fail_job(f"Sandbox returned unexpected HTTP {resp.status_code}", "unexpected_http_response")
                logger.error("[ERROR] Sandbox job query error (HTTP %s).", resp.status_code)
                return

            try:
                job_info = resp.json()
                if not isinstance(job_info, dict):
                    raise ValueError("JSON root is not an object")
            except ValueError:
                consecutive_errors += 1
                logger.warning(
                    "[WARN] Sandbox returned non-JSON status payload (%d/%d).",
                    consecutive_errors,
                    max_consecutive_errors,
                )
                if consecutive_errors >= max_consecutive_errors:
                    _fail_job("Sandbox returned repeated invalid HTTP status responses.", "unexpected_http_response")
                    logger.error("[ERROR] Sandbox returned invalid payloads repeatedly on job %s.", job_id)
                    return
                time.sleep(state.poll_interval)
                continue

            with state.lock:
                if state.active_job and state.active_job.get("job_id") == job_id:
                    state.active_job["stage"] = job_info.get("stage", "")
                    state.active_job["job_status"] = job_info.get("job_status", "")

            if job_info.get("evidence_ready"):
                safe_id = sanitize_job_id(job_id)
                zip_path = state.archive_dir / f"evidence_{safe_id}.zip"
                tmp_download_path = state.temp_dir / f".dl_evidence_{safe_id}.zip"
                try:
                    with requests.get(
                        f"{state.sandbox_base_url}/jobs/{safe_id}/evidence",
                        stream=True,
                        timeout=(state.connect_timeout, max(state.request_timeout, 300)),
                    ) as dl:
                        if dl.status_code == 404 or dl.status_code == 409:
                            raise FileNotFoundError(f"evidence_unavailable: HTTP {dl.status_code}: {dl.text.strip()}")
                        if dl.status_code != 200:
                            raise RuntimeError(f"unexpected_http_response: HTTP {dl.status_code}: {dl.text.strip()}")
                        expected_sha256 = dl.headers.get("X-Archive-SHA256", "").strip().lower()
                        digest = hashlib.sha256()
                        total_zip_bytes = 0
                        with tmp_download_path.open("wb") as fh:
                            for chunk in dl.iter_content(chunk_size=state.chunk_size):
                                if chunk:
                                    total_zip_bytes += len(chunk)
                                    if total_zip_bytes > state.max_archive_bytes:
                                        raise ValueError(
                                            f"Evidence archive exceeds max_evidence_archive_mb limit ({state.max_archive_bytes // (1024 * 1024)} MB)."
                                        )
                                    fh.write(chunk)
                                    digest.update(chunk)

                    if total_zip_bytes == 0:
                        raise ValueError("evidence_unavailable: Downloaded evidence archive is empty.")

                    actual_sha256 = digest.hexdigest().lower()
                    if expected_sha256 and actual_sha256 != expected_sha256:
                        raise ValueError(
                            f"Evidence checksum mismatch ({actual_sha256} != {expected_sha256})"
                        )

                    # Validate ZIP metadata limits and safety BEFORE CRC checks or retention.
                    with zipfile.ZipFile(tmp_download_path, "r") as zf:
                        validate_evidence_zip(
                            zf,
                            max_entries=state.max_archive_entries,
                            max_single_file_bytes=state.max_single_file_bytes,
                            max_total_bytes=state.max_extracted_bytes,
                        )
                        bad_member = zf.testzip()
                        if bad_member is not None:
                            raise zipfile.BadZipFile(f"Corrupt ZIP entry from sandbox: {bad_member}")

                    tmp_download_path.replace(zip_path)

                    # Optionally save Machine 2 isolated network-simulation diagnostics as a SEPARATE artifact
                    # without modifying evidence_<job_id>.zip or breaking X-Archive-SHA256 integrity.
                    if bool(state.config.get("inetsim_diagnostics_enabled", False)):
                        with state.lock:
                            started_utc = (
                                state.active_job.get("started_at_utc")
                                if state.active_job and state.active_job.get("job_id") == job_id
                                else None
                            )
                        sess_start = started_utc or datetime.now(timezone.utc)
                        sess_end = datetime.now(timezone.utc)
                        netdiag_doc = collect_session_inetsim_evidence(
                            job_id=safe_id,
                            session_start_utc=sess_start,
                            session_end_utc=sess_end,
                            config=state.config,
                        )
                        netdiag_path = state.archive_dir / f"gateway_netdiag_{safe_id}.json"
                        netdiag_path.write_text(json.dumps(netdiag_doc, indent=2), encoding="utf-8")

                    # Acknowledge transfer only after full validation so Sandbox moves to RESTORE_REQUIRED.
                    sandbox_ack_ok = False
                    try:
                        ack_resp = requests.post(
                            f"{state.sandbox_base_url}/jobs/{safe_id}/ack",
                            timeout=(state.connect_timeout, state.request_timeout),
                        )
                        if ack_resp.status_code == 200:
                            sandbox_ack_ok = True
                        else:
                            logger.warning(
                                "[WARN] Sandbox ack returned HTTP %s: %s",
                                ack_resp.status_code,
                                ack_resp.text.strip(),
                            )
                    except requests.RequestException as ack_exc:
                        logger.warning("[WARN] Failed to ack evidence receipt to sandbox: %s", ack_exc)

                    logger.info("[OK] Evidence received from sandbox (retained at %s).", zip_path.name)
                    with state.lock:
                        if state.active_job and state.active_job.get("job_id") == job_id:
                            state.active_job["status"] = "EVIDENCE_READY"
                            state.active_job["evidence_ready"] = True
                            state.active_job["zip_path"] = zip_path
                            state.active_job["archive_sha256"] = actual_sha256
                            state.active_job["sandbox_ack_confirmed"] = sandbox_ack_ok
                    return
                except (
                    requests.RequestException,
                    OSError,
                    RuntimeError,
                    ValueError,
                    zipfile.BadZipFile,
                    NotImplementedError,
                    zlib.error,
                ) as exc:
                    safe_unlink(tmp_download_path)
                    logger.error("[ERROR] Evidence transfer from sandbox failed: %s", exc)
                    err_cat = (
                        "evidence_unavailable"
                        if isinstance(exc, (FileNotFoundError, zipfile.BadZipFile, ValueError, NotImplementedError, zlib.error))
                        else "unexpected_http_response"
                    )
                    _fail_job(f"Evidence transfer failed: {exc}", err_cat)
                    return

            if str(job_info.get("job_status", "")).lower() == "failed" and not job_info.get(
                "evidence_ready"
            ):
                err = job_info.get("error") or "Sandbox analysis failed."
                logger.error("[ERROR] Sandbox analysis failed: %s", err)
                _fail_job(err, "interrupted_job")
                return

            time.sleep(state.poll_interval)

        logger.error("[ERROR] Timed out waiting for sandbox evidence on job %s.", job_id)
        _fail_job("Timed out waiting for sandbox evidence.", "connection_timeout")

    @app.get("/health")
    def health() -> tuple[Response, int]:
        logger.info("[OK] Client connected.")
        with state.lock:
            active_id = state.active_job.get("job_id") if state.active_job else None
        return jsonify({"status": "ok", "service": "malbox-gateway", "active_job": active_id}), 200

    @app.get("/status")
    def status() -> tuple[Response, int]:
        sb_code, sb_data = query_sandbox_status()
        with state.lock:
            active = (
                {
                    "job_id": state.active_job.get("job_id"),
                    "status": state.active_job.get("status"),
                    "evidence_ready": state.active_job.get("evidence_ready", False),
                }
                if state.active_job
                else None
            )
        return (
            jsonify(
                {
                    "gateway": "ok",
                    "active_job": active,
                    "sandbox_http_status": sb_code,
                    "sandbox": sb_data,
                }
            ),
            200,
        )

    @app.post("/analyze")
    def analyze() -> tuple[Response, int]:
        with state.lock:
            if state.active_job is not None:
                job_status = state.active_job.get("status")
                # Allow replacing a stale failed/abandoned job if sandbox is ready again.
                if job_status == "ANALYZING":
                    return (
                        jsonify(
                            {
                                "error_code": "GATEWAY_BUSY",
                                "error": "Gateway already has an analysis job in progress.",
                            }
                        ),
                        409,
                    )
                if not state.retain_evidence_archives:
                    safe_unlink(state.active_job.get("zip_path"))
                state.active_job = None

        filename = sanitize_filename(request.headers.get("X-Sample-Filename", "sample.bin"))
        expected_sha256 = request.headers.get("X-Sample-SHA256", "").strip().lower()
        temp_sample = state.temp_dir / f"incoming_{uuid.uuid4().hex}.bin"

        try:
            total_bytes = 0
            digest = hashlib.sha256()

            if "sample" in request.files:
                uploaded = request.files["sample"]
                filename = sanitize_filename(uploaded.filename or filename)
                with temp_sample.open("wb") as out:
                    while True:
                        chunk = uploaded.stream.read(state.chunk_size)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > state.max_sample_bytes:
                            raise ValueError("Sample exceeds max_sample_size_mb limit.")
                        digest.update(chunk)
                        out.write(chunk)
            else:
                with temp_sample.open("wb") as out:
                    while True:
                        chunk = request.stream.read(state.chunk_size)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > state.max_sample_bytes:
                            raise ValueError("Sample exceeds max_sample_size_mb limit.")
                        digest.update(chunk)
                        out.write(chunk)

            if total_bytes == 0:
                safe_unlink(temp_sample)
                return (
                    jsonify({"error_code": "EMPTY_SAMPLE", "error": "Uploaded sample is empty."}),
                    400,
                )

            actual_sha256 = digest.hexdigest().lower()
            if expected_sha256 and actual_sha256 != expected_sha256:
                safe_unlink(temp_sample)
                return (
                    jsonify(
                        {
                            "error_code": "CHECKSUM_MISMATCH",
                            "error": "Sample SHA-256 mismatch during transfer to gateway.",
                        }
                    ),
                    400,
                )

            logger.info("[GATEWAY] Sample received: %s", filename)
            logger.info("[GATEWAY] Checking sandbox status...")

            sb_code, sb_data = query_sandbox_status()
            if sb_code >= 500 or sb_data.get("state") == "UNAVAILABLE":
                safe_unlink(temp_sample)
                logger.error("[ERROR] Sandbox unavailable.")
                return (
                    jsonify(
                        {
                            "error_code": "SANDBOX_UNAVAILABLE",
                            "error": "Sandbox unreachable. Verify Machine 3 service and Internal Network 2.",
                        }
                    ),
                    503,
                )

            sb_state = str(sb_data.get("state") or "").upper()
            if sb_state == "RESTORE_REQUIRED":
                safe_unlink(temp_sample)
                logger.error("[ERROR] Snapshot restore required on sandbox.")
                return (
                    jsonify(
                        {
                            "error_code": "RESTORE_REQUIRED",
                            "error": "Sandbox requires restoring the CLEAN snapshot before a new analysis.",
                        }
                    ),
                    409,
                )

            if sb_state != "READY":
                safe_unlink(temp_sample)
                logger.error("[ERROR] Sandbox busy (state: %s).", sb_state)
                return (
                    jsonify(
                        {
                            "error_code": "SANDBOX_BUSY",
                            "error": f"Sandbox is currently in state '{sb_state}'.",
                        }
                    ),
                    409,
                )

            logger.info("[OK] Sandbox available.")
            logger.info("[GATEWAY] Forwarding sample...")

            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(total_bytes),
                "X-Sample-Filename": filename,
                "X-Sample-SHA256": actual_sha256,
            }
            with temp_sample.open("rb") as fh:
                sb_resp = requests.post(
                    f"{state.sandbox_base_url}/analyze",
                    data=fh,
                    headers=headers,
                    timeout=(state.connect_timeout, max(state.request_timeout, 120)),
                )

            if sb_resp.status_code not in (200, 202):
                try:
                    err_payload = sb_resp.json()
                except ValueError:
                    err_payload = {"error": sb_resp.text.strip()}
                logger.error("[ERROR] Sandbox rejected sample: %s", err_payload)
                return jsonify(err_payload), sb_resp.status_code

            sb_job = sb_resp.json()
            job_id = str(sb_job["job_id"])

            with state.lock:
                state.active_job = {
                    "job_id": job_id,
                    "filename": filename,
                    "sha256": actual_sha256,
                    "started_at_utc": datetime.now(timezone.utc),
                    "status": "ANALYZING",
                    "job_status": "running",
                    "stage": "submitted",
                    "evidence_ready": False,
                    "zip_path": None,
                    "archive_sha256": "",
                    "error": None,
                }

            worker = threading.Thread(
                target=monitor_and_fetch_evidence,
                args=(job_id,),
                daemon=True,
                name=f"relay-{job_id}",
            )
            worker.start()

            logger.info("[GATEWAY] Waiting for evidence...")
            return jsonify({"job_id": job_id, "status": "ANALYZING"}), 202

        except ValueError as exc:
            logger.error("[ERROR] %s", exc)
            return jsonify({"error_code": "INVALID_SAMPLE", "error": str(exc)}), 400
        except requests.RequestException as exc:
            logger.error("[ERROR] Sample transfer to sandbox failed: %s", exc)
            return (
                jsonify(
                    {
                        "error_code": "SAMPLE_TRANSFER_FAILED",
                        "error": f"Failed forwarding sample to sandbox: {exc}",
                    }
                ),
                502,
            )
        finally:
            # Never keep sample binaries on Machine 2 after forwarding or failure.
            safe_unlink(temp_sample)

    @app.get("/jobs/<job_id>")
    def get_job(job_id: str) -> tuple[Response, int]:
        with state.lock:
            job = state.active_job
            if not job or job.get("job_id") != job_id:
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404
            payload = {
                "job_id": job["job_id"],
                "status": job.get("status"),
                "job_status": job.get("job_status"),
                "stage": job.get("stage"),
                "evidence_ready": bool(job.get("evidence_ready")),
                "archive_sha256": job.get("archive_sha256", ""),
                "error": job.get("error"),
                "error_code": job.get("error_code"),
            }
        return jsonify(payload), 200

    @app.get("/jobs/<job_id>/evidence")
    def get_job_evidence(job_id: str) -> Response | tuple[Response, int]:
        try:
            safe_id = sanitize_job_id(job_id)
        except ValueError as exc:
            return jsonify({"error_code": "INVALID_JOB_ID", "error": str(exc)}), 400

        zip_path: Path | None = None
        archive_sha256 = ""
        with state.lock:
            job = state.active_job
            if job and job.get("job_id") == safe_id:
                if not job.get("evidence_ready"):
                    return (
                        jsonify(
                            {
                                "error_code": "EVIDENCE_NOT_READY",
                                "error": "Evidence archive is not ready yet.",
                            }
                        ),
                        409,
                    )
                zip_path = Path(job["zip_path"]) if job.get("zip_path") else None
                archive_sha256 = str(job.get("archive_sha256") or "")

        if zip_path is None:
            candidate = state.archive_dir / f"evidence_{safe_id}.zip"
            if candidate.is_file():
                zip_path = candidate
                digest = hashlib.sha256()
                with candidate.open("rb") as fh:
                    while True:
                        chunk = fh.read(state.chunk_size)
                        if not chunk:
                            break
                        digest.update(chunk)
                archive_sha256 = digest.hexdigest()

        if zip_path is None or not zip_path.is_file():
            return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Evidence archive not found for job ID."}), 404

        zip_file = zip_path
        file_size = zip_file.stat().st_size
        logger.info("[GATEWAY] Returning evidence to client...")

        def stream_evidence():
            completed = False
            try:
                with zip_file.open("rb") as fh:
                    while True:
                        chunk = fh.read(state.chunk_size)
                        if not chunk:
                            break
                        yield chunk
                completed = True
            finally:
                if completed:
                    logger.info("[OK] Transfer completed (archive retained at %s).", zip_file)
                else:
                    logger.error(
                        "[ERROR] Evidence transfer to client interrupted; archive retained at %s for recovery.",
                        zip_file,
                    )

        headers = {
            "Content-Length": str(file_size),
            "Content-Disposition": f'attachment; filename="evidence_{safe_id}.zip"',
            "X-Archive-SHA256": archive_sha256,
        }
        return Response(stream_evidence(), status=200, mimetype="application/zip", headers=headers)

    @app.get("/jobs/<job_id>/network-diagnostics")
    def get_network_diagnostics(job_id: str) -> tuple[Response, int]:
        """Return separate Machine 2 isolated network diagnostic JSON without modifying Sandbox ZIP."""
        try:
            safe_id = sanitize_job_id(job_id)
        except ValueError as exc:
            return jsonify({"error_code": "INVALID_JOB_ID", "error": str(exc)}), 400

        netdiag_path = state.archive_dir / f"gateway_netdiag_{safe_id}.json"
        if not netdiag_path.is_file():
            return (
                jsonify(
                    {
                        "error_code": "DIAGNOSTICS_UNAVAILABLE",
                        "error": "No Machine 2 INetSim diagnostics artifact recorded for this job.",
                        "inetsim_diagnostics_enabled": bool(state.config.get("inetsim_diagnostics_enabled", False)),
                    }
                ),
                404,
            )
        try:
            doc = json.loads(netdiag_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            return jsonify({"error_code": "DIAGNOSTICS_READ_ERROR", "error": str(exc)}), 500
        return jsonify(doc), 200

    @app.post("/jobs/<job_id>/ack")
    def ack_client_receipt(job_id: str) -> tuple[Response, int]:
        try:
            safe_id = sanitize_job_id(job_id)
        except ValueError as exc:
            return jsonify({"error_code": "INVALID_JOB_ID", "error": str(exc)}), 400

        retained_path = state.archive_dir / f"evidence_{safe_id}.zip"
        with state.lock:
            job = state.active_job
            if job and job.get("job_id") == safe_id:
                zip_ref = Path(job["zip_path"]) if job.get("zip_path") else retained_path
                if not state.retain_evidence_archives:
                    safe_unlink(zip_ref)
                state.active_job = None
            elif not retained_path.is_file():
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404

        logger.info("[OK] Client verified evidence receipt for job %s.", safe_id)
        logger.info("[GATEWAY] Waiting for client...")
        return jsonify(
            {
                "status": "acknowledged",
                "job_id": safe_id,
                "retained_on_gateway": state.retain_evidence_archives,
            }
        ), 200

    return app


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments for the Machine 2 Gateway server."""
    parser = argparse.ArgumentParser(description="MalBox Machine 2 HTTP Gateway Relay")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to gateway config.json (default: machine2-gateway/config.json).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Start the Machine 2 Gateway HTTP server."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logger = setup_logging(verbose=args.verbose)

    config_path = Path(args.config).resolve()
    try:
        config = load_config(config_path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        logger.error("[ERROR] Failed to load gateway config: %s", exc)
        return 1

    app = create_app(config=config, config_dir=config_path.parent, logger=logger)
    host = str(config.get("listen_host", "0.0.0.0"))
    port = int(config.get("listen_port", 8000))

    logger.info("[GATEWAY] Server started on %s:%d.", host, port)
    logger.info("[GATEWAY] Waiting for client...")
    app.run(host=host, port=port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
