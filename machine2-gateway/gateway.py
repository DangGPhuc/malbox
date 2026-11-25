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
from pathlib import Path
from typing import Any

import requests
from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
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


def load_config(config_path: Path) -> dict[str, Any]:
    """Load Machine 2 Gateway configuration from JSON."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


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


def safe_unlink(path: Path | None) -> None:
    """Remove a temporary file if it exists without raising."""
    if path is None:
        return
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


class GatewayState:
    """Thread-safe single-job state holder for the Gateway relay."""

    def __init__(self, config: dict[str, Any], temp_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.temp_dir = temp_dir
        self.logger = logger
        self.lock = threading.Lock()
        self.active_job: dict[str, Any] | None = None

    @property
    def sandbox_base_url(self) -> str:
        host = self.config.get("sandbox_host", "10.10.20.30")
        port = int(self.config.get("sandbox_port", 8001))
        return f"http://{host}:{port}"

    @property
    def connect_timeout(self) -> float:
        return float(self.config.get("connect_timeout_seconds", 5))

    @property
    def request_timeout(self) -> float:
        return float(self.config.get("request_timeout_seconds", 30))

    @property
    def poll_interval(self) -> float:
        return float(self.config.get("poll_interval_seconds", 3))

    @property
    def analysis_timeout(self) -> float:
        return float(self.config.get("analysis_timeout_seconds", 1800))

    @property
    def chunk_size(self) -> int:
        return int(self.config.get("chunk_size_bytes", 65536))

    @property
    def max_sample_bytes(self) -> int:
        return int(self.config.get("max_sample_size_mb", 200)) * 1024 * 1024


def create_app(config: dict[str, Any], config_dir: Path, logger: logging.Logger) -> Flask:
    """Create the Flask Gateway application."""
    temp_dir = resolve_dir(str(config.get("temp_dir", "./tmp")), config_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)

    state = GatewayState(config=config, temp_dir=temp_dir, logger=logger)
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
        deadline = time.monotonic() + state.analysis_timeout
        consecutive_errors = 0
        max_consecutive_errors = 5

        while time.monotonic() < deadline:
            try:
                resp = requests.get(
                    f"{state.sandbox_base_url}/jobs/{job_id}",
                    timeout=(state.connect_timeout, state.request_timeout),
                )
                consecutive_errors = 0
            except requests.RequestException as exc:
                consecutive_errors += 1
                logger.warning(
                    "[WARN] Sandbox status poll failed (%d/%d): %s",
                    consecutive_errors,
                    max_consecutive_errors,
                    exc,
                )
                if consecutive_errors >= max_consecutive_errors:
                    with state.lock:
                        if state.active_job and state.active_job.get("job_id") == job_id:
                            state.active_job["status"] = "FAILED"
                            state.active_job["error"] = "Sandbox unavailable during analysis."
                    logger.error("[ERROR] Sandbox became unreachable during job %s.", job_id)
                    return
                time.sleep(state.poll_interval)
                continue

            if resp.status_code != 200:
                with state.lock:
                    if state.active_job and state.active_job.get("job_id") == job_id:
                        state.active_job["status"] = "FAILED"
                        state.active_job["error"] = f"Sandbox returned HTTP {resp.status_code}"
                logger.error("[ERROR] Sandbox job query error (HTTP %s).", resp.status_code)
                return

            try:
                job_info = resp.json()
            except ValueError:
                time.sleep(state.poll_interval)
                continue

            with state.lock:
                if state.active_job and state.active_job.get("job_id") == job_id:
                    state.active_job["stage"] = job_info.get("stage", "")
                    state.active_job["job_status"] = job_info.get("job_status", "")

            if job_info.get("evidence_ready"):
                zip_path = state.temp_dir / f"evidence_{job_id}.zip"
                try:
                    with requests.get(
                        f"{state.sandbox_base_url}/jobs/{job_id}/evidence",
                        stream=True,
                        timeout=(state.connect_timeout, max(state.request_timeout, 300)),
                    ) as dl:
                        if dl.status_code != 200:
                            raise RuntimeError(f"HTTP {dl.status_code}: {dl.text.strip()}")
                        expected_sha256 = dl.headers.get("X-Archive-SHA256", "").strip().lower()
                        digest = hashlib.sha256()
                        with zip_path.open("wb") as fh:
                            for chunk in dl.iter_content(chunk_size=state.chunk_size):
                                if chunk:
                                    fh.write(chunk)
                                    digest.update(chunk)

                    actual_sha256 = digest.hexdigest().lower()
                    if expected_sha256 and actual_sha256 != expected_sha256:
                        raise ValueError(
                            f"Evidence checksum mismatch ({actual_sha256} != {expected_sha256})"
                        )

                    # Acknowledge transfer so Sandbox moves to RESTORE_REQUIRED.
                    try:
                        requests.post(
                            f"{state.sandbox_base_url}/jobs/{job_id}/ack",
                            timeout=(state.connect_timeout, state.request_timeout),
                        )
                    except requests.RequestException as ack_exc:
                        logger.warning("[WARN] Failed to ack evidence receipt to sandbox: %s", ack_exc)

                    logger.info("[OK] Evidence received from sandbox.")
                    with state.lock:
                        if state.active_job and state.active_job.get("job_id") == job_id:
                            state.active_job["status"] = "EVIDENCE_READY"
                            state.active_job["evidence_ready"] = True
                            state.active_job["zip_path"] = zip_path
                            state.active_job["archive_sha256"] = actual_sha256
                    return
                except (requests.RequestException, OSError, RuntimeError, ValueError) as exc:
                    safe_unlink(zip_path)
                    logger.error("[ERROR] Evidence transfer from sandbox failed: %s", exc)
                    with state.lock:
                        if state.active_job and state.active_job.get("job_id") == job_id:
                            state.active_job["status"] = "FAILED"
                            state.active_job["error"] = f"Evidence transfer failed: {exc}"
                    return

            if str(job_info.get("job_status", "")).lower() == "failed" and not job_info.get(
                "evidence_ready"
            ):
                err = job_info.get("error") or "Sandbox analysis failed."
                logger.error("[ERROR] Sandbox analysis failed: %s", err)
                with state.lock:
                    if state.active_job and state.active_job.get("job_id") == job_id:
                        state.active_job["status"] = "FAILED"
                        state.active_job["error"] = err
                return

            time.sleep(state.poll_interval)

        logger.error("[ERROR] Timed out waiting for sandbox evidence on job %s.", job_id)
        with state.lock:
            if state.active_job and state.active_job.get("job_id") == job_id:
                state.active_job["status"] = "FAILED"
                state.active_job["error"] = "Timed out waiting for sandbox evidence."

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
            }
        return jsonify(payload), 200

    @app.get("/jobs/<job_id>/evidence")
    def get_job_evidence(job_id: str) -> Response | tuple[Response, int]:
        with state.lock:
            job = state.active_job
            if not job or job.get("job_id") != job_id:
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404
            zip_path = job.get("zip_path")
            archive_sha256 = job.get("archive_sha256", "")
            if not job.get("evidence_ready") or not zip_path or not Path(zip_path).is_file():
                return (
                    jsonify(
                        {
                            "error_code": "EVIDENCE_NOT_READY",
                            "error": "Evidence archive is not ready yet.",
                        }
                    ),
                    409,
                )

        zip_file = Path(zip_path)
        file_size = zip_file.stat().st_size
        logger.info("[GATEWAY] Returning evidence to client...")

        def stream_and_cleanup():
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
                    safe_unlink(zip_file)
                    with state.lock:
                        if state.active_job and state.active_job.get("job_id") == job_id:
                            state.active_job = None
                    logger.info("[OK] Transfer completed.")
                    logger.info("[GATEWAY] Waiting for client...")
                else:
                    logger.error("[ERROR] Evidence transfer to client interrupted.")

        headers = {
            "Content-Length": str(file_size),
            "Content-Disposition": f'attachment; filename="evidence_{job_id}.zip"',
            "X-Archive-SHA256": archive_sha256,
        }
        return Response(stream_and_cleanup(), status=200, mimetype="application/zip", headers=headers)

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
    except (FileNotFoundError, json.JSONDecodeError) as exc:
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
