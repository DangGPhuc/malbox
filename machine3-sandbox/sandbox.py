#!/usr/bin/env python3
"""MalBox Machine 3 Sandbox HTTP Server (Windows 11).

Accepts sample binaries from the Machine 2 Gateway over Internal Network 2,
runs static + dynamic analysis in isolation, packages evidence ZIP archives,
and enforces CLEAN snapshot restoration before accepting another sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from analyzer import run_analysis  # noqa: E402
from collectors.common import utc_now_iso  # noqa: E402

DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"

STATE_READY = "READY"
STATE_ANALYZING = "ANALYZING"
STATE_RETURNING_EVIDENCE = "RETURNING_EVIDENCE"
STATE_RESTORE_REQUIRED = "RESTORE_REQUIRED"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure concise terminal logging for the Sandbox service."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    return logging.getLogger("malbox.sandbox")


def _cfg_bool(config: dict[str, Any], key: str, default: bool) -> bool:
    val = config.get(key, default)
    if isinstance(val, bool):
        return val
    raise ValueError(f"Sandbox config '{key}' must be a boolean (got {type(val).__name__}).")


def _cfg_int(
    config: dict[str, Any],
    key: str,
    default: int,
    min_val: int = 1,
    max_val: int | None = None,
) -> int:
    val = config.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Sandbox config '{key}' must be an integer (got {type(val).__name__}).")
    if val < min_val or (max_val is not None and val > max_val):
        raise ValueError(f"Sandbox config '{key}' out of range: {val}.")
    return val


def _cfg_float(config: dict[str, Any], key: str, default: float, min_val: float = 0.1) -> float:
    val = config.get(key, default)
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"Sandbox config '{key}' must be a finite number (got {type(val).__name__}).")
    fval = float(val)
    if fval != fval or fval in (float("inf"), float("-inf")) or fval < min_val:
        raise ValueError(f"Sandbox config '{key}' must be finite and >= {min_val}.")
    return fval


def load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate Machine 3 Sandbox configuration (supports UTF-8 with or without BOM)."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Sandbox config root must be a JSON object (got {type(data).__name__}).")
    _cfg_int(data, "listen_port", 8001, min_val=1, max_val=65535)
    _cfg_float(data, "observation_duration_seconds", 120.0, min_val=1.0)
    _cfg_bool(data, "require_local_approval", True)
    _cfg_float(data, "poll_sample_interval_seconds", 0.5, min_val=0.05)
    _cfg_float(data, "ghidra_timeout_seconds", 300.0, min_val=1.0)
    _cfg_float(data, "floss_timeout_seconds", 120.0, min_val=1.0)
    _cfg_float(data, "capa_timeout_seconds", 120.0, min_val=1.0)
    _cfg_float(data, "die_timeout_seconds", 60.0, min_val=1.0)
    _cfg_float(data, "volatility_timeout_seconds", 180.0, min_val=1.0)
    _cfg_bool(data, "enable_attack_mapping", True)
    _cfg_int(data, "chunk_size_bytes", 65536, min_val=1024)
    _cfg_int(data, "min_free_disk_mb", 2048, min_val=1)
    _cfg_bool(data, "procdump_enabled", True)
    _cfg_bool(data, "winpmem_enabled", False)
    _cfg_bool(data, "include_raw_pml", False)
    _cfg_int(data, "max_raw_pml_mb", 200, min_val=1)
    _cfg_int(data, "max_procmon_export_rows", 15000, min_val=100)
    _cfg_bool(data, "canary_fixtures_enabled", False)
    return data


def resolve_dir(raw_path: str, base_dir: Path) -> Path:
    """Resolve relative paths against the sandbox base directory."""
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (base_dir / candidate).resolve()


def sanitize_filename(name: str) -> str:
    """Strip path traversal characters from incoming sample filename."""
    cleaned = os.path.basename(name or "sample.bin").strip()
    cleaned = "".join(ch for ch in cleaned if ch.isalnum() or ch in (".", "-", "_"))
    return cleaned or "sample.bin"


class SandboxController:
    """Holds Sandbox state machine (`READY`, `ANALYZING`, `RETURNING_EVIDENCE`, `RESTORE_REQUIRED`)."""

    def __init__(
        self,
        config: dict[str, Any],
        config_dir: Path,
        workspace_root: Path,
        evidence_root: Path,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.config_dir = config_dir
        self.workspace_root = workspace_root
        self.evidence_root = evidence_root
        self.logger = logger
        self.lock = threading.Lock()
        self.prompt_lock = threading.Lock()

        self.dirty_marker = self.workspace_root / ".dirty_state"
        self.state = STATE_RESTORE_REQUIRED if self.dirty_marker.exists() else STATE_READY
        self.current_job: dict[str, Any] | None = None

    def mark_dirty(self, job_id: str, sha256: str) -> None:
        """Persist dirty marker on disk so VM restarts cannot reuse a tainted snapshot."""
        payload = {"job_id": job_id, "sha256": sha256, "marked_at": utc_now_iso()}
        self.dirty_marker.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def prompt_local_approval(self, filename: str, sha256: str) -> bool:
        """Ask local operator on the Sandbox console whether to launch dynamic execution."""
        with self.prompt_lock:
            try:
                answer = input(
                    f"[SANDBOX] Approve dynamic execution for '{filename}' (SHA256: {sha256[:16]}...)? [y/N]: "
                )
            except EOFError:
                self.logger.warning("[WARN] Non-interactive terminal; dynamic execution skipped.")
                return False
            return answer.strip().lower() in ("y", "yes")


def create_app(config: dict[str, Any], config_dir: Path, logger: logging.Logger) -> tuple[Flask, SandboxController]:
    """Create the Sandbox Flask application and state controller."""
    workspace_root = resolve_dir(str(config.get("workspace_dir", "./workspace")), config_dir)
    evidence_root = resolve_dir(str(config.get("evidence_dir", "./evidence")), config_dir)
    workspace_root.mkdir(parents=True, exist_ok=True)
    evidence_root.mkdir(parents=True, exist_ok=True)

    controller = SandboxController(
        config=config,
        config_dir=config_dir,
        workspace_root=workspace_root,
        evidence_root=evidence_root,
        logger=logger,
    )
    app = Flask(__name__)
    chunk_size = _cfg_int(config, "chunk_size_bytes", 65536, min_val=1024)
    min_free_disk_mb = _cfg_int(config, "min_free_disk_mb", 2048, min_val=1)

    def execute_job_thread(
        job_id: str,
        sample_path: Path,
        sample_sha256: str,
        job_workspace: Path,
        job_evidence: Path,
    ) -> None:
        def update_stage(stage: str) -> None:
            with controller.lock:
                if controller.current_job and controller.current_job.get("job_id") == job_id:
                    controller.current_job["stage"] = stage

        try:
            result = run_analysis(
                job_id=job_id,
                sample_path=sample_path,
                sample_sha256=sample_sha256,
                config=controller.config,
                base_dir=controller.config_dir,
                workspace_dir=job_workspace,
                evidence_dir=job_evidence,
                approval_prompt_fn=controller.prompt_local_approval,
                stage_callback=update_stage,
                terminal_logger=logger,
            )
        except Exception as exc:
            logger.error("[ERROR] Unhandled worker exception on job %s: %s", job_id, exc)
            result = {
                "job_status": "failed",
                "zip_path": None,
                "archive_sha256": "",
                "error": f"Unhandled worker error: {exc}",
            }

        zip_path = result.get("zip_path")
        evidence_ready = bool(zip_path and Path(zip_path).is_file())
        with controller.lock:
            if controller.current_job and controller.current_job.get("job_id") == job_id:
                controller.current_job["job_status"] = result.get("job_status", "failed")
                controller.current_job["zip_path"] = zip_path
                controller.current_job["archive_sha256"] = result.get("archive_sha256", "")
                controller.current_job["evidence_ready"] = evidence_ready
                controller.current_job["error"] = result.get("error")
                controller.current_job["stage"] = "returning_evidence" if evidence_ready else "failed"
            controller.state = STATE_RETURNING_EVIDENCE if evidence_ready else STATE_RESTORE_REQUIRED

        if evidence_ready:
            if result.get("job_status") == "failed":
                logger.warning(
                    "[WARN] Analysis failed (%s); partial evidence packaged for transfer.",
                    result.get("error"),
                )
            logger.info("[SANDBOX] Returning evidence to gateway...")
        else:
            logger.error("[ERROR] Evidence packaging failed: %s", result.get("error"))
            logger.info("\n[ACTION REQUIRED]\nRestore the CLEAN snapshot before the next analysis.")

    @app.get("/health")
    def health() -> tuple[Response, int]:
        with controller.lock:
            return jsonify({"status": "ok", "service": "malbox-sandbox", "state": controller.state}), 200

    @app.get("/status")
    def status() -> tuple[Response, int]:
        with controller.lock:
            job_id = controller.current_job.get("job_id") if controller.current_job else None
            return (
                jsonify(
                    {
                        "state": controller.state,
                        "active_job_id": job_id,
                        "dirty_marker_present": controller.dirty_marker.exists(),
                    }
                ),
                200,
            )

    @app.post("/analyze")
    def analyze() -> tuple[Response, int]:
        with controller.lock:
            if controller.state == STATE_RESTORE_REQUIRED:
                return (
                    jsonify(
                        {
                            "error_code": "RESTORE_REQUIRED",
                            "error": "Sandbox requires restoring the CLEAN snapshot before a new analysis.",
                        }
                    ),
                    409,
                )
            if controller.state != STATE_READY:
                return (
                    jsonify(
                        {
                            "error_code": "SANDBOX_BUSY",
                            "error": f"Sandbox is currently in state '{controller.state}'.",
                        }
                    ),
                    409,
                )

            for label, target_dir in (("workspace", controller.workspace_root), ("evidence", controller.evidence_root)):
                free_mb = shutil.disk_usage(target_dir).free // (1024 * 1024)
                if free_mb < min_free_disk_mb:
                    logger.error(
                        "[ERROR] Insufficient disk space on %s (%d MB free < %d MB required).",
                        label,
                        free_mb,
                        min_free_disk_mb,
                    )
                    return (
                        jsonify(
                            {
                                "error_code": "INSUFFICIENT_DISK_SPACE",
                                "error": f"Only {free_mb} MB free on {label}; at least {min_free_disk_mb} MB required.",
                            }
                        ),
                        507,
                    )
                probe_file = target_dir / f".write_probe_{os.getpid()}"
                try:
                    probe_file.write_text("ok", encoding="utf-8")
                    probe_file.unlink()
                except OSError as exc:
                    logger.error("[ERROR] %s directory is not writable (%s): %s", label, target_dir, exc)
                    return (
                        jsonify(
                            {
                                "error_code": "DIRECTORY_NOT_WRITABLE",
                                "error": f"{label} directory is not writable: {exc}",
                            }
                        ),
                        500,
                    )

            # Reserve sandbox immediately before reading sample stream.
            controller.state = STATE_ANALYZING

        filename = sanitize_filename(request.headers.get("X-Sample-Filename", "sample.bin"))
        expected_sha256 = request.headers.get("X-Sample-SHA256", "").strip().lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        staging_dir = controller.workspace_root / f"staging_{stamp}"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staging_sample = staging_dir / filename
        job_workspace: Path | None = None

        try:
            total_bytes = 0
            digest = hashlib.sha256()
            with staging_sample.open("wb") as fh:
                while True:
                    chunk = request.stream.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    digest.update(chunk)
                    fh.write(chunk)

            if total_bytes == 0:
                shutil.rmtree(staging_dir, ignore_errors=True)
                with controller.lock:
                    controller.state = STATE_READY
                return jsonify({"error_code": "EMPTY_SAMPLE", "error": "Empty sample received."}), 400

            actual_sha256 = digest.hexdigest().lower()
            if expected_sha256 and actual_sha256 != expected_sha256:
                shutil.rmtree(staging_dir, ignore_errors=True)
                with controller.lock:
                    controller.state = STATE_READY
                return (
                    jsonify(
                        {
                            "error_code": "CHECKSUM_MISMATCH",
                            "error": "Sample SHA-256 mismatch during transfer to sandbox.",
                        }
                    ),
                    400,
                )

            job_id = f"{stamp}_{actual_sha256[:12]}"
            job_workspace = controller.workspace_root / job_id
            sample_dir = job_workspace / "sample"
            job_evidence = controller.evidence_root / job_id
            sample_dir.mkdir(parents=True, exist_ok=True)
            sample_path = sample_dir / filename
            shutil.move(str(staging_sample), str(sample_path))
            shutil.rmtree(staging_dir, ignore_errors=True)

            controller.mark_dirty(job_id=job_id, sha256=actual_sha256)
            logger.info("[OK] Sample received: %s (Job ID: %s).", filename, job_id)

            with controller.lock:
                controller.current_job = {
                    "job_id": job_id,
                    "filename": filename,
                    "sha256": actual_sha256,
                    "job_status": "running",
                    "stage": "received",
                    "evidence_ready": False,
                    "zip_path": None,
                    "archive_sha256": "",
                    "error": None,
                }

            worker = threading.Thread(
                target=execute_job_thread,
                args=(job_id, sample_path, actual_sha256, job_workspace, job_evidence),
                daemon=True,
                name=f"sandbox-{job_id}",
            )
            worker.start()

            return jsonify({"job_id": job_id, "state": STATE_ANALYZING}), 202
        except OSError as exc:
            shutil.rmtree(staging_dir, ignore_errors=True)
            if job_workspace is not None:
                shutil.rmtree(job_workspace, ignore_errors=True)
            with controller.lock:
                controller.state = STATE_READY
            logger.error("[ERROR] Failed saving incoming sample: %s", exc)
            return jsonify({"error_code": "SAMPLE_TRANSFER_FAILED", "error": str(exc)}), 500

    @app.get("/jobs/<job_id>")
    def get_job(job_id: str) -> tuple[Response, int]:
        with controller.lock:
            job = controller.current_job
            if not job or job.get("job_id") != job_id:
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404
            payload = {
                "job_id": job["job_id"],
                "state": controller.state,
                "job_status": job.get("job_status"),
                "stage": job.get("stage"),
                "evidence_ready": bool(job.get("evidence_ready")),
                "archive_sha256": job.get("archive_sha256", ""),
                "error": job.get("error"),
            }
        return jsonify(payload), 200

    @app.get("/jobs/<job_id>/evidence")
    def get_job_evidence(job_id: str) -> Response | tuple[Response, int]:
        with controller.lock:
            job = controller.current_job
            if not job or job.get("job_id") != job_id:
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404
            zip_path = job.get("zip_path")
            archive_sha256 = job.get("archive_sha256", "")
            if not job.get("evidence_ready") or not zip_path or not Path(zip_path).is_file():
                return (
                    jsonify({"error_code": "EVIDENCE_NOT_READY", "error": "Evidence ZIP not ready."}),
                    409,
                )

        zip_file = Path(zip_path)
        file_size = zip_file.stat().st_size

        def stream_zip():
            with zip_file.open("rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

        headers = {
            "Content-Length": str(file_size),
            "Content-Disposition": f'attachment; filename="evidence_{job_id}.zip"',
            "X-Archive-SHA256": archive_sha256,
        }
        return Response(stream_zip(), status=200, mimetype="application/zip", headers=headers)

    @app.post("/jobs/<job_id>/ack")
    def ack_evidence(job_id: str) -> tuple[Response, int]:
        with controller.lock:
            job = controller.current_job
            if not job or job.get("job_id") != job_id:
                return jsonify({"error_code": "JOB_NOT_FOUND", "error": "Unknown job ID."}), 404
            controller.state = STATE_RESTORE_REQUIRED

        logger.info("[OK] Evidence transfer completed.")
        logger.info("")
        logger.info("[ACTION REQUIRED]")
        logger.info("Restore the CLEAN snapshot before the next analysis.")
        return jsonify({"state": STATE_RESTORE_REQUIRED}), 200

    return app, controller


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments for the Machine 3 Sandbox server."""
    parser = argparse.ArgumentParser(description="MalBox Machine 3 Windows 11 Sandbox Server")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to sandbox config.json (default: machine3-sandbox/config.json).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Start the Machine 3 Sandbox HTTP server."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logger = setup_logging(verbose=args.verbose)

    config_path = Path(args.config).resolve()
    try:
        config = load_config(config_path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        logger.error("[ERROR] Failed to load sandbox config: %s", exc)
        return 1

    app, controller = create_app(config=config, config_dir=config_path.parent, logger=logger)
    host = str(config.get("listen_host", "0.0.0.0"))
    port = int(config.get("listen_port", 8001))

    logger.info("[SANDBOX] Server started on %s:%d.", host, port)
    if controller.state == STATE_RESTORE_REQUIRED:
        logger.warning("[ACTION REQUIRED]")
        logger.warning("Previous dirty sandbox state detected. Restore the CLEAN snapshot before analyzing new samples.")
    else:
        logger.info("[SANDBOX] Waiting for sample...")

    app.run(host=host, port=port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
