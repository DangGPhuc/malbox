#!/usr/bin/env python3
"""MalBox Machine 1 Client CLI (`doctor`).

Submits a sample binary over HTTP to the Machine 2 Gateway, waits for
sandbox analysis on Machine 3, and downloads the resulting evidence ZIP.
Never executes or loads the sample binary on Machine 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import requests

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure concise terminal logging for client operations."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger("malbox.client")


def load_config(config_path: Path) -> dict[str, Any]:
    """Load Machine 1 client configuration from JSON (tolerates UTF-8 BOM)."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def resolve_evidence_dir(raw_path: str, config_dir: Path) -> Path:
    """Resolve evidence storage path relative to the config directory."""
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (config_dir / candidate).resolve()


def compute_sha256(file_path: Path, chunk_size: int) -> str:
    """Compute SHA-256 of the sample purely by reading binary chunks."""
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def check_gateway(base_url: str, connect_timeout: float, logger: logging.Logger) -> bool:
    """Verify HTTP connectivity with the Machine 2 Gateway."""
    logger.info("[CLIENT] Checking gateway connection...")
    try:
        resp = requests.get(f"{base_url}/health", timeout=(connect_timeout, connect_timeout))
        if resp.status_code == 200:
            logger.info("[OK] Gateway connected.")
            return True
        logger.error(
            "[ERROR] Gateway unavailable (HTTP %s): %s",
            resp.status_code,
            resp.text.strip(),
        )
        return False
    except requests.RequestException as exc:
        logger.error("[ERROR] Gateway unavailable at %s (%s)", base_url, exc)
        return False


def format_gateway_error(resp: requests.Response) -> str:
    """Extract a readable error message from a Gateway JSON response."""
    try:
        payload = resp.json()
        code = payload.get("error_code", "")
        msg = payload.get("error", resp.text.strip())
        if code:
            return f"{code}: {msg}"
        return msg
    except ValueError:
        return resp.text.strip() or f"HTTP {resp.status_code}"


def upload_sample(
    base_url: str,
    sample_path: Path,
    sha256: str,
    connect_timeout: float,
    request_timeout: float,
    logger: logging.Logger,
) -> str | None:
    """Stream the sample binary to Gateway POST /analyze and return the job_id."""
    logger.info("[CLIENT] Sample: %s", sample_path.name)
    logger.info("[CLIENT] SHA-256: %s", sha256)
    logger.info("[CLIENT] Uploading sample...")

    file_size = sample_path.stat().st_size
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(file_size),
        "X-Sample-Filename": sample_path.name,
        "X-Sample-SHA256": sha256,
    }

    try:
        with sample_path.open("rb") as fh:
            resp = requests.post(
                f"{base_url}/analyze",
                data=fh,
                headers=headers,
                timeout=(connect_timeout, max(request_timeout, 120)),
            )
    except requests.RequestException as exc:
        logger.error("[ERROR] Sample transfer failed: %s", exc)
        return None

    if resp.status_code not in (200, 202):
        detail = format_gateway_error(resp)
        if resp.status_code == 503:
            logger.error("[ERROR] Sandbox unavailable. %s", detail)
        elif resp.status_code == 409:
            logger.error("[ERROR] %s", detail)
        elif resp.status_code == 507:
            logger.error("[ERROR] Insufficient disk space. %s", detail)
        else:
            logger.error("[ERROR] Sample transfer failed (HTTP %s): %s", resp.status_code, detail)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("[ERROR] Sample transfer failed: invalid JSON response from gateway.")
        return None

    job_id = data.get("job_id")
    if not job_id:
        logger.error("[ERROR] Sample transfer failed: gateway did not return job_id.")
        return None

    logger.info("[OK] Sample submitted (Job ID: %s).", job_id)
    return str(job_id)


def wait_for_evidence(
    base_url: str,
    job_id: str,
    connect_timeout: float,
    request_timeout: float,
    poll_interval: float,
    analysis_timeout: float,
    logger: logging.Logger,
) -> dict[str, Any] | None:
    """Poll Gateway for job completion without infinite retries."""
    logger.info("[CLIENT] Waiting for analysis...")
    deadline = time.monotonic() + analysis_timeout
    consecutive_errors = 0
    max_consecutive_errors = 3
    last_stage = ""

    while time.monotonic() < deadline:
        try:
            resp = requests.get(
                f"{base_url}/jobs/{job_id}",
                timeout=(connect_timeout, request_timeout),
            )
            consecutive_errors = 0
        except requests.RequestException as exc:
            consecutive_errors += 1
            logger.warning(
                "[WARN] Gateway poll failed (%d/%d): %s",
                consecutive_errors,
                max_consecutive_errors,
                exc,
            )
            if consecutive_errors >= max_consecutive_errors:
                logger.error("[ERROR] Gateway became unreachable while waiting for analysis.")
                return None
            time.sleep(poll_interval)
            continue

        if resp.status_code != 200:
            logger.error("[ERROR] Gateway job query failed: %s", format_gateway_error(resp))
            return None

        try:
            job_data = resp.json()
        except ValueError:
            logger.error("[ERROR] Invalid status payload received from gateway.")
            return None

        stage = str(job_data.get("stage") or "")
        if stage and stage != last_stage:
            logger.debug("[CLIENT] Sandbox stage: %s", stage)
            last_stage = stage

        if job_data.get("evidence_ready"):
            return job_data

        job_status = str(job_data.get("status") or "").upper()
        if job_status == "FAILED" and not job_data.get("evidence_ready"):
            logger.error("[ERROR] Analysis failed: %s", job_data.get("error") or "Unknown error")
            return None

        time.sleep(poll_interval)

    logger.error("[ERROR] Analysis timed out after %d seconds.", int(analysis_timeout))
    return None


def allocate_job_dir(evidence_root: Path, job_id: str) -> Path:
    """Create a unique evidence directory for this job without overwriting prior jobs."""
    safe_job_id = "".join(ch for ch in job_id if ch.isalnum() or ch in ("-", "_")) or "job"
    evidence_root.mkdir(parents=True, exist_ok=True)
    target = evidence_root / safe_job_id
    if not target.exists():
        target.mkdir(parents=True, exist_ok=False)
        return target

    suffix = 1
    while True:
        candidate = evidence_root / f"{safe_job_id}_{suffix}"
        if not candidate.exists():
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        suffix += 1


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    """Safely extract a ZIP archive preventing path traversal and symlink creation."""
    dest_real = dest_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Skip symlinks (Unix mode 0120000 in external_attr >> 16)
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                continue

            member_path = (dest_real / member.filename).resolve()
            if member_path != dest_real and dest_real not in member_path.parents:
                raise ValueError(f"Unsafe archive entry path detected: {member.filename}")

            if member.is_dir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue

            member_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, member_path.open("wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)


def download_evidence(
    base_url: str,
    job_id: str,
    evidence_root: Path,
    connect_timeout: float,
    request_timeout: float,
    chunk_size: int,
    extract_archive: bool,
    keep_zip: bool,
    logger: logging.Logger,
) -> Path | None:
    """Stream the evidence ZIP archive from Gateway, verify integrity, extract, and acknowledge."""
    evidence_root.mkdir(parents=True, exist_ok=True)
    safe_id = "".join(ch for ch in job_id if ch.isalnum() or ch in ("-", "_")) or "job"
    staging_zip = evidence_root / f".downloading_{safe_id}.zip"

    try:
        with requests.get(
            f"{base_url}/jobs/{job_id}/evidence",
            stream=True,
            timeout=(connect_timeout, max(request_timeout, 300)),
        ) as resp:
            if resp.status_code != 200:
                logger.error(
                    "[ERROR] Evidence transfer failed (HTTP %s): %s",
                    resp.status_code,
                    format_gateway_error(resp),
                )
                return None

            expected_sha256 = resp.headers.get("X-Archive-SHA256", "").strip().lower()
            digest = hashlib.sha256()

            with staging_zip.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        fh.write(chunk)
                        digest.update(chunk)

        if not staging_zip.is_file() or staging_zip.stat().st_size == 0:
            raise ValueError("Downloaded evidence archive is empty.")

        actual_sha256 = digest.hexdigest().lower()
        if expected_sha256 and actual_sha256 != expected_sha256:
            raise ValueError(
                f"Archive checksum mismatch ({actual_sha256} != {expected_sha256})."
            )

        with zipfile.ZipFile(staging_zip, "r") as zf:
            corrupt_member = zf.testzip()
            if corrupt_member is not None:
                raise zipfile.BadZipFile(f"Corrupt ZIP member: {corrupt_member}")

        logger.info("[OK] Evidence received.")

        job_dir = allocate_job_dir(evidence_root, job_id)
        zip_path = job_dir / f"evidence_{safe_id}.zip"
        staging_zip.replace(zip_path)

        if extract_archive:
            try:
                safe_extract_zip(zip_path, job_dir)
            except (zipfile.BadZipFile, OSError, ValueError) as ext_exc:
                logger.error(
                    "[ERROR] Failed extracting %s (%s). Archive preserved at %s and retained on gateway.",
                    zip_path,
                    ext_exc,
                    zip_path,
                )
                return None
            if not keep_zip and zip_path.exists():
                zip_path.unlink()

        try:
            requests.post(
                f"{base_url}/jobs/{job_id}/ack",
                timeout=(connect_timeout, request_timeout),
            )
        except requests.RequestException as ack_exc:
            logger.warning("[WARN] Could not send receipt ack to gateway: %s", ack_exc)

        return job_dir
    except (requests.RequestException, zipfile.BadZipFile, OSError, ValueError) as exc:
        if staging_zip.exists():
            try:
                staging_zip.unlink()
            except OSError:
                pass
        logger.error(
            "[ERROR] Evidence transfer failed: %s\n"
            "[HINT] If gateway received the archive, you can recover it via: curl -f -o evidence_%s.zip %s/jobs/%s/evidence",
            exc,
            safe_id,
            base_url,
            job_id,
        )
        return None


def display_saved_path(job_dir: Path) -> str:
    """Format evidence directory cleanly relative to CWD when inside it."""
    try:
        rel = job_dir.resolve().relative_to(Path.cwd().resolve())
        return f"{rel}/"
    except ValueError:
        return f"{job_dir}/"


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse terminal CLI arguments for `doctor`."""
    parser = argparse.ArgumentParser(
        prog="doctor",
        description="MalBox Client: submit a sample to the Gateway for isolated Sandbox analysis.",
    )
    parser.add_argument("sample", help="Path to the sample file to submit (never executed locally).")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to client config.json (default: machine1-client/config.json).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the Machine 1 `doctor` command."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logger = setup_logging(verbose=args.verbose)

    config_path = Path(args.config).resolve()
    try:
        config = load_config(config_path)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error("[ERROR] Failed to load config: %s", exc)
        return 1

    sample_path = Path(args.sample).expanduser()
    if not sample_path.exists():
        logger.error("[ERROR] Sample file not found: %s", sample_path)
        return 1
    if not sample_path.is_file():
        logger.error("[ERROR] Target is not a regular file: %s", sample_path)
        return 1
    if sample_path.stat().st_size == 0:
        logger.error("[ERROR] Sample file is empty (0 bytes): %s", sample_path)
        return 1

    gateway_host = config.get("gateway_host", "10.10.10.20")
    gateway_port = int(config.get("gateway_port", 8000))
    base_url = f"http://{gateway_host}:{gateway_port}"

    connect_timeout = float(config.get("connect_timeout_seconds", 5))
    request_timeout = float(config.get("request_timeout_seconds", 30))
    poll_interval = float(config.get("poll_interval_seconds", 3))
    analysis_timeout = float(config.get("analysis_timeout_seconds", 1800))
    chunk_size = int(config.get("chunk_size_bytes", 65536))
    extract_archive = bool(config.get("extract_archive", True))
    keep_zip = bool(config.get("keep_zip", False))
    evidence_root = resolve_evidence_dir(str(config.get("evidence_dir", "./evidence")), config_path.parent)

    if not check_gateway(base_url, connect_timeout, logger):
        return 1

    sha256 = compute_sha256(sample_path, chunk_size)
    job_id = upload_sample(
        base_url=base_url,
        sample_path=sample_path,
        sha256=sha256,
        connect_timeout=connect_timeout,
        request_timeout=request_timeout,
        logger=logger,
    )
    if not job_id:
        return 1

    job_result = wait_for_evidence(
        base_url=base_url,
        job_id=job_id,
        connect_timeout=connect_timeout,
        request_timeout=request_timeout,
        poll_interval=poll_interval,
        analysis_timeout=analysis_timeout,
        logger=logger,
    )
    if not job_result:
        return 1

    saved_dir = download_evidence(
        base_url=base_url,
        job_id=job_id,
        evidence_root=evidence_root,
        connect_timeout=connect_timeout,
        request_timeout=request_timeout,
        chunk_size=chunk_size,
        extract_archive=extract_archive,
        keep_zip=keep_zip,
        logger=logger,
    )
    if not saved_dir:
        return 1

    logger.info("[OK] Saved to %s", display_saved_path(saved_dir))

    job_status = str(job_result.get("job_status") or "").lower()
    if job_status in ("partial", "failed"):
        logger.warning(
            "[WARN] Analysis finished with status '%s'. Check manifest.json and logs/errors.log.",
            job_status,
        )
    else:
        logger.info("[CLIENT] Analysis completed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
