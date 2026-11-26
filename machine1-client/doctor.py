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
        except requests.Timeout as exc:
            consecutive_errors += 1
            logger.warning(
                "[WARN] Gateway poll timed out (%d/%d): %s",
                consecutive_errors,
                max_consecutive_errors,
                exc,
            )
            if consecutive_errors >= max_consecutive_errors:
                logger.error("[ERROR] Connection timeout: Gateway stopped responding while waiting for analysis.")
                return None
            time.sleep(poll_interval)
            continue
        except requests.RequestException as exc:
            consecutive_errors += 1
            logger.warning(
                "[WARN] Gateway poll failed (%d/%d): %s",
                consecutive_errors,
                max_consecutive_errors,
                exc,
            )
            if consecutive_errors >= max_consecutive_errors:
                logger.error("[ERROR] Service unavailable: Gateway became unreachable while waiting for analysis.")
                return None
            time.sleep(poll_interval)
            continue

        if resp.status_code == 404:
            logger.error("[ERROR] Interrupted job: Gateway no longer tracks job %s (HTTP 404).", job_id)
            return None
        if resp.status_code != 200:
            logger.error("[ERROR] Unexpected HTTP response during job query: %s", format_gateway_error(resp))
            return None

        try:
            job_data = resp.json()
            if not isinstance(job_data, dict):
                raise ValueError("JSON root is not an object")
        except ValueError:
            logger.error("[ERROR] Unexpected HTTP response: invalid status payload received from gateway.")
            return None

        stage = str(job_data.get("stage") or "")
        if stage and stage != last_stage:
            logger.debug("[CLIENT] Sandbox stage: %s", stage)
            last_stage = stage

        if job_data.get("evidence_ready"):
            return job_data

        job_status = str(job_data.get("status") or "").upper()
        if job_status == "FAILED" and not job_data.get("evidence_ready"):
            err_cat = job_data.get("error_code")
            prefix = f"[{err_cat}] " if err_cat else ""
            logger.error("[ERROR] Analysis failed: %s%s", prefix, job_data.get("error") or "Unknown error")
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


def validate_evidence_zip(
    zf: zipfile.ZipFile,
    max_entries: int,
    max_single_file_bytes: int,
    max_total_bytes: int,
) -> None:
    """Reject unsafe archive metadata before CRC checks or extraction."""
    infos = zf.infolist()
    if len(infos) > max_entries:
        raise ValueError("Archive entry count exceeds safety limit.")
    seen: set[str] = set()
    total_bytes = 0
    for member in infos:
        name = member.filename
        parts = name.rstrip("/").split("/")
        if (not name or "\\" in name or name.startswith("/")
                or any(part in ("", ".", "..") or ":" in part for part in parts)):
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
        if member.file_size > max_single_file_bytes:
            raise ValueError(f"Archive entry {name} exceeds max single file size limit.")
        total_bytes += member.file_size
        if total_bytes > max_total_bytes:
            raise ValueError("Total declared archive size exceeds safety expansion limit.")


def safe_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    max_entries: int = 5000,
    max_single_file_bytes: int = 256 * 1024 * 1024,
    max_total_bytes: int = 1024 * 1024 * 1024,
) -> None:
    """Safely extract a ZIP archive with traversal, symlink, and ZIP-bomb expansion guards."""
    dest_real = dest_dir.resolve()
    total_extracted = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        validate_evidence_zip(zf, max_entries, max_single_file_bytes, max_total_bytes)

        for member in infos:
            raw_name = member.filename
            if not raw_name or "\\" in raw_name or raw_name.startswith("/") or (len(raw_name) >= 2 and raw_name[1] == ":"):
                raise ValueError(f"Unsafe archive entry path detected: {raw_name}")
            if any(part == ".." for part in raw_name.split("/")):
                raise ValueError(f"Path traversal component in archive entry: {raw_name}")

            # Skip symlinks (Unix mode 0120000 in external_attr >> 16)
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                continue

            member_path = (dest_real / raw_name).resolve()
            if member_path != dest_real and dest_real not in member_path.parents:
                raise ValueError(f"Unsafe archive entry path detected: {raw_name}")

            if member.is_dir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue

            if member.file_size > max_single_file_bytes:
                raise ValueError(f"Archive entry {raw_name} exceeds max single file size limit.")

            member_path.parent.mkdir(parents=True, exist_ok=True)
            entry_bytes = 0
            with zf.open(member, "r") as src, member_path.open("xb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    entry_bytes += len(chunk)
                    total_extracted += len(chunk)
                    if entry_bytes > max_single_file_bytes:
                        raise ValueError(f"Decompressed entry {raw_name} exceeded single-file expansion limit.")
                    if total_extracted > max_total_bytes:
                        raise ValueError("Total decompressed archive size exceeded safety expansion limit.")
                    dst.write(chunk)


def verify_extracted_manifest(job_dir: Path, logger: logging.Logger) -> bool:
    """Verify manifest.json structure and cross-check inventory entries against extracted files."""
    manifest_path = job_dir / "manifest.json"
    if not manifest_path.is_file():
        logger.warning("[WARN] Extracted evidence lacks manifest.json for inventory cross-check.")
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest.json root is not a JSON object")
    except (OSError, ValueError) as exc:
        logger.error("[ERROR] Malformed manifest.json in evidence archive: %s", exc)
        return False

    inventory = manifest.get("evidence_file_inventory")
    if not isinstance(inventory, list):
        logger.error("[ERROR] Missing or invalid manifest evidence_file_inventory.")
        return False

    mismatches: list[str] = []
    for entry in inventory:
        if not isinstance(entry, dict):
            mismatches.append("invalid manifest inventory entry")
            continue
        rel = str(entry.get("path") or "")
        if not rel:
            mismatches.append("missing manifest inventory path")
            continue
        target = (job_dir / rel).resolve()
        if job_dir.resolve() not in target.parents:
            mismatches.append(f"unsafe manifest path: {rel}")
            continue
        if not target.is_file():
            mismatches.append(f"missing: {rel}")
            continue
        expected_size = entry.get("size_bytes")
        if expected_size is not None and expected_size != target.stat().st_size:
            mismatches.append(f"size mismatch: {rel}")
        expected_sha = str(entry.get("sha256") or "").lower()
        if expected_sha:
            actual_sha = compute_sha256(target, 65536).lower()
            if actual_sha != expected_sha:
                mismatches.append(f"sha256 mismatch: {rel}")

    if mismatches:
        logger.warning(
            "[WARN] Manifest/archive consistency warnings (%d): %s",
            len(mismatches),
            "; ".join(mismatches[:5]),
        )
        return False
    return True


def fetch_optional_gateway_netdiag(
    base_url: str,
    job_id: str,
    job_dir: Path,
    connect_timeout: float,
    request_timeout: float,
    logger: logging.Logger,
) -> None:
    """Optionally save separate Machine 2 isolated network diagnostic artifact without altering ZIP."""
    try:
        resp = requests.get(
            f"{base_url}/jobs/{job_id}/network-diagnostics",
            timeout=(connect_timeout, request_timeout),
        )
        if resp.status_code == 200:
            doc = resp.json()
            if isinstance(doc, dict):
                out_path = job_dir / "gateway_network_diagnostics.json"
                out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                logger.debug("[CLIENT] Saved separate Machine 2 network diagnostics to %s", out_path.name)
    except (requests.RequestException, OSError, ValueError) as exc:
        logger.debug("[CLIENT] Optional gateway network-diagnostics fetch skipped (%s)", exc)


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
    max_archive_bytes: int = 512 * 1024 * 1024,
    max_entries: int = 5000,
    max_extracted_bytes: int = 1024 * 1024 * 1024,
    fetch_gateway_netdiag: bool = False,
) -> Path | None:
    """Stream the evidence ZIP archive from Gateway, verify integrity, extract, and acknowledge."""
    evidence_root.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(evidence_root, 0o750)
        except OSError:
            pass
    safe_id = "".join(ch for ch in job_id if ch.isalnum() or ch in ("-", "_")) or "job"
    staging_zip = evidence_root / f".downloading_{safe_id}.zip"

    try:
        with requests.get(
            f"{base_url}/jobs/{job_id}/evidence",
            stream=True,
            timeout=(connect_timeout, max(request_timeout, 300)),
        ) as resp:
            if resp.status_code in (404, 409):
                logger.error(
                    "[ERROR] Evidence unavailable (HTTP %s): %s",
                    resp.status_code,
                    format_gateway_error(resp),
                )
                return None
            if resp.status_code != 200:
                logger.error(
                    "[ERROR] Evidence transfer failed (HTTP %s): %s",
                    resp.status_code,
                    format_gateway_error(resp),
                )
                return None

            expected_sha256 = resp.headers.get("X-Archive-SHA256", "").strip().lower()
            digest = hashlib.sha256()
            total_zip_bytes = 0

            with staging_zip.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        total_zip_bytes += len(chunk)
                        if total_zip_bytes > max_archive_bytes:
                            raise ValueError(
                                f"Evidence archive exceeds max size limit ({max_archive_bytes // (1024 * 1024)} MB)."
                            )
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
            validate_evidence_zip(zf, max_entries, 256 * 1024 * 1024, max_extracted_bytes)
            corrupt_member = zf.testzip()
            if corrupt_member is not None:
                raise zipfile.BadZipFile(f"Corrupt ZIP member: {corrupt_member}")

        logger.info("[OK] Evidence received.")

        job_dir = allocate_job_dir(evidence_root, job_id)
        zip_path = job_dir / f"evidence_{safe_id}.zip"
        staging_zip.replace(zip_path)

        if extract_archive:
            try:
                safe_extract_zip(
                    zip_path,
                    job_dir,
                    max_entries=max_entries,
                    max_total_bytes=max_extracted_bytes,
                )
            except (zipfile.BadZipFile, OSError, ValueError) as ext_exc:
                logger.error(
                    "[ERROR] Failed extracting %s (%s). Archive preserved at %s and retained on gateway.",
                    zip_path,
                    ext_exc,
                    zip_path,
                )
                return None
            if not verify_extracted_manifest(job_dir, logger):
                logger.error("[ERROR] Manifest verification failed; archive preserved at %s and receipt not acknowledged.", zip_path)
                return None
            if not keep_zip and zip_path.exists():
                zip_path.unlink()

        if fetch_gateway_netdiag:
            fetch_optional_gateway_netdiag(
                base_url=base_url,
                job_id=job_id,
                job_dir=job_dir,
                connect_timeout=connect_timeout,
                request_timeout=request_timeout,
                logger=logger,
            )

        try:
            ack_resp = requests.post(
                f"{base_url}/jobs/{job_id}/ack",
                timeout=(connect_timeout, request_timeout),
            )
            if ack_resp.status_code != 200:
                logger.warning(
                    "[WARN] Gateway receipt ack returned HTTP %s: %s",
                    ack_resp.status_code,
                    format_gateway_error(ack_resp),
                )
        except requests.RequestException as ack_exc:
            logger.warning("[WARN] Could not send receipt ack to gateway: %s", ack_exc)

        return job_dir
    except (requests.RequestException, zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError) as exc:
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
    max_archive_bytes = max(1, int(config.get("max_evidence_archive_mb", 512))) * 1024 * 1024
    max_entries = max(10, int(config.get("max_archive_entries", 5000)))
    max_extracted_bytes = max(1, int(config.get("max_extracted_size_mb", 1024))) * 1024 * 1024
    fetch_gateway_netdiag = bool(config.get("fetch_gateway_network_diagnostics", False))
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
        max_archive_bytes=max_archive_bytes,
        max_entries=max_entries,
        max_extracted_bytes=max_extracted_bytes,
        fetch_gateway_netdiag=fetch_gateway_netdiag,
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
