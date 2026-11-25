"""Shared utilities, status constants, and safe subprocess helpers for collectors."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_UNAVAILABLE = "unavailable"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".ocx",
    ".drv",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
}


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def timestamp_from_epoch(epoch: float) -> str:
    """Convert an epoch timestamp to UTC ISO-8601 string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_path(raw_path: str | None, base_dir: Path) -> Path | None:
    """Resolve a configured file or directory path against base_dir."""
    if not raw_path:
        return None
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (base_dir / candidate).resolve()


def resolve_tool_path(
    configured_path: str | None,
    base_dir: Path,
    fallback_names: list[str] | None = None,
) -> Path | None:
    """Locate an external tool via configured path or PATH lookup."""
    resolved = resolve_path(configured_path, base_dir)
    if resolved and resolved.exists():
        return resolved

    for name in fallback_names or []:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def write_json(path: Path, data: Any) -> None:
    """Write JSON data cleanly with UTF-8 encoding."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def compute_file_hashes(path: Path, chunk_size: int = 65536) -> dict[str, Any]:
    """Compute MD5, SHA-1, SHA-256, and byte size for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0

    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "filename": path.name,
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def run_subprocess_safe(
    cmd: list[str],
    timeout: float = 120.0,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a subprocess safely without raising on non-zero return or timeout."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=creationflags,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timed_out": False,
            "error": None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": -1,
            "stdout": exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            "stderr": exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            "timed_out": True,
            "error": f"Command timed out after {timeout} seconds.",
        }
    except OSError as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "error": str(exc),
        }


def get_tool_version(tool_path: Path | None, version_arg: str = "--version") -> str:
    """Attempt to query a CLI tool's version string."""
    if not tool_path or not tool_path.exists():
        return "unavailable"
    res = run_subprocess_safe([str(tool_path), version_arg], timeout=10.0)
    output = (res["stdout"] or res["stderr"] or "").strip().splitlines()
    if output:
        return output[0][:160]
    return "present (version unknown)"


@dataclass
class CollectorResult:
    """Normalized collector output recorded in tool_status.json and manifest.json."""

    name: str
    status: str = STATUS_UNAVAILABLE
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str = ""
    tool_versions: dict[str, str] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def finish(self, status: str | None = None) -> "CollectorResult":
        """Stamp completion time and optional status."""
        if status is not None:
            self.status = status
        self.ended_at = utc_now_iso()
        return self

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "tool_versions": self.tool_versions,
            "artifacts": self.artifacts,
            "limitations": self.limitations,
            "errors": self.errors,
            "summary": self.summary,
        }
