from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


SECRET_ENV_KEYS = {
    "MALBOX_OPERATOR_TOKEN",
    "MALBOX_AI_API_KEY",
    "MALBOX_SECRET_KEY",
    "MALBOX_CAPE_API_TOKEN",
}

REQUIRED_REPLAY_FIXTURES = (
    "ransomware_wannacry_mock",
    "infostealer_redline_mock",
)

REQUIRED_DB_TABLES = {
    "samples",
    "analyses",
    "analysis_events",
    "behavioral_findings",
    "orchestration_records",
    "analysis_reports",
}


@dataclass
class CheckResult:
    id: str
    name: str
    status: CheckStatus
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    repaired: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


CommandRunner = Callable[..., subprocess.CompletedProcess]


def default_command_runner(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """Executes subprocess commands safely without invoking a shell."""
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def strip_unquoted_inline_comment(value: str) -> str:
    """Strips inline `# comment` only when outside matching quotes."""
    val = value.strip()
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]

    in_single = False
    in_double = False
    for idx, ch in enumerate(val):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or val[idx - 1].isspace():
                val = val[:idx].strip()
                break

    if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
        return val[1:-1]
    return val


def parse_env_file(env_path: Path) -> Dict[str, str]:
    """Safely parses a .env file into key/value pairs without shell execution."""
    parsed: Dict[str, str] = {}
    if not env_path.is_file():
        return parsed

    with env_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            parsed[key] = strip_unquoted_inline_comment(val)
    return parsed


def resolve_effective_config(root_dir: Path, environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Loads .env (if present) and applies explicit process environment overrides.
    Mirrors Settings precedence in backend/app/core/config.py.
    """
    env_map = environ if environ is not None else os.environ
    defaults = {
        "MALBOX_HOST": "127.0.0.1",
        "MALBOX_PORT": "8000",
        "MALBOX_DATA_DIR": "./data",
        "MALBOX_QUARANTINE_DIR": "./data/quarantine",
        "MALBOX_ARTIFACTS_DIR": "./data/artifacts",
        "MALBOX_DATABASE_URL": "",
        "MALBOX_LIVE_MODE_ENABLED": "false",
        "MALBOX_REQUIRE_EXPLICIT_APPROVAL": "true",
        "MALBOX_OPERATOR_TOKEN": "",
        "MALBOX_DEFAULT_SANDBOX_BACKEND": "replay",
        "MALBOX_AI_PROVIDER": "mock",
        "MALBOX_AI_API_KEY": "",
        "MALBOX_CAPE_API_URL": "http://127.0.0.1:8008",
        "MALBOX_CAPE_API_TOKEN": "",
        "MALBOX_FRONTEND_PORT": "5173",
    }

    config = dict(defaults)
    for candidate in (root_dir / "backend" / ".env", root_dir / ".env"):
        if candidate.is_file():
            config.update(parse_env_file(candidate))

    for key, value in env_map.items():
        if key.upper().startswith("MALBOX_"):
            config[key.upper()] = value

    return config


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_repo_path(root_dir: Path, raw_path: str, fallback: Path) -> Path:
    if not raw_path:
        return fallback
    p = Path(raw_path)
    return p if p.is_absolute() else (root_dir / p).resolve()


def resolve_sqlite_db_path(root_dir: Path, config: Dict[str, str]) -> Tuple[Optional[Path], str]:
    """
    Resolves database path for SQLite URLs.
    Returns (sqlite_path_or_none, database_url_or_type).
    """
    raw_db_url = (config.get("MALBOX_DATABASE_URL") or "").strip()
    if not raw_db_url:
        data_dir = resolve_repo_path(root_dir, config.get("MALBOX_DATA_DIR", "./data"), root_dir / "data")
        db_path = data_dir / "malbox.db"
        return db_path, f"sqlite:///{db_path}"

    if raw_db_url.startswith("sqlite:///"):
        raw_rel = raw_db_url[len("sqlite:///"):]
        if raw_rel == ":memory:":
            return None, raw_db_url
        p = Path(raw_rel)
        resolved = p if raw_rel.startswith("/") else (root_dir / p).resolve()
        return resolved, raw_db_url

    return None, raw_db_url.split("://", 1)[0] + "://[configured]"


def detect_memory_mb() -> Tuple[Optional[int], Optional[int]]:
    """Returns (total_ram_mb, available_ram_mb) using OS interfaces without third-party libs."""
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        total_kb = None
        avail_kb = None
        try:
            for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail_kb = int(line.split()[1])
            return (
                total_kb // 1024 if total_kb is not None else None,
                avail_kb // 1024 if avail_kb is not None else None,
            )
        except Exception:
            pass

    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=5)
            total_mb = int(out.strip()) // (1024 * 1024)
            return total_mb, None
        except Exception:
            pass

    return None, None


def get_system_info() -> Dict[str, Any]:
    rel = platform.release()
    distro = platform.platform()
    os_release = Path("/etc/os-release")
    if os_release.is_file():
        for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                distro = line.split("=", 1)[1].strip().strip('"')
                break
    return {
        "system": platform.system(),
        "release": rel,
        "machine": platform.machine(),
        "distro": distro,
        "is_wsl": "microsoft" in rel.lower() or "wsl" in rel.lower(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
    }


def is_port_in_use(host: str, port: int, timeout: float = 0.4) -> bool:
    """Checks if a TCP service is already listening on host:port."""
    target_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target_host, port)) == 0
    except OSError:
        return False


def get_venv_python(root_dir: Path) -> Path:
    unix_py = root_dir / ".venv" / "bin" / "python"
    if unix_py.exists():
        return unix_py
    win_py = root_dir / ".venv" / "Scripts" / "python.exe"
    if win_py.exists():
        return win_py
    return unix_py


def get_runtime_dir(root_dir: Path) -> Path:
    return root_dir / ".malbox"


def read_pid_state(pid_file: Path) -> Optional[Dict[str, Any]]:
    if not pid_file.is_file():
        return None
    try:
        raw = pid_file.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get("pid"), int):
            return data
    except Exception:
        pass
    return None


def _read_proc_cmdline(pid: int) -> Optional[str]:
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    if not cmdline_path.is_file():
        return None
    try:
        raw = cmdline_path.read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _is_zombie_proc(pid: int) -> bool:
    status_path = Path(f"/proc/{pid}/status")
    if not status_path.is_file():
        return False
    try:
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("State:"):
                parts = line.split(":", 1)[1].strip()
                return parts.startswith("Z") or "zombie" in parts.lower()
    except Exception:
        pass
    return False


def is_pid_running(pid: int, expected_substrings: Optional[List[str]] = None) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    if _is_zombie_proc(pid):
        return False

    if expected_substrings:
        cmdline = _read_proc_cmdline(pid)
        if cmdline:
            lowered = cmdline.lower()
            if not any(sub.lower() in lowered for sub in expected_substrings):
                return False
    return True


def redacted_config_summary(config: Dict[str, str]) -> Dict[str, Any]:
    """Returns safe summary metadata without exposing secrets."""
    return {
        "host": config.get("MALBOX_HOST", "127.0.0.1"),
        "port": config.get("MALBOX_PORT", "8000"),
        "frontend_port": config.get("MALBOX_FRONTEND_PORT", "5173"),
        "default_backend": config.get("MALBOX_DEFAULT_SANDBOX_BACKEND", "replay"),
        "live_mode_enabled": parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False),
        "require_explicit_approval": parse_bool(config.get("MALBOX_REQUIRE_EXPLICIT_APPROVAL"), default=True),
        "operator_token_configured": bool((config.get("MALBOX_OPERATOR_TOKEN") or "").strip()),
        "ai_provider": config.get("MALBOX_AI_PROVIDER", "mock"),
        "ai_api_key_configured": bool((config.get("MALBOX_AI_API_KEY") or "").strip()),
        "cape_api_url": config.get("MALBOX_CAPE_API_URL", "http://127.0.0.1:8008"),
    }
