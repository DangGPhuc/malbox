from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass, field
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


@dataclass
class ProcessVerification:
    """Result of strong OS-level process ownership verification."""
    status: str  # "valid", "stale", "reused_pid", "unverified", "invalid_state"
    pid: Optional[int]
    os_pgid: Optional[int]
    reason: str


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


def chmod_safe(path: Path, mode: int) -> bool:
    """Applies POSIX permissions safely on supported platforms."""
    if os.name != "posix" or not path.exists():
        return False
    try:
        current = path.stat().st_mode & 0o777
        if current != mode:
            path.chmod(mode)
            return True
    except OSError:
        pass
    return False


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


def parse_port_value(raw: Optional[str], default: int, var_name: str) -> Tuple[Optional[int], Optional[str]]:
    """Validates TCP port strings strictly (1-65535)."""
    if raw is None or raw.strip() == "":
        return default, None
    clean = raw.strip()
    if not re.fullmatch(r"\d+", clean):
        return None, f"Invalid {var_name} value '{raw}': must be an integer between 1 and 65535."
    port = int(clean)
    if port < 1 or port > 65535:
        return None, f"Invalid {var_name} port {port}: must be between 1 and 65535."
    return port, None


def resolve_ports_strict(config: Dict[str, str]) -> Tuple[Optional[Tuple[str, int, int]], List[str]]:
    """
    Validates host, backend port, and frontend port strictly without silent fallback.
    Returns ((host, backend_port, frontend_port), errors).
    """
    errors: List[str] = []
    host = (config.get("MALBOX_HOST") or "127.0.0.1").strip()
    if not host:
        errors.append("Invalid MALBOX_HOST: cannot be empty.")

    be_port, be_err = parse_port_value(config.get("MALBOX_PORT"), 8000, "MALBOX_PORT")
    fe_port, fe_err = parse_port_value(config.get("MALBOX_FRONTEND_PORT"), 5173, "MALBOX_FRONTEND_PORT")
    if be_err:
        errors.append(be_err)
    if fe_err:
        errors.append(fe_err)
    if be_port is not None and fe_port is not None and be_port == fe_port:
        errors.append(f"Port collision in configuration: MALBOX_PORT and MALBOX_FRONTEND_PORT cannot both be {be_port}.")

    if errors or be_port is None or fe_port is None:
        return None, errors
    return (host, be_port, fe_port), []


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
        if isinstance(data, dict) and isinstance(data.get("pid"), int) and not isinstance(data.get("pid"), bool):
            return data
    except Exception:
        pass
    return None


def _read_proc_cmdline(pid: int) -> Optional[str]:
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    if cmdline_path.is_file():
        try:
            raw = cmdline_path.read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except Exception:
            return None
    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True, timeout=3)
            return out.strip()
        except Exception:
            return None
    return None


def get_process_start_time(pid: int) -> Optional[str]:
    """
    Returns an immutable OS start-time token for a live PID to defend against PID reuse.
    Reads field 22 (starttime in clock ticks) of /proc/<pid>/stat on Linux,
    or `ps -o lstart=` on macOS/BSD.
    """
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.is_file():
        try:
            content = stat_path.read_text(encoding="utf-8", errors="replace")
            rparen = content.rfind(")")
            if rparen != -1:
                fields = content[rparen + 2:].split()
                # Field 3 is index 0 after ')'; field 22 (starttime) is index 19
                if len(fields) > 19:
                    return f"ticks:{fields[19]}"
        except Exception:
            return None
    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3).strip()
            if out:
                return f"lstart:{out}"
        except Exception:
            return None
    return None


def get_process_cwd(pid: int) -> Optional[Path]:
    cwd_link = Path(f"/proc/{pid}/cwd")
    if cwd_link.exists():
        try:
            return cwd_link.resolve()
        except Exception:
            return None
    return None


def get_os_process_group(pid: int) -> Optional[int]:
    try:
        return os.getpgid(pid)
    except OSError:
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


def _probe_pid_liveness(pid: int) -> str:
    """Returns 'alive', 'dead', or 'permission_denied'."""
    if pid <= 0:
        return "dead"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead"
    except PermissionError:
        return "permission_denied"
    except OSError:
        return "dead"

    if _is_zombie_proc(pid):
        return "dead"
    return "alive"


def verify_managed_process(
    state: Optional[Dict[str, Any]],
    expected_service: str,
    root_dir: Path,
    *,
    liveness_fn: Callable[[int], str] = _probe_pid_liveness,
    start_time_fn: Callable[[int], Optional[str]] = get_process_start_time,
    cmdline_fn: Callable[[int], Optional[str]] = _read_proc_cmdline,
    cwd_fn: Callable[[int], Optional[Path]] = get_process_cwd,
    getpgid_fn: Callable[[int], Optional[int]] = get_os_process_group,
) -> ProcessVerification:
    """
    Strictly verifies whether a PID state file corresponds to a genuine live malbox service process.
    Defends against stale PIDs, PID reuse, manipulated PID/PGID state files, and unrelated Python/Node processes.
    """
    if not state or not isinstance(state, dict):
        return ProcessVerification("invalid_state", None, None, "PID file is missing or corrupt JSON.")

    pid = state.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return ProcessVerification("invalid_state", None, None, f"PID file contains invalid PID value: {pid!r}.")

    recorded_service = state.get("service")
    if recorded_service and recorded_service != expected_service:
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"PID file service '{recorded_service}' does not match expected '{expected_service}'.",
        )

    liveness = liveness_fn(pid)
    if liveness == "dead":
        return ProcessVerification("stale", pid, None, f"Process PID {pid} is no longer running.")
    if liveness == "permission_denied":
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"OS denied access inspecting live PID {pid}; refusing to signal process owned by another user.",
        )

    # Mandatory start identity verification against PID reuse
    recorded_start = state.get("proc_start_time")
    if not recorded_start or not isinstance(recorded_start, str):
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"PID file for PID {pid} lacks verified process start identity (`proc_start_time`).",
        )

    live_start = start_time_fn(pid)
    if not live_start:
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"Unable to read OS start time for live PID {pid}; refusing blind signal.",
        )

    if live_start != recorded_start:
        return ProcessVerification(
            "reused_pid",
            pid,
            None,
            f"PID {pid} was reused by another process (recorded start={recorded_start}, live start={live_start}).",
        )

    # Exact service command signature verification (NEVER match bare "python" or "node")
    cmdline = cmdline_fn(pid)
    if not cmdline:
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"Unable to read OS command line for PID {pid}.",
        )

    lowered_cmd = cmdline.lower()
    if expected_service == "backend":
        has_signature = ("uvicorn" in lowered_cmd) and ("app.main:app" in lowered_cmd)
        expected_cwd = root_dir.resolve()
    elif expected_service == "frontend":
        has_signature = "vite" in lowered_cmd
        expected_cwd = (root_dir / "frontend").resolve()
    else:
        return ProcessVerification("unverified", pid, None, f"Unknown service type '{expected_service}'.")

    if not has_signature:
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"Live PID {pid} command line does not match managed {expected_service} signature (`{cmdline[:120]}`).",
        )

    # Verify recorded port / expected command tokens if present
    recorded_port = state.get("port")
    if isinstance(recorded_port, int):
        port_token = str(recorded_port)
        if port_token not in cmdline:
            return ProcessVerification(
                "unverified",
                pid,
                None,
                f"Live PID {pid} command line does not include expected port {port_token}.",
            )

    # Verify working directory / repo association when OS exposes cwd
    recorded_root = state.get("root_dir")
    if recorded_root and Path(recorded_root).resolve() != root_dir.resolve():
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"PID file belongs to a different workspace (`{recorded_root}` != `{root_dir.resolve()}`).",
        )

    live_cwd = cwd_fn(pid)
    if live_cwd is not None and live_cwd != expected_cwd and str(root_dir.resolve()) not in cmdline:
        return ProcessVerification(
            "unverified",
            pid,
            None,
            f"Live PID {pid} working directory (`{live_cwd}`) does not match expected `{expected_cwd}`.",
        )

    # Query actual OS PGID directly (NEVER trust a stored PGID from disk)
    os_pgid = getpgid_fn(pid)
    return ProcessVerification(
        "valid",
        pid,
        os_pgid,
        f"Verified live managed {expected_service} PID {pid} (os_pgid={os_pgid}).",
    )


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
