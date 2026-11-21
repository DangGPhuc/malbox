from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import (
    ProcessVerification,
    chmod_safe,
    get_os_process_group,
    get_process_start_time,
    get_runtime_dir,
    get_venv_python,
    is_port_in_use,
    parse_bool,
    read_pid_state,
    resolve_effective_config,
    resolve_ports_strict,
    verify_managed_process,
)


def _http_health_check(host: str, port: int, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    target = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    url = f"http://{target}:{port}/api/v1/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    return None


def _tail_log(log_path: Path, lines: int = 15) -> str:
    if not log_path.is_file():
        return ""
    try:
        content = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except OSError:
        return ""


def _write_pid_state(pid_file: Path, payload: Dict[str, Any]) -> None:
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    chmod_safe(pid_file.parent, 0o700)
    raw = json.dumps(payload, indent=2).encode("utf-8")
    if os.name == "posix":
        fd = os.open(str(pid_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
        chmod_safe(pid_file, 0o600)
    else:
        pid_file.write_bytes(raw)


def _open_restricted_log(log_path: Path):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    chmod_safe(log_path.parent, 0o700)
    if os.name == "posix":
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        fh = os.fdopen(fd, "a", encoding="utf-8")
        chmod_safe(log_path, 0o600)
        return fh
    return log_path.open("a", encoding="utf-8")


def _terminate_verified_process(
    state: Optional[Dict[str, Any]],
    expected_service: str,
    root_dir: Path,
    timeout: float = 8.0,
    *,
    verify_fn: Callable[..., ProcessVerification] = verify_managed_process,
    kill_fn: Callable[[int, int], None] = os.kill,
    killpg_fn: Callable[[int, int], None] = os.killpg,
) -> Tuple[str, str]:
    """
    Safely verifies ownership of a process state file, verifies OS PGID directly,
    and sends SIGTERM -> SIGKILL only to verified malbox service processes.
    Returns (outcome_code, detail_message).
    """
    ver = verify_fn(state, expected_service, root_dir)
    if ver.status == "stale":
        return "already_stopped", ver.reason
    if ver.status == "invalid_state":
        return "cleaned_invalid_pid", ver.reason
    if ver.status != "valid" or ver.pid is None:
        return f"refused_{ver.status}", f"Refusing to signal {expected_service}: {ver.reason}"

    pid = ver.pid
    os_pgid = ver.os_pgid
    own_pgrp = os.getpgrp()

    # Never trust stored PGID; only signal process group if live OS PGID proves this PID leads its own session group
    use_group_signal = bool(os_pgid is not None and os_pgid == pid and os_pgid > 1 and os_pgid != own_pgrp)

    def _send(sig: int) -> None:
        try:
            if use_group_signal and os_pgid is not None:
                killpg_fn(os_pgid, sig)
            else:
                kill_fn(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            raise

    try:
        _send(signal.SIGTERM)
    except PermissionError as exc:
        return "permission_denied", f"Permission denied sending SIGTERM to verified {expected_service} PID {pid}: {exc}"

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check = verify_fn(state, expected_service, root_dir)
        if check.status != "valid":
            if check.status == "stale":
                return "stopped_gracefully", f"Stopped {expected_service} PID {pid} gracefully (SIGTERM)."
            return "refused_" + check.status, f"Process identity changed mid-shutdown for PID {pid}: {check.reason}"
        time.sleep(0.15)

    try:
        _send(signal.SIGKILL)
    except PermissionError as exc:
        return "permission_denied", f"Permission denied sending SIGKILL to verified {expected_service} PID {pid}: {exc}"

    kill_deadline = time.monotonic() + 2.0
    while time.monotonic() < kill_deadline:
        check = verify_fn(state, expected_service, root_dir)
        if check.status == "stale":
            return "stopped_force", f"Force-stopped {expected_service} PID {pid} (SIGKILL)."
        time.sleep(0.1)

    return "kill_failed", f"{expected_service} PID {pid} did not terminate after SIGTERM and SIGKILL."


def get_status(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
    health_fn: Callable[[str, int], Optional[Dict[str, Any]]] = _http_health_check,
    port_fn: Callable[[str, int], bool] = is_port_in_use,
    verify_fn: Callable[..., ProcessVerification] = verify_managed_process,
) -> Dict[str, Any]:
    config = resolve_effective_config(root_dir, environ=environ)
    parsed_ports, port_errors = resolve_ports_strict(config)
    if port_errors or parsed_ports is None:
        return {
            "exit_code": 1,
            "status": "invalid_config",
            "errors": port_errors,
        }

    host, backend_port, frontend_port = parsed_ports
    runtime_dir = get_runtime_dir(root_dir)

    backend_pid_file = runtime_dir / "backend.pid"
    frontend_pid_file = runtime_dir / "frontend.pid"

    backend_state = read_pid_state(backend_pid_file)
    frontend_state = read_pid_state(frontend_pid_file)

    be_ver = verify_fn(backend_state, "backend", root_dir) if backend_pid_file.exists() else None
    fe_ver = verify_fn(frontend_state, "frontend", root_dir) if frontend_pid_file.exists() else None

    be_alive = bool(be_ver and be_ver.status == "valid")
    be_health = health_fn(host, backend_port) if be_alive else None

    fe_alive = bool(fe_ver and fe_ver.status == "valid")
    fe_listening = port_fn("127.0.0.1", frontend_port) if fe_alive else False

    def _derive_status(ver: Optional[ProcessVerification], healthy_flag: bool, live_label: str, deg_label: str) -> str:
        if ver is None:
            return "stopped"
        if ver.status == "valid":
            return live_label if healthy_flag else deg_label
        if ver.status == "stale":
            return "stale_pid"
        return ver.status  # "reused_pid", "unverified", "invalid_state"

    live_enabled = parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False)
    be_status = _derive_status(be_ver, bool(be_health), "running", "degraded")
    fe_status = _derive_status(fe_ver, fe_listening, "running", "starting")

    return {
        "exit_code": 0,
        "mode": "live" if live_enabled else "replay",
        "live_mode_enabled": live_enabled,
        "default_backend": config.get("MALBOX_DEFAULT_SANDBOX_BACKEND", "replay"),
        "backend": {
            "status": be_status,
            "pid": backend_state["pid"] if backend_state else None,
            "alive": be_alive,
            "verified_ownership": be_alive,
            "ownership_reason": be_ver.reason if be_ver else "Not running",
            "url": f"http://{host}:{backend_port}",
            "docs_url": f"http://{host}:{backend_port}/docs",
            "health": be_health,
            "log_file": str(runtime_dir / "backend.log"),
        },
        "frontend": {
            "status": fe_status,
            "pid": frontend_state["pid"] if frontend_state else None,
            "alive": fe_alive,
            "verified_ownership": fe_alive,
            "ownership_reason": fe_ver.reason if fe_ver else "Not running",
            "listening": fe_listening,
            "url": f"http://127.0.0.1:{frontend_port}",
            "log_file": str(runtime_dir / "frontend.log"),
        },
    }


def start_services(
    root_dir: Path,
    backend_only: bool = False,
    frontend_only: bool = False,
    wait_seconds: int = 20,
    environ: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    config = resolve_effective_config(root_dir, environ=environ)
    parsed_ports, port_errors = resolve_ports_strict(config)
    if port_errors or parsed_ports is None:
        return {
            "exit_code": 1,
            "status": "invalid_config",
            "error": "; ".join(port_errors),
            "remediation": "Fix invalid port configuration in `.env` or environment variables (valid range: 1-65535).",
        }

    host, backend_port, frontend_port = parsed_ports
    live_enabled = parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False)
    op_token = (config.get("MALBOX_OPERATOR_TOKEN") or "").strip()

    if live_enabled and not op_token:
        return {
            "exit_code": 1,
            "status": "blocked",
            "error": "Refusing to start with unsafe configuration: MALBOX_LIVE_MODE_ENABLED=true without MALBOX_OPERATOR_TOKEN.",
            "remediation": "Set MALBOX_LIVE_MODE_ENABLED=false in .env or configure MALBOX_OPERATOR_TOKEN.",
        }

    runtime_dir = get_runtime_dir(root_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    chmod_safe(runtime_dir, 0o700)

    backend_pid_file = runtime_dir / "backend.pid"
    frontend_pid_file = runtime_dir / "frontend.pid"

    started_now: List[str] = []
    messages: List[str] = []

    want_backend = not frontend_only
    want_frontend = not backend_only

    venv_python = get_venv_python(root_dir)
    if want_backend and not venv_python.exists():
        return {
            "exit_code": 1,
            "status": "error",
            "error": "Python virtual environment `.venv` not found.",
            "remediation": "Run `./malbox doctor` to set up dependencies before starting.",
        }

    vite_bin = root_dir / "frontend" / "node_modules" / ".bin" / "vite"
    if want_frontend and not vite_bin.exists():
        return {
            "exit_code": 1,
            "status": "error",
            "error": "Frontend dependencies not found (`frontend/node_modules/.bin/vite` missing).",
            "remediation": "Run `./malbox doctor` or use `./malbox start --backend-only`.",
        }

    # Inspect existing PID state files safely before starting
    pid_targets = []
    if want_backend:
        pid_targets.append(("backend", backend_pid_file))
    if want_frontend:
        pid_targets.append(("frontend", frontend_pid_file))

    verified_existing: Dict[str, Optional[Dict[str, Any]]] = {}
    for svc_name, pid_f in pid_targets:
        if not pid_f.exists():
            verified_existing[svc_name] = None
            continue
        state = read_pid_state(pid_f)
        ver = verify_managed_process(state, svc_name, root_dir)
        if ver.status == "valid":
            verified_existing[svc_name] = state
        elif ver.status in ("stale", "invalid_state"):
            pid_f.unlink(missing_ok=True)
            messages.append(f"Cleaned {ver.status} PID state `{pid_f.name}`")
            verified_existing[svc_name] = None
        else:
            # Live unverified or reused PID: NEVER overwrite or signal blindly!
            return {
                "exit_code": 1,
                "status": "unverified_pid",
                "error": f"Refusing to overwrite or signal existing `.malbox/{pid_f.name}`: {ver.reason}",
                "remediation": f"Inspect PID {ver.pid} manually and remove `.malbox/{pid_f.name}` if safe.",
            }

    be_pid: Optional[int] = None
    be_state: Optional[Dict[str, Any]] = None
    fe_pid: Optional[int] = None

    child_env = dict(os.environ if environ is None else environ)
    child_env["PYTHONPATH"] = str(root_dir / "backend")
    child_env["MALBOX_HOST"] = host
    child_env["MALBOX_PORT"] = str(backend_port)
    child_env["MALBOX_FRONTEND_PORT"] = str(frontend_port)

    # Start Backend
    if want_backend:
        existing_be = verified_existing.get("backend")
        if existing_be:
            be_pid = existing_be["pid"]
            be_state = existing_be
            messages.append(f"Backend already running (verified PID {be_pid}) at http://{host}:{backend_port}")
        else:
            if is_port_in_use(host, backend_port):
                return {
                    "exit_code": 1,
                    "status": "port_conflict",
                    "error": f"Backend port {backend_port} on {host} is already in use by an external process.",
                    "remediation": f"Stop the external process on port {backend_port} or change `MALBOX_PORT` in `.env`.",
                }

            be_log_path = runtime_dir / "backend.log"
            with _open_restricted_log(be_log_path) as log_fh:
                log_fh.write(f"\n--- malbox backend start at {datetime.now(timezone.utc).isoformat()} ---\n")
                be_proc = subprocess.Popen(
                    [str(venv_python), "-m", "uvicorn", "app.main:app", "--host", host, "--port", str(backend_port)],
                    cwd=str(root_dir),
                    env=child_env,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )

            be_pid = be_proc.pid
            be_state = {
                "service": "backend",
                "pid": be_pid,
                "root_dir": str(root_dir.resolve()),
                "proc_start_time": get_process_start_time(be_pid),
                "host": host,
                "port": backend_port,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            _write_pid_state(backend_pid_file, be_state)
            started_now.append("backend")

            deadline = time.monotonic() + wait_seconds
            healthy = False
            while time.monotonic() < deadline:
                if be_proc.poll() is not None:
                    break
                if _http_health_check(host, backend_port, timeout=1.0):
                    healthy = True
                    break
                time.sleep(0.25)

            if not healthy:
                _terminate_verified_process(be_state, "backend", root_dir, timeout=3.0)
                backend_pid_file.unlink(missing_ok=True)
                return {
                    "exit_code": 1,
                    "status": "error",
                    "error": f"Backend failed to become healthy on http://{host}:{backend_port}/api/v1/health.",
                    "log_tail": _tail_log(be_log_path),
                }
            messages.append(f"Started FastAPI backend (PID {be_pid}) at http://{host}:{backend_port}")

    # Start Frontend
    if want_frontend:
        existing_fe = verified_existing.get("frontend")
        if existing_fe:
            fe_pid = existing_fe["pid"]
            messages.append(f"Frontend already running (verified PID {fe_pid}) at http://127.0.0.1:{frontend_port}")
        else:
            if is_port_in_use("127.0.0.1", frontend_port):
                if "backend" in started_now and be_state:
                    _terminate_verified_process(be_state, "backend", root_dir, timeout=3.0)
                    backend_pid_file.unlink(missing_ok=True)
                return {
                    "exit_code": 1,
                    "status": "port_conflict",
                    "error": f"Frontend port {frontend_port} is already in use by an external process.",
                    "remediation": f"Stop the external process on port {frontend_port} or run `./malbox start --backend-only`.",
                }

            fe_log_path = runtime_dir / "frontend.log"
            with _open_restricted_log(fe_log_path) as log_fh:
                log_fh.write(f"\n--- malbox frontend start at {datetime.now(timezone.utc).isoformat()} ---\n")
                fe_proc = subprocess.Popen(
                    [str(vite_bin), "--host", "127.0.0.1", "--port", str(frontend_port), "--strictPort"],
                    cwd=str(root_dir / "frontend"),
                    env=child_env,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )

            fe_pid = fe_proc.pid
            fe_state = {
                "service": "frontend",
                "pid": fe_pid,
                "root_dir": str(root_dir.resolve()),
                "proc_start_time": get_process_start_time(fe_pid),
                "host": "127.0.0.1",
                "port": frontend_port,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            _write_pid_state(frontend_pid_file, fe_state)
            started_now.append("frontend")

            deadline = time.monotonic() + wait_seconds
            fe_ready = False
            while time.monotonic() < deadline:
                if fe_proc.poll() is not None:
                    break
                if is_port_in_use("127.0.0.1", frontend_port):
                    fe_ready = True
                    break
                time.sleep(0.25)

            if not fe_ready:
                _terminate_verified_process(fe_state, "frontend", root_dir, timeout=3.0)
                frontend_pid_file.unlink(missing_ok=True)
                if "backend" in started_now and be_state:
                    _terminate_verified_process(be_state, "backend", root_dir, timeout=3.0)
                    backend_pid_file.unlink(missing_ok=True)
                return {
                    "exit_code": 1,
                    "status": "error",
                    "error": f"Frontend failed to listen on http://127.0.0.1:{frontend_port}.",
                    "log_tail": _tail_log(fe_log_path),
                }
            messages.append(f"Started Vite UI (PID {fe_pid}) at http://127.0.0.1:{frontend_port}")

    return {
        "exit_code": 0,
        "status": "running",
        "mode": "live" if live_enabled else "replay",
        "messages": messages,
        "backend": {"pid": be_pid, "url": f"http://{host}:{backend_port}", "docs_url": f"http://{host}:{backend_port}/docs"} if want_backend else None,
        "frontend": {"pid": fe_pid, "url": f"http://127.0.0.1:{frontend_port}"} if want_frontend else None,
    }


def stop_services(
    root_dir: Path,
    timeout: float = 8.0,
    *,
    verify_fn: Callable[..., ProcessVerification] = verify_managed_process,
    kill_fn: Callable[[int, int], None] = os.kill,
    killpg_fn: Callable[[int, int], None] = os.killpg,
) -> Dict[str, Any]:
    runtime_dir = get_runtime_dir(root_dir)
    results: Dict[str, str] = {}
    details: Dict[str, str] = {}
    errors: List[str] = []

    targets = (
        ("frontend", runtime_dir / "frontend.pid"),
        ("backend", runtime_dir / "backend.pid"),
    )

    safe_outcomes = {"not_running", "already_stopped", "cleaned_invalid_pid", "stopped_gracefully", "stopped_force"}

    for name, pid_file in targets:
        if not pid_file.exists():
            results[name] = "not_running"
            continue

        state = read_pid_state(pid_file)
        if not state:
            pid_file.unlink(missing_ok=True)
            results[name] = "cleaned_invalid_pid"
            details[name] = "Removed corrupt or unparseable PID file."
            continue

        outcome, msg = _terminate_verified_process(
            state,
            name,
            root_dir,
            timeout=timeout,
            verify_fn=verify_fn,
            kill_fn=kill_fn,
            killpg_fn=killpg_fn,
        )
        results[name] = outcome
        details[name] = msg

        if outcome in safe_outcomes:
            pid_file.unlink(missing_ok=True)
        else:
            errors.append(msg)

    has_failure = bool(errors)
    stopped_any = any(v in ("stopped_gracefully", "stopped_force") for v in results.values())
    status = ("partial_failure" if stopped_any else "failed") if has_failure else "stopped"

    return {
        "exit_code": 1 if has_failure else 0,
        "status": status,
        "services": results,
        "details": details,
        "errors": errors,
    }
