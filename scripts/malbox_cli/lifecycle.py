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
from typing import Any, Callable, Dict, List, Optional

from .models import (
    get_runtime_dir,
    get_venv_python,
    is_pid_running,
    is_port_in_use,
    parse_bool,
    read_pid_state,
    resolve_effective_config,
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
    pid_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _terminate_managed_process(pid: int, pgid: Optional[int], expected_subs: List[str], timeout: float = 8.0) -> str:
    if not is_pid_running(pid, expected_subs):
        return "already_stopped"

    own_pgrp = os.getpgrp()
    use_pg = bool(pgid and pgid > 0 and pgid != own_pgrp)

    def _send(sig: int) -> None:
        try:
            if use_pg:
                os.killpg(pgid, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                os.kill(pid, sig)
            except OSError:
                pass

    _send(signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_pid_running(pid, expected_subs):
            return "stopped_gracefully"
        time.sleep(0.15)

    _send(signal.SIGKILL)
    kill_deadline = time.monotonic() + 2.0
    while time.monotonic() < kill_deadline:
        if not is_pid_running(pid, expected_subs):
            return "stopped_force"
        time.sleep(0.1)

    return "kill_failed"


def _parse_ports(config: Dict[str, str]) -> tuple[str, int, int]:
    host = (config.get("MALBOX_HOST") or "127.0.0.1").strip()
    try:
        backend_port = int(config.get("MALBOX_PORT", "8000"))
    except ValueError:
        backend_port = 8000
    try:
        frontend_port = int(config.get("MALBOX_FRONTEND_PORT", "5173"))
    except ValueError:
        frontend_port = 5173
    return host, backend_port, frontend_port


def get_status(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
    health_fn: Callable[[str, int], Optional[Dict[str, Any]]] = _http_health_check,
    port_fn: Callable[[str, int], bool] = is_port_in_use,
) -> Dict[str, Any]:
    config = resolve_effective_config(root_dir, environ=environ)
    host, backend_port, frontend_port = _parse_ports(config)
    runtime_dir = get_runtime_dir(root_dir)

    backend_pid_file = runtime_dir / "backend.pid"
    frontend_pid_file = runtime_dir / "frontend.pid"

    backend_state = read_pid_state(backend_pid_file)
    frontend_state = read_pid_state(frontend_pid_file)

    be_pid = backend_state["pid"] if backend_state else None
    be_alive = bool(be_pid and is_pid_running(be_pid, ["uvicorn", "python"]))
    be_health = health_fn(host, backend_port) if be_alive or port_fn(host, backend_port) else None

    fe_pid = frontend_state["pid"] if frontend_state else None
    fe_alive = bool(fe_pid and is_pid_running(fe_pid, ["vite", "node", "npm"]))
    fe_listening = port_fn("127.0.0.1", frontend_port)

    live_enabled = parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False)
    be_status = "running" if (be_alive and be_health) else ("degraded" if be_alive else ("stale_pid" if be_pid else "stopped"))
    fe_status = "running" if (fe_alive and fe_listening) else ("starting" if fe_alive else ("stale_pid" if fe_pid else "stopped"))

    return {
        "exit_code": 0,
        "mode": "live" if live_enabled else "replay",
        "live_mode_enabled": live_enabled,
        "default_backend": config.get("MALBOX_DEFAULT_SANDBOX_BACKEND", "replay"),
        "backend": {
            "status": be_status,
            "pid": be_pid,
            "alive": be_alive,
            "url": f"http://{host}:{backend_port}",
            "docs_url": f"http://{host}:{backend_port}/docs",
            "health": be_health,
            "log_file": str(runtime_dir / "backend.log"),
        },
        "frontend": {
            "status": fe_status,
            "pid": fe_pid,
            "alive": fe_alive,
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
    host, backend_port, frontend_port = _parse_ports(config)
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
    backend_pid_file = runtime_dir / "backend.pid"
    frontend_pid_file = runtime_dir / "frontend.pid"

    started_now: List[str] = []
    messages: List[str] = []

    want_backend = not frontend_only
    want_frontend = not backend_only

    # Verify prerequisites before launching
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

    # Clean stale PIDs safely
    for pid_f, subs in ((backend_pid_file, ["uvicorn", "python"]), (frontend_pid_file, ["vite", "node", "npm"])):
        st = read_pid_state(pid_f)
        if st and not is_pid_running(st["pid"], subs):
            pid_f.unlink(missing_ok=True)
            messages.append(f"Cleaned stale PID state `{pid_f.name}`")

    be_pid: Optional[int] = None
    fe_pid: Optional[int] = None

    # Start Backend
    if want_backend:
        existing_be = read_pid_state(backend_pid_file)
        if existing_be and is_pid_running(existing_be["pid"], ["uvicorn", "python"]):
            be_pid = existing_be["pid"]
            messages.append(f"Backend already running (PID {be_pid}) at http://{host}:{backend_port}")
        else:
            if is_port_in_use(host, backend_port):
                return {
                    "exit_code": 1,
                    "status": "port_conflict",
                    "error": f"Backend port {backend_port} on {host} is already in use by an external process.",
                    "remediation": f"Stop the process using port {backend_port} or set MALBOX_PORT in .env.",
                }

            be_log_path = runtime_dir / "backend.log"
            be_env = dict(os.environ if environ is None else environ)
            be_env["PYTHONPATH"] = str(root_dir / "backend")

            with be_log_path.open("a", encoding="utf-8") as log_fh:
                log_fh.write(f"\n--- malbox backend start at {datetime.now(timezone.utc).isoformat()} ---\n")
                be_proc = subprocess.Popen(
                    [str(venv_python), "-m", "uvicorn", "app.main:app", "--host", host, "--port", str(backend_port)],
                    cwd=str(root_dir),
                    env=be_env,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )

            be_pid = be_proc.pid
            _write_pid_state(backend_pid_file, {
                "service": "backend",
                "pid": be_pid,
                "pgid": be_pid,
                "host": host,
                "port": backend_port,
                "started_at": datetime.now(timezone.utc).isoformat(),
            })
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
                _terminate_managed_process(be_pid, be_pid, ["uvicorn", "python"], timeout=3.0)
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
        existing_fe = read_pid_state(frontend_pid_file)
        if existing_fe and is_pid_running(existing_fe["pid"], ["vite", "node", "npm"]):
            fe_pid = existing_fe["pid"]
            messages.append(f"Frontend already running (PID {fe_pid}) at http://127.0.0.1:{frontend_port}")
        else:
            if is_port_in_use("127.0.0.1", frontend_port):
                if "backend" in started_now and be_pid:
                    _terminate_managed_process(be_pid, be_pid, ["uvicorn", "python"])
                    backend_pid_file.unlink(missing_ok=True)
                return {
                    "exit_code": 1,
                    "status": "port_conflict",
                    "error": f"Frontend port {frontend_port} is already in use by an external process.",
                    "remediation": f"Stop the process using port {frontend_port} or run `./malbox start --backend-only`.",
                }

            fe_log_path = runtime_dir / "frontend.log"
            with fe_log_path.open("a", encoding="utf-8") as log_fh:
                log_fh.write(f"\n--- malbox frontend start at {datetime.now(timezone.utc).isoformat()} ---\n")
                fe_proc = subprocess.Popen(
                    [str(vite_bin), "--host", "127.0.0.1", "--port", str(frontend_port), "--strictPort"],
                    cwd=str(root_dir / "frontend"),
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )

            fe_pid = fe_proc.pid
            _write_pid_state(frontend_pid_file, {
                "service": "frontend",
                "pid": fe_pid,
                "pgid": fe_pid,
                "host": "127.0.0.1",
                "port": frontend_port,
                "started_at": datetime.now(timezone.utc).isoformat(),
            })
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
                _terminate_managed_process(fe_pid, fe_pid, ["vite", "node", "npm"], timeout=3.0)
                frontend_pid_file.unlink(missing_ok=True)
                if "backend" in started_now and be_pid:
                    _terminate_managed_process(be_pid, be_pid, ["uvicorn", "python"], timeout=3.0)
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


def stop_services(root_dir: Path, timeout: float = 8.0) -> Dict[str, Any]:
    runtime_dir = get_runtime_dir(root_dir)
    results: Dict[str, str] = {}

    targets = (
        ("frontend", runtime_dir / "frontend.pid", ["vite", "node", "npm"]),
        ("backend", runtime_dir / "backend.pid", ["uvicorn", "python"]),
    )

    for name, pid_file, subs in targets:
        if not pid_file.exists():
            results[name] = "not_running"
            continue

        state = read_pid_state(pid_file)
        if not state:
            pid_file.unlink(missing_ok=True)
            results[name] = "cleaned_invalid_pid"
            continue

        pid = state["pid"]
        pgid = state.get("pgid")
        outcome = _terminate_managed_process(pid, pgid, subs, timeout=timeout)
        pid_file.unlink(missing_ok=True)
        results[name] = outcome

    return {
        "exit_code": 0,
        "status": "stopped",
        "services": results,
    }
