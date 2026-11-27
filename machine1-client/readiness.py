#!/usr/bin/env python3
"""MalBox Machine 1 (Kali Linux Client) Environment Readiness Checker.

Exit codes (standardized across all MalBox readiness checkers):
  0: Mandatory local checks passed (LOCAL_READINESS is READY or LIMITED).
  1: LOCAL_READINESS is NOT_READY (missing/failing mandatory check or invalid config)
     in either setup or check-only mode, or setup_report.json could not be written.
  2: Invalid command-line arguments.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_REPORT_PATH = BASE_DIR / "setup_report.json"
MIN_PYTHON = (3, 10)

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_MISSING = "MISSING"
STATUS_OPTIONAL = "OPTIONAL"
STATUS_PENDING = "PENDING"
STATUS_SKIPPED = "SKIPPED"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_bounded(cmd: list[str], timeout: float = 10.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "timed_out": False,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True, "error": f"Timed out after {timeout}s"}
    except OSError as exc:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": False, "error": str(exc)}


def make_check(
    name: str,
    category: str,
    required: bool,
    status: str,
    diagnostic_message: str,
    recommended_action: str = "",
    detected_version: str | None = None,
    configured_path: str | None = None,
    resolved_path: str | None = None,
    installed: bool = False,
    runtime_verified: bool = False,
    feature_verified: bool = False,
) -> dict[str, Any]:
    if feature_verified:
        vstate = "feature_verified"
    elif runtime_verified:
        vstate = "runtime_verified"
    elif detected_version:
        vstate = "version_detected"
    elif installed:
        vstate = "installed_only"
    else:
        vstate = "not_verified"
    return {
        "name": name,
        "category": category,
        "required": required,
        "status": status,
        "detected_version": detected_version,
        "configured_path": configured_path,
        "resolved_path": resolved_path,
        "installed": installed,
        "runtime_verified": runtime_verified,
        "feature_verified": feature_verified,
        "verification_state": vstate,
        "diagnostic_message": diagnostic_message,
        "recommended_action": recommended_action,
    }


def _validate_str(cfg: dict[str, Any], key: str, errors: list[str], allow_empty: bool = False) -> str | None:
    if key not in cfg:
        errors.append(f"Missing key '{key}'")
        return None
    val = cfg[key]
    if not isinstance(val, str):
        errors.append(f"Key '{key}' must be a string (got {type(val).__name__})")
        return None
    if "\x00" in val:
        errors.append(f"Key '{key}' contains embedded null byte")
        return None
    if not allow_empty and not val.strip():
        errors.append(f"Key '{key}' must not be empty")
        return None
    return val.strip()


def _validate_int(
    cfg: dict[str, Any],
    key: str,
    errors: list[str],
    min_val: int,
    max_val: int | None = None,
    required: bool = True,
) -> int | None:
    if key not in cfg:
        if required:
            errors.append(f"Missing key '{key}'")
        return None
    val = cfg[key]
    if isinstance(val, bool) or not isinstance(val, int):
        errors.append(f"Key '{key}' must be an integer (got {type(val).__name__})")
        return None
    if val < min_val or (max_val is not None and val > max_val):
        bound = f"{min_val}..{max_val}" if max_val is not None else f">= {min_val}"
        errors.append(f"Key '{key}' out of range ({bound}): {val}")
        return None
    return val


def _validate_number(
    cfg: dict[str, Any],
    key: str,
    errors: list[str],
    min_val: float,
    required: bool = True,
) -> float | None:
    if key not in cfg:
        if required:
            errors.append(f"Missing key '{key}'")
        return None
    val = cfg[key]
    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(float(val)):
        errors.append(f"Key '{key}' must be a finite number (got {type(val).__name__})")
        return None
    fval = float(val)
    if fval < min_val:
        errors.append(f"Key '{key}' must be >= {min_val} (got {fval})")
        return None
    return fval


def _validate_bool(cfg: dict[str, Any], key: str, errors: list[str], required: bool = False) -> bool | None:
    if key not in cfg:
        if required:
            errors.append(f"Missing key '{key}'")
        return None
    if not isinstance(cfg[key], bool):
        errors.append(f"Key '{key}' must be a boolean (got {type(cfg[key]).__name__})")
        return None
    return cfg[key]


def load_and_validate_config(config_path: Path) -> tuple[dict[str, Any], list[str], str]:
    """Validate config.json without crashing; always returns safe fallback dict for downstream probes."""
    defaults: dict[str, Any] = {
        "gateway_host": "10.10.10.20",
        "gateway_port": 8000,
        "evidence_dir": "./evidence",
        "connect_timeout_seconds": 5.0,
        "request_timeout_seconds": 30.0,
        "poll_interval_seconds": 3.0,
        "analysis_timeout_seconds": 1800.0,
        "chunk_size_bytes": 65536,
        "extract_archive": True,
        "keep_zip": False,
        "max_evidence_archive_mb": 512,
        "max_extracted_size_mb": 1024,
        "max_single_file_mb": 256,
        "max_archive_entries": 5000,
        "fetch_gateway_network_diagnostics": False,
    }
    errors: list[str] = []
    if not config_path.is_file():
        errors.append(f"Missing configuration file: {config_path}")
        return defaults, errors, "missing"

    try:
        raw_text = config_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        errors.append(f"Failed reading {config_path.name}: {exc}")
        return defaults, errors, "read_error"

    try:
        parsed = json.loads(raw_text)
    except ValueError as exc:
        errors.append(f"Invalid JSON in {config_path.name}: {exc}")
        return defaults, errors, "invalid_json"

    if not isinstance(parsed, dict):
        errors.append(f"Root of {config_path.name} must be a JSON object (got {type(parsed).__name__})")
        return defaults, errors, "invalid_type"

    gw_host = _validate_str(parsed, "gateway_host", errors)
    gw_port = _validate_int(parsed, "gateway_port", errors, min_val=1, max_val=65535, required=True)
    ev_dir = _validate_str(parsed, "evidence_dir", errors)
    conn_t = _validate_number(parsed, "connect_timeout_seconds", errors, min_val=0.1, required=True)
    req_t = _validate_number(parsed, "request_timeout_seconds", errors, min_val=0.1, required=False)
    poll_i = _validate_number(parsed, "poll_interval_seconds", errors, min_val=0.1, required=False)
    ana_t = _validate_number(parsed, "analysis_timeout_seconds", errors, min_val=1.0, required=False)
    chunk_sz = _validate_int(parsed, "chunk_size_bytes", errors, min_val=1024, required=False)
    max_arch = _validate_int(parsed, "max_evidence_archive_mb", errors, min_val=1, required=False)
    max_ext = _validate_int(parsed, "max_extracted_size_mb", errors, min_val=1, required=False)
    max_sf = _validate_int(parsed, "max_single_file_mb", errors, min_val=1, required=False)
    max_ent = _validate_int(parsed, "max_archive_entries", errors, min_val=10, required=False)
    ext_arch = _validate_bool(parsed, "extract_archive", errors, required=False)
    keep_z = _validate_bool(parsed, "keep_zip", errors, required=False)
    fetch_nd = _validate_bool(parsed, "fetch_gateway_network_diagnostics", errors, required=False)

    safe_cfg = dict(defaults)
    updates: dict[str, Any] = {
        "gateway_host": gw_host,
        "gateway_port": gw_port,
        "evidence_dir": ev_dir,
        "connect_timeout_seconds": conn_t,
        "request_timeout_seconds": req_t,
        "poll_interval_seconds": poll_i,
        "analysis_timeout_seconds": ana_t,
        "chunk_size_bytes": chunk_sz,
        "max_evidence_archive_mb": max_arch,
        "max_extracted_size_mb": max_ext,
        "max_single_file_mb": max_sf,
        "max_archive_entries": max_ent,
        "extract_archive": ext_arch,
        "keep_zip": keep_z,
        "fetch_gateway_network_diagnostics": fetch_nd,
    }
    for k, v in updates.items():
        if v is not None:
            safe_cfg[k] = v

    return safe_cfg, errors, "valid" if not errors else "validation_error"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MalBox Machine 1 Readiness Checker")
    parser.add_argument("--mode", choices=("setup", "check-only"), default="check-only")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    config_path = Path(args.config).resolve()
    report_path = Path(args.report).resolve()
    venv_dir = BASE_DIR / ".venv"
    venv_python = venv_dir / "bin" / "python"
    venv_pip = venv_dir / "bin" / "pip"

    checks: list[dict[str, Any]] = []
    manual_actions: list[str] = []

    # 1. OS check
    is_linux = sys.platform.startswith("linux")
    os_ver = f"{platform.system()} {platform.release()} ({platform.machine()})"
    checks.append(
        make_check(
            name="linux_os",
            category="os",
            required=True,
            status=STATUS_PASS if is_linux else STATUS_FAIL,
            detected_version=os_ver,
            installed=True,
            runtime_verified=is_linux,
            feature_verified=is_linux,
            diagnostic_message=f"Detected OS: {os_ver}",
            recommended_action="" if is_linux else "Run Machine 1 Client on Kali Linux or Debian-based Linux.",
        )
    )

    # 2. Python runtime (>= 3.10 standardized across MalBox)
    py_ver = platform.python_version()
    py_ok = sys.version_info >= MIN_PYTHON
    checks.append(
        make_check(
            name="python_runtime",
            category="runtime",
            required=True,
            status=STATUS_PASS if py_ok else STATUS_FAIL,
            detected_version=py_ver,
            resolved_path=sys.executable,
            installed=True,
            runtime_verified=py_ok,
            feature_verified=py_ok,
            diagnostic_message=f"Python {py_ver} ({platform.machine()})",
            recommended_action="" if py_ok else "Install Python 3.10+ and recreate .venv.",
        )
    )

    # 3. Virtual environment (verify binary runs cleanly AND meets >= 3.10)
    venv_py_ok = False
    if venv_python.is_file():
        v_probe = run_bounded(
            [
                str(venv_python),
                "-c",
                "import platform, sys; print(platform.python_version()); sys.exit(0 if sys.version_info >= (3, 10) else 3)",
            ],
            timeout=10.0,
        )
        v_ver = v_probe["stdout"].splitlines()[0].strip() if v_probe["stdout"] else None
        venv_py_ok = v_probe["returncode"] == 0
        if v_probe["returncode"] == 3:
            diag = f".venv Python {v_ver} is below required minimum 3.10."
        elif venv_py_ok:
            diag = f"Virtual environment Python {v_ver} executes cleanly."
        else:
            v_err_detail = v_probe["stderr"] or v_probe["error"] or f"exit {v_probe['returncode']}"
            diag = f"venv probe failed: {v_err_detail}"
        checks.append(
            make_check(
                name="python_venv",
                category="runtime",
                required=True,
                status=STATUS_PASS if venv_py_ok else STATUS_FAIL,
                detected_version=v_ver,
                configured_path=str(venv_dir),
                resolved_path=str(venv_python),
                installed=True,
                runtime_verified=venv_py_ok,
                diagnostic_message=diag,
                recommended_action="" if venv_py_ok else "Run bash setup.sh to recreate .venv with Python 3.10+.",
            )
        )
    else:
        checks.append(
            make_check(
                name="python_venv",
                category="runtime",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(venv_dir),
                diagnostic_message="Python virtual environment .venv not found.",
                recommended_action="Run bash setup.sh (or bash install.sh) while online.",
            )
        )

    # 4. pip version
    pip_ver = None
    if venv_pip.is_file():
        p_probe = run_bounded([str(venv_pip), "--version"], timeout=10.0)
        p_ok = p_probe["returncode"] == 0
        pip_ver = p_probe["stdout"].splitlines()[0] if p_probe["stdout"] else None
        checks.append(
            make_check(
                name="pip_runtime",
                category="runtime",
                required=True,
                status=STATUS_PASS if p_ok else STATUS_FAIL,
                detected_version=pip_ver,
                resolved_path=str(venv_pip),
                installed=True,
                runtime_verified=p_ok,
                diagnostic_message=pip_ver or f"pip probe failed: {p_probe['stderr'] or p_probe['error']}",
                recommended_action="" if p_ok else "Recreate .venv with python3-venv installed.",
            )
        )
    else:
        checks.append(
            make_check(
                name="pip_runtime",
                category="runtime",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(venv_pip),
                diagnostic_message="pip inside .venv not found.",
                recommended_action="Run bash setup.sh.",
            )
        )

    # 5. Python packages & dependency consistency inside .venv
    pkg_versions: dict[str, str] = {}
    req_ver = None
    pip_check_ok = False
    pip_check_msg = ""
    if venv_py_ok:
        req_probe = run_bounded(
            [str(venv_python), "-c", "import requests; print(requests.__version__)"],
            timeout=10.0,
        )
        req_ver = req_probe["stdout"].strip() if req_probe["returncode"] == 0 else None
        if req_ver:
            pkg_versions["requests"] = req_ver
        pc = run_bounded([str(venv_python), "-m", "pip", "check"], timeout=15.0)
        pip_check_ok = pc["returncode"] == 0
        pip_check_msg = pc["stdout"] or pc["stderr"] or pc["error"] or ""
    else:
        pip_check_msg = ".venv missing or unsupported Python version"

    pkg_ok = bool(req_ver) and pip_check_ok
    checks.append(
        make_check(
            name="python_packages",
            category="runtime",
            required=True,
            status=STATUS_PASS if pkg_ok else (STATUS_MISSING if not venv_python.is_file() or not req_ver else STATUS_FAIL),
            detected_version=f"requests=={req_ver}" if req_ver else None,
            installed=bool(req_ver),
            runtime_verified=bool(req_ver),
            feature_verified=pkg_ok,
            diagnostic_message=(
                f"requests=={req_ver}; pip check: {pip_check_msg or 'OK'}"
                if req_ver
                else f"requests package not verified in .venv ({pip_check_msg})."
            ),
            recommended_action="" if pkg_ok else "Run bash setup.sh to install requirements.txt.",
        )
    )

    # 6. Strict, crash-safe config.json validation
    cfg, cfg_errors, cfg_state = load_and_validate_config(config_path)
    checks.append(
        make_check(
            name="config_json",
            category="config",
            required=True,
            status=STATUS_PASS if not cfg_errors else (STATUS_MISSING if cfg_state == "missing" else STATUS_FAIL),
            configured_path=str(config_path),
            resolved_path=str(config_path) if config_path.is_file() else None,
            installed=config_path.is_file(),
            runtime_verified=not cfg_errors,
            feature_verified=not cfg_errors,
            diagnostic_message=(
                f"Gateway target {cfg['gateway_host']}:{cfg['gateway_port']}"
                if not cfg_errors
                else "; ".join(cfg_errors)
            ),
            recommended_action="" if not cfg_errors else "Fix machine1-client/config.json.",
        )
    )

    # 7. doctor command & doctor --help
    doctor_path = shutil.which("doctor")
    if not doctor_path:
        for cand in (Path.home() / ".local" / "bin" / "doctor", Path("/usr/local/bin/doctor")):
            if cand.is_file() and os.access(cand, os.X_OK):
                doctor_path = str(cand)
                break

    if doctor_path:
        help_res = run_bounded([doctor_path, "--help"], timeout=10.0)
        help_ok = help_res["returncode"] == 0 and "sample" in help_res["stdout"].lower()
        in_path = shutil.which("doctor") is not None
        diag = f"doctor --help exited 0 ({doctor_path})."
        if not in_path:
            diag += " Note: ~/.local/bin is not currently in PATH."
            manual_actions.append("Add ~/.local/bin to PATH or symlink /usr/local/bin/doctor.")
        checks.append(
            make_check(
                name="doctor_command",
                category="command",
                required=True,
                status=STATUS_PASS if help_ok else STATUS_FAIL,
                configured_path="doctor",
                resolved_path=doctor_path,
                installed=True,
                runtime_verified=help_ok,
                feature_verified=help_ok,
                diagnostic_message=diag if help_ok else f"doctor --help failed: {help_res['stderr'] or help_res['error']}",
                recommended_action="" if help_ok else "Re-run bash setup.sh --force.",
            )
        )
    else:
        checks.append(
            make_check(
                name="doctor_command",
                category="command",
                required=True,
                status=STATUS_MISSING,
                configured_path="doctor",
                diagnostic_message="doctor launcher command not found.",
                recommended_action="Run bash setup.sh (or bash install.sh).",
            )
        )

    # 8. Evidence directory permissions (non-destructive probe cleanup in finally)
    raw_ev = str(cfg["evidence_dir"])
    ev_ok = False
    ev_exists = False
    ev_dir_resolved: Path | None = None
    try:
        ev_candidate = Path(raw_ev)
        ev_dir = ev_candidate if ev_candidate.is_absolute() else (config_path.parent / ev_candidate).resolve()
        ev_exists = ev_dir.exists()
        if ev_dir.is_dir():
            ev_dir_resolved = ev_dir
            probe_file = ev_dir / f".readiness_probe_{os.getpid()}"
            try:
                probe_file.write_text("ok", encoding="utf-8")
                _ = probe_file.read_text(encoding="utf-8")
                ev_ok = True
                ev_msg = f"Writable evidence directory: {ev_dir}"
            except OSError as exc:
                ev_msg = f"Evidence directory not writable: {exc}"
            finally:
                try:
                    if probe_file.exists():
                        probe_file.unlink()
                except OSError:
                    pass
        elif ev_exists:
            ev_msg = f"Configured evidence_dir is not a directory: {ev_dir}"
        else:
            ev_msg = f"Evidence directory missing: {ev_dir}"
    except (ValueError, OSError) as exc:
        ev_msg = f"Invalid evidence_dir path '{raw_ev}': {exc}"

    checks.append(
        make_check(
            name="evidence_directory",
            category="filesystem",
            required=True,
            status=STATUS_PASS if ev_ok else (STATUS_MISSING if not ev_exists else STATUS_FAIL),
            configured_path=raw_ev,
            resolved_path=str(ev_dir_resolved) if ev_dir_resolved else None,
            installed=bool(ev_dir_resolved),
            runtime_verified=ev_ok,
            feature_verified=ev_ok,
            diagnostic_message=ev_msg,
            recommended_action="" if ev_ok else "Run bash setup.sh or check directory permissions/path.",
        )
    )

    # 9. Disk space
    disk_target = ev_dir_resolved if ev_dir_resolved else BASE_DIR
    try:
        free_mb = shutil.disk_usage(disk_target).free // (1024 * 1024)
        disk_ok = free_mb >= 512
        disk_status = STATUS_PASS if disk_ok else STATUS_FAIL
        disk_ver = f"{free_mb} MB free"
        disk_msg = f"{free_mb} MB free disk space on client partition."
    except OSError as exc:
        disk_ok = False
        disk_status = STATUS_FAIL
        disk_ver = None
        disk_msg = f"Failed checking disk space on {disk_target}: {exc}"

    checks.append(
        make_check(
            name="disk_space",
            category="filesystem",
            required=True,
            status=disk_status,
            detected_version=disk_ver,
            resolved_path=str(disk_target),
            installed=True,
            runtime_verified=disk_ver is not None,
            feature_verified=disk_ok,
            diagnostic_message=disk_msg,
            recommended_action="" if disk_ok else "Free at least 512 MB for evidence downloads.",
        )
    )

    # 10. Network / Peer checks (distinguishing local service, peer connectivity, application state, snapshot state)
    gw_host = str(cfg["gateway_host"])
    gw_port = int(cfg["gateway_port"])
    gw_url = f"http://{gw_host}:{gw_port}"
    timeout_s = float(cfg["connect_timeout_seconds"])

    # Advisory check for default Internal Network 1 IP (10.10.10.10) when pointing to 10.10.10.20
    if gw_host == "10.10.10.20":
        nic_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            nic_sock.bind(("10.10.10.10", 0))
            nic1_ok = True
        except OSError:
            nic1_ok = False
        finally:
            nic_sock.close()
        checks.append(
            make_check(
                name="internal_network1_ip",
                category="peer",
                required=False,
                status=STATUS_PASS if nic1_ok else STATUS_PENDING,
                detected_version="10.10.10.10" if nic1_ok else None,
                diagnostic_message=(
                    "Internal Network 1 IP 10.10.10.10 is assigned locally."
                    if nic1_ok
                    else "Default Client static IP 10.10.10.10 not assigned yet (pending manual network setup)."
                ),
                recommended_action="" if nic1_ok else "Assign 10.10.10.10/24 on Internal Network 1 (see docs/network-setup.md).",
            )
        )

    def _http_get_json(url: str) -> tuple[int, dict[str, Any], str | None]:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8-sig", errors="replace")
                try:
                    data = json.loads(raw)
                    return resp.status, data if isinstance(data, dict) else {}, None if isinstance(data, dict) else "JSON root not object"
                except ValueError:
                    return resp.status, {}, "non-JSON response"
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8-sig", errors="replace") if exc.fp else ""
            try:
                data = json.loads(raw)
                return exc.code, data if isinstance(data, dict) else {}, None
            except ValueError:
                return exc.code, {}, f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            return 0, {}, str(exc)

    gw_health_status = STATUS_PENDING
    gw_status_val = STATUS_PENDING
    sandbox_app_state = "UNKNOWN"
    h_code, h_data, h_err = _http_get_json(f"{gw_url}/health")
    if h_code == 0:
        gw_health_status = STATUS_PENDING
        checks.append(
            make_check(
                name="gateway_health_peer",
                category="peer",
                required=False,
                status=STATUS_PENDING,
                configured_path=f"{gw_url}/health",
                diagnostic_message=f"Gateway not reachable yet ({h_err}).",
                recommended_action="Configure Internal Network 1 (10.10.10.10 <-> 10.10.10.20) and start gateway.py on Machine 2.",
            )
        )
    elif h_code == 200 and h_data.get("status") == "ok" and h_data.get("service") == "malbox-gateway":
        gw_health_status = STATUS_PASS
        checks.append(
            make_check(
                name="gateway_health_peer",
                category="peer",
                required=False,
                status=STATUS_PASS,
                configured_path=f"{gw_url}/health",
                resolved_path=gw_url,
                runtime_verified=True,
                diagnostic_message="Gateway HTTP /health endpoint responded with valid MalBox Gateway identity (full submission not tested).",
            )
        )
    else:
        gw_health_status = STATUS_FAIL
        checks.append(
            make_check(
                name="gateway_health_peer",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{gw_url}/health",
                diagnostic_message=f"Unexpected service response on {gw_url}/health (HTTP {h_code}: {h_err or h_data}).",
                recommended_action="Verify Machine 2 runs MalBox gateway.py on port 8000.",
            )
        )

    if gw_health_status == STATUS_PASS:
        st_code, st_data, st_err = _http_get_json(f"{gw_url}/status")
        sb_block = st_data.get("sandbox")
        sb_state = str(sb_block.get("state", "UNAVAILABLE")).upper() if isinstance(sb_block, dict) else "UNAVAILABLE"
        if st_code == 200 and st_data.get("gateway") == "ok" and sb_state in (
            "READY",
            "ANALYZING",
            "RETURNING_EVIDENCE",
            "RESTORE_REQUIRED",
        ):
            gw_status_val = STATUS_PASS
            sandbox_app_state = sb_state
            checks.append(
                make_check(
                    name="gateway_sandbox_relay_status",
                    category="peer",
                    required=False,
                    status=STATUS_PASS,
                    detected_version=f"sandbox_state={sb_state}",
                    configured_path=f"{gw_url}/status",
                    runtime_verified=True,
                    diagnostic_message=(
                        f"HTTP control plane reachable through Gateway -> Sandbox (application state: {sb_state}; "
                        "end-to-end upload/analysis/download flow verified only during controlled test)."
                    ),
                    recommended_action=(
                        "Restore Windows 11 CLEAN snapshot on Machine 3."
                        if sb_state == "RESTORE_REQUIRED"
                        else ""
                    ),
                )
            )
        elif st_code == 200 and st_data.get("gateway") == "ok":
            gw_status_val = STATUS_PENDING
            sandbox_app_state = "UNREACHABLE"
            checks.append(
                make_check(
                    name="gateway_sandbox_relay_status",
                    category="peer",
                    required=False,
                    status=STATUS_PENDING,
                    configured_path=f"{gw_url}/status",
                    diagnostic_message="Gateway connected, but Machine 3 Sandbox is not reachable yet.",
                    recommended_action="Configure Internal Network 2 and start sandbox.py on Machine 3.",
                )
            )
        else:
            gw_status_val = STATUS_FAIL
            checks.append(
                make_check(
                    name="gateway_sandbox_relay_status",
                    category="peer",
                    required=False,
                    status=STATUS_FAIL,
                    configured_path=f"{gw_url}/status",
                    diagnostic_message=f"Invalid Gateway /status payload (HTTP {st_code}: {st_err}).",
                    recommended_action="Check Machine 2 gateway.py logs.",
                )
            )

    # Separated Readiness Semantics
    required_bad = [c for c in checks if c["required"] and c["status"] in (STATUS_FAIL, STATUS_MISSING)]
    optional_degraded = [
        c
        for c in checks
        if not c["required"]
        and c["category"] != "peer"
        and c["status"] in (STATUS_FAIL, STATUS_MISSING, STATUS_OPTIONAL, STATUS_PENDING)
    ]
    if required_bad:
        local_readiness = "NOT_READY"
    elif optional_degraded:
        local_readiness = "LIMITED"
    else:
        local_readiness = "READY"

    local_service_state = "NOT_APPLICABLE"

    if gw_health_status == STATUS_FAIL or gw_status_val == STATUS_FAIL:
        peer_connectivity = "PEER_ERROR"
        network_readiness = "NOT_READY"
    elif gw_health_status == STATUS_PASS and gw_status_val == STATUS_PASS:
        peer_connectivity = "GATEWAY_AND_SANDBOX_HTTP_REACHABLE"
        if sandbox_app_state == "READY":
            network_readiness = "CONTROL_PATH_READY"
        else:
            network_readiness = "CONTROL_PATH_SANDBOX_NOT_READY"
    elif gw_health_status == STATUS_PASS:
        peer_connectivity = "GATEWAY_ONLY_SANDBOX_UNREACHABLE"
        network_readiness = "PENDING"
    else:
        peer_connectivity = "GATEWAY_UNREACHABLE"
        network_readiness = "PENDING"

    snapshot_state = "NOT_APPLICABLE"

    missing_required = [c["name"] for c in checks if c["required"] and c["status"] in (STATUS_MISSING, STATUS_FAIL)]
    missing_optional = [c["name"] for c in checks if not c["required"] and c["status"] in (STATUS_MISSING, STATUS_OPTIONAL)]
    for c in checks:
        if c["recommended_action"] and c["status"] != STATUS_PASS:
            manual_actions.append(f"[{c['name']}] {c['recommended_action']}")

    report = {
        "schema_version": "1.1",
        "machine": "machine1-client",
        "mode": args.mode,
        "generated_at": utc_now_iso(),
        "local_readiness": local_readiness,
        "local_service_state": local_service_state,
        "network_readiness": network_readiness,
        "peer_connectivity": peer_connectivity,
        "application_state": sandbox_app_state,
        "snapshot_state": snapshot_state,
        "config_validation_state": cfg_state,
        "environment": {
            "os": os_ver,
            "python_version": py_ver,
            "pip_version": pip_ver,
            "python_packages": pkg_versions,
            "gateway_target": gw_url,
        },
        "checks": checks,
        "missing_required_tools": missing_required,
        "missing_optional_tools": missing_optional,
        "manual_actions_required": list(dict.fromkeys(manual_actions)),
    }

    print("")
    print("=== MalBox Machine 1 Readiness Report ===")
    for c in checks:
        ver = f" ({c['detected_version']})" if c["detected_version"] else ""
        req_tag = "REQ" if c["required"] else "OPT"
        print(f"  [{c['status']:<8}] [{req_tag}] {c['name']:<30}{ver} - {c['diagnostic_message']}")

    print("")
    print(f"LOCAL_READINESS     : {local_readiness}")
    print(f"LOCAL_SERVICE_STATE : {local_service_state}")
    print(f"NETWORK_READINESS   : {network_readiness}")
    print(f"PEER_CONNECTIVITY   : {peer_connectivity}")
    print(f"APPLICATION_STATE   : {sandbox_app_state} (remote Sandbox reported state)")
    print(f"SNAPSHOT_STATE      : {snapshot_state}")
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"REPORT_SAVED        : {report_path}")
    except OSError as exc:
        print(f"[ERROR] Failed writing report {report_path}: {exc}", file=sys.stderr)
        return 1

    if report["manual_actions_required"]:
        print("\nNext Actions:")
        for act in report["manual_actions_required"]:
            print(f"  - {act}")

    if local_readiness == "NOT_READY":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
