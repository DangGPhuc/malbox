#!/usr/bin/env python3
"""MalBox Machine 1 (Kali Linux Client) Environment Readiness Checker."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
import platform
import shutil
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

    # 2. Python runtime
    py_ver = platform.python_version()
    py_ok = sys.version_info >= (3, 9)
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
            recommended_action="" if py_ok else "Install Python 3.9+ and recreate .venv.",
        )
    )

    # 3. Virtual environment
    if venv_python.is_file():
        v_probe = run_bounded([str(venv_python), "--version"], timeout=10.0)
        v_ok = v_probe["returncode"] == 0
        checks.append(
            make_check(
                name="python_venv",
                category="runtime",
                required=True,
                status=STATUS_PASS if v_ok else STATUS_FAIL,
                detected_version=v_probe["stdout"] or None,
                configured_path=str(venv_dir),
                resolved_path=str(venv_python),
                installed=True,
                runtime_verified=v_ok,
                diagnostic_message="Virtual environment Python executes cleanly." if v_ok else f"venv probe failed: {v_probe['stderr'] or v_probe['error']}",
                recommended_action="" if v_ok else "Run bash setup.sh to recreate .venv.",
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

    # 5. Python packages & dependency consistency (explicitly inspect .venv)
    pkg_versions: dict[str, str] = {}
    req_ver = None
    pip_check_ok = False
    pip_check_msg = ""
    if venv_python.is_file():
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
        pip_check_msg = ".venv missing"

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

    # 6. config.json parsing and validation
    cfg: dict[str, Any] = {}
    cfg_errors: list[str] = []
    if not config_path.is_file():
        cfg_errors.append(f"Missing {config_path}")
    else:
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8-sig"))
            for key in ("gateway_host", "gateway_port", "evidence_dir", "connect_timeout_seconds"):
                if key not in cfg:
                    cfg_errors.append(f"Missing key '{key}'")
            port_val = int(cfg.get("gateway_port", 0))
            if not (1 <= port_val <= 65535):
                cfg_errors.append(f"Invalid gateway_port: {port_val}")
        except (ValueError, TypeError) as exc:
            cfg_errors.append(f"Invalid config.json: {exc}")

    checks.append(
        make_check(
            name="config_json",
            category="config",
            required=True,
            status=STATUS_PASS if not cfg_errors else STATUS_FAIL,
            configured_path=str(config_path),
            resolved_path=str(config_path) if config_path.is_file() else None,
            installed=config_path.is_file(),
            runtime_verified=not cfg_errors,
            feature_verified=not cfg_errors,
            diagnostic_message=(
                f"Gateway target {cfg.get('gateway_host')}:{cfg.get('gateway_port')}"
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

    # 8. Evidence directory permissions
    raw_ev = str(cfg.get("evidence_dir", "./evidence"))
    ev_dir = Path(raw_ev) if Path(raw_ev).is_absolute() else (config_path.parent / raw_ev).resolve()
    ev_ok = False
    ev_msg = ""
    if ev_dir.is_dir():
        probe_file = ev_dir / f".readiness_probe_{os.getpid()}"
        try:
            probe_file.write_text("ok", encoding="utf-8")
            _ = probe_file.read_text(encoding="utf-8")
            probe_file.unlink()
            ev_ok = True
            ev_msg = f"Writable evidence directory: {ev_dir}"
        except OSError as exc:
            ev_msg = f"Evidence directory not writable: {exc}"
    else:
        ev_msg = f"Evidence directory missing: {ev_dir}"

    checks.append(
        make_check(
            name="evidence_directory",
            category="filesystem",
            required=True,
            status=STATUS_PASS if ev_ok else (STATUS_MISSING if not ev_dir.exists() else STATUS_FAIL),
            configured_path=raw_ev,
            resolved_path=str(ev_dir) if ev_dir.exists() else None,
            installed=ev_dir.is_dir(),
            runtime_verified=ev_ok,
            feature_verified=ev_ok,
            diagnostic_message=ev_msg,
            recommended_action="" if ev_ok else "Run bash setup.sh or check directory permissions.",
        )
    )

    # 9. Disk space
    disk_target = ev_dir if ev_dir.exists() else BASE_DIR
    free_mb = shutil.disk_usage(disk_target).free // (1024 * 1024)
    disk_ok = free_mb >= 512
    checks.append(
        make_check(
            name="disk_space",
            category="filesystem",
            required=True,
            status=STATUS_PASS if disk_ok else STATUS_FAIL,
            detected_version=f"{free_mb} MB free",
            resolved_path=str(disk_target),
            installed=True,
            runtime_verified=True,
            feature_verified=disk_ok,
            diagnostic_message=f"{free_mb} MB free disk space on client partition.",
            recommended_action="" if disk_ok else "Free at least 512 MB for evidence downloads.",
        )
    )

    # 10. Optional peer check: Gateway health & status (stdlib urllib works even if .venv missing)
    gw_host = str(cfg.get("gateway_host", "10.10.10.20"))
    gw_port = int(cfg.get("gateway_port", 8000))
    gw_url = f"http://{gw_host}:{gw_port}"
    gw_health_status = STATUS_PENDING
    gw_status_val = STATUS_PENDING
    timeout_s = float(cfg.get("connect_timeout_seconds", 5))

    def _http_get_json(url: str) -> tuple[int, dict[str, Any], str | None]:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8-sig", errors="replace")
                try:
                    return resp.status, json.loads(raw), None
                except ValueError:
                    return resp.status, {}, "non-JSON response"
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8-sig", errors="replace") if exc.fp else ""
            try:
                return exc.code, json.loads(raw), None
            except ValueError:
                return exc.code, {}, f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            return 0, {}, str(exc)

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
                feature_verified=True,
                diagnostic_message="Gateway health endpoint responded with valid MalBox Gateway identity.",
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
        sb_state = str(st_data.get("sandbox", {}).get("state", "UNAVAILABLE")).upper()
        if st_code == 200 and st_data.get("gateway") == "ok" and sb_state in (
            "READY",
            "ANALYZING",
            "RETURNING_EVIDENCE",
            "RESTORE_REQUIRED",
        ):
            gw_status_val = STATUS_PASS
            checks.append(
                make_check(
                    name="gateway_sandbox_relay_status",
                    category="peer",
                    required=False,
                    status=STATUS_PASS,
                    configured_path=f"{gw_url}/status",
                    runtime_verified=True,
                    feature_verified=True,
                    diagnostic_message=f"Gateway reached Sandbox (Sandbox state: {sb_state}).",
                    recommended_action=(
                        "Restore Windows 11 CLEAN snapshot on Machine 3."
                        if sb_state == "RESTORE_REQUIRED"
                        else ""
                    ),
                )
            )
        elif st_code == 200 and st_data.get("gateway") == "ok":
            gw_status_val = STATUS_PENDING
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

    # Overall readiness computation
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

    if gw_health_status == STATUS_FAIL or gw_status_val == STATUS_FAIL:
        network_readiness = "NOT_READY"
    elif gw_health_status == STATUS_PASS and gw_status_val == STATUS_PASS:
        network_readiness = "READY"
    else:
        network_readiness = "PENDING"

    missing_required = [c["name"] for c in checks if c["required"] and c["status"] in (STATUS_MISSING, STATUS_FAIL)]
    missing_optional = [c["name"] for c in checks if not c["required"] and c["status"] in (STATUS_MISSING, STATUS_OPTIONAL)]
    for c in checks:
        if c["recommended_action"] and c["status"] != STATUS_PASS:
            manual_actions.append(f"[{c['name']}] {c['recommended_action']}")

    report = {
        "schema_version": "1.0",
        "machine": "machine1-client",
        "mode": args.mode,
        "generated_at": utc_now_iso(),
        "local_readiness": local_readiness,
        "network_readiness": network_readiness,
        "snapshot_state": "NOT_APPLICABLE",
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

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("")
    print("=== MalBox Machine 1 Readiness Report ===")
    for c in checks:
        ver = f" ({c['detected_version']})" if c["detected_version"] else ""
        req_tag = "REQ" if c["required"] else "OPT"
        print(f"  [{c['status']:<8}] [{req_tag}] {c['name']:<30}{ver} - {c['diagnostic_message']}")

    print("")
    print(f"LOCAL_READINESS   : {local_readiness}")
    print(f"NETWORK_READINESS : {network_readiness}")
    print(f"REPORT_SAVED      : {report_path}")
    if report["manual_actions_required"]:
        print("\nNext Actions:")
        for act in report["manual_actions_required"]:
            print(f"  - {act}")

    if args.mode == "check-only" and local_readiness == "NOT_READY":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
