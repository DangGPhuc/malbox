#!/usr/bin/env python3
"""MalBox Machine 2 (REMnux/Kali Gateway) Environment Readiness Checker."""

from __future__ import annotations

import argparse
import json
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


def probe_dir_rw(label: str, raw_path: str, config_dir: Path) -> tuple[str, Path, bool, str]:
    target = Path(raw_path) if Path(raw_path).is_absolute() else (config_dir / raw_path).resolve()
    if not target.is_dir():
        return STATUS_MISSING, target, False, f"{label} missing: {target}"
    probe = target / f".readiness_probe_{os.getpid()}"
    try:
        probe.write_text("ok", encoding="utf-8")
        _ = probe.read_text(encoding="utf-8")
        probe.unlink()
        return STATUS_PASS, target, True, f"{label} is readable and writable: {target}"
    except OSError as exc:
        return STATUS_FAIL, target, False, f"{label} permission error: {exc}"


def check_port_free(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        bind_host = "0.0.0.0" if host in ("0.0.0.0", "") else host
        sock.bind((bind_host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MalBox Machine 2 Gateway Readiness Checker")
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
            recommended_action="" if is_linux else "Run Machine 2 Gateway on REMnux or Kali Linux.",
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

    # 4. pip runtime
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

    # 5. Flask & Requests versions + pip check (explicitly inspect .venv)
    pkg_versions: dict[str, str] = {}
    pip_check_ok = False
    pip_check_msg = ""
    if venv_python.is_file():
        pkg_probe = run_bounded(
            [
                str(venv_python),
                "-c",
                "import json, importlib.metadata as m; print(json.dumps({'flask': m.version('Flask'), 'requests': m.version('requests')}))",
            ],
            timeout=10.0,
        )
        if pkg_probe["returncode"] == 0 and pkg_probe["stdout"]:
            try:
                pkg_versions = json.loads(pkg_probe["stdout"])
            except ValueError:
                pkg_versions = {}
        pc = run_bounded([str(venv_python), "-m", "pip", "check"], timeout=15.0)
        pip_check_ok = pc["returncode"] == 0
        pip_check_msg = pc["stdout"] or pc["stderr"] or pc["error"] or ""
    else:
        pip_check_msg = ".venv missing"

    pkgs_installed = "flask" in pkg_versions and "requests" in pkg_versions
    pkgs_ok = pkgs_installed and pip_check_ok
    ver_str = ", ".join(f"{k}=={v}" for k, v in pkg_versions.items()) if pkg_versions else None
    checks.append(
        make_check(
            name="python_packages",
            category="runtime",
            required=True,
            status=STATUS_PASS if pkgs_ok else (STATUS_MISSING if not venv_python.is_file() or not pkgs_installed else STATUS_FAIL),
            detected_version=ver_str,
            installed=pkgs_installed,
            runtime_verified=pkgs_installed,
            feature_verified=pkgs_ok,
            diagnostic_message=(
                f"{ver_str}; pip check: {pip_check_msg or 'OK'}"
                if pkgs_installed
                else f"Flask and/or requests not verified in .venv ({pip_check_msg})."
            ),
            recommended_action="" if pkgs_ok else "Run bash setup.sh to install requirements.txt.",
        )
    )

    # 6. config.json
    cfg: dict[str, Any] = {}
    cfg_errors: list[str] = []
    if not config_path.is_file():
        cfg_errors.append(f"Missing {config_path}")
    else:
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8-sig"))
            for key in (
                "listen_host",
                "listen_port",
                "sandbox_host",
                "sandbox_port",
                "temp_dir",
                "evidence_archive_dir",
                "retain_evidence_archives",
            ):
                if key not in cfg:
                    cfg_errors.append(f"Missing key '{key}'")
            lport = int(cfg.get("listen_port", 0))
            sport = int(cfg.get("sandbox_port", 0))
            if not (1 <= lport <= 65535):
                cfg_errors.append(f"Invalid listen_port: {lport}")
            if not (1 <= sport <= 65535):
                cfg_errors.append(f"Invalid sandbox_port: {sport}")
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
                f"Listen {cfg.get('listen_host')}:{cfg.get('listen_port')} -> Sandbox {cfg.get('sandbox_host')}:{cfg.get('sandbox_port')}"
                if not cfg_errors
                else "; ".join(cfg_errors)
            ),
            recommended_action="" if not cfg_errors else "Fix machine2-gateway/config.json.",
        )
    )

    # 7 & 8. Temporary and retained evidence directories
    raw_tmp = str(cfg.get("temp_dir", "./tmp"))
    tmp_st, tmp_path, tmp_ok, tmp_msg = probe_dir_rw("Temp directory", raw_tmp, config_path.parent)
    checks.append(
        make_check(
            name="temp_directory",
            category="filesystem",
            required=True,
            status=tmp_st,
            configured_path=raw_tmp,
            resolved_path=str(tmp_path) if tmp_path.exists() else None,
            installed=tmp_path.is_dir(),
            runtime_verified=tmp_ok,
            feature_verified=tmp_ok,
            diagnostic_message=tmp_msg,
            recommended_action="" if tmp_ok else "Run bash setup.sh or fix directory permissions.",
        )
    )

    raw_ret = str(cfg.get("evidence_archive_dir", "./retained_evidence"))
    ret_st, ret_path, ret_ok, ret_msg = probe_dir_rw("Retained evidence directory", raw_ret, config_path.parent)
    checks.append(
        make_check(
            name="retained_evidence_directory",
            category="filesystem",
            required=True,
            status=ret_st,
            configured_path=raw_ret,
            resolved_path=str(ret_path) if ret_path.exists() else None,
            installed=ret_path.is_dir(),
            runtime_verified=ret_ok,
            feature_verified=ret_ok,
            diagnostic_message=ret_msg,
            recommended_action="" if ret_ok else "Run bash setup.sh or fix directory permissions.",
        )
    )

    # 9. Disk space
    disk_target = ret_path if ret_path.exists() else BASE_DIR
    free_mb = shutil.disk_usage(disk_target).free // (1024 * 1024)
    disk_ok = free_mb >= 1024
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
            diagnostic_message=f"{free_mb} MB free disk space on gateway partition.",
            recommended_action="" if disk_ok else "Free at least 1024 MB for relaying/retaining evidence archives.",
        )
    )

    # 10. Linux IP forwarding safety check (never modify network config!)
    ip_fwd_path = Path("/proc/sys/net/ipv4/ip_forward")
    if ip_fwd_path.is_file():
        val = ip_fwd_path.read_text(encoding="utf-8", errors="replace").strip()
        fwd_off = val == "0"
        checks.append(
            make_check(
                name="ip_forwarding_disabled",
                category="network",
                required=True,
                status=STATUS_PASS if fwd_off else STATUS_FAIL,
                detected_version=f"ip_forward={val}",
                resolved_path=str(ip_fwd_path),
                installed=True,
                runtime_verified=True,
                feature_verified=fwd_off,
                diagnostic_message=(
                    "Kernel IP forwarding is disabled (0), preserving network isolation."
                    if fwd_off
                    else "Kernel IP forwarding is enabled (1); Machine 2 must not route traffic directly between Net 1 and Net 2."
                ),
                recommended_action="" if fwd_off else "Manually disable IP forwarding: sudo sysctl -w net.ipv4.ip_forward=0",
            )
        )

    def _http_get_json(url: str, timeout_val: float) -> tuple[int, dict[str, Any], str | None]:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_val) as resp:
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

    # 11. Local Gateway port & service check
    listen_host = str(cfg.get("listen_host", "0.0.0.0"))
    listen_port = int(cfg.get("listen_port", 8000))
    gw_service_status = STATUS_PENDING
    probe_host = "127.0.0.1" if listen_host in ("0.0.0.0", "") else listen_host
    g_code, g_body, g_err = _http_get_json(f"http://{probe_host}:{listen_port}/health", 2.0)

    if g_code == 200 and g_body.get("service") == "malbox-gateway":
        gw_service_status = STATUS_PASS
        checks.append(
            make_check(
                name="gateway_listen_service",
                category="peer",
                required=False,
                status=STATUS_PASS,
                configured_path=f"{listen_host}:{listen_port}",
                resolved_path=f"http://{probe_host}:{listen_port}/health",
                runtime_verified=True,
                feature_verified=True,
                diagnostic_message="MalBox Gateway service is running and responded with valid identity.",
            )
        )
    elif g_code > 0:
        gw_service_status = STATUS_FAIL
        checks.append(
            make_check(
                name="gateway_listen_service",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Wrong service responding on port {listen_port} (HTTP {g_code}: {g_err or g_body}).",
                recommended_action=f"Stop conflicting service on port {listen_port} or adjust listen_port in config.json.",
            )
        )
    elif check_port_free(listen_host, listen_port):
        gw_service_status = STATUS_PENDING
        checks.append(
            make_check(
                name="gateway_listen_service",
                category="peer",
                required=False,
                status=STATUS_PENDING,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Gateway service not started yet; port {listen_port} is free.",
                recommended_action="Start Gateway with: source .venv/bin/activate && python gateway.py",
            )
        )
    else:
        gw_service_status = STATUS_FAIL
        checks.append(
            make_check(
                name="gateway_listen_service",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Port {listen_port} is already occupied by a non-HTTP or non-Gateway process.",
                recommended_action=f"Free port {listen_port} or change listen_port in config.json.",
            )
        )

    # 12. Sandbox peer status check
    sb_host = str(cfg.get("sandbox_host", "10.10.20.30"))
    sb_port = int(cfg.get("sandbox_port", 8001))
    sb_url = f"http://{sb_host}:{sb_port}"
    timeout_s = float(cfg.get("connect_timeout_seconds", 5))
    sb_code, sb_data, sb_err = _http_get_json(f"{sb_url}/status", timeout_s)
    sb_state = str(sb_data.get("state", "")).upper()

    if sb_code == 0:
        sb_peer_status = STATUS_PENDING
        checks.append(
            make_check(
                name="sandbox_peer_status",
                category="peer",
                required=False,
                status=STATUS_PENDING,
                configured_path=f"{sb_url}/status",
                diagnostic_message=f"Sandbox peer unreachable ({sb_err}).",
                recommended_action="Configure Internal Network 2 (10.10.20.20 <-> 10.10.20.30) and start sandbox.py on Machine 3.",
            )
        )
    elif sb_code == 200 and sb_state in ("READY", "ANALYZING", "RETURNING_EVIDENCE", "RESTORE_REQUIRED"):
        sb_peer_status = STATUS_PASS
        checks.append(
            make_check(
                name="sandbox_peer_status",
                category="peer",
                required=False,
                status=STATUS_PASS,
                configured_path=f"{sb_url}/status",
                resolved_path=sb_url,
                runtime_verified=True,
                feature_verified=True,
                diagnostic_message=f"Sandbox responded with valid state '{sb_state}'.",
                recommended_action=(
                    "Restore Windows 11 CLEAN snapshot on Machine 3."
                    if sb_state == "RESTORE_REQUIRED"
                    else ""
                ),
            )
        )
    else:
        sb_peer_status = STATUS_FAIL
        checks.append(
            make_check(
                name="sandbox_peer_status",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{sb_url}/status",
                diagnostic_message=f"Wrong service responding on Sandbox endpoint {sb_url}/status (HTTP {sb_code}: {sb_err or sb_data}).",
                recommended_action="Verify Machine 3 runs sandbox.py on port 8001.",
            )
        )

    # Overall readiness
    required_bad = [c for c in checks if c["required"] and c["status"] in (STATUS_FAIL, STATUS_MISSING)]
    if required_bad:
        local_readiness = "NOT_READY"
    elif any(
        not c["required"] and c["category"] != "peer" and c["status"] in (STATUS_FAIL, STATUS_MISSING, STATUS_OPTIONAL)
        for c in checks
    ):
        local_readiness = "LIMITED"
    else:
        local_readiness = "READY"

    if gw_service_status == STATUS_FAIL or sb_peer_status == STATUS_FAIL:
        network_readiness = "NOT_READY"
    elif gw_service_status == STATUS_PASS and sb_peer_status == STATUS_PASS:
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
        "machine": "machine2-gateway",
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
            "listen": f"{listen_host}:{listen_port}",
            "sandbox_target": sb_url,
        },
        "checks": checks,
        "missing_required_tools": missing_required,
        "missing_optional_tools": missing_optional,
        "manual_actions_required": list(dict.fromkeys(manual_actions)),
    }

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("")
    print("=== MalBox Machine 2 Readiness Report ===")
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
