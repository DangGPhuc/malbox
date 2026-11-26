#!/usr/bin/env python3
"""MalBox Machine 3 (Windows 11 Sandbox) Environment Readiness Checker.

Performs non-destructive, offline-capable readiness verification across
Windows 11 OS/build, Python runtime, tools, collectors, MalBox MCP stdio handshake,
Ghidra Headless, optional GhidraMCP, service/network separation, and snapshot state.
Never clears .dirty_state, never runs malware, and never modifies drivers/protections.

Exit codes (standardized across all MalBox readiness checkers):
  0: Mandatory local checks passed (LOCAL_READINESS is READY or LIMITED).
  1: LOCAL_READINESS is NOT_READY (missing/failing mandatory check, RESTORE_REQUIRED
     dirty marker, or invalid config) in either setup or check-only mode, or report
     could not be saved.
  2: Invalid command-line arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
MCP_DIR = BASE_DIR / "mcp"
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_REPORT_PATH = BASE_DIR / "setup_report.json"
MIN_PYTHON = (3, 10)
WIN10_MIN_BUILD = 10240
WIN11_MIN_BUILD = 22000

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_MISSING = "MISSING"
STATUS_OPTIONAL = "OPTIONAL"
STATUS_PENDING = "PENDING"
STATUS_SKIPPED = "SKIPPED"

EXPECTED_MCP_TOOLS = {
    "get_analysis_status",
    "get_sample_metadata",
    "get_static_analysis",
    "get_process_tree",
    "get_process_events",
    "get_network_connections",
    "get_dns_queries",
    "get_memory_summary",
    "get_filesystem_changes",
    "get_registry_changes",
    "get_windows_events",
    "get_ghidra_results",
    "get_yara_matches",
    "get_analysis_timeline",
    "list_evidence",
    "get_evidence_summary",
}

CORE_TOOL_KEYS = (
    "floss",
    "capa",
    "capa_rules",
    "yara_rules_dir",
    "ghidra_headless",
    "ghidra_script_dir",
    "sysmon",
    "dumpcap",
    "tshark",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_bounded(cmd: list[str], timeout: float = 12.0, cwd: Path | None = None) -> dict[str, Any]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
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
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "timed_out": False,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "error": f"Timed out after {timeout}s",
        }
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
    verification_stages: dict[str, Any] | None = None,
    unavailable_evidence_if_missing: str | None = None,
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
    item: dict[str, Any] = {
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
    if verification_stages is not None:
        item["verification_stages"] = verification_stages
    if unavailable_evidence_if_missing is not None:
        item["unavailable_evidence_if_missing"] = unavailable_evidence_if_missing
    return item


def _validate_str(
    cfg: dict[str, Any],
    key: str,
    errors: list[str],
    allow_empty: bool = False,
    required: bool = True,
) -> str | None:
    if key not in cfg:
        if required:
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
    """Strictly validate sandbox config.json while returning safe fallback values for remaining probes."""
    default_tools: dict[str, str] = {
        "floss": "./tools/floss/floss.exe",
        "capa": "./tools/capa/capa.exe",
        "capa_rules": "./tools/capa-rules",
        "yara": "./tools/yara/yara64.exe",
        "yara_rules_dir": "./scripts/yara_rules",
        "die": "./tools/die/diec.exe",
        "ghidra_headless": "./tools/ghidra/support/analyzeHeadless.bat",
        "ghidra_script_dir": "./scripts",
        "ghidra_export_script": "GhidraExport.java",
        "ghidra_mcp_dir": "./tools/GhidraMCP",
        "sysmon": "C:\\Windows\\Sysmon64.exe",
        "procmon": "./tools/sysinternals/Procmon64.exe",
        "procdump": "./tools/sysinternals/procdump64.exe",
        "dumpcap": "C:\\Program Files\\Wireshark\\dumpcap.exe",
        "tshark": "C:\\Program Files\\Wireshark\\tshark.exe",
        "winpmem": "./tools/winpmem/winpmem.exe",
        "volatility3": "./tools/volatility3/vol.py",
        "volatility_symbols_dir": "./tools/volatility3/symbols",
    }
    defaults: dict[str, Any] = {
        "listen_host": "0.0.0.0",
        "listen_port": 8001,
        "workspace_dir": "./workspace",
        "evidence_dir": "./evidence",
        "observation_duration_seconds": 120,
        "require_local_approval": True,
        "poll_sample_interval_seconds": 0.5,
        "ghidra_timeout_seconds": 300,
        "floss_timeout_seconds": 120.0,
        "capa_timeout_seconds": 120.0,
        "die_timeout_seconds": 60,
        "volatility_timeout_seconds": 180.0,
        "enable_attack_mapping": True,
        "chunk_size_bytes": 65536,
        "min_free_disk_mb": 2048,
        "procdump_enabled": True,
        "winpmem_enabled": False,
        "include_raw_pml": False,
        "max_raw_pml_mb": 200,
        "max_procmon_export_rows": 15000,
        "canary_fixtures_enabled": False,
        "network_interface": "",
        "tools": dict(default_tools),
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

    lhost = _validate_str(parsed, "listen_host", errors)
    lport = _validate_int(parsed, "listen_port", errors, min_val=1, max_val=65535, required=True)
    ws_dir = _validate_str(parsed, "workspace_dir", errors)
    ev_dir = _validate_str(parsed, "evidence_dir", errors)
    obs_dur = _validate_number(parsed, "observation_duration_seconds", errors, min_val=1.0, required=True)
    req_app = _validate_bool(parsed, "require_local_approval", errors, required=True)
    gh_timeout = _validate_number(parsed, "ghidra_timeout_seconds", errors, min_val=1.0, required=True)
    die_timeout = _validate_number(parsed, "die_timeout_seconds", errors, min_val=1.0, required=False)
    attack_en = _validate_bool(parsed, "enable_attack_mapping", errors, required=False)
    min_disk = _validate_int(parsed, "min_free_disk_mb", errors, min_val=1, required=True)

    poll_intv = _validate_number(parsed, "poll_sample_interval_seconds", errors, min_val=0.05, required=False)
    floss_to = _validate_number(parsed, "floss_timeout_seconds", errors, min_val=1.0, required=False)
    capa_to = _validate_number(parsed, "capa_timeout_seconds", errors, min_val=1.0, required=False)
    vol_to = _validate_number(parsed, "volatility_timeout_seconds", errors, min_val=1.0, required=False)
    chunk_sz = _validate_int(parsed, "chunk_size_bytes", errors, min_val=1024, required=False)
    pd_en = _validate_bool(parsed, "procdump_enabled", errors, required=False)
    wp_en = _validate_bool(parsed, "winpmem_enabled", errors, required=False)
    raw_pml_en = _validate_bool(parsed, "include_raw_pml", errors, required=False)
    max_pml_mb = _validate_int(parsed, "max_raw_pml_mb", errors, min_val=1, required=False)
    max_pml_rows = _validate_int(parsed, "max_procmon_export_rows", errors, min_val=100, required=False)
    canary_en = _validate_bool(parsed, "canary_fixtures_enabled", errors, required=False)
    net_if = _validate_str(parsed, "network_interface", errors, allow_empty=True, required=False)

    safe_tools = dict(default_tools)
    if "tools" not in parsed:
        errors.append("Missing key 'tools'")
    elif not isinstance(parsed["tools"], dict):
        errors.append(f"Key 'tools' must be a JSON object (got {type(parsed['tools']).__name__})")
    else:
        raw_tools = parsed["tools"]
        for tkey, tval in raw_tools.items():
            if not isinstance(tval, str):
                errors.append(f"tools.{tkey} must be a string path (got {type(tval).__name__})")
            elif "\x00" in tval:
                errors.append(f"tools.{tkey} contains embedded null byte")
            elif tkey in CORE_TOOL_KEYS and not tval.strip():
                errors.append(f"tools.{tkey} must not be empty")
            elif tval.strip():
                safe_tools[tkey] = tval.strip()

    safe_cfg = dict(defaults)
    updates: dict[str, Any] = {
        "listen_host": lhost,
        "listen_port": lport,
        "workspace_dir": ws_dir,
        "evidence_dir": ev_dir,
        "observation_duration_seconds": obs_dur,
        "require_local_approval": req_app,
        "poll_sample_interval_seconds": poll_intv,
        "ghidra_timeout_seconds": gh_timeout,
        "floss_timeout_seconds": floss_to,
        "capa_timeout_seconds": capa_to,
        "die_timeout_seconds": die_timeout,
        "volatility_timeout_seconds": vol_to,
        "enable_attack_mapping": attack_en,
        "chunk_size_bytes": chunk_sz,
        "min_free_disk_mb": min_disk,
        "procdump_enabled": pd_en,
        "winpmem_enabled": wp_en,
        "include_raw_pml": raw_pml_en,
        "max_raw_pml_mb": max_pml_mb,
        "max_procmon_export_rows": max_pml_rows,
        "canary_fixtures_enabled": canary_en,
        "network_interface": net_if,
    }
    for k, v in updates.items():
        if v is not None:
            safe_cfg[k] = v
    safe_cfg["tools"] = safe_tools

    return safe_cfg, errors, "valid" if not errors else "validation_error"


def resolve_cfg_path(raw: str | None) -> Path | None:
    if not raw or not isinstance(raw, str) or "\x00" in raw or not raw.strip():
        return None
    try:
        p = Path(raw.strip())
        return p if p.is_absolute() else (BASE_DIR / p).resolve()
    except (ValueError, OSError):
        return None


def resolve_tool(raw_cfg: str | None, fallbacks: list[str]) -> Path | None:
    cand = resolve_cfg_path(raw_cfg)
    try:
        if cand and cand.exists():
            return cand
    except OSError:
        pass
    for name in fallbacks:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def get_git_commit(repo_dir: Path | None) -> str | None:
    if not repo_dir or not (repo_dir / ".git").exists():
        return None
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    res = run_bounded([git_bin, "-C", str(repo_dir), "rev-parse", "--short", "HEAD"], timeout=5.0)
    if res["returncode"] == 0 and res["stdout"]:
        return res["stdout"].splitlines()[0].strip()
    return None


def get_windows_file_version(file_path: Path) -> str | None:
    if not sys.platform.startswith("win") or not file_path.is_file():
        return None
    escaped = str(file_path).replace("'", "''")
    res = run_bounded(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-Item -LiteralPath '{escaped}').VersionInfo.ProductVersion",
        ],
        timeout=8.0,
    )
    if res["returncode"] == 0 and res["stdout"]:
        return res["stdout"].splitlines()[0].strip()
    return None


def check_sysinternals_eula(tool_reg_name: str) -> bool | None:
    """Read-only HKCU registry check so -CheckOnly never hangs on interactive EULA modal or mutates HKCU."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import winreg  # type: ignore

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Software\Sysinternals\{tool_reg_name}") as key:
            val, _ = winreg.QueryValueEx(key, "EulaAccepted")
            return int(val) == 1
    except OSError:
        return False


def query_windows_service(service_names: list[str]) -> tuple[str, str]:
    """Query Windows service status via sc.exe without modifying anything."""
    if not sys.platform.startswith("win"):
        return "UNAVAILABLE", "Non-Windows OS"
    for svc in service_names:
        res = run_bounded(["sc.exe", "query", svc], timeout=8.0)
        combined = f"{res['stdout']}\n{res['stderr']}".upper()
        if "RUNNING" in combined:
            return "RUNNING", svc
        if "STOPPED" in combined:
            return "STOPPED", svc
        if "PAUSED" in combined:
            return "PAUSED", svc
    return "NOT_INSTALLED", ", ".join(service_names)


def parse_java_major(raw_text: str) -> int | None:
    match = re.search(r'version\s+"(\d+)(?:\.(\d+))?', raw_text)
    if not match:
        return None
    first = int(match.group(1))
    if first == 1 and match.group(2):
        return int(match.group(2))
    return first


def get_ghidra_props(headless_bin: Path | None) -> tuple[str | None, int | None]:
    if not headless_bin:
        return None, None
    ghidra_root = headless_bin.parent.parent
    props = ghidra_root / "Ghidra" / "application.properties"
    ver: str | None = None
    java_min: int | None = None
    if props.is_file():
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                ver = line.split("=", 1)[1].strip()
            elif line.startswith("application.java.min="):
                try:
                    java_min = int(line.split("=", 1)[1].strip().split(".", 1)[0])
                except ValueError:
                    pass
    return ver, java_min


def check_ghidra_script_syntax(script_path: Path) -> tuple[bool, str | None]:
    """Perform static non-executing structure check on .java or .py Ghidra post-script."""
    if script_path.suffix.lower() != ".java":
        return check_python_syntax_ast(script_path)
    try:
        src = script_path.read_text(encoding="utf-8-sig", errors="replace")
        # Strip line/block comments and char/string literals before checking brace balance and class header
        stripped = re.sub(r"//[^\n]*|/\*.*?\*/", "", src, flags=re.DOTALL)
        stripped = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', stripped)
        expected_class = script_path.stem
        if not re.search(rf"\bclass\s+{re.escape(expected_class)}\s+extends\s+GhidraScript\b", stripped):
            return False, f"Missing 'class {expected_class} extends GhidraScript' matching script filename."
        if "public void run()" not in stripped:
            return False, "Missing 'public void run()' entry method."
        depth = 0
        saw_brace = False
        for ch in stripped:
            if ch == "{":
                depth += 1
                saw_brace = True
            elif ch == "}":
                depth -= 1
                if depth < 0:
                    return False, "Unbalanced closing brace '}' in Java source."
        if not saw_brace or depth != 0:
            return False, "Unbalanced curly braces in Java source."
        return True, None
    except OSError as exc:
        return False, str(exc)


def check_python_syntax_ast(script_path: Path) -> tuple[bool, str | None]:
    """Verify static Python syntax only without executing the file."""
    try:
        src = script_path.read_text(encoding="utf-8-sig", errors="replace")
        compile(src, str(script_path), "exec")
        return True, None
    except (OSError, SyntaxError) as exc:
        return False, str(exc)


def parse_requirements_names(req_path: Path) -> list[str]:
    names: list[str] = []
    if not req_path.is_file():
        return names
    for line in req_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        pkg = re.split(r"[<>=!~;\[\s]", line, maxsplit=1)[0].strip()
        if pkg:
            names.append(pkg)
    return names


def build_synthetic_pe_fixture() -> bytes:
    """Build a harmless minimal synthetic PE32 byte sequence purely in memory for pefile parsing."""
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x014C, 0, 0, 0, 0, 0xE0, 0x0102)
    struct.pack_into("<H", buf, 0x98, 0x010B)
    return bytes(buf)


def probe_malbox_mcp(venv_python: str) -> dict[str, Any]:
    """Run an actual MCP stdio initialize + tools/list probe using venv Python and close cleanly."""
    server_py = MCP_DIR / "server.py"
    if not server_py.is_file():
        return {"ok": False, "error": "mcp/server.py missing", "tools": []}

    probe_code = (
        "import asyncio, json, sys\n"
        "from pathlib import Path\n"
        f"mcp_dir = Path({str(MCP_DIR)!r}).resolve()\n"
        f"base_dir = Path({str(BASE_DIR)!r}).resolve()\n"
        "sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() not in (mcp_dir, base_dir)]\n"
        "from mcp import ClientSession, StdioServerParameters\n"
        "from mcp.client.stdio import stdio_client\n"
        "async def run():\n"
        f"    params = StdioServerParameters(command={venv_python!r}, args=[{str(server_py)!r}])\n"
        "    async with stdio_client(params) as (r, w):\n"
        "        async with ClientSession(r, w) as s:\n"
        "            init_res = await s.initialize()\n"
        "            tools_res = await s.list_tools()\n"
        "            print(json.dumps({'ok': True, 'server_name': getattr(getattr(init_res, 'serverInfo', None), 'name', None), 'tools': sorted(t.name for t in tools_res.tools)}))\n"
        "asyncio.run(asyncio.wait_for(run(), timeout=14.0))\n"
    )
    res = run_bounded([venv_python, "-c", probe_code], timeout=18.0)
    if res["returncode"] == 0 and res["stdout"]:
        try:
            return json.loads(res["stdout"].splitlines()[-1])
        except ValueError:
            pass
    return {
        "ok": False,
        "error": res["stderr"] or res["error"] or f"MCP probe exited {res['returncode']}",
        "tools": [],
    }


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
    parser = argparse.ArgumentParser(description="MalBox Machine 3 Sandbox Readiness Checker")
    parser.add_argument("--mode", choices=("setup", "check-only"), default="check-only")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    config_path = Path(args.config).resolve()
    report_path = Path(args.report).resolve()
    venv_dir = BASE_DIR / ".venv"
    venv_python = venv_dir / "Scripts" / "python.exe"
    if not venv_python.is_file():
        unix_venv_py = venv_dir / "bin" / "python"
        if unix_venv_py.is_file():
            venv_python = unix_venv_py

    checks: list[dict[str, Any]] = []
    manual_actions: list[str] = []
    cloned_repos: dict[str, str | None] = {}

    # === 1. Windows OS Detection vs Supported Windows 10 x64 / Windows 11 Build Verification ===
    is_win = sys.platform.startswith("win")
    arch_raw = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or platform.machine()).upper()
    is_x64_os = arch_raw in ("AMD64", "X86_64", "ARM64")
    win_build_int: int | None = None
    win_ubr: str | None = None
    win_display: str | None = None
    win_edition: str | None = None
    win_product: str | None = None
    if is_win:
        try:
            win_build_int = int(sys.getwindowsversion().build)
        except Exception:
            win_build_int = None
        try:
            import winreg  # type: ignore

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                for reg_name, setter in (
                    ("DisplayVersion", "disp"),
                    ("ReleaseId", "relid"),
                    ("EditionID", "ed"),
                    ("ProductName", "prod"),
                    ("CurrentBuildNumber", "build"),
                    ("UBR", "ubr"),
                ):
                    try:
                        val, _ = winreg.QueryValueEx(key, reg_name)
                        if setter == "disp" and str(val).strip():
                            win_display = str(val)
                        elif setter == "relid" and not win_display and str(val).strip():
                            win_display = str(val)
                        elif setter == "ed":
                            win_edition = str(val)
                        elif setter == "prod":
                            win_product = str(val)
                        elif setter == "ubr":
                            win_ubr = str(val)
                        elif setter == "build" and win_build_int is None:
                            win_build_int = int(str(val))
                    except (OSError, ValueError):
                        pass
        except Exception:
            pass

    os_desc = f"{platform.system()} {platform.release()} (arch={arch_raw})"
    checks.append(
        make_check(
            name="windows_os",
            category="os",
            required=True,
            status=STATUS_PASS if is_win else STATUS_FAIL,
            detected_version=os_desc,
            installed=True,
            runtime_verified=is_win,
            feature_verified=is_win,
            diagnostic_message=f"Detected host OS: {os_desc}",
            recommended_action="" if is_win else "Machine 3 Sandbox must run on Windows 10 x64 (e.g. REMWin) or Windows 11 x64 VM.",
        )
    )

    win_family = None
    if is_win and win_build_int is not None:
        if win_build_int >= WIN11_MIN_BUILD:
            win_family = "Windows 11"
        elif win_build_int >= WIN10_MIN_BUILD:
            win_family = "Windows 10"
        else:
            win_family = f"Legacy Windows (build {win_build_int})"

    win_supported = bool(is_win and is_x64_os and win_build_int is not None and win_build_int >= WIN10_MIN_BUILD)
    win_ver_label = (
        f"{win_family or 'Windows'} build={win_build_int}.{win_ubr or '0'}, arch={arch_raw}, display={win_display or 'N/A'}, edition={win_edition or 'N/A'}"
        if is_win and win_build_int is not None
        else None
    )
    if not is_win:
        checks.append(
            make_check(
                name="windows_version_compat",
                category="os",
                required=True,
                status=STATUS_SKIPPED,
                installed=False,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message="Skipped Windows 10/11 build verification: host OS is not Windows.",
                recommended_action="Run setup.ps1 inside a Windows 10 x64 (REMWin) or Windows 11 x64 VM.",
            )
        )
    elif win_supported:
        checks.append(
            make_check(
                name="windows_version_compat",
                category="os",
                required=True,
                status=STATUS_PASS,
                detected_version=win_ver_label,
                installed=True,
                runtime_verified=True,
                feature_verified=True,
                diagnostic_message=(
                    f"Verified supported {win_family} x64 environment (build {win_build_int}, {win_display or 'N/A'}, {win_edition or win_product or 'Windows'})."
                ),
            )
        )
    elif win_build_int is not None:
        checks.append(
            make_check(
                name="windows_version_compat",
                category="os",
                required=True,
                status=STATUS_FAIL,
                detected_version=win_ver_label,
                installed=True,
                runtime_verified=True,
                feature_verified=False,
                diagnostic_message=(
                    f"Windows detected (build={win_build_int}, arch={arch_raw}), but MalBox requires Windows 10 x64 (build >= {WIN10_MIN_BUILD}) or Windows 11 x64 (build >= {WIN11_MIN_BUILD})."
                ),
                recommended_action="Deploy Machine 3 Sandbox on a 64-bit Windows 10 (e.g. REMWin) or Windows 11 VM.",
            )
        )
    else:
        checks.append(
            make_check(
                name="windows_version_compat",
                category="os",
                required=True,
                status=STATUS_FAIL,
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message="Windows OS detected, but build number could not be read to verify Windows 10/11.",
                recommended_action="Verify OS version (winver) is 64-bit Windows 10 (build >= 10240) or Windows 11.",
            )
        )

    # PowerShell check
    ps_bin = shutil.which("pwsh") or shutil.which("powershell")
    ps_ver = None
    ps_ok = False
    if ps_bin:
        ps_res = run_bounded([ps_bin, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], timeout=10.0)
        if ps_res["returncode"] == 0 and ps_res["stdout"]:
            ps_ver = ps_res["stdout"].splitlines()[0].strip()
            ps_ok = True
    checks.append(
        make_check(
            name="powershell_runtime",
            category="runtime",
            required=True,
            status=STATUS_PASS if ps_ok else (STATUS_MISSING if not ps_bin else STATUS_FAIL),
            detected_version=ps_ver,
            resolved_path=ps_bin,
            installed=bool(ps_bin),
            runtime_verified=ps_ok,
            feature_verified=ps_ok,
            diagnostic_message=f"PowerShell {ps_ver}" if ps_ok else "PowerShell unavailable.",
            recommended_action="" if ps_ok else "Ensure Windows PowerShell 5.1 or PowerShell 7+ is available.",
        )
    )

    # Python version (>= 3.10 standardized) & 64-bit architecture check
    py_ver = platform.python_version()
    py_bits = struct.calcsize("P") * 8
    py_ok = sys.version_info >= MIN_PYTHON and py_bits == 64
    checks.append(
        make_check(
            name="python_runtime",
            category="runtime",
            required=True,
            status=STATUS_PASS if py_ok else STATUS_FAIL,
            detected_version=f"{py_ver} ({py_bits}-bit)",
            resolved_path=sys.executable,
            installed=True,
            runtime_verified=py_ok,
            feature_verified=py_ok,
            diagnostic_message=f"Python {py_ver} ({py_bits}-bit, arch={platform.machine()})",
            recommended_action="" if py_ok else "Install 64-bit Python 3.10+ (recommended 3.11/3.12 x64).",
        )
    )

    # Virtual environment (verifies >= 3.10 & 64-bit)
    venv_exists = venv_python.is_file()
    venv_ok = False
    venv_ver = None
    if venv_exists:
        vp = run_bounded(
            [
                str(venv_python),
                "-c",
                "import platform, struct, sys; print(f'{platform.python_version()} ({struct.calcsize(\"P\")*8}-bit)'); sys.exit(0 if (sys.version_info >= (3, 10) and struct.calcsize('P')*8 == 64) else 3)",
            ],
            timeout=10.0,
        )
        venv_ver = vp["stdout"].splitlines()[0].strip() if vp["stdout"] else None
        venv_ok = vp["returncode"] == 0
        venv_msg = (
            f"Sandbox .venv Python {venv_ver} runs cleanly."
            if venv_ok
            else (
                f".venv Python {venv_ver} does not meet 64-bit Python 3.10+ requirement."
                if vp["returncode"] == 3
                else f"Sandbox .venv failed to execute: {vp['stderr'] or vp['error']}"
            )
        )
    else:
        venv_msg = "Sandbox .venv not created."

    checks.append(
        make_check(
            name="python_venv",
            category="runtime",
            required=True,
            status=STATUS_PASS if venv_ok else (STATUS_MISSING if not venv_exists else STATUS_FAIL),
            detected_version=venv_ver,
            configured_path=str(venv_dir),
            resolved_path=str(venv_python) if venv_exists else None,
            installed=venv_exists,
            runtime_verified=venv_ok,
            diagnostic_message=venv_msg,
            recommended_action="" if venv_ok else "Run .\\setup.ps1 while online to create 64-bit Python 3.10+ .venv.",
        )
    )

    # pip version
    pip_ver = None
    pip_ok = False
    if venv_ok:
        pp = run_bounded([str(venv_python), "-m", "pip", "--version"], timeout=10.0)
        pip_ok = pp["returncode"] == 0
        pip_ver = pp["stdout"].splitlines()[0] if pp["stdout"] else None
    checks.append(
        make_check(
            name="pip_runtime",
            category="runtime",
            required=True,
            status=STATUS_PASS if pip_ok else (STATUS_MISSING if not venv_exists else STATUS_FAIL),
            detected_version=pip_ver,
            installed=pip_ok,
            runtime_verified=pip_ok,
            diagnostic_message=pip_ver or "pip inside .venv unavailable.",
            recommended_action="" if pip_ok else "Run .\\setup.ps1.",
        )
    )

    # Python package versions & pip check
    req_pkgs = ["Flask", "requests", "psutil", "pefile", "yara-python", "python-evtx", "mcp"]
    pkg_versions: dict[str, str] = {}
    pkg_ok = False
    pip_check_msg = ""
    if venv_ok:
        ver_script = (
            "import json, importlib.metadata as m\n"
            f"names = {req_pkgs!r}\n"
            "out = {}\n"
            "for n in names:\n"
            "    try:\n"
            "        out[n] = m.version(n)\n"
            "    except Exception:\n"
            "        pass\n"
            "import flask, requests, psutil, pefile, yara, Evtx, mcp\n"
            "print(json.dumps(out))\n"
        )
        p_res = run_bounded([str(venv_python), "-c", ver_script], timeout=15.0)
        if p_res["returncode"] == 0 and p_res["stdout"]:
            try:
                parsed_pkgs = json.loads(p_res["stdout"])
                if isinstance(parsed_pkgs, dict):
                    pkg_versions = parsed_pkgs
            except ValueError:
                pass
        pc_res = run_bounded([str(venv_python), "-m", "pip", "check"], timeout=20.0)
        pip_check_ok = pc_res["returncode"] == 0
        pip_check_msg = pc_res["stdout"] or pc_res["stderr"] or pc_res["error"] or ""
        pkg_ok = len(pkg_versions) == len(req_pkgs) and pip_check_ok
    else:
        pip_check_msg = ".venv missing or unsupported Python version"

    checks.append(
        make_check(
            name="python_packages",
            category="runtime",
            required=True,
            status=STATUS_PASS if pkg_ok else (STATUS_MISSING if not venv_exists or not pkg_versions else STATUS_FAIL),
            detected_version=", ".join(f"{k}=={v}" for k, v in pkg_versions.items()) if pkg_versions else None,
            installed=len(pkg_versions) == len(req_pkgs),
            runtime_verified=len(pkg_versions) == len(req_pkgs),
            feature_verified=pkg_ok,
            diagnostic_message=(
                f"All {len(req_pkgs)} required packages imported; pip check: {pip_check_msg or 'OK'}"
                if pkg_ok
                else f"Missing/inconsistent Python packages (installed={list(pkg_versions.keys())}; pip check={pip_check_msg})"
            ),
            recommended_action="" if pkg_ok else "Run .\\setup.ps1 while online to install requirements.txt.",
        )
    )

    # Strict, crash-safe config.json parsing & validation
    cfg, cfg_errors, cfg_state = load_and_validate_config(config_path)
    tools_cfg: dict[str, str] = cfg["tools"]
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
                f"Sandbox listens {cfg['listen_host']}:{cfg['listen_port']}; require_local_approval={cfg['require_local_approval']}"
                if not cfg_errors
                else "; ".join(cfg_errors)
            ),
            recommended_action="" if not cfg_errors else "Fix machine3-sandbox/config.json.",
        )
    )

    # Workspace & evidence directories + disk space
    ws_dir = resolve_cfg_path(cfg["workspace_dir"]) or (BASE_DIR / "workspace")
    ev_dir = resolve_cfg_path(cfg["evidence_dir"]) or (BASE_DIR / "evidence")
    ws_ok = False
    ev_ok = False
    dir_msgs: list[str] = []
    for label, dpath in (("workspace", ws_dir), ("evidence", ev_dir)):
        if dpath.is_dir():
            probe = dpath / f".readiness_probe_{os.getpid()}"
            try:
                probe.write_text("ok", encoding="utf-8")
                _ = probe.read_text(encoding="utf-8")
                if label == "workspace":
                    ws_ok = True
                else:
                    ev_ok = True
            except OSError as exc:
                dir_msgs.append(f"{label} not writable: {exc}")
            finally:
                try:
                    if probe.exists():
                        probe.unlink()
                except OSError:
                    pass
        elif dpath.exists():
            dir_msgs.append(f"{label} is not a directory: {dpath}")
        else:
            dir_msgs.append(f"{label} missing: {dpath}")

    dirs_ok = ws_ok and ev_ok
    checks.append(
        make_check(
            name="workspace_and_evidence_dirs",
            category="filesystem",
            required=True,
            status=STATUS_PASS if dirs_ok else (STATUS_MISSING if (not ws_dir.exists() or not ev_dir.exists()) else STATUS_FAIL),
            resolved_path=f"{ws_dir}; {ev_dir}",
            installed=ws_dir.is_dir() and ev_dir.is_dir(),
            runtime_verified=dirs_ok,
            feature_verified=dirs_ok,
            diagnostic_message="Workspace and evidence directories are readable/writable." if dirs_ok else "; ".join(dir_msgs),
            recommended_action="" if dirs_ok else "Run .\\setup.ps1 or fix folder ACL permissions.",
        )
    )

    min_disk_mb = int(cfg["min_free_disk_mb"])
    disk_target = ws_dir if ws_dir.is_dir() else BASE_DIR
    try:
        free_mb = shutil.disk_usage(disk_target).free // (1024 * 1024)
        disk_ok = free_mb >= min_disk_mb
        disk_status = STATUS_PASS if disk_ok else STATUS_FAIL
        disk_ver = f"{free_mb} MB free (min {min_disk_mb} MB)"
        disk_msg = f"{free_mb} MB free (required >= {min_disk_mb} MB)."
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
            recommended_action="" if disk_ok else f"Free at least {min_disk_mb} MB on Windows VM disk.",
        )
    )

    # Privilege context (informational, never auto-elevates!)
    is_admin = False
    if is_win:
        try:
            import ctypes

            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    checks.append(
        make_check(
            name="privilege_context",
            category="os",
            required=False,
            status=STATUS_PASS,
            detected_version="Administrator/Elevated" if is_admin else "Standard User",
            installed=True,
            runtime_verified=True,
            feature_verified=True,
            diagnostic_message=(
                "Running elevated (Procmon/Security log/WinPmem privileges available; note samples should normally run non-elevated)."
                if is_admin
                else "Running as Standard User (recommended for sample isolation; Procmon, Security EVTX, and WinPmem are unavailable or limited without elevation)."
            ),
        )
    )

    # === 2. Static Analysis Tools ===
    try:
        h_val = hashlib.sha256(b"MalBoxReadinessFixture").hexdigest()
        checks.append(
            make_check(
                name="hashlib_static",
                category="static",
                required=True,
                status=STATUS_PASS if len(h_val) == 64 else STATUS_FAIL,
                detected_version="stdlib",
                installed=True,
                runtime_verified=True,
                feature_verified=True,
                diagnostic_message="SHA-256 fixture hash probe succeeded.",
            )
        )
    except Exception as exc:
        checks.append(
            make_check(name="hashlib_static", category="static", required=True, status=STATUS_FAIL, diagnostic_message=str(exc))
        )

    # pefile synthetic fixture probe inside .venv
    if venv_ok:
        pe_fixture_hex = build_synthetic_pe_fixture().hex()
        pe_code = (
            "import json, pefile\n"
            f"pe = pefile.PE(data=bytes.fromhex({pe_fixture_hex!r}), fast_load=True)\n"
            "print(json.dumps({'ver': getattr(pefile, '__version__', 'installed'), 'machine': hex(pe.FILE_HEADER.Machine)}))\n"
            "pe.close()\n"
        )
        pe_res = run_bounded([str(venv_python), "-c", pe_code], timeout=10.0)
        if pe_res["returncode"] == 0 and pe_res["stdout"]:
            try:
                pe_info = json.loads(pe_res["stdout"].splitlines()[-1])
                checks.append(
                    make_check(
                        name="pefile_static",
                        category="static",
                        required=True,
                        status=STATUS_PASS,
                        detected_version=pe_info.get("ver"),
                        installed=True,
                        runtime_verified=True,
                        feature_verified=True,
                        diagnostic_message=f"pefile parsed synthetic in-memory PE header (Machine={pe_info.get('machine')}).",
                    )
                )
            except ValueError as exc:
                checks.append(
                    make_check(
                        name="pefile_static",
                        category="static",
                        required=True,
                        status=STATUS_FAIL,
                        diagnostic_message=f"pefile probe output parse failed: {exc}",
                    )
                )
        else:
            checks.append(
                make_check(
                    name="pefile_static",
                    category="static",
                    required=True,
                    status=STATUS_MISSING if "ModuleNotFoundError" in pe_res["stderr"] else STATUS_FAIL,
                    diagnostic_message=f"pefile fixture parse failed: {pe_res['stderr'] or pe_res['error']}",
                    recommended_action="Run .\\setup.ps1 to install pefile.",
                )
            )
    else:
        checks.append(
            make_check(
                name="pefile_static",
                category="static",
                required=True,
                status=STATUS_MISSING,
                diagnostic_message="Skipped pefile probe: valid .venv missing.",
                recommended_action="Run .\\setup.ps1.",
            )
        )

    # FLOSS
    floss_bin = resolve_tool(tools_cfg.get("floss"), ["floss.exe", "floss"])
    if floss_bin:
        f_res = run_bounded([str(floss_bin), "--version"], timeout=15.0)
        f_ver = (f_res["stdout"] or f_res["stderr"]).splitlines()[0][:120] if (f_res["stdout"] or f_res["stderr"]) else None
        f_ok = f_res["returncode"] == 0
        checks.append(
            make_check(
                name="floss",
                category="static",
                required=True,
                status=STATUS_PASS if f_ok else STATUS_FAIL,
                detected_version=f_ver,
                configured_path=str(tools_cfg.get("floss")),
                resolved_path=str(floss_bin),
                installed=True,
                runtime_verified=f_ok,
                diagnostic_message=f"FLOSS responded ({f_ver})." if f_ok else f"FLOSS --version failed: {f_res['stderr'] or f_res['error']}",
                recommended_action="" if f_ok else "Verify official FLOSS binary at tools\\floss\\floss.exe.",
            )
        )
    else:
        checks.append(
            make_check(
                name="floss",
                category="static",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("floss")),
                diagnostic_message="floss.exe not found (built-in Python string extractor handles basic ASCII/UTF-16LE fallback only; stack/decoded strings unavailable).",
                recommended_action="Download official FLOSS release zip to tools\\floss\\floss.exe.",
            )
        )

    # capa + capa-rules
    capa_bin = resolve_tool(tools_cfg.get("capa"), ["capa.exe", "capa"])
    if capa_bin:
        c_res = run_bounded([str(capa_bin), "--version"], timeout=15.0)
        c_ver = (c_res["stdout"] or c_res["stderr"]).splitlines()[0][:120] if (c_res["stdout"] or c_res["stderr"]) else None
        c_ok = c_res["returncode"] == 0
        checks.append(
            make_check(
                name="capa",
                category="static",
                required=True,
                status=STATUS_PASS if c_ok else STATUS_FAIL,
                detected_version=c_ver,
                configured_path=str(tools_cfg.get("capa")),
                resolved_path=str(capa_bin),
                installed=True,
                runtime_verified=c_ok,
                diagnostic_message=f"capa responded ({c_ver})." if c_ok else f"capa --version failed: {c_res['stderr'] or c_res['error']}",
                recommended_action="" if c_ok else "Verify official capa.exe at tools\\capa\\capa.exe.",
            )
        )
    else:
        checks.append(
            make_check(
                name="capa",
                category="static",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("capa")),
                diagnostic_message="capa.exe not found.",
                recommended_action="Download official capa release zip to tools\\capa\\capa.exe.",
            )
        )

    capa_rules_dir = resolve_cfg_path(tools_cfg.get("capa_rules"))
    capa_commit = get_git_commit(capa_rules_dir)
    if capa_commit:
        cloned_repos["capa-rules"] = capa_commit
    if capa_rules_dir and capa_rules_dir.is_dir():
        yml_count = sum(1 for _ in capa_rules_dir.rglob("*.yml"))
        rules_ok = yml_count > 0
        checks.append(
            make_check(
                name="capa_rules",
                category="static",
                required=True,
                status=STATUS_PASS if rules_ok else STATUS_FAIL,
                detected_version=f"{yml_count} rules (commit={capa_commit or 'unknown'})",
                configured_path=str(tools_cfg.get("capa_rules")),
                resolved_path=str(capa_rules_dir),
                installed=True,
                runtime_verified=rules_ok,
                feature_verified=rules_ok,
                diagnostic_message=f"Found {yml_count} YAML rules in capa-rules." if rules_ok else "capa-rules folder has no .yml rules.",
                recommended_action="" if rules_ok else "Run .\\setup.ps1 -CloneGitTools to clone mandiant/capa-rules.",
            )
        )
    else:
        checks.append(
            make_check(
                name="capa_rules",
                category="static",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("capa_rules")),
                diagnostic_message="capa-rules directory not found.",
                recommended_action="Run .\\setup.ps1 -CloneGitTools (while online) to clone capa-rules.",
            )
        )

    # yara-python & rule compilation inside .venv
    yara_rules_dir = resolve_cfg_path(tools_cfg.get("yara_rules_dir"))
    yar_files = sorted(list(yara_rules_dir.glob("*.yar")) + list(yara_rules_dir.glob("*.yara"))) if (yara_rules_dir and yara_rules_dir.is_dir()) else []
    if venv_ok:
        yar_strs = [str(p) for p in yar_files]
        y_code = (
            "import json, yara\n"
            f"files = {yar_strs!r}\n"
            "ver = getattr(yara, '__version__', 'installed')\n"
            "if not files:\n"
            "    print(json.dumps({'ver': ver, 'rules': 0, 'hits': 0}))\n"
            "else:\n"
            "    fp = {f'r_{i}': p for i, p in enumerate(files)}\n"
            "    c = yara.compile(filepaths=fp)\n"
            "    m = c.match(data=b'MZ\\x90\\x00MalBoxFixture')\n"
            "    print(json.dumps({'ver': ver, 'rules': len(files), 'hits': len(m)}))\n"
        )
        y_res = run_bounded([str(venv_python), "-c", y_code], timeout=12.0)
        if y_res["returncode"] == 0 and y_res["stdout"]:
            try:
                y_info = json.loads(y_res["stdout"].splitlines()[-1])
            except ValueError as exc:
                y_info = None
                checks.append(
                    make_check(
                        name="yara_python",
                        category="static",
                        required=True,
                        status=STATUS_FAIL,
                        diagnostic_message=f"yara-python probe output parse failed: {exc}",
                    )
                )
            if y_info is None:
                pass
            elif y_info["rules"] == 0:
                checks.append(
                    make_check(
                        name="yara_python",
                        category="static",
                        required=True,
                        status=STATUS_FAIL,
                        detected_version=y_info["ver"],
                        configured_path=str(tools_cfg.get("yara_rules_dir")),
                        installed=True,
                        runtime_verified=True,
                        diagnostic_message="yara-python imported, but no .yar/.yara rules found in yara_rules_dir.",
                        recommended_action="Restore scripts\\yara_rules\\baseline.yar or add .yar rules.",
                    )
                )
            else:
                checks.append(
                    make_check(
                        name="yara_python",
                        category="static",
                        required=True,
                        status=STATUS_PASS,
                        detected_version=y_info["ver"],
                        configured_path=str(tools_cfg.get("yara_rules_dir")),
                        resolved_path=str(yara_rules_dir),
                        installed=True,
                        runtime_verified=True,
                        feature_verified=True,
                        diagnostic_message=f"yara-python {y_info['ver']} compiled {y_info['rules']} rule file(s) and matched harmless MZ fixture ({y_info['hits']} hit).",
                    )
                )
        else:
            checks.append(
                make_check(
                    name="yara_python",
                    category="static",
                    required=True,
                    status=STATUS_MISSING if "ModuleNotFoundError" in y_res["stderr"] else STATUS_FAIL,
                    diagnostic_message=f"yara-python check failed: {y_res['stderr'] or y_res['error']}",
                    recommended_action="Fix YARA rules or run .\\setup.ps1 to install yara-python.",
                )
            )
    else:
        checks.append(
            make_check(
                name="yara_python",
                category="static",
                required=True,
                status=STATUS_MISSING,
                diagnostic_message="Skipped yara-python probe: valid .venv missing.",
                recommended_action="Run .\\setup.ps1.",
            )
        )

    # Optional YARA CLI
    yara_cli = resolve_tool(tools_cfg.get("yara"), ["yara64.exe", "yara64", "yara"])
    if yara_cli:
        yc = run_bounded([str(yara_cli), "--version"], timeout=10.0)
        yc_ver = yc["stdout"].splitlines()[0] if yc["stdout"] else None
        checks.append(
            make_check(
                name="yara_cli_optional",
                category="static",
                required=False,
                status=STATUS_PASS if yc["returncode"] == 0 else STATUS_FAIL,
                detected_version=yc_ver,
                configured_path=str(tools_cfg.get("yara")),
                resolved_path=str(yara_cli),
                installed=True,
                runtime_verified=yc["returncode"] == 0,
                diagnostic_message=f"Optional YARA CLI {yc_ver}" if yc["returncode"] == 0 else f"YARA CLI probe failed: {yc['stderr']}",
                unavailable_evidence_if_missing="CLI fallback only; static/yara.json remains available via yara-python.",
            )
        )
    else:
        checks.append(
            make_check(
                name="yara_cli_optional",
                category="static",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("yara")),
                diagnostic_message="Optional YARA CLI not installed (static/yara.json remains available via yara-python).",
                unavailable_evidence_if_missing="CLI fallback only; static/yara.json remains available via yara-python.",
            )
        )

    # Optional Detect It Easy (diec)
    die_cli = resolve_tool(tools_cfg.get("die"), ["diec.exe", "diec"])
    if die_cli:
        dc = run_bounded([str(die_cli), "--version"], timeout=10.0)
        dc_ver = dc["stdout"].splitlines()[0] if dc["stdout"] else None
        checks.append(
            make_check(
                name="detect_it_easy_optional",
                category="static",
                required=False,
                status=STATUS_PASS if dc["returncode"] == 0 else STATUS_FAIL,
                detected_version=dc_ver,
                configured_path=str(tools_cfg.get("die")),
                resolved_path=str(die_cli),
                installed=True,
                runtime_verified=dc["returncode"] == 0,
                diagnostic_message=(
                    f"Optional Detect It Easy CLI {dc_ver}"
                    if dc["returncode"] == 0
                    else f"Detect It Easy probe failed: {dc['stderr']}"
                ),
                unavailable_evidence_if_missing=(
                    "Optional DIE compiler/packer signatures (static/die.json) unavailable; "
                    "PE metadata and file signatures remain active."
                ),
            )
        )
    else:
        checks.append(
            make_check(
                name="detect_it_easy_optional",
                category="static",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("die")),
                diagnostic_message=(
                    "Optional Detect It Easy CLI (diec) not installed "
                    "(static/hashes.json and static/pe_info.json remain active)."
                ),
                unavailable_evidence_if_missing=(
                    "Optional DIE compiler/packer signatures (static/die.json) unavailable; "
                    "PE metadata and file signatures remain active."
                ),
            )
        )

    # Java runtime + Separated Ghidra Headless checks (installation vs version/JDK compat vs launcher/functional verification)
    java_bin = shutil.which("java")
    java_ver_str = None
    java_major = None
    java_ok = False
    if java_bin:
        jr = run_bounded([java_bin, "-version"], timeout=10.0)
        combined = f"{jr['stderr']}\n{jr['stdout']}".strip()
        java_ver_str = combined.splitlines()[0][:120] if combined else None
        java_major = parse_java_major(combined)
        java_ok = jr["returncode"] == 0 and java_major is not None

    checks.append(
        make_check(
            name="java_runtime",
            category="static",
            required=True,
            status=STATUS_PASS if (java_ok and (java_major or 0) >= 17) else (STATUS_MISSING if not java_bin else STATUS_FAIL),
            detected_version=java_ver_str,
            resolved_path=java_bin,
            installed=bool(java_bin),
            runtime_verified=java_ok,
            diagnostic_message=java_ver_str or "Java executable not found in PATH.",
            recommended_action="" if (java_ok and (java_major or 0) >= 17) else "Install JDK 17 or JDK 21 (x64) and ensure java is on PATH.",
        )
    )

    ghidra_bin = resolve_tool(tools_cfg.get("ghidra_headless"), ["analyzeHeadless.bat", "analyzeHeadless"])
    ghidra_script_dir = resolve_cfg_path(tools_cfg.get("ghidra_script_dir")) or (BASE_DIR / "scripts")
    ghidra_export_name = str(tools_cfg.get("ghidra_export_script") or "GhidraExport.java").strip()
    ghidra_script = ghidra_script_dir / ghidra_export_name
    ghidra_script_exists = ghidra_script.is_file()
    ghidra_script_syntax_ok, ghidra_script_err = check_ghidra_script_syntax(ghidra_script) if ghidra_script_exists else (False, "missing")
    ghidra_root_valid = bool(ghidra_bin and (ghidra_bin.parent.parent / "Ghidra").is_dir())
    ghidra_installed = bool(ghidra_bin) and ghidra_root_valid and ghidra_script_exists

    # Stage A: Ghidra Headless installation check (never equates file existence with verified functionality)
    if ghidra_installed and ghidra_script_syntax_ok:
        checks.append(
            make_check(
                name="ghidra_headless_install",
                category="static",
                required=True,
                status=STATUS_PASS,
                configured_path=str(tools_cfg.get("ghidra_headless")),
                resolved_path=str(ghidra_bin),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                verification_stages={
                    "binary_present": True,
                    "ghidra_home_present": True,
                    "export_script_present": True,
                    "export_script_name": ghidra_export_name,
                    "export_script_structure_valid": True,
                },
                diagnostic_message=(
                    f"Ghidra headless binary and scripts/{ghidra_export_name} exist with valid static structure "
                    "(installation check only; compilation and export require Ghidra Headless execution on VM)."
                ),
            )
        )
    elif ghidra_installed and not ghidra_script_syntax_ok:
        checks.append(
            make_check(
                name="ghidra_headless_install",
                category="static",
                required=True,
                status=STATUS_FAIL,
                configured_path=str(tools_cfg.get("ghidra_headless")),
                resolved_path=str(ghidra_bin),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=f"scripts/{ghidra_export_name} structure/syntax check failed: {ghidra_script_err}",
                recommended_action=f"Restore scripts/{ghidra_export_name} from repository.",
            )
        )
    else:
        missing_parts = []
        if not ghidra_bin:
            missing_parts.append("analyzeHeadless binary")
        elif not ghidra_root_valid:
            missing_parts.append("Ghidra/ layout directory next to support/")
        if not ghidra_script_exists:
            missing_parts.append(f"scripts/{ghidra_export_name}")
        checks.append(
            make_check(
                name="ghidra_headless_install",
                category="static",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("ghidra_headless")),
                resolved_path=str(ghidra_bin) if ghidra_bin else None,
                installed=bool(ghidra_bin),
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=f"Ghidra Headless installation incomplete: missing {', '.join(missing_parts)}.",
                recommended_action=f"Extract official Ghidra release to tools\\ghidra\\ (with scripts\\{ghidra_export_name} present).",
            )
        )

    # Stage B: Ghidra version detection & JDK compatibility (supports Ghidra 10/11/12 + application.java.min)
    ghidra_ver, ghidra_prop_java_min = get_ghidra_props(ghidra_bin)
    compat_ok = False
    compat_msg = ""
    if not ghidra_bin:
        compat_msg = "Ghidra binary missing; version & JDK compatibility cannot be checked."
        checks.append(
            make_check(
                name="ghidra_version_compat",
                category="static",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("ghidra_headless")),
                installed=False,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=compat_msg,
                recommended_action="Install official Ghidra release first.",
            )
        )
    else:
        if not ghidra_ver:
            compat_msg = "Ghidra/application.properties missing or application.version unreadable; version compatibility unverified."
        elif not java_ok or java_major is None:
            compat_msg = f"Ghidra {ghidra_ver} detected, but Java runtime is missing or failed `java -version`."
        else:
            m = re.match(r"(\d+)\.(\d+)", ghidra_ver)
            if not m:
                compat_msg = f"Unrecognized Ghidra version '{ghidra_ver}'; JDK compatibility unverified."
            else:
                g_maj, g_min = int(m.group(1)), int(m.group(2))
                req_jdk = ghidra_prop_java_min
                if req_jdk is None:
                    if (g_maj > 12) or (g_maj == 12 and g_min >= 2):
                        req_jdk = 25
                    elif (g_maj == 12) or (g_maj == 11 and g_min >= 2):
                        req_jdk = 21
                    else:
                        req_jdk = 17
                if java_major < req_jdk:
                    compat_msg = f"Ghidra {ghidra_ver} requires JDK {req_jdk}+, detected JDK {java_major}."
                else:
                    compat_ok = True

        checks.append(
            make_check(
                name="ghidra_version_compat",
                category="static",
                required=True,
                status=STATUS_PASS if compat_ok else STATUS_FAIL,
                detected_version=f"Ghidra {ghidra_ver or 'unknown'} / JDK {java_major or 'N/A'}",
                configured_path=str(tools_cfg.get("ghidra_headless")),
                resolved_path=str(ghidra_bin),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=(
                    f"Ghidra {ghidra_ver} and JDK {java_major} version metadata match requirements (functional export not tested here)."
                    if compat_ok
                    else compat_msg
                ),
                recommended_action="" if compat_ok else (compat_msg or "Verify Ghidra version and compatible JDK installation."),
            )
        )

    # Stage C: Honest Ghidra Headless launcher & functional verification reporting
    if ghidra_installed and compat_ok and ghidra_bin:
        g_probe = run_bounded([str(ghidra_bin), "-help"], timeout=20.0)
        rc = g_probe["returncode"]
        probe_out = f"{g_probe['stdout']}\n{g_probe['stderr']}"
        lower_out = probe_out.lower()
        fatal_markers = (
            "unsupportedclassversionerror",
            "could not find",
            "is not recognized",
            "exception in thread",
            "java_home",
            "error occurred during initialization of vm",
        )
        has_fatal = g_probe["timed_out"] or bool(g_probe["error"]) or any(tok in lower_out for tok in fatal_markers)
        # Specific HeadlessAnalyzer CLI flags (not generic "usage:" or filename echo)
        has_specific_cli_flags = all(opt in lower_out for opt in ("-import", "-postscript", "-deleteproject"))

        if has_fatal or rc not in (0, 1) or not has_specific_cli_flags:
            err_hint = (
                g_probe["error"]
                or (probe_out.splitlines()[0][:140] if probe_out else f"exit code {rc}")
            )
            checks.append(
                make_check(
                    name="ghidra_headless_verification",
                    category="static",
                    required=True,
                    status=STATUS_FAIL,
                    detected_version=f"exit_code={rc}",
                    configured_path=str(tools_cfg.get("ghidra_headless")),
                    resolved_path=str(ghidra_bin),
                    installed=True,
                    runtime_verified=False,
                    feature_verified=False,
                    verification_stages={
                        "installed": True,
                        "version_compatible": True,
                        "launcher_exit_zero": False,
                        "specific_cli_flags_seen": has_specific_cli_flags,
                        "functional_export_verified": False,
                    },
                    diagnostic_message=(
                        f"Ghidra analyzeHeadless probe failed or did not emit HeadlessAnalyzer CLI options "
                        f"(exit_code={rc}; detail={err_hint})."
                    ),
                    recommended_action="Inspect JDK/Ghidra path and run analyzeHeadless.bat manually on Windows 11.",
                )
            )
        elif rc == 0:
            checks.append(
                make_check(
                    name="ghidra_headless_verification",
                    category="static",
                    required=False,
                    status=STATUS_PENDING,
                    detected_version=f"exit_code=0 (launcher only)",
                    configured_path=str(tools_cfg.get("ghidra_headless")),
                    resolved_path=str(ghidra_bin),
                    installed=True,
                    runtime_verified=True,
                    feature_verified=False,
                    verification_stages={
                        "installed": True,
                        "version_compatible": True,
                        "launcher_exit_zero": True,
                        "specific_cli_flags_seen": True,
                        "functional_export_verified": False,
                    },
                    diagnostic_message=(
                        f"analyzeHeadless -help exited 0 and displayed HeadlessAnalyzer options, but end-to-end binary "
                        f"import, auto-analysis, and scripts/{ghidra_export_name} export remain UNVERIFIED until VM testing."
                    ),
                    recommended_action="Verify full Ghidra Headless export on VM using a harmless test binary.",
                    unavailable_evidence_if_missing="If Ghidra Headless fails at runtime, ghidra/functions.json, disassembly.txt, and decompiled/*.c are unavailable.",
                )
            )
        else:
            # rc == 1 with specific HeadlessAnalyzer usage flags: NEVER promote non-zero exit code to PASS/runtime_verified
            checks.append(
                make_check(
                    name="ghidra_headless_verification",
                    category="static",
                    required=False,
                    status=STATUS_PENDING,
                    detected_version=f"exit_code={rc} (unsuccessful exit code)",
                    configured_path=str(tools_cfg.get("ghidra_headless")),
                    resolved_path=str(ghidra_bin),
                    installed=True,
                    runtime_verified=False,
                    feature_verified=False,
                    verification_stages={
                        "installed": True,
                        "version_compatible": True,
                        "launcher_exit_zero": False,
                        "specific_cli_flags_seen": True,
                        "functional_export_verified": False,
                    },
                    diagnostic_message=(
                        f"analyzeHeadless -help exited {rc} (unsuccessful exit code; normal for Ghidra CLI usage banner, "
                        f"NOT proof of verified execution). Runtime execution and scripts/{ghidra_export_name} export remain UNVERIFIED until VM testing."
                    ),
                    recommended_action="Verify full Ghidra Headless export on VM using a harmless test binary.",
                    unavailable_evidence_if_missing="If Ghidra Headless fails at runtime, ghidra/functions.json, disassembly.txt, and decompiled/*.c are unavailable.",
                )
            )
    else:
        checks.append(
            make_check(
                name="ghidra_headless_verification",
                category="static",
                required=False,
                status=STATUS_SKIPPED,
                installed=ghidra_installed,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message="Skipped Ghidra launcher probe because installation or JDK compatibility prerequisites failed.",
                recommended_action="Fix ghidra_headless_install and ghidra_version_compat first.",
            )
        )

    # === 3. Process & System Monitoring Tools ===
    sysmon_bin = resolve_tool(tools_cfg.get("sysmon"), ["Sysmon64.exe", "Sysmon.exe"])
    sysmon_ver = get_windows_file_version(sysmon_bin) if sysmon_bin else None
    checks.append(
        make_check(
            name="sysmon_executable",
            category="process",
            required=True,
            status=STATUS_PASS if sysmon_bin else STATUS_MISSING,
            detected_version=sysmon_ver,
            configured_path=str(tools_cfg.get("sysmon")),
            resolved_path=str(sysmon_bin) if sysmon_bin else None,
            installed=bool(sysmon_bin),
            runtime_verified=bool(sysmon_ver),
            diagnostic_message=f"Sysmon binary present ({sysmon_bin})." if sysmon_bin else "Sysmon64.exe not found.",
            recommended_action="" if sysmon_bin else "Download Sysinternals Sysmon64.exe to tools\\sysinternals\\.",
        )
    )

    svc_state, svc_name = query_windows_service(["Sysmon64", "Sysmon"])
    svc_running = svc_state == "RUNNING"
    checks.append(
        make_check(
            name="sysmon_service",
            category="process",
            required=True,
            status=STATUS_PASS if svc_running else (STATUS_MISSING if svc_state == "NOT_INSTALLED" else STATUS_FAIL),
            detected_version=svc_state,
            configured_path=svc_name,
            installed=svc_state != "NOT_INSTALLED",
            runtime_verified=svc_running,
            diagnostic_message=f"Windows service {svc_name} state: {svc_state}.",
            recommended_action="" if svc_running else "In Admin PowerShell run: .\\tools\\sysinternals\\Sysmon64.exe -accepteula -i .\\configs\\sysmon.xml",
        )
    )

    if is_win:
        ev_chk = run_bounded(
            ["wevtutil.exe", "qe", "Microsoft-Windows-Sysmon/Operational", "/c:1", "/f:text"],
            timeout=10.0,
        )
        ch_exists = run_bounded(["wevtutil.exe", "gl", "Microsoft-Windows-Sysmon/Operational"], timeout=10.0)
        sysmon_ch_ok = ch_exists["returncode"] == 0 and ev_chk["returncode"] == 0
        checks.append(
            make_check(
                name="sysmon_eventlog_channel",
                category="process",
                required=True,
                status=STATUS_PASS if sysmon_ch_ok else STATUS_FAIL,
                configured_path="Microsoft-Windows-Sysmon/Operational",
                installed=ch_exists["returncode"] == 0,
                runtime_verified=ch_exists["returncode"] == 0,
                feature_verified=sysmon_ch_ok,
                diagnostic_message=(
                    "Sysmon Operational channel exists and is readable."
                    if sysmon_ch_ok
                    else f"Sysmon channel probe failed: {ev_chk['stderr'] or ch_exists['stderr'] or ev_chk['error']}"
                ),
                recommended_action="" if sysmon_ch_ok else "Ensure Sysmon64 is installed and current user can read Microsoft-Windows-Sysmon/Operational (or add user to Event Log Readers).",
            )
        )

        # Standard Windows Event Logs (non-destructive wevtutil read check)
        sys_chk = run_bounded(["wevtutil.exe", "qe", "System", "/c:1", "/f:text"], timeout=10.0)
        app_chk = run_bounded(["wevtutil.exe", "qe", "Application", "/c:1", "/f:text"], timeout=10.0)
        sec_chk = run_bounded(["wevtutil.exe", "qe", "Security", "/c:1", "/f:text"], timeout=10.0)
        core_ev_ok = sys_chk["returncode"] == 0 and app_chk["returncode"] == 0
        sec_note = (
            "Security channel readable"
            if sec_chk["returncode"] == 0
            else "Security channel denied (normal for standard user; security.evtx unavailable unless elevated)"
        )
        checks.append(
            make_check(
                name="windows_event_logs",
                category="process",
                required=True,
                status=STATUS_PASS if core_ev_ok else STATUS_FAIL,
                installed=True,
                runtime_verified=core_ev_ok,
                feature_verified=core_ev_ok,
                diagnostic_message=f"System/Application logs readable ({sec_note}).",
                recommended_action="" if core_ev_ok else "Verify wevtutil.exe permissions on System and Application logs.",
            )
        )
    else:
        checks.append(
            make_check(
                name="sysmon_eventlog_channel",
                category="process",
                required=True,
                status=STATUS_MISSING,
                diagnostic_message="Windows Event Log channels unavailable on non-Windows host.",
                recommended_action="Run on Windows 11 VM.",
            )
        )
        checks.append(
            make_check(
                name="windows_event_logs",
                category="process",
                required=True,
                status=STATUS_MISSING,
                diagnostic_message="wevtutil.exe Windows Event Logs unavailable on non-Windows host.",
                recommended_action="Run on Windows 11 VM.",
            )
        )

    # psutil probe inside .venv
    if venv_ok:
        ps_code = (
            "import json, os, psutil\n"
            "vm = psutil.virtual_memory()\n"
            "pname = psutil.Process(os.getpid()).name()\n"
            "print(json.dumps({'ver': getattr(psutil, '__version__', 'installed'), 'pname': pname, 'pct': vm.percent}))\n"
        )
        ps_res = run_bounded([str(venv_python), "-c", ps_code], timeout=10.0)
        if ps_res["returncode"] == 0 and ps_res["stdout"]:
            try:
                ps_info = json.loads(ps_res["stdout"].splitlines()[-1])
            except ValueError as exc:
                ps_info = None
                checks.append(
                    make_check(
                        name="psutil_monitor",
                        category="process",
                        required=True,
                        status=STATUS_FAIL,
                        diagnostic_message=f"psutil probe output parse failed: {exc}",
                    )
                )
            if ps_info is not None:
                checks.append(
                    make_check(
                        name="psutil_monitor",
                        category="process",
                        required=True,
                        status=STATUS_PASS,
                        detected_version=ps_info.get("ver"),
                        installed=True,
                        runtime_verified=True,
                        feature_verified=True,
                        diagnostic_message=f"psutil probed self process '{ps_info.get('pname')}' & RAM ({ps_info.get('pct')}% used).",
                    )
                )
        else:
            checks.append(
                make_check(
                    name="psutil_monitor",
                    category="process",
                    required=True,
                    status=STATUS_MISSING if "ModuleNotFoundError" in ps_res["stderr"] else STATUS_FAIL,
                    diagnostic_message=f"psutil failed: {ps_res['stderr'] or ps_res['error']}",
                    recommended_action="Run .\\setup.ps1.",
                )
            )
    else:
        checks.append(
            make_check(
                name="psutil_monitor",
                category="process",
                required=True,
                status=STATUS_MISSING,
                diagnostic_message="Skipped psutil probe: valid .venv missing.",
                recommended_action="Run .\\setup.ps1.",
            )
        )

    # Optional Procmon (never loads driver or pops EULA dialog in readiness check)
    procmon_bin = resolve_tool(tools_cfg.get("procmon"), ["Procmon64.exe", "Procmon.exe"])
    procmon_unavail_msg = (
        "raw/procmon.pml and Procmon-derived filesystem/registry rows unavailable "
        "(Sysmon EID 11/12/13/14/23 continues providing file and registry coverage)."
    )
    if procmon_bin:
        pm_ver = get_windows_file_version(procmon_bin)
        pm_eula = check_sysinternals_eula("Process Monitor")
        checks.append(
            make_check(
                name="procmon_optional",
                category="process",
                required=False,
                status=STATUS_PENDING if is_admin else STATUS_OPTIONAL,
                detected_version=pm_ver,
                configured_path=str(tools_cfg.get("procmon")),
                resolved_path=str(procmon_bin),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=(
                    f"Procmon binary present (ver={pm_ver or 'N/A'}, hkcu_eula={pm_eula}, admin={is_admin}); "
                    "driver not loaded during non-destructive check."
                ),
                recommended_action=(
                    "Optional: Run Procmon64.exe once to accept EULA if using elevated capture; driver requires Admin privilege."
                    if (is_admin and pm_eula is False)
                    else ("Optional: Running non-admin; Procmon kernel capture skipped, Sysmon provides coverage." if not is_admin else "")
                ),
                unavailable_evidence_if_missing=procmon_unavail_msg,
            )
        )
    else:
        checks.append(
            make_check(
                name="procmon_optional",
                category="process",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("procmon")),
                diagnostic_message="Optional Procmon64.exe not installed (Sysmon provides process/file/registry coverage).",
                unavailable_evidence_if_missing=procmon_unavail_msg,
            )
        )

    # Optional ProcDump (only invokes `-?` if HKCU EULA already accepted so CheckOnly never hangs or edits HKCU)
    procdump_bin = resolve_tool(tools_cfg.get("procdump"), ["procdump64.exe", "procdump.exe"])
    procdump_unavail_msg = (
        "User-mode process memory minidumps (dynamic/memory/dumps/proc_<pid>.dmp) unavailable "
        "(psutil RAM telemetry in memory_usage.json remains available)."
    )
    if procdump_bin:
        pd_eula = check_sysinternals_eula("ProcDump")
        pd_fver = get_windows_file_version(procdump_bin)
        if not is_win:
            checks.append(
                make_check(
                    name="procdump_optional",
                    category="memory",
                    required=False,
                    status=STATUS_PENDING,
                    detected_version=pd_fver,
                    configured_path=str(tools_cfg.get("procdump")),
                    resolved_path=str(procdump_bin),
                    installed=True,
                    runtime_verified=False,
                    diagnostic_message="ProcDump file found on non-Windows host; runtime unverified.",
                    unavailable_evidence_if_missing=procdump_unavail_msg,
                )
            )
        elif pd_eula is False:
            checks.append(
                make_check(
                    name="procdump_optional",
                    category="memory",
                    required=False,
                    status=STATUS_PENDING,
                    detected_version=pd_fver,
                    configured_path=str(tools_cfg.get("procdump")),
                    resolved_path=str(procdump_bin),
                    installed=True,
                    runtime_verified=False,
                    diagnostic_message=(
                        f"ProcDump present (ver={pd_fver or 'N/A'}), but HKCU Sysinternals EULA is not accepted yet; "
                        "skipping binary launch in non-modifying probe to avoid modal GUI prompt."
                    ),
                    recommended_action="Optional: Run `procdump64.exe -accepteula -?` once before taking CLEAN snapshot.",
                    unavailable_evidence_if_missing=procdump_unavail_msg,
                )
            )
        else:
            pd_res = run_bounded([str(procdump_bin), "-?"], timeout=10.0)
            pd_banner = (pd_res["stdout"] or pd_res["stderr"]).splitlines()[0][:120] if (pd_res["stdout"] or pd_res["stderr"]) else pd_fver
            pd_ok = bool(pd_banner and "procdump" in pd_banner.lower())
            checks.append(
                make_check(
                    name="procdump_optional",
                    category="memory",
                    required=False,
                    status=STATUS_PASS if pd_ok else STATUS_FAIL,
                    detected_version=pd_banner,
                    configured_path=str(tools_cfg.get("procdump")),
                    resolved_path=str(procdump_bin),
                    installed=True,
                    runtime_verified=pd_ok,
                    diagnostic_message=f"ProcDump responded ({pd_banner}); no arbitrary process dumped." if pd_ok else "ProcDump probe failed.",
                    unavailable_evidence_if_missing=procdump_unavail_msg,
                )
            )
    else:
        checks.append(
            make_check(
                name="procdump_optional",
                category="memory",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("procdump")),
                diagnostic_message="Optional procdump64.exe not installed (RAM telemetry still available via psutil).",
                unavailable_evidence_if_missing=procdump_unavail_msg,
            )
        )

    # === 4. Network Monitoring Tools ===
    dumpcap_bin = resolve_tool(tools_cfg.get("dumpcap"), ["dumpcap.exe", "dumpcap"])
    tshark_bin = resolve_tool(tools_cfg.get("tshark"), ["tshark.exe", "tshark"])

    if dumpcap_bin:
        dc_res = run_bounded([str(dumpcap_bin), "--version"], timeout=10.0)
        dc_ver = dc_res["stdout"].splitlines()[0][:120] if dc_res["stdout"] else None
        dc_ok = dc_res["returncode"] == 0
        checks.append(
            make_check(
                name="wireshark_dumpcap",
                category="network",
                required=True,
                status=STATUS_PASS if dc_ok else STATUS_FAIL,
                detected_version=dc_ver,
                configured_path=str(tools_cfg.get("dumpcap")),
                resolved_path=str(dumpcap_bin),
                installed=True,
                runtime_verified=dc_ok,
                diagnostic_message=dc_ver or f"dumpcap --version failed: {dc_res['stderr'] or dc_res['error']}",
                recommended_action="" if dc_ok else "Install official Wireshark + Npcap.",
            )
        )
    else:
        checks.append(
            make_check(
                name="wireshark_dumpcap",
                category="network",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("dumpcap")),
                diagnostic_message="Wireshark dumpcap.exe not found.",
                recommended_action="Install official Wireshark Windows release (includes Npcap).",
            )
        )

    if tshark_bin:
        ts_res = run_bounded([str(tshark_bin), "--version"], timeout=10.0)
        ts_ver = ts_res["stdout"].splitlines()[0][:120] if ts_res["stdout"] else None
        ts_ok = ts_res["returncode"] == 0
        checks.append(
            make_check(
                name="wireshark_tshark",
                category="network",
                required=True,
                status=STATUS_PASS if ts_ok else STATUS_FAIL,
                detected_version=ts_ver,
                configured_path=str(tools_cfg.get("tshark")),
                resolved_path=str(tshark_bin),
                installed=True,
                runtime_verified=ts_ok,
                diagnostic_message=ts_ver or f"tshark --version failed: {ts_res['stderr'] or ts_res['error']}",
                recommended_action="" if ts_ok else "Verify Wireshark installation.",
            )
        )
    else:
        checks.append(
            make_check(
                name="wireshark_tshark",
                category="network",
                required=True,
                status=STATUS_MISSING,
                configured_path=str(tools_cfg.get("tshark")),
                diagnostic_message="Wireshark tshark.exe not found.",
                recommended_action="Install official Wireshark Windows release.",
            )
        )

    npcap_state, npcap_name = query_windows_service(["npcap", "npf"])
    npcap_ok = npcap_state == "RUNNING"
    checks.append(
        make_check(
            name="npcap_driver",
            category="network",
            required=True,
            status=STATUS_PASS if npcap_ok else (STATUS_MISSING if npcap_state == "NOT_INSTALLED" else STATUS_FAIL),
            detected_version=npcap_state,
            configured_path=npcap_name,
            installed=npcap_state != "NOT_INSTALLED",
            runtime_verified=npcap_ok,
            diagnostic_message=f"Npcap driver service ({npcap_name}) state: {npcap_state}.",
            recommended_action="" if npcap_ok else "Install Npcap (via Wireshark installer) without restricting capture to Administrators only.",
        )
    )

    configured_iface = str(cfg["network_interface"])
    if dumpcap_bin:
        if_res = run_bounded([str(dumpcap_bin), "-D"], timeout=10.0)
        if if_res["returncode"] == 0 and if_res["stdout"]:
            iface_lines = [line.strip() for line in if_res["stdout"].splitlines() if line.strip()]
            non_loopback = [l for l in iface_lines if "loopback" not in l.lower()]
            if configured_iface:
                matched = any(
                    l.startswith(f"{configured_iface}.") or configured_iface.lower() in l.lower()
                    for l in iface_lines
                )
                checks.append(
                    make_check(
                        name="capture_interfaces",
                        category="network",
                        required=True,
                        status=STATUS_PASS if matched else STATUS_FAIL,
                        detected_version=f"{len(iface_lines)} interfaces",
                        configured_path=configured_iface,
                        installed=True,
                        runtime_verified=True,
                        feature_verified=matched,
                        diagnostic_message=(
                            f"Configured interface '{configured_iface}' found among {len(iface_lines)} dumpcap interfaces."
                            if matched
                            else f"Configured interface '{configured_iface}' not found in dumpcap -D output."
                        ),
                        recommended_action="" if matched else "Update network_interface in config.json based on dumpcap -D.",
                    )
                )
            elif non_loopback:
                checks.append(
                    make_check(
                        name="capture_interfaces",
                        category="network",
                        required=True,
                        status=STATUS_PASS,
                        detected_version=f"{len(non_loopback)} non-loopback interfaces",
                        installed=True,
                        runtime_verified=True,
                        feature_verified=True,
                        diagnostic_message=f"dumpcap -D detected {len(non_loopback)} non-loopback interface(s) for auto-selection.",
                    )
                )
            else:
                checks.append(
                    make_check(
                        name="capture_interfaces",
                        category="network",
                        required=False,
                        status=STATUS_PENDING,
                        detected_version=f"{len(iface_lines)} interfaces (loopback only)",
                        installed=True,
                        runtime_verified=True,
                        diagnostic_message="Only loopback capture interface detected; Internal Network 2 NIC may not be attached yet.",
                        recommended_action="Attach Internal Network 2 NIC and re-run setup.ps1 -CheckOnly.",
                        unavailable_evidence_if_missing="Off-host packet capture in dynamic/network/capture.pcapng requires a non-loopback capture adapter.",
                    )
                )
        else:
            checks.append(
                make_check(
                    name="capture_interfaces",
                    category="network",
                    required=True,
                    status=STATUS_FAIL,
                    diagnostic_message=f"dumpcap -D failed: {if_res['stderr'] or if_res['error'] or 'no interfaces listed'}",
                    recommended_action="Verify Npcap driver permissions for standard user capture.",
                )
            )

    # === 5. Memory Analysis Tools (Optional) ===
    winpmem_bin = resolve_tool(tools_cfg.get("winpmem"), ["winpmem.exe", "winpmem_mini_x64_rc2.exe"])
    winpmem_enabled = bool(cfg["winpmem_enabled"])
    winpmem_unavail_msg = (
        "Full physical RAM acquisition (dynamic/memory/dumps/physical_memory.raw) unavailable; "
        "RAM usage telemetry (psutil) and process dumps (ProcDump) remain independent."
    )
    if not winpmem_bin:
        checks.append(
            make_check(
                name="winpmem_optional",
                category="memory",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("winpmem")),
                installed=False,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=f"Optional WinPmem not installed (winpmem_enabled={winpmem_enabled}).",
                unavailable_evidence_if_missing=winpmem_unavail_msg,
            )
        )
    else:
        # Never mark PASS or verified just from binary presence — driver compatibility on Win 11 is NOT tested offline
        checks.append(
            make_check(
                name="winpmem_optional",
                category="memory",
                required=False,
                status=STATUS_PENDING if winpmem_enabled else STATUS_OPTIONAL,
                detected_version=get_windows_file_version(winpmem_bin),
                configured_path=str(tools_cfg.get("winpmem")),
                resolved_path=str(winpmem_bin),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message=(
                    f"WinPmem executable present (winpmem_enabled={winpmem_enabled}), but Windows 11 kernel driver "
                    "loading and acquisition are NOT verified offline."
                ),
                recommended_action=(
                    "Optional: Test WinPmem acquisition manually as Administrator on Windows 11 if full physical RAM dumps are desired."
                    if winpmem_enabled
                    else ""
                ),
                unavailable_evidence_if_missing=winpmem_unavail_msg,
            )
        )

    vol_script = resolve_cfg_path(tools_cfg.get("volatility3"))
    vol_sym_dir = resolve_cfg_path(tools_cfg.get("volatility_symbols_dir"))
    vol_commit = get_git_commit(vol_script.parent if vol_script else None)
    if vol_commit:
        cloned_repos["volatility3"] = vol_commit
    vol_unavail_msg = (
        "Offline physical RAM forensic tables (dynamic/memory/volatility/windows.{pslist,pstree,cmdline,netscan,malfind}.json) unavailable "
        "(Volatility 3 runs only when WinPmem full physical RAM dump succeeds)."
    )
    if vol_script and vol_script.is_file() and venv_ok:
        v_help = run_bounded([str(venv_python), str(vol_script), "--help"], timeout=15.0)
        sym_count = (
            sum(1 for _ in vol_sym_dir.rglob("*.json")) + sum(1 for _ in vol_sym_dir.rglob("*.zip"))
            if (vol_sym_dir and vol_sym_dir.is_dir())
            else 0
        )
        v_ok = v_help["returncode"] == 0
        checks.append(
            make_check(
                name="volatility3_optional",
                category="memory",
                required=False,
                status=STATUS_PASS if (v_ok and sym_count > 0) else (STATUS_PENDING if v_ok else STATUS_FAIL),
                detected_version=f"commit={vol_commit or 'unknown'}, symbols={sym_count}",
                configured_path=str(tools_cfg.get("volatility3")),
                resolved_path=str(vol_script),
                installed=True,
                runtime_verified=v_ok,
                feature_verified=False,
                diagnostic_message=(
                    f"Volatility 3 --help succeeded (offline symbols files={sym_count}; plugin analysis against a RAM image requires WinPmem dump)."
                    if v_ok
                    else f"Volatility 3 --help failed: {v_help['stderr'] or v_help['error']}"
                ),
                recommended_action="" if (v_ok and sym_count > 0) else "Pre-cache offline Windows ISF symbol packs under tools\\volatility3\\symbols\\ before isolating VM.",
                unavailable_evidence_if_missing=vol_unavail_msg,
            )
        )
    else:
        checks.append(
            make_check(
                name="volatility3_optional",
                category="memory",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("volatility3")),
                diagnostic_message="Optional Volatility 3 not cloned (requires full physical RAM dump from WinPmem).",
                unavailable_evidence_if_missing=vol_unavail_msg,
            )
        )

    # === 6. MalBox MCP & Optional GhidraMCP ===
    mcp_cfg_path = MCP_DIR / "config.json"
    mcp_ex_path = MCP_DIR / "config.example.json"
    mcp_cfg_ok = mcp_cfg_path.is_file()
    mcp_sdk_ver = pkg_versions.get("mcp")

    if venv_ok and mcp_sdk_ver and (MCP_DIR / "server.py").is_file():
        mcp_probe = probe_malbox_mcp(str(venv_python))
        discovered = set(mcp_probe.get("tools", []))
        missing_tools = sorted(EXPECTED_MCP_TOOLS - discovered)
        has_shell_tool = any("shell" in t.lower() or "exec" in t.lower() for t in discovered)
        mcp_pass = bool(mcp_probe.get("ok")) and not missing_tools and not has_shell_tool and mcp_cfg_ok
        diag = (
            f"MCP stdio handshake verified ({len(discovered)}/16 tools registered; config={'mcp/config.json' if mcp_cfg_ok else 'missing mcp/config.json'})."
            if mcp_probe.get("ok")
            else str(mcp_probe.get("error"))
        )
        if missing_tools and mcp_probe.get("ok"):
            diag += f" Missing tools: {missing_tools}."
        checks.append(
            make_check(
                name="malbox_mcp",
                category="mcp",
                required=True,
                status=STATUS_PASS if mcp_pass else STATUS_FAIL,
                detected_version=f"mcp=={mcp_sdk_ver} ({len(discovered)} tools)",
                configured_path=str(mcp_cfg_path if mcp_cfg_ok else mcp_ex_path),
                resolved_path=str(MCP_DIR / "server.py"),
                installed=True,
                runtime_verified=bool(mcp_probe.get("ok")),
                feature_verified=mcp_pass,
                diagnostic_message=diag,
                recommended_action="" if mcp_pass else "Run .\\setup.ps1 to generate mcp\\config.json and verify mcp SDK.",
            )
        )
    else:
        checks.append(
            make_check(
                name="malbox_mcp",
                category="mcp",
                required=True,
                status=STATUS_MISSING,
                resolved_path=str(MCP_DIR / "server.py"),
                diagnostic_message="MalBox MCP cannot be verified until valid .venv and mcp SDK are installed.",
                recommended_action="Run .\\setup.ps1 while online.",
            )
        )

    # Optional GhidraMCP (multi-stage; HTTP 200 alone NEVER equates to working MCP integration!)
    gmcp_dir = resolve_cfg_path(tools_cfg.get("ghidra_mcp_dir"))
    gmcp_commit = get_git_commit(gmcp_dir)
    if gmcp_commit:
        cloned_repos["GhidraMCP"] = gmcp_commit
    gmcp_bridge = (gmcp_dir / "bridge_mcp_ghidra.py") if gmcp_dir else None
    gmcp_bridge_present = bool(gmcp_bridge and gmcp_bridge.is_file())
    gmcp_dir_exists = bool(gmcp_dir and gmcp_dir.is_dir())
    gmcp_cloned = gmcp_dir_exists and (gmcp_bridge_present or (gmcp_dir / ".git").exists())

    gmcp_unavail_msg = (
        "Optional interactive Ghidra GUI MCP bridge unavailable; automated ghidra/ headless exports "
        "and MalBox's own 16-tool stdio MCP server remain completely unaffected."
    )

    if not gmcp_dir_exists:
        checks.append(
            make_check(
                name="ghidramcp_optional",
                category="mcp",
                required=False,
                status=STATUS_OPTIONAL,
                configured_path=str(tools_cfg.get("ghidra_mcp_dir")),
                installed=False,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message="Optional GhidraMCP not cloned (Ghidra Headless & MalBox MCP operate independently).",
                unavailable_evidence_if_missing=gmcp_unavail_msg,
            )
        )
    elif not gmcp_bridge_present:
        checks.append(
            make_check(
                name="ghidramcp_optional",
                category="mcp",
                required=False,
                status=STATUS_FAIL,
                configured_path=str(tools_cfg.get("ghidra_mcp_dir")),
                resolved_path=str(gmcp_dir),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                diagnostic_message="GhidraMCP directory exists without bridge_mcp_ghidra.py; incomplete clone.",
                recommended_action="Optional: Remove tools\\GhidraMCP and re-run .\\setup.ps1 -CloneGitTools.",
                unavailable_evidence_if_missing=gmcp_unavail_msg,
            )
        )
    else:
        bridge_syntax_ok, bridge_syntax_err = check_python_syntax_ast(gmcp_bridge) if gmcp_bridge else (False, "missing")
        gmcp_reqs_file = gmcp_dir / "requirements.txt" if gmcp_dir else None
        expected_gmcp_deps = parse_requirements_names(gmcp_reqs_file) if gmcp_reqs_file else []
        if not expected_gmcp_deps:
            expected_gmcp_deps = ["mcp", "requests"]
        gmcp_deps_missing: list[str] = expected_gmcp_deps
        if venv_ok:
            dep_code = (
                "import importlib.metadata as m, json\n"
                f"names = {expected_gmcp_deps!r}\n"
                "missing = []\n"
                "for n in names:\n"
                "    try: m.version(n)\n"
                "    except Exception: missing.append(n)\n"
                "print(json.dumps(missing))\n"
            )
            dep_res = run_bounded([str(venv_python), "-c", dep_code], timeout=10.0)
            if dep_res["returncode"] == 0 and dep_res["stdout"]:
                try:
                    gmcp_deps_missing = json.loads(dep_res["stdout"].splitlines()[-1])
                except ValueError:
                    pass
        gmcp_deps_ok = venv_ok and len(gmcp_deps_missing) == 0

        ext_installed = False
        ext_dirs: list[Path] = []
        if ghidra_bin:
            ext_dirs.append(ghidra_bin.parent.parent / "Ghidra" / "Extensions")
        user_gh = Path.home() / ".ghidra"
        if user_gh.is_dir():
            for sub in user_gh.iterdir():
                if sub.is_dir() and (sub / "Extensions").is_dir():
                    ext_dirs.append(sub / "Extensions")
        for ed in ext_dirs:
            if ed.is_dir() and any("ghidramcp" in p.name.lower() for p in ed.iterdir()):
                ext_installed = True
                break

        # Raw HTTP probe on 127.0.0.1:8080/methods (HTTP 200 alone NEVER proves a working MCP bridge!)
        port8080_code = 0
        port8080_kind = "unreachable"
        try:
            with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8080/methods", method="GET"), timeout=1.5) as resp:
                port8080_code = resp.status
                ctype = (resp.headers.get("Content-Type") or "").lower()
                snippet = resp.read(512).decode("utf-8-sig", errors="replace").lstrip()
                if "html" in ctype or snippet.lower().startswith(("<!doctype", "<html")):
                    port8080_kind = "html_non_ghidramcp_or_unknown"
                elif snippet.startswith(("[", "{")) or "text/plain" in ctype or snippet:
                    port8080_kind = "http_response_unverified"
                else:
                    port8080_kind = "empty_200"
        except urllib.error.HTTPError as exc:
            port8080_code = exc.code
            port8080_kind = f"http_{exc.code}"
        except (urllib.error.URLError, OSError):
            port8080_code = 0
            port8080_kind = "unreachable"

        stages = {
            "repo_cloned": gmcp_cloned,
            "repo_commit": gmcp_commit,
            "bridge_script_present": gmcp_bridge_present,
            "bridge_script_syntax_ok": bridge_syntax_ok,
            "bridge_script_syntax_error": bridge_syntax_err,
            "bridge_deps_installed": gmcp_deps_ok,
            "bridge_deps_missing": gmcp_deps_missing,
            "plugin_extension_installed": ext_installed,
            "http_8080_status_code": port8080_code,
            "http_8080_payload_type": port8080_kind,
            "mcp_bridge_verified": False,
        }

        if not bridge_syntax_ok:
            diag_msg = (
                f"GhidraMCP cloned, but bridge_mcp_ghidra.py failed syntax check ({bridge_syntax_err}); "
                "interactive MCP bridge UNVERIFIED."
            )
            gmcp_status = STATUS_FAIL
        elif port8080_code == 200 and port8080_kind == "html_non_ghidramcp_or_unknown":
            diag_msg = (
                f"GhidraMCP cloned (commit={gmcp_commit or 'unknown'}, deps_ok={gmcp_deps_ok}, "
                f"plugin_installed={ext_installed}); port 8080 returned HTML HTTP 200 (likely another service), "
                "and interactive MCP bridge integration remains UNVERIFIED."
            )
            gmcp_status = STATUS_PENDING
        elif port8080_code == 200:
            diag_msg = (
                f"GhidraMCP cloned (commit={gmcp_commit or 'unknown'}, deps_ok={gmcp_deps_ok}, "
                f"plugin_installed={ext_installed}); 127.0.0.1:8080/methods returned HTTP 200, "
                "which is insufficient alone to verify working MCP bridge/plugin integration (end-to-end MCP bridge UNVERIFIED)."
            )
            gmcp_status = STATUS_PENDING
        else:
            diag_msg = (
                f"GhidraMCP cloned (commit={gmcp_commit or 'unknown'}, deps_ok={gmcp_deps_ok}, "
                f"plugin_installed={ext_installed}, http_8080={port8080_code}); Ghidra GUI HTTP/MCP integration NOT verified."
            )
            gmcp_status = STATUS_PENDING

        checks.append(
            make_check(
                name="ghidramcp_optional",
                category="mcp",
                required=False,
                status=gmcp_status,
                detected_version=(
                    f"commit={gmcp_commit or 'unknown'}, plugin={ext_installed}, deps_ok={gmcp_deps_ok}, http_8080={port8080_code}"
                ),
                configured_path=str(tools_cfg.get("ghidra_mcp_dir")),
                resolved_path=str(gmcp_bridge),
                installed=True,
                runtime_verified=False,
                feature_verified=False,
                verification_stages=stages,
                diagnostic_message=diag_msg,
                recommended_action=(
                    "Optional: Install GhidraMCP extension inside Ghidra GUI and test bridge_mcp_ghidra.py manually during interactive RE."
                    if ext_installed and gmcp_deps_ok
                    else "Optional: Install GhidraMCP GUI extension inside Ghidra and verify requirements inside .venv before interactive use."
                ),
                unavailable_evidence_if_missing=gmcp_unavail_msg,
            )
        )

    # === 7. Snapshot State, Local HTTP Service & Separated Network Semantics ===
    dirty_marker = ws_dir / ".dirty_state"
    dirty_present = dirty_marker.exists()
    snapshot_state = "RESTORE_REQUIRED" if dirty_present else "NO_DIRTY_MARKER"
    checks.append(
        make_check(
            name="sandbox_snapshot_state",
            category="state",
            required=True,
            status=STATUS_FAIL if dirty_present else STATUS_PASS,
            detected_version=snapshot_state,
            resolved_path=str(dirty_marker) if dirty_present else None,
            installed=True,
            runtime_verified=True,
            feature_verified=not dirty_present,
            diagnostic_message=(
                "Dirty marker workspace/.dirty_state exists; RESTORE_REQUIRED before analyzing new samples."
                if dirty_present
                else "No workspace/.dirty_state marker on disk (absence of marker does not verify VM cleanliness; confirm CLEAN snapshot manually)."
            ),
            recommended_action="Restore the Windows 11 CLEAN VM snapshot." if dirty_present else "",
        )
    )

    def _http_get_json(url: str, timeout_val: float) -> tuple[int, dict[str, Any], str | None]:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_val) as resp:
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

    listen_host = str(cfg["listen_host"])
    listen_port = int(cfg["listen_port"])
    loopback_only = listen_host in ("127.0.0.1", "localhost", "::1")
    probe_host = "127.0.0.1" if listen_host in ("0.0.0.0", "") else listen_host
    sc_code, sdata, s_err = _http_get_json(f"http://{probe_host}:{listen_port}/status", 2.0)
    s_state = str(sdata.get("state", "")).upper()

    if loopback_only:
        local_service_state = "LOOPBACK_ONLY_MISCONFIGURED"
        sb_net_status = STATUS_FAIL
        application_state = s_state if sc_code == 200 and s_state else ("RESTORE_REQUIRED" if dirty_present else "LOOPBACK_ONLY")
        checks.append(
            make_check(
                name="sandbox_http_service",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"listen_host is '{listen_host}'; Machine 2 Gateway cannot reach loopback-only Sandbox.",
                recommended_action="Set listen_host to '0.0.0.0' or '10.10.20.30' in machine3-sandbox/config.json.",
            )
        )
    elif sc_code == 200 and s_state in ("READY", "ANALYZING", "RETURNING_EVIDENCE", "RESTORE_REQUIRED"):
        local_service_state = "RUNNING"
        sb_net_status = STATUS_PASS
        application_state = s_state
        checks.append(
            make_check(
                name="sandbox_http_service",
                category="peer",
                required=False,
                status=STATUS_PASS,
                detected_version=f"application_state={s_state}",
                configured_path=f"{listen_host}:{listen_port}",
                resolved_path=f"http://{probe_host}:{listen_port}/status",
                runtime_verified=True,
                diagnostic_message=(
                    f"Local Sandbox HTTP /status responded (application_state={s_state}); "
                    "this checks local service availability only — inbound reachability from Machine 2 is NOT verified by localhost."
                ),
            )
        )
    elif sc_code > 0:
        local_service_state = "PORT_CONFLICT"
        sb_net_status = STATUS_FAIL
        application_state = "INVALID_ENDPOINT"
        checks.append(
            make_check(
                name="sandbox_http_service",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Wrong service responding on Sandbox port {listen_port} (HTTP {sc_code}: {s_err or sdata}).",
                recommended_action=f"Free port {listen_port} or adjust listen_port in config.json.",
            )
        )
    elif check_port_free(listen_host, listen_port):
        local_service_state = "NOT_STARTED"
        sb_net_status = STATUS_PENDING
        application_state = "RESTORE_REQUIRED" if dirty_present else "NOT_RUNNING"
        checks.append(
            make_check(
                name="sandbox_http_service",
                category="peer",
                required=False,
                status=STATUS_PENDING,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Sandbox HTTP server not started yet; port {listen_port} is free.",
                recommended_action="Start Sandbox with: .\\.venv\\Scripts\\Activate.ps1; python sandbox.py",
            )
        )
    else:
        local_service_state = "PORT_CONFLICT"
        sb_net_status = STATUS_FAIL
        application_state = "PORT_OCCUPIED"
        checks.append(
            make_check(
                name="sandbox_http_service",
                category="peer",
                required=False,
                status=STATUS_FAIL,
                configured_path=f"{listen_host}:{listen_port}",
                diagnostic_message=f"Port {listen_port} is occupied by another process.",
                recommended_action=f"Stop conflicting process on port {listen_port}.",
            )
        )

    # Check if Internal Network 2 static IP (10.10.20.30) is assigned locally
    nic_ok = False
    nic_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        nic_sock.bind(("10.10.20.30", 0))
        nic_ok = True
    except OSError:
        nic_ok = False
    finally:
        nic_sock.close()
    checks.append(
        make_check(
            name="internal_network2_ip",
            category="peer",
            required=False,
            status=STATUS_PASS if nic_ok else STATUS_PENDING,
            detected_version="10.10.20.30" if nic_ok else None,
            diagnostic_message=(
                "Internal Network 2 IP 10.10.20.30 is assigned on local interface (firewall/peer routing still must be tested from Machine 2)."
                if nic_ok
                else "Static IP 10.10.20.30 not assigned yet (pending manual network setup)."
            ),
            recommended_action="" if nic_ok else "Manually assign 10.10.20.30/24 on Internal Network 2 (see docs\\network-setup.md).",
        )
    )

    # Overall readiness computations (strictly separated)
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

    peer_connectivity = "UNVERIFIED_PASSIVE_LISTENER"
    if sb_net_status == STATUS_FAIL:
        network_readiness = "NOT_READY"
    elif sb_net_status == STATUS_PASS and nic_ok:
        # Never claim end-to-end NETWORK_READINESS=READY from localhost HTTP check alone
        network_readiness = "LOCAL_SERVICE_ONLY"
    else:
        network_readiness = "PENDING"

    missing_required = [c["name"] for c in checks if c["required"] and c["status"] in (STATUS_MISSING, STATUS_FAIL)]
    missing_optional = [c["name"] for c in checks if not c["required"] and c["status"] in (STATUS_MISSING, STATUS_OPTIONAL)]
    evidence_impact_summary = {
        c["name"]: c["unavailable_evidence_if_missing"]
        for c in checks
        if c.get("unavailable_evidence_if_missing") and c["status"] != STATUS_PASS
    }
    for c in checks:
        if c["recommended_action"] and c["status"] != STATUS_PASS:
            manual_actions.append(f"[{c['name']}] {c['recommended_action']}")

    report = {
        "schema_version": "1.1",
        "machine": "machine3-sandbox",
        "mode": args.mode,
        "generated_at": utc_now_iso(),
        "local_readiness": local_readiness,
        "local_service_state": local_service_state,
        "network_readiness": network_readiness,
        "peer_connectivity": peer_connectivity,
        "application_state": application_state,
        "snapshot_state": snapshot_state,
        "config_validation_state": cfg_state,
        "environment": {
            "os": os_desc,
            "windows_supported": win_supported,
            "windows_family": win_family,
            "windows_11_verified": bool(is_win and win_build_int is not None and win_build_int >= WIN11_MIN_BUILD),
            "windows_build": str(win_build_int) if win_build_int is not None else None,
            "windows_ubr": win_ubr,
            "windows_display_version": win_display,
            "windows_edition": win_edition,
            "windows_product_name": win_product,
            "python_version": py_ver,
            "python_bits": py_bits,
            "pip_version": pip_ver,
            "python_packages": pkg_versions,
            "java_version": java_ver_str,
            "ghidra_version": ghidra_ver,
            "mcp_sdk_version": mcp_sdk_ver,
            "cloned_repositories": cloned_repos,
            "elevated_shell": is_admin,
        },
        "checks": checks,
        "missing_required_tools": missing_required,
        "missing_optional_tools": missing_optional,
        "evidence_impact_when_optional_missing": evidence_impact_summary,
        "manual_actions_required": list(dict.fromkeys(manual_actions)),
    }

    print("")
    print("=== MalBox Machine 3 Readiness Report ===")
    for c in checks:
        ver = f" ({c['detected_version']})" if c["detected_version"] else ""
        req_tag = "REQ" if c["required"] else "OPT"
        print(f"  [{c['status']:<8}] [{req_tag}] {c['name']:<29}{ver} - {c['diagnostic_message']}")

    print("")
    print(f"LOCAL_READINESS     : {local_readiness}")
    print(f"LOCAL_SERVICE_STATE : {local_service_state} ({listen_host}:{listen_port})")
    print(f"NETWORK_READINESS   : {network_readiness}")
    print(f"PEER_CONNECTIVITY   : {peer_connectivity} (verify Gateway <-> Sandbox from Machine 2/1)")
    print(f"APPLICATION_STATE   : {application_state}")
    print(f"SNAPSHOT_STATE      : {snapshot_state}")
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"REPORT_SAVED        : {report_path}")
    except OSError as exc:
        print(f"[ERROR] Failed writing report {report_path}: {exc}", file=sys.stderr)
        return 1

    if evidence_impact_summary:
        print("\nEvidence Unavailable / Degraded While Optional/Pending Checks Remain:")
        for cname, impact in evidence_impact_summary.items():
            print(f"  - {cname}: {impact}")

    if report["manual_actions_required"]:
        print("\nManual Actions / Next Steps:")
        for act in report["manual_actions_required"]:
            print(f"  - {act}")

    if local_readiness == "NOT_READY":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
