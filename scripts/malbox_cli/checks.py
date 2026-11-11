from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import (
    REQUIRED_DB_TABLES,
    REQUIRED_REPLAY_FIXTURES,
    CheckResult,
    CheckStatus,
    CommandRunner,
    ProcessVerification,
    default_command_runner,
    detect_memory_mb,
    get_runtime_dir,
    get_system_info,
    get_venv_python,
    is_port_in_use,
    parse_bool,
    parse_env_file,
    read_pid_state,
    redacted_config_summary,
    resolve_effective_config,
    resolve_ports_strict,
    resolve_repo_path,
    resolve_sqlite_db_path,
    verify_managed_process,
)


def check_os(system_info_fn: Callable[[], Dict[str, Any]] = get_system_info) -> CheckResult:
    info = system_info_fn()
    sys_name = info.get("system", "Unknown")
    distro = info.get("distro", sys_name)
    if sys_name in ("Linux", "Darwin"):
        label = f"{distro} (WSL)" if info.get("is_wsl") else distro
        return CheckResult(
            id="os_platform",
            name="Operating System",
            status=CheckStatus.PASS,
            summary=f"Supported OS detected: {label} ({info.get('machine', 'unknown')})",
            details=info,
        )
    return CheckResult(
        id="os_platform",
        name="Operating System",
        status=CheckStatus.WARN,
        summary=f"Uncommon host OS detected: {distro}. Linux/macOS/WSL is recommended.",
        details=info,
    )


def check_python(
    version_info: Optional[Tuple[int, ...]] = None,
    runner: CommandRunner = default_command_runner,
    python_exe: Optional[str] = None,
) -> CheckResult:
    ver = version_info or sys.version_info
    ver_str = f"{ver[0]}.{ver[1]}.{ver[2]}"
    exe = python_exe or sys.executable

    if (ver[0], ver[1]) < (3, 10):
        return CheckResult(
            id="python_runtime",
            name="Python Runtime & venv",
            status=CheckStatus.FAIL,
            summary=f"Python {ver_str} detected; Python 3.10+ is required.",
            details={"version": ver_str, "executable": exe},
            remediation="Install Python 3.10 or newer via your OS package manager (never run doctor with sudo).",
        )

    venv_check = runner([exe, "-m", "venv", "--help"])
    ensurepip_check = runner([exe, "-c", "import ensurepip, venv"])
    if venv_check.returncode != 0 or ensurepip_check.returncode != 0:
        return CheckResult(
            id="python_runtime",
            name="Python Runtime & venv",
            status=CheckStatus.FAIL,
            summary=f"Python {ver_str} found, but stdlib venv/ensurepip support is incomplete.",
            details={"version": ver_str, "executable": exe},
            remediation="Install the python3-venv package (e.g., `sudo apt install python3-venv` on Debian/Ubuntu) and re-run `./malbox doctor`.",
        )

    return CheckResult(
        id="python_runtime",
        name="Python Runtime & venv",
        status=CheckStatus.PASS,
        summary=f"Python {ver_str} with venv support available ({exe})",
        details={"version": ver_str, "executable": exe},
    )


def _parse_major_version(raw: str) -> Optional[int]:
    m = re.search(r"(\d+)", raw.strip())
    return int(m.group(1)) if m else None


def check_node_npm(
    skip_frontend: bool = False,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
    runner: CommandRunner = default_command_runner,
) -> CheckResult:
    if skip_frontend:
        return CheckResult(
            id="node_npm",
            name="Node.js & npm",
            status=CheckStatus.SKIP,
            summary="Skipped Node.js/npm check (--skip-frontend specified).",
        )

    node_bin = which_fn("node")
    npm_bin = which_fn("npm")

    if not node_bin or not npm_bin:
        missing = [name for name, path in (("node", node_bin), ("npm", npm_bin)) if not path]
        return CheckResult(
            id="node_npm",
            name="Node.js & npm",
            status=CheckStatus.FAIL,
            summary=f"Missing required frontend toolchain: {', '.join(missing)}.",
            details={"node": node_bin, "npm": npm_bin},
            remediation="Install Node.js 18+ and npm (e.g., via nvm or your OS package manager), or run backend-only with `--skip-frontend`.",
        )

    node_res = runner([node_bin, "-v"])
    npm_res = runner([npm_bin, "-v"])
    node_ver = (node_res.stdout or "").strip() if node_res.returncode == 0 else "unknown"
    npm_ver = (npm_res.stdout or "").strip() if npm_res.returncode == 0 else "unknown"
    node_major = _parse_major_version(node_ver)

    if node_major is not None and node_major < 18:
        return CheckResult(
            id="node_npm",
            name="Node.js & npm",
            status=CheckStatus.WARN,
            summary=f"Node.js {node_ver} is below recommended v18+ (npm {npm_ver}).",
            details={"node_version": node_ver, "npm_version": npm_ver},
            remediation="Upgrade to Node.js 18+ or 20 LTS for reliable Vite builds.",
        )

    return CheckResult(
        id="node_npm",
        name="Node.js & npm",
        status=CheckStatus.PASS,
        summary=f"Node.js {node_ver} and npm {npm_ver} available",
        details={"node_version": node_ver, "npm_version": npm_ver, "node": node_bin, "npm": npm_bin},
    )


def check_resources(
    root_dir: Path,
    disk_usage_fn: Callable[[Path], Any] = shutil.disk_usage,
    memory_fn: Callable[[], Tuple[Optional[int], Optional[int]]] = detect_memory_mb,
) -> CheckResult:
    usage = disk_usage_fn(root_dir)
    free_mb = int(usage.free // (1024 * 1024))
    total_ram_mb, avail_ram_mb = memory_fn()

    details = {
        "disk_free_mb": free_mb,
        "ram_total_mb": total_ram_mb,
        "ram_available_mb": avail_ram_mb,
    }

    if free_mb < 250:
        return CheckResult(
            id="system_resources",
            name="Disk Space & RAM",
            status=CheckStatus.FAIL,
            summary=f"Critically low disk space: {free_mb} MB free (< 250 MB minimum).",
            details=details,
            remediation="Free up at least 1.5 GB of disk space before installing dependencies.",
        )

    if total_ram_mb is not None and total_ram_mb < 512:
        return CheckResult(
            id="system_resources",
            name="Disk Space & RAM",
            status=CheckStatus.FAIL,
            summary=f"Critically low system RAM: {total_ram_mb} MB (< 512 MB minimum).",
            details=details,
            remediation="Allocate at least 1.5 GB – 2 GB RAM to this VM.",
        )

    warnings: List[str] = []
    if free_mb < 1500:
        warnings.append(f"low free disk ({free_mb} MB < 1500 MB recommended)")
    if total_ram_mb is not None and total_ram_mb < 1500:
        warnings.append(f"tight total RAM ({total_ram_mb} MB < 1500 MB recommended)")
    if avail_ram_mb is not None and avail_ram_mb < 400:
        warnings.append(f"low available RAM ({avail_ram_mb} MB)")

    ram_desc = f"{total_ram_mb} MB total" if total_ram_mb is not None else "RAM unknown"
    if avail_ram_mb is not None:
        ram_desc = f"{avail_ram_mb} MB free / {total_ram_mb} MB total"

    if warnings:
        return CheckResult(
            id="system_resources",
            name="Disk Space & RAM",
            status=CheckStatus.WARN,
            summary=f"Resources tight ({'; '.join(warnings)}; disk free {free_mb} MB, {ram_desc}).",
            details=details,
        )

    return CheckResult(
        id="system_resources",
        name="Disk Space & RAM",
        status=CheckStatus.PASS,
        summary=f"Disk free: {free_mb} MB; Memory: {ram_desc}",
        details=details,
    )


def check_env_config(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
) -> CheckResult:
    env_file = root_dir / ".env"
    example_file = root_dir / ".env.example"
    config = resolve_effective_config(root_dir, environ=environ)
    safe_summary = redacted_config_summary(config)

    if not env_file.is_file():
        return CheckResult(
            id="env_config",
            name="Configuration (.env) & Safety Policy",
            status=CheckStatus.FAIL,
            summary=".env file is missing.",
            details={"env_exists": False, "example_exists": example_file.is_file(), "config": safe_summary},
            remediation="Run `./malbox doctor --repair` to generate `.env` from `.env.example` with Live Mode disabled.",
        )

    raw_env_values = parse_env_file(env_file)
    _, port_errors = resolve_ports_strict(config)
    if port_errors:
        return CheckResult(
            id="env_config",
            name="Configuration (.env) & Safety Policy",
            status=CheckStatus.FAIL,
            summary=f"Invalid port configuration: {'; '.join(port_errors)}",
            details={"env_exists": True, "config": safe_summary, "port_errors": port_errors},
            remediation="Set valid integer ports (1-65535) for `MALBOX_PORT` and `MALBOX_FRONTEND_PORT` in `.env`.",
        )

    live_enabled = parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False)
    op_token_set = bool((config.get("MALBOX_OPERATOR_TOKEN") or "").strip())
    default_backend = (config.get("MALBOX_DEFAULT_SANDBOX_BACKEND") or "replay").strip().lower()
    host = (config.get("MALBOX_HOST") or "127.0.0.1").strip()

    if live_enabled and not op_token_set:
        return CheckResult(
            id="env_config",
            name="Configuration (.env) & Safety Policy",
            status=CheckStatus.FAIL,
            summary="UNSAFE CONFIGURATION: MALBOX_LIVE_MODE_ENABLED=true without MALBOX_OPERATOR_TOKEN.",
            details={"env_exists": True, "config": safe_summary, "keys_count": len(raw_env_values)},
            remediation="Set `MALBOX_LIVE_MODE_ENABLED=false` in `.env` for Replay Mode, or configure a strong `MALBOX_OPERATOR_TOKEN` if an isolated CAPE lab is intended.",
        )

    warnings: List[str] = []
    if live_enabled:
        warnings.append("Live Mode is ENABLED (`MALBOX_LIVE_MODE_ENABLED=true`); ensure VM isolation")
    if default_backend != "replay" and not live_enabled:
        warnings.append(f"MALBOX_DEFAULT_SANDBOX_BACKEND={default_backend} while Live Mode is disabled")
    if host not in ("127.0.0.1", "localhost", "::1"):
        warnings.append(f"MALBOX_HOST={host} exposes API beyond localhost")

    if os.name == "posix":
        env_mode = env_file.stat().st_mode & 0o777
        if env_mode & 0o077:
            warnings.append(f"`.env` permissions too permissive ({oct(env_mode)}; expected 0o600)")

    if warnings:
        return CheckResult(
            id="env_config",
            name="Configuration (.env) & Safety Policy",
            status=CheckStatus.WARN,
            summary=f".env present with safety warnings: {'; '.join(warnings)}.",
            details={"env_exists": True, "config": safe_summary, "keys_count": len(raw_env_values)},
            remediation="Run `./malbox doctor --repair` to tighten `.env` to `0600` (secrets untouched) and verify Replay Mode defaults.",
        )

    return CheckResult(
        id="env_config",
        name="Configuration (.env) & Safety Policy",
        status=CheckStatus.PASS,
        summary="Safe Replay Mode defaults active (Live Mode disabled, localhost-bound, .env protected).",
        details={"env_exists": True, "config": safe_summary, "keys_count": len(raw_env_values)},
    )


def check_directories(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
) -> CheckResult:
    config = resolve_effective_config(root_dir, environ=environ)
    data_dir = resolve_repo_path(root_dir, config.get("MALBOX_DATA_DIR", "./data"), root_dir / "data")
    quarantine_dir = resolve_repo_path(root_dir, config.get("MALBOX_QUARANTINE_DIR", "./data/quarantine"), data_dir / "quarantine")
    artifacts_dir = resolve_repo_path(root_dir, config.get("MALBOX_ARTIFACTS_DIR", "./data/artifacts"), data_dir / "artifacts")
    runtime_dir = get_runtime_dir(root_dir)

    missing = [str(p) for p in (data_dir, quarantine_dir, artifacts_dir, runtime_dir) if not p.is_dir()]
    if missing:
        return CheckResult(
            id="directories",
            name="Runtime & Quarantine Directories",
            status=CheckStatus.FAIL,
            summary=f"Missing required runtime directories: {', '.join(missing)}.",
            details={"missing": missing},
            remediation="Run `./malbox doctor --repair` to create data, quarantine (0700), artifacts, and .malbox directories.",
        )

    if os.name == "posix":
        perm_warnings: List[str] = []
        q_mode = quarantine_dir.stat().st_mode & 0o777
        if q_mode & 0o077:
            perm_warnings.append(f"quarantine dir `{quarantine_dir}` has permissive mode {oct(q_mode)} (expected 0o700)")
        rt_mode = runtime_dir.stat().st_mode & 0o777
        if rt_mode & 0o077:
            perm_warnings.append(f"runtime dir `.malbox` has permissive mode {oct(rt_mode)} (expected 0o700)")
        for rt_file in list(runtime_dir.glob("*.pid")) + list(runtime_dir.glob("*.log")):
            if rt_file.is_file():
                f_mode = rt_file.stat().st_mode & 0o777
                if f_mode & 0o077:
                    perm_warnings.append(f"runtime file `.malbox/{rt_file.name}` has permissive mode {oct(f_mode)} (expected 0o600)")
        if perm_warnings:
            return CheckResult(
                id="directories",
                name="Runtime & Quarantine Directories",
                status=CheckStatus.WARN,
                summary=f"Insecure directory/file permissions: {'; '.join(perm_warnings)}.",
                details={"quarantine_dir": str(quarantine_dir), "runtime_dir": str(runtime_dir), "warnings": perm_warnings},
                remediation="Run `./malbox doctor --repair` to restrict quarantine/runtime dirs (0700) and PID/log files (0600).",
            )

    return CheckResult(
        id="directories",
        name="Runtime & Quarantine Directories",
        status=CheckStatus.PASS,
        summary="Data, artifacts, runtime, and quarantine directories initialized safely.",
        details={
            "data_dir": str(data_dir),
            "quarantine_dir": str(quarantine_dir),
            "artifacts_dir": str(artifacts_dir),
            "runtime_dir": str(runtime_dir),
        },
    )


def check_venv_backend(
    root_dir: Path,
    runner: CommandRunner = default_command_runner,
) -> CheckResult:
    venv_dir = root_dir / ".venv"
    venv_python = get_venv_python(root_dir)

    if not venv_dir.is_dir() or not venv_python.exists():
        return CheckResult(
            id="backend_venv",
            name="Virtualenv & Backend Dependencies",
            status=CheckStatus.FAIL,
            summary="Python virtual environment `.venv` is missing or broken.",
            details={"venv_dir": str(venv_dir), "python": str(venv_python)},
            remediation="Run `./malbox doctor --repair` to create `.venv` and run `pip install -e \"backend[dev]\"`.",
        )

    probe_code = (
        "import app, fastapi, uvicorn, pydantic, pydantic_settings, "
        "sqlalchemy, httpx, pefile, jinja2, pytest; print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root_dir / "backend")
    res = runner([str(venv_python), "-c", probe_code], cwd=root_dir, env=env)
    if res.returncode != 0 or "OK" not in (res.stdout or ""):
        err_snippet = ((res.stderr or "") or (res.stdout or "")).strip().splitlines()
        last_line = err_snippet[-1] if err_snippet else "Import probe failed"
        return CheckResult(
            id="backend_venv",
            name="Virtualenv & Backend Dependencies",
            status=CheckStatus.FAIL,
            summary=f"Backend dependencies incomplete in `.venv` ({last_line}).",
            details={"venv_python": str(venv_python), "error": last_line},
            remediation="Run `./malbox doctor --repair` or `.venv/bin/pip install -e \"backend[dev]\"`.",
        )

    return CheckResult(
        id="backend_venv",
        name="Virtualenv & Backend Dependencies",
        status=CheckStatus.PASS,
        summary="`.venv` healthy and all FastAPI/SQLAlchemy/PE/test packages import cleanly.",
        details={"venv_python": str(venv_python)},
    )


def check_frontend(
    root_dir: Path,
    skip_frontend: bool = False,
) -> CheckResult:
    if skip_frontend:
        return CheckResult(
            id="frontend_deps",
            name="Frontend Dependencies & Build",
            status=CheckStatus.SKIP,
            summary="Skipped frontend check (--skip-frontend specified).",
        )

    frontend_dir = root_dir / "frontend"
    node_modules = frontend_dir / "node_modules"
    vite_bin = node_modules / ".bin" / "vite"
    dist_index = frontend_dir / "dist" / "index.html"

    if not (frontend_dir / "package.json").is_file():
        return CheckResult(
            id="frontend_deps",
            name="Frontend Dependencies & Build",
            status=CheckStatus.FAIL,
            summary="Missing `frontend/package.json`.",
            remediation="Ensure you are in the repository root of `malbox`.",
        )

    if not node_modules.is_dir() or not vite_bin.exists():
        return CheckResult(
            id="frontend_deps",
            name="Frontend Dependencies & Build",
            status=CheckStatus.FAIL,
            summary="`frontend/node_modules` is missing or incomplete (Vite not installed).",
            details={"node_modules": str(node_modules)},
            remediation="Run `./malbox doctor --repair` or `cd frontend && npm ci`.",
        )

    if not dist_index.is_file():
        return CheckResult(
            id="frontend_deps",
            name="Frontend Dependencies & Build",
            status=CheckStatus.WARN,
            summary="`frontend/node_modules` installed (`npm run dev` ready), but production bundle `frontend/dist` is not built yet.",
            details={"node_modules_present": True, "dist_built": False},
            remediation="Optional: run `cd frontend && npm run build` or `./malbox doctor --repair`.",
        )

    return CheckResult(
        id="frontend_deps",
        name="Frontend Dependencies & Build",
        status=CheckStatus.PASS,
        summary="Frontend dependencies and production bundle verified.",
        details={"node_modules_present": True, "dist_built": True},
    )


def check_database(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
) -> CheckResult:
    config = resolve_effective_config(root_dir, environ=environ)
    db_path, db_desc = resolve_sqlite_db_path(root_dir, config)

    if db_path is None:
        return CheckResult(
            id="database_health",
            name="Database Health",
            status=CheckStatus.PASS,
            summary=f"External/in-memory database configured ({db_desc}).",
            details={"database": db_desc},
        )

    if not db_path.is_file():
        return CheckResult(
            id="database_health",
            name="Database Health",
            status=CheckStatus.WARN,
            summary=f"SQLite database not yet initialized ({db_path}).",
            details={"db_path": str(db_path), "initialized": False},
            remediation="Run `./malbox doctor --repair` (or `./malbox start`) to initialize schema tables.",
        )

    try:
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            quick = conn.execute("PRAGMA quick_check;").fetchone()
            if not quick or quick[0] != "ok":
                return CheckResult(
                    id="database_health",
                    name="Database Health",
                    status=CheckStatus.FAIL,
                    summary=f"SQLite integrity check failed on {db_path}: {quick}",
                    details={"db_path": str(db_path)},
                    remediation="Back up and inspect/remove the corrupt SQLite file, then run `./malbox doctor --repair`.",
                )
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            }
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return CheckResult(
            id="database_health",
            name="Database Health",
            status=CheckStatus.FAIL,
            summary=f"Cannot open SQLite database {db_path}: {exc}",
            details={"db_path": str(db_path), "error": str(exc)},
            remediation="Check file permissions or back up/recreate the corrupt SQLite file.",
        )

    missing_tables = sorted(REQUIRED_DB_TABLES - tables)
    if missing_tables:
        return CheckResult(
            id="database_health",
            name="Database Health",
            status=CheckStatus.WARN,
            summary=f"SQLite file exists at {db_path}, but missing schema tables: {', '.join(missing_tables)}.",
            details={"db_path": str(db_path), "missing_tables": missing_tables},
            remediation="Run `./malbox doctor --repair` to initialize schema tables.",
        )

    return CheckResult(
        id="database_health",
        name="Database Health",
        status=CheckStatus.PASS,
        summary=f"SQLite database healthy ({db_path}; {len(tables)} tables verified).",
        details={"db_path": str(db_path), "tables_count": len(tables)},
    )


def check_replay_fixtures(root_dir: Path) -> CheckResult:
    fixtures_dir = root_dir / "fixtures" / "replay"
    if not fixtures_dir.is_dir():
        return CheckResult(
            id="replay_fixtures",
            name="Replay Mode Fixtures",
            status=CheckStatus.FAIL,
            summary=f"Replay fixtures directory missing: {fixtures_dir}",
            remediation="Restore `fixtures/replay/*.json` from git (`git checkout -- fixtures/replay`).",
        )

    missing: List[str] = []
    invalid: List[str] = []
    verified: List[str] = []

    for scenario_id in REQUIRED_REPLAY_FIXTURES:
        fpath = fixtures_dir / f"{scenario_id}.json"
        if not fpath.is_file():
            missing.append(scenario_id)
            continue
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "processes" not in data:
                invalid.append(f"{scenario_id} (missing 'processes' key)")
            else:
                verified.append(scenario_id)
        except Exception as exc:
            invalid.append(f"{scenario_id} ({exc})")

    if missing or invalid:
        issues = []
        if missing:
            issues.append(f"missing: {', '.join(missing)}")
        if invalid:
            issues.append(f"invalid: {', '.join(invalid)}")
        return CheckResult(
            id="replay_fixtures",
            name="Replay Mode Fixtures",
            status=CheckStatus.FAIL,
            summary=f"Replay fixtures check failed ({'; '.join(issues)}).",
            details={"missing": missing, "invalid": invalid, "verified": verified},
            remediation="Restore missing/corrupt fixtures via `git checkout -- fixtures/replay`.",
        )

    return CheckResult(
        id="replay_fixtures",
        name="Replay Mode Fixtures",
        status=CheckStatus.PASS,
        summary=f"All {len(verified)} registered Replay scenarios valid ({', '.join(verified)}).",
        details={"verified_scenarios": verified, "fixtures_dir": str(fixtures_dir)},
    )


def check_ports(
    root_dir: Path,
    skip_frontend: bool = False,
    environ: Optional[Dict[str, str]] = None,
    port_in_use_fn: Callable[[str, int], bool] = is_port_in_use,
    verify_fn: Callable[..., ProcessVerification] = verify_managed_process,
) -> CheckResult:
    config = resolve_effective_config(root_dir, environ=environ)
    parsed_ports, port_errors = resolve_ports_strict(config)
    if port_errors or parsed_ports is None:
        return CheckResult(
            id="ports",
            name="Network Port Availability",
            status=CheckStatus.FAIL,
            summary=f"Cannot inspect ports due to invalid configuration: {'; '.join(port_errors)}",
            details={"port_errors": port_errors},
            remediation="Configure valid ports (1-65535) for `MALBOX_PORT` and `MALBOX_FRONTEND_PORT`.",
        )

    host, backend_port, frontend_port = parsed_ports

    runtime_dir = get_runtime_dir(root_dir)
    be_state = read_pid_state(runtime_dir / "backend.pid")
    fe_state = read_pid_state(runtime_dir / "frontend.pid")

    be_verify = verify_fn(be_state, "backend", root_dir) if (runtime_dir / "backend.pid").exists() else None
    fe_verify = verify_fn(fe_state, "frontend", root_dir) if (runtime_dir / "frontend.pid").exists() else None

    backend_managed = bool(be_verify and be_verify.status == "valid")
    frontend_managed = bool(fe_verify and fe_verify.status == "valid")

    conflicts: List[str] = []
    running_managed: List[str] = []
    pid_warnings: List[str] = []

    if be_verify and be_verify.status in ("unverified", "reused_pid"):
        pid_warnings.append(f"backend.pid: {be_verify.reason}")
    if fe_verify and fe_verify.status in ("unverified", "reused_pid"):
        pid_warnings.append(f"frontend.pid: {fe_verify.reason}")

    if port_in_use_fn(host, backend_port):
        if backend_managed:
            running_managed.append(f"backend:{backend_port} (verified malbox PID {be_state['pid']})")
        else:
            conflicts.append(f"backend port {backend_port}")

    if not skip_frontend and port_in_use_fn("127.0.0.1", frontend_port):
        if frontend_managed:
            running_managed.append(f"frontend:{frontend_port} (verified malbox PID {fe_state['pid']})")
        else:
            conflicts.append(f"frontend port {frontend_port}")

    details = {
        "backend_port": backend_port,
        "frontend_port": frontend_port,
        "conflicts": conflicts,
        "running_managed": running_managed,
        "pid_warnings": pid_warnings,
    }

    if conflicts or pid_warnings:
        msg_parts = []
        if conflicts:
            msg_parts.append(f"Port conflict detected on {', '.join(conflicts)} (held by external/unmanaged process)")
        if pid_warnings:
            msg_parts.append("; ".join(pid_warnings))
        return CheckResult(
            id="ports",
            name="Network Port Availability",
            status=CheckStatus.WARN,
            summary=". ".join(msg_parts) + ".",
            details=details,
            remediation="Stop the conflicting external process or update `MALBOX_PORT` / `MALBOX_FRONTEND_PORT` in `.env`. Inspect any unverified PID files in `.malbox/` manually.",
        )

    if running_managed:
        return CheckResult(
            id="ports",
            name="Network Port Availability",
            status=CheckStatus.PASS,
            summary=f"Ports bound by verified malbox services: {', '.join(running_managed)}.",
            details=details,
        )

    return CheckResult(
        id="ports",
        name="Network Port Availability",
        status=CheckStatus.PASS,
        summary=f"Ports clear (backend :{backend_port}" + ("" if skip_frontend else f", frontend :{frontend_port}") + ").",
        details=details,
    )


def _probe_ghidra_and_jdk(
    ghidra_home_raw: str,
    which_fn: Callable[[str], Optional[str]],
    runner: CommandRunner,
    env_map: Dict[str, str],
) -> Dict[str, Any]:
    """Read-only probe for optional Ghidra installation and JDK compatibility."""
    ghidra_dir: Optional[Path] = None
    headless_path: Optional[Path] = None

    if ghidra_home_raw:
        cand = Path(ghidra_home_raw)
        if cand.is_dir() and (cand / "support" / "analyzeHeadless").is_file():
            ghidra_dir = cand.resolve()
            headless_path = ghidra_dir / "support" / "analyzeHeadless"
    else:
        which_ah = which_fn("analyzeHeadless")
        if which_ah:
            ah = Path(which_ah).resolve()
            if ah.is_file():
                headless_path = ah
                if ah.parent.name == "support":
                    ghidra_dir = ah.parent.parent
        elif which_fn is shutil.which:
            for std_dir in ("/usr/share/ghidra", "/opt/ghidra"):
                cand = Path(std_dir)
                if cand.is_dir() and (cand / "support" / "analyzeHeadless").is_file():
                    ghidra_dir = cand.resolve()
                    headless_path = ghidra_dir / "support" / "analyzeHeadless"
                    break

    if headless_path is None:
        return {"installed": False}

    ghidra_ver = "unknown"
    req_java_min = 21
    if ghidra_dir is not None:
        props = ghidra_dir / "Ghidra" / "application.properties"
        if props.is_file():
            for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s.startswith("application.version="):
                    ghidra_ver = s.partition("=")[2].strip() or ghidra_ver
                elif s.startswith("application.java.min="):
                    val = s.partition("=")[2].strip()
                    if val.isdigit():
                        req_java_min = int(val)

    java_home = (env_map.get("JAVA_HOME") or "").strip()
    java_bin = (
        str(Path(java_home) / "bin" / "java")
        if java_home and (Path(java_home) / "bin" / "java").is_file()
        else which_fn("java")
    )
    javac_bin = (
        str(Path(java_home) / "bin" / "javac")
        if java_home and (Path(java_home) / "bin" / "javac").is_file()
        else which_fn("javac")
    )

    java_major: Optional[int] = None
    java_raw = ""
    if java_bin:
        try:
            proc = runner([java_bin, "-version"])
            raw = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
            java_raw = raw.splitlines()[0] if raw else ""
            m = re.search(r'"(\d+)(?:\.(\d+))?[^"]*"', raw) or re.search(
                r"\b(?:openjdk|java)\s+(\d+)(?:\.(\d+))?", raw, re.IGNORECASE
            )
            if m:
                first = int(m.group(1))
                second = int(m.group(2)) if m.group(2) else None
                java_major = second if (first == 1 and second is not None) else first
        except Exception:
            java_major = None

    jdk_ok = bool(java_bin and javac_bin and java_major is not None and java_major >= req_java_min)
    return {
        "installed": True,
        "ghidra_home": str(ghidra_dir) if ghidra_dir else None,
        "analyze_headless": str(headless_path),
        "ghidra_version": ghidra_ver,
        "required_java_major": req_java_min,
        "java_bin": java_bin,
        "javac_bin": javac_bin,
        "java_version": java_raw,
        "java_major": java_major,
        "jdk_compatible": jdk_ok,
    }


def check_optional_integrations(
    root_dir: Path,
    environ: Optional[Dict[str, str]] = None,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
    runner: CommandRunner = default_command_runner,
) -> List[CheckResult]:
    config = resolve_effective_config(root_dir, environ=environ)
    env_map = environ if environ is not None else os.environ
    results: List[CheckResult] = []

    # 1. CAPE Sandbox
    live_enabled = parse_bool(config.get("MALBOX_LIVE_MODE_ENABLED"), default=False)
    cape_url = config.get("MALBOX_CAPE_API_URL", "http://127.0.0.1:8008")
    if live_enabled:
        results.append(CheckResult(
            id="opt_cape",
            name="Optional: CAPE Sandbox",
            status=CheckStatus.WARN,
            summary=f"Live Mode enabled targeting {cape_url} (hypervisor is NOT contacted automatically by doctor).",
            details={"cape_api_url": cape_url, "live_mode_enabled": True},
        ))
    else:
        results.append(CheckResult(
            id="opt_cape",
            name="Optional: CAPE Sandbox",
            status=CheckStatus.SKIP,
            summary="Optional live CAPE Sandbox disabled in Replay Mode (configured URL: " + cape_url + ").",
            details={"cape_api_url": cape_url, "live_mode_enabled": False},
        ))

    # 2. Ghidra Headless & JDK (optional; missing Ghidra must never block Replay readiness)
    ghidra_enabled = parse_bool(config.get("MALBOX_GHIDRA_ENABLED"), default=False)
    ghidra_home = (config.get("MALBOX_GHIDRA_HOME") or env_map.get("GHIDRA_HOME") or "").strip()
    g_info = _probe_ghidra_and_jdk(
        ghidra_home_raw=ghidra_home,
        which_fn=which_fn,
        runner=runner,
        env_map=env_map,
    )
    if not g_info["installed"]:
        if ghidra_enabled:
            results.append(CheckResult(
                id="opt_ghidra",
                name="Optional: Ghidra Headless",
                status=CheckStatus.WARN,
                summary="MALBOX_GHIDRA_ENABLED=true, but Ghidra analyzeHeadless was not found (Replay Mode remains ready).",
                details={"ghidra_enabled": True, "ghidra_home": ghidra_home or None},
                remediation="Install Ghidra and set MALBOX_GHIDRA_HOME, or set MALBOX_GHIDRA_ENABLED=false.",
            ))
        else:
            results.append(CheckResult(
                id="opt_ghidra",
                name="Optional: Ghidra Headless",
                status=CheckStatus.SKIP,
                summary="Optional Ghidra not installed/configured (not required for Replay Mode).",
                details={"ghidra_enabled": False},
            ))
    elif not g_info["jdk_compatible"]:
        results.append(CheckResult(
            id="opt_ghidra",
            name="Optional: Ghidra Headless",
            status=CheckStatus.WARN,
            summary=(
                f"Ghidra {g_info['ghidra_version']} found at {g_info['ghidra_home'] or g_info['analyze_headless']}, "
                f"but compatible JDK {g_info['required_java_major']}+ (with javac) is unavailable "
                f"(detected Java={g_info['java_major'] or 'missing'}; Replay Mode unaffected)."
            ),
            details={**g_info, "ghidra_enabled": ghidra_enabled},
            remediation=f"Install OpenJDK {g_info['required_java_major']}+ JDK package (including javac) without running doctor with sudo.",
        ))
    else:
        results.append(CheckResult(
            id="opt_ghidra",
            name="Optional: Ghidra Headless",
            status=CheckStatus.PASS,
            summary=(
                f"Optional Ghidra {g_info['ghidra_version']} & JDK {g_info['java_major']} verified "
                f"({g_info['ghidra_home'] or g_info['analyze_headless']}; "
                f"{'enabled' if ghidra_enabled else 'disabled by default'})."
            ),
            details={**g_info, "ghidra_enabled": ghidra_enabled},
        ))

    # 3. OpenCode CLI
    opencode_bin = which_fn("opencode")
    if opencode_bin:
        results.append(CheckResult(
            id="opt_opencode",
            name="Optional: OpenCode CLI",
            status=CheckStatus.PASS,
            summary=f"Optional OpenCode CLI detected at {opencode_bin}.",
        ))
    else:
        results.append(CheckResult(
            id="opt_opencode",
            name="Optional: OpenCode CLI",
            status=CheckStatus.SKIP,
            summary="Optional OpenCode CLI not installed (not required for Replay Mode).",
        ))

    # 4. External AI Provider
    ai_provider = (config.get("MALBOX_AI_PROVIDER") or "mock").strip()
    ai_key_set = bool((config.get("MALBOX_AI_API_KEY") or "").strip())
    if ai_provider == "mock" or not ai_key_set:
        results.append(CheckResult(
            id="opt_ai_provider",
            name="Optional: External AI Credentials",
            status=CheckStatus.SKIP,
            summary="Using deterministic MockLLMProvider (no external API key required for Replay Mode).",
            details={"ai_provider": ai_provider, "api_key_configured": ai_key_set},
        ))
    else:
        results.append(CheckResult(
            id="opt_ai_provider",
            name="Optional: External AI Credentials",
            status=CheckStatus.PASS,
            summary=f"External AI provider configured (`{ai_provider}`, API key redacted).",
            details={"ai_provider": ai_provider, "api_key_configured": True},
        ))

    return results


def run_all_checks(
    root_dir: Path,
    skip_frontend: bool = False,
    environ: Optional[Dict[str, str]] = None,
    runner: CommandRunner = default_command_runner,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
) -> List[CheckResult]:
    """Runs all read-only diagnostic checks and returns structured results."""
    results = [
        check_os(),
        check_python(runner=runner),
        check_node_npm(skip_frontend=skip_frontend, which_fn=which_fn, runner=runner),
        check_resources(root_dir),
        check_env_config(root_dir, environ=environ),
        check_directories(root_dir, environ=environ),
        check_venv_backend(root_dir, runner=runner),
        check_frontend(root_dir, skip_frontend=skip_frontend),
        check_database(root_dir, environ=environ),
        check_replay_fixtures(root_dir),
        check_ports(root_dir, skip_frontend=skip_frontend, environ=environ),
    ]
    results.extend(check_optional_integrations(root_dir, environ=environ, which_fn=which_fn, runner=runner))
    return results
