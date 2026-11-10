from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .checks import (
    check_database,
    check_env_config,
    check_frontend,
    check_node_npm,
    check_python,
    check_resources,
    check_venv_backend,
    run_all_checks,
)
from .models import (
    CheckResult,
    CheckStatus,
    CommandRunner,
    default_command_runner,
    get_runtime_dir,
    get_venv_python,
    is_pid_running,
    read_pid_state,
    resolve_effective_config,
    resolve_repo_path,
)

MINIMAL_SAFE_ENV = """# Auto-generated minimal safe Replay Mode configuration
MALBOX_ENV=development
MALBOX_HOST=127.0.0.1
MALBOX_PORT=8000
MALBOX_DATA_DIR=./data
MALBOX_QUARANTINE_DIR=./data/quarantine
MALBOX_ARTIFACTS_DIR=./data/artifacts
MALBOX_LIVE_MODE_ENABLED=false
MALBOX_REQUIRE_EXPLICIT_APPROVAL=true
MALBOX_OPERATOR_TOKEN=
MALBOX_DEFAULT_SANDBOX_BACKEND=replay
MALBOX_AI_PROVIDER=mock
MALBOX_CAPE_API_URL=http://127.0.0.1:8008
"""


def cleanup_stale_pids(root_dir: Path, actions: List[str]) -> None:
    runtime_dir = get_runtime_dir(root_dir)
    if not runtime_dir.is_dir():
        return

    expectations = {
        "backend.pid": ["uvicorn", "python"],
        "frontend.pid": ["vite", "node", "npm"],
    }
    for filename, subs in expectations.items():
        pid_file = runtime_dir / filename
        if not pid_file.exists():
            continue
        state = read_pid_state(pid_file)
        if not state or not is_pid_running(state["pid"], subs):
            try:
                pid_file.unlink()
                actions.append(f"Removed stale PID file `.malbox/{filename}`")
            except OSError:
                pass


def repair_env_file(
    root_dir: Path,
    actions: List[str],
    confirm_overwrite_env: bool = False,
) -> None:
    env_file = root_dir / ".env"
    example_file = root_dir / ".env.example"

    if env_file.exists() and not confirm_overwrite_env:
        return

    if example_file.is_file():
        shutil.copyfile(example_file, env_file)
        if confirm_overwrite_env:
            actions.append("Reset `.env` from `.env.example` with explicit confirmation")
        else:
            actions.append("Created `.env` from `.env.example` (Live Mode disabled, Replay Mode active)")
    else:
        env_file.write_text(MINIMAL_SAFE_ENV, encoding="utf-8")
        actions.append("Created minimal `.env` with safe Replay defaults")


def repair_directories(
    root_dir: Path,
    environ: Optional[Dict[str, str]],
    actions: List[str],
) -> None:
    config = resolve_effective_config(root_dir, environ=environ)
    data_dir = resolve_repo_path(root_dir, config.get("MALBOX_DATA_DIR", "./data"), root_dir / "data")
    quarantine_dir = resolve_repo_path(root_dir, config.get("MALBOX_QUARANTINE_DIR", "./data/quarantine"), data_dir / "quarantine")
    artifacts_dir = resolve_repo_path(root_dir, config.get("MALBOX_ARTIFACTS_DIR", "./data/artifacts"), data_dir / "artifacts")
    runtime_dir = get_runtime_dir(root_dir)

    for directory in (data_dir, quarantine_dir, artifacts_dir, runtime_dir):
        if not directory.is_dir():
            directory.mkdir(parents=True, exist_ok=True)
            actions.append(f"Created directory `{directory}`")

    if os.name == "posix" and quarantine_dir.is_dir():
        current_mode = quarantine_dir.stat().st_mode & 0o777
        if current_mode & 0o077:
            quarantine_dir.chmod(0o700)
            actions.append(f"Restricted quarantine permissions on `{quarantine_dir}` to 0700")


def repair_venv_and_backend(
    root_dir: Path,
    runner: CommandRunner,
    actions: List[str],
    errors: List[str],
    python_exe: Optional[str] = None,
) -> bool:
    venv_check = check_venv_backend(root_dir, runner=runner)
    if venv_check.status == CheckStatus.PASS:
        return True

    py_bin = python_exe or sys.executable
    venv_dir = root_dir / ".venv"
    venv_python = get_venv_python(root_dir)

    needs_venv_create = not venv_dir.is_dir() or not venv_python.exists()
    if not needs_venv_create:
        alive = runner([str(venv_python), "-c", "import sys, pip; print('ALIVE')"], cwd=root_dir)
        if alive.returncode != 0 or "ALIVE" not in (alive.stdout or ""):
            needs_venv_create = True

    if needs_venv_create:
        cmd = [py_bin, "-m", "venv"]
        if venv_dir.exists():
            cmd.append("--clear")
        cmd.append(str(venv_dir))
        res = runner(cmd, cwd=root_dir)
        if res.returncode != 0:
            err = (res.stderr or res.stdout or "Failed creating .venv").strip()
            errors.append(f"Failed to create `.venv`: {err}")
            return False
        actions.append(f"Created clean Python virtual environment at `{venv_dir}`")
        venv_python = get_venv_python(root_dir)

    pip_cmd = [str(venv_python), "-m", "pip", "install", "-e", "backend[dev]"]
    pip_res = runner(pip_cmd, cwd=root_dir, timeout=600)
    if pip_res.returncode != 0:
        err = (pip_res.stderr or pip_res.stdout or "pip install failed").strip()
        tail = "\n".join(err.splitlines()[-8:])
        errors.append(f"Backend dependency installation failed (`pip install -e backend[dev]`): {tail}")
        return False

    actions.append("Installed backend dependencies (`pip install -e backend[dev]`)")
    return True


def repair_database(
    root_dir: Path,
    runner: CommandRunner,
    environ: Optional[Dict[str, str]],
    actions: List[str],
    errors: List[str],
) -> bool:
    db_check = check_database(root_dir, environ=environ)
    if db_check.status == CheckStatus.FAIL:
        errors.append(f"Database integrity error (manual backup/inspection required): {db_check.summary}")
        return False

    if db_check.status == CheckStatus.PASS:
        return True

    venv_python = get_venv_python(root_dir)
    if not venv_python.exists():
        return False

    env = dict(os.environ if environ is None else environ)
    env["PYTHONPATH"] = str(root_dir / "backend")
    res = runner(
        [str(venv_python), "-c", "from app.core.database import init_db; init_db(); print('DB_INITIALIZED')"],
        cwd=root_dir,
        env=env,
    )
    if res.returncode != 0 or "DB_INITIALIZED" not in (res.stdout or ""):
        err = (res.stderr or res.stdout or "DB init failed").strip()
        errors.append(f"Failed to initialize SQLite database schema: {err}")
        return False

    actions.append("Initialized/updated SQLite database schema (`app.core.database.init_db`)")
    return True


def repair_frontend(
    root_dir: Path,
    runner: CommandRunner,
    which_fn: Callable[[str], Optional[str]],
    skip_frontend: bool,
    build_bundle: bool,
    actions: List[str],
    errors: List[str],
) -> bool:
    if skip_frontend:
        return True

    npm_bin = which_fn("npm")
    node_bin = which_fn("node")
    if not npm_bin or not node_bin:
        return False

    frontend_dir = root_dir / "frontend"
    fe_check = check_frontend(root_dir, skip_frontend=False)
    if fe_check.status == CheckStatus.PASS:
        return True

    if fe_check.status == CheckStatus.FAIL:
        lockfile = frontend_dir / "package-lock.json"
        cmd = [npm_bin, "ci" if lockfile.is_file() else "install"]
        npm_res = runner(cmd, cwd=frontend_dir, timeout=600)
        if npm_res.returncode != 0:
            err = (npm_res.stderr or npm_res.stdout or "npm install failed").strip()
            tail = "\n".join(err.splitlines()[-8:])
            errors.append(f"Frontend dependency install failed (`{' '.join(cmd)}`): {tail}")
            return False
        actions.append(f"Installed frontend dependencies via `{' '.join(cmd)}`")

    if build_bundle and not (frontend_dir / "dist" / "index.html").is_file():
        build_res = runner([npm_bin, "run", "build"], cwd=frontend_dir, timeout=600)
        if build_res.returncode != 0:
            err = (build_res.stderr or build_res.stdout or "npm run build failed").strip()
            tail = "\n".join(err.splitlines()[-8:])
            errors.append(f"Frontend build failed (`npm run build`): {tail}")
            return False
        actions.append("Built frontend production bundle (`npm run build`)")

    return True


def run_doctor(
    root_dir: Path,
    mode: str = "default",
    skip_frontend: bool = False,
    confirm_overwrite_env: bool = False,
    build_frontend: bool = True,
    environ: Optional[Dict[str, str]] = None,
    runner: CommandRunner = default_command_runner,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
) -> Dict[str, Any]:
    """
    Runs diagnostic checks and optionally performs safe, idempotent setup/repair.
    mode: 'check' (read-only), 'repair' (explicit repair), 'default' (check + safe bootstrap).
    """
    if mode not in ("check", "repair", "default"):
        raise ValueError(f"Unsupported doctor mode: {mode}")

    before_results = run_all_checks(
        root_dir,
        skip_frontend=skip_frontend,
        environ=environ,
        runner=runner,
        which_fn=which_fn,
    )
    before_map = {r.id: r.status for r in before_results}

    actions_taken: List[str] = []
    errors: List[str] = []

    if mode in ("default", "repair"):
        py_ok = before_map.get("python_runtime") != CheckStatus.FAIL
        res_ok = before_map.get("system_resources") != CheckStatus.FAIL

        cleanup_stale_pids(root_dir, actions_taken)
        repair_env_file(root_dir, actions_taken, confirm_overwrite_env=confirm_overwrite_env)
        repair_directories(root_dir, environ, actions_taken)

        if py_ok and res_ok:
            if repair_venv_and_backend(root_dir, runner, actions_taken, errors):
                repair_database(root_dir, runner, environ, actions_taken, errors)
            repair_frontend(
                root_dir,
                runner=runner,
                which_fn=which_fn,
                skip_frontend=skip_frontend,
                build_bundle=build_frontend,
                actions=actions_taken,
                errors=errors,
            )

    final_results = (
        before_results
        if mode == "check"
        else run_all_checks(
            root_dir,
            skip_frontend=skip_frontend,
            environ=environ,
            runner=runner,
            which_fn=which_fn,
        )
    )

    if mode in ("default", "repair") and actions_taken:
        for item in final_results:
            prev = before_map.get(item.id)
            if prev in (CheckStatus.FAIL, CheckStatus.WARN) and item.status == CheckStatus.PASS:
                item.repaired = True

    counts = {status.value: 0 for status in CheckStatus}
    for item in final_results:
        counts[item.status.value] += 1

    has_failures = counts["FAIL"] > 0 or bool(errors)
    overall = "FAIL" if has_failures else ("WARN" if counts["WARN"] > 0 else "PASS")

    return {
        "mode": mode,
        "overall_status": overall,
        "exit_code": 1 if has_failures else 0,
        "root_dir": str(root_dir),
        "actions_taken": actions_taken,
        "errors": errors,
        "summary": counts,
        "checks": [r.to_dict() for r in final_results],
    }
