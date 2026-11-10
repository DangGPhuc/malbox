from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .checks import (
    check_database,
    check_env_config,
    check_frontend,
    check_node_npm,
    check_python,
    check_replay_fixtures,
    check_resources,
    check_venv_backend,
    run_all_checks,
)
from .models import (
    CheckResult,
    CheckStatus,
    CommandRunner,
    chmod_safe,
    default_command_runner,
    get_runtime_dir,
    get_venv_python,
    read_pid_state,
    resolve_effective_config,
    resolve_repo_path,
    verify_managed_process,
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

SMOKE_TEST_SCRIPT = r"""
import io
import json
import os
import resource
import sys
import time

t0 = time.perf_counter()

from fastapi.testclient import TestClient
from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.main import app

assert settings.LIVE_MODE_ENABLED is False, "Unsafe Live Mode enabled during smoke test"
assert str(settings.DATA_DIR).startswith(os.environ["MALBOX_SMOKE_TMPDIR"]), "Settings DATA_DIR escaped isolated tmpdir"

init_db()

with TestClient(app) as client:
    h = client.get("/api/v1/health")
    assert h.status_code == 200, f"Health check HTTP {h.status_code}"
    hd = h.json()
    assert hd["live_mode_enabled"] is False
    assert hd["default_backend"] == "replay"

    synthetic_pe = b"MZ" + b"\x00" * 80 + b"MALBOX_DOCTOR_SYNTHETIC_SMOKE_SAMPLE"
    up = client.post(
        "/api/v1/samples",
        files={"file": ("smoke_synthetic.exe", io.BytesIO(synthetic_pe), "application/octet-stream")},
    )
    assert up.status_code == 201, f"Sample upload failed: {up.status_code} {up.text}"
    sample_id = up.json()["id"]

    an = client.post(
        "/api/v1/analyses?run_sync=true",
        json={
            "sample_id": sample_id,
            "backend_type": "replay",
            "profile": "ransomware_focus",
            "replay_scenario_id": "ransomware_wannacry_mock",
            "live_mode": False,
            "timeout_seconds": 30,
        },
    )
    assert an.status_code == 201, f"Replay analysis failed: {an.status_code} {an.text}"
    an_data = an.json()
    assert an_data["status"] == "COMPLETED", f"Unexpected analysis status: {an_data['status']}"
    assert an_data["replay_scenario_id"] == "ransomware_wannacry_mock"
    analysis_id = an_data["id"]

    gr = client.get(f"/api/v1/analyses/{analysis_id}/graph")
    assert gr.status_code == 200, f"Graph endpoint failed: {gr.status_code}"
    gr_data = gr.json()
    assert gr_data["total_nodes"] > 0 and gr_data["total_edges"] > 0

    rp = client.get(f"/api/v1/analyses/{analysis_id}/report")
    assert rp.status_code == 200, f"Report endpoint failed: {rp.status_code}"
    rp_data = rp.json()
    assert rp_data["is_replay"] is True
    assert rp_data["replay_scenario_id"] == "ransomware_wannacry_mock"
    assert rp_data["risk_score"] > 0
    full_rep = rp_data["full_report"]
    assert "REPLAY DATA PROVENANCE" in full_rep["provenance_disclaimer"]
    findings = full_rep["findings"]
    assert len(findings) >= 1, "Expected behavioral findings in Replay report"
    assert all(len(f.get("supporting_event_ids", [])) >= 1 for f in findings), "Missing event provenance on findings"

elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
peak_rss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)
print("SMOKE_JSON:" + json.dumps({
    "analysis_id": analysis_id,
    "risk_score": rp_data["risk_score"],
    "risk_level": rp_data["risk_level"],
    "findings_count": len(findings),
    "graph_nodes": gr_data["total_nodes"],
    "graph_edges": gr_data["total_edges"],
    "elapsed_ms": elapsed_ms,
    "peak_rss_mb": peak_rss_mb,
}))
"""


def cleanup_stale_pids(root_dir: Path, actions: List[str]) -> None:
    runtime_dir = get_runtime_dir(root_dir)
    if not runtime_dir.is_dir():
        return

    for filename, service in (("backend.pid", "backend"), ("frontend.pid", "frontend")):
        pid_file = runtime_dir / filename
        if not pid_file.exists():
            continue
        state = read_pid_state(pid_file)
        ver = verify_managed_process(state, service, root_dir)
        # Only automatically unlink genuinely dead/stale or corrupt JSON PID files.
        # Live unverified or reused PIDs are preserved for operator inspection and flagged by checks.
        if ver.status in ("stale", "invalid_state"):
            try:
                pid_file.unlink()
                actions.append(f"Removed {ver.status} PID file `.malbox/{filename}`")
            except OSError:
                pass


def repair_env_file(
    root_dir: Path,
    actions: List[str],
    confirm_overwrite_env: bool = False,
) -> None:
    env_file = root_dir / ".env"
    example_file = root_dir / ".env.example"

    if not env_file.exists() or confirm_overwrite_env:
        if example_file.is_file():
            content = example_file.read_text(encoding="utf-8")
            label = "Reset `.env` from `.env.example` with explicit confirmation" if confirm_overwrite_env else "Created `.env` from `.env.example` (Live Mode disabled, Replay Mode active)"
        else:
            content = MINIMAL_SAFE_ENV
            label = "Created minimal `.env` with safe Replay defaults"

        if os.name == "posix":
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(str(env_file), flags, 0o600)
            try:
                os.write(fd, content.encode("utf-8"))
            finally:
                os.close(fd)
            chmod_safe(env_file, 0o600)
        else:
            env_file.write_text(content, encoding="utf-8")
        actions.append(label)
        return

    # Existing .env: never alter contents, only tighten overly permissive POSIX mode to 0600
    if chmod_safe(env_file, 0o600):
        actions.append("Restricted permissions on existing `.env` to 0600 (contents untouched)")


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

    if chmod_safe(quarantine_dir, 0o700):
        actions.append(f"Restricted quarantine permissions on `{quarantine_dir}` to 0700")
    if chmod_safe(runtime_dir, 0o700):
        actions.append("Restricted runtime directory `.malbox` permissions to 0700")

    if runtime_dir.is_dir():
        for rt_file in list(runtime_dir.glob("*.pid")) + list(runtime_dir.glob("*.log")):
            if rt_file.is_file() and chmod_safe(rt_file, 0o600):
                actions.append(f"Restricted runtime file `.malbox/{rt_file.name}` permissions to 0600")


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


def run_replay_smoke_test(
    root_dir: Path,
    runner: CommandRunner = default_command_runner,
    environ: Optional[Dict[str, str]] = None,
    timeout_seconds: int = 30,
) -> CheckResult:
    """
    Runs a bounded, isolated end-to-end Replay smoke test via FastAPI TestClient
    inside a disposable TemporaryDirectory without modifying existing user data or secrets.
    """
    venv_python = get_venv_python(root_dir)
    if not venv_python.exists():
        return CheckResult(
            id="replay_smoke_test",
            name="Replay Pipeline Smoke Test",
            status=CheckStatus.FAIL,
            summary="Cannot run Replay smoke test: `.venv` is missing.",
            remediation="Run `./malbox doctor` first to install backend dependencies.",
        )

    fix_check = check_replay_fixtures(root_dir)
    if fix_check.status == CheckStatus.FAIL:
        return CheckResult(
            id="replay_smoke_test",
            name="Replay Pipeline Smoke Test",
            status=CheckStatus.FAIL,
            summary=f"Cannot run Replay smoke test: {fix_check.summary}",
            remediation=fix_check.remediation,
        )

    with tempfile.TemporaryDirectory(prefix="malbox_smoke_") as tmpdir_str:
        tmp_path = Path(tmpdir_str)
        smoke_env = dict(os.environ if environ is None else environ)
        smoke_env.update({
            "PYTHONPATH": str(root_dir / "backend"),
            "MALBOX_SMOKE_TMPDIR": tmpdir_str,
            "MALBOX_DATA_DIR": str(tmp_path / "data"),
            "MALBOX_QUARANTINE_DIR": str(tmp_path / "data" / "quarantine"),
            "MALBOX_ARTIFACTS_DIR": str(tmp_path / "data" / "artifacts"),
            "MALBOX_FIXTURES_DIR": str(root_dir / "fixtures" / "replay"),
            "MALBOX_DATABASE_URL": f"sqlite:///{tmp_path / 'smoke.db'}",
            "MALBOX_LIVE_MODE_ENABLED": "false",
            "MALBOX_DEFAULT_SANDBOX_BACKEND": "replay",
            "MALBOX_AI_PROVIDER": "mock",
            "MALBOX_OPERATOR_TOKEN": "",
        })

        t_start = time.perf_counter()
        try:
            res = runner([str(venv_python), "-c", SMOKE_TEST_SCRIPT], cwd=root_dir, env=smoke_env, timeout=timeout_seconds)
        except Exception as exc:
            return CheckResult(
                id="replay_smoke_test",
                name="Replay Pipeline Smoke Test",
                status=CheckStatus.FAIL,
                summary=f"Replay smoke test timed out or crashed: {exc}",
                remediation="Inspect backend environment via `./malbox doctor --check` or run `pytest backend/tests/test_replay_pipeline.py`.",
            )
        wall_ms = round((time.perf_counter() - t_start) * 1000, 2)

        if res.returncode != 0:
            err_lines = ((res.stderr or "") + "\n" + (res.stdout or "")).strip().splitlines()
            tail = "\n".join(err_lines[-6:]) if err_lines else "Unknown error"
            return CheckResult(
                id="replay_smoke_test",
                name="Replay Pipeline Smoke Test",
                status=CheckStatus.FAIL,
                summary=f"Replay smoke test failed (exit {res.returncode}): {err_lines[-1] if err_lines else tail}",
                details={"stderr_tail": tail, "wall_ms": wall_ms},
                remediation="Run `./malbox doctor --repair` and `pytest -v backend/tests/test_replay_pipeline.py` to diagnose.",
            )

        smoke_meta: Dict[str, Any] = {"wall_ms": wall_ms, "isolated": True}
        for line in (res.stdout or "").splitlines():
            if line.startswith("SMOKE_JSON:"):
                try:
                    smoke_meta.update(json.loads(line[len("SMOKE_JSON:"):]))
                except Exception:
                    pass

        return CheckResult(
            id="replay_smoke_test",
            name="Replay Pipeline Smoke Test",
            status=CheckStatus.PASS,
            summary=(
                f"Isolated Replay E2E verified (WannaCry scenario, {smoke_meta.get('findings_count', '?')} findings, "
                f"{smoke_meta.get('graph_nodes', '?')} graph nodes, {smoke_meta.get('elapsed_ms', wall_ms)} ms, "
                f"{smoke_meta.get('peak_rss_mb', '?')} MB peak RSS)."
            ),
            details=smoke_meta,
        )


def run_doctor(
    root_dir: Path,
    mode: str = "default",
    skip_frontend: bool = False,
    confirm_overwrite_env: bool = False,
    build_frontend: bool = True,
    smoke_test: bool = False,
    environ: Optional[Dict[str, str]] = None,
    runner: CommandRunner = default_command_runner,
    which_fn: Callable[[str], Optional[str]] = shutil.which,
) -> Dict[str, Any]:
    """
    Runs diagnostic checks and optionally performs safe, idempotent setup/repair.
    mode: 'check' (read-only), 'smoke' (checks + isolated smoke test), 'repair' (explicit repair), 'default' (check + safe bootstrap).
    """
    if mode not in ("check", "smoke", "repair", "default"):
        raise ValueError(f"Unsupported doctor mode: {mode}")
    if mode == "check" and smoke_test:
        raise ValueError("Read-only --check mode cannot execute --smoke-test.")
    if mode == "smoke":
        smoke_test = True

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
        if mode in ("check", "smoke")
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

    if smoke_test:
        smoke_result = run_replay_smoke_test(root_dir, runner=runner, environ=environ)
        final_results.append(smoke_result)

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
