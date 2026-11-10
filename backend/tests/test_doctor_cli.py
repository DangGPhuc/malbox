import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest

# Ensure scripts/ is importable cleanly
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from malbox_cli.checks import (  # noqa: E402
    check_database,
    check_node_npm,
    check_optional_integrations,
    check_ports,
    check_python,
    check_replay_fixtures,
    check_resources,
)
from malbox_cli.cli import main as cli_main  # noqa: E402
from malbox_cli.lifecycle import get_status, start_services, stop_services  # noqa: E402
from malbox_cli.models import CheckStatus, REQUIRED_DB_TABLES, parse_env_file  # noqa: E402
from malbox_cli.repair import run_doctor  # noqa: E402


def _make_isolated_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "malbox_ws"
    ws.mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / ".env.example", ws / ".env.example")

    (ws / "backend").mkdir()
    shutil.copyfile(REPO_ROOT / "backend" / "pyproject.toml", ws / "backend" / "pyproject.toml")

    (ws / "frontend").mkdir()
    shutil.copyfile(REPO_ROOT / "frontend" / "package.json", ws / "frontend" / "package.json")
    shutil.copyfile(REPO_ROOT / "frontend" / "package-lock.json", ws / "frontend" / "package-lock.json")

    fixtures_dst = ws / "fixtures" / "replay"
    fixtures_dst.mkdir(parents=True)
    for f in (REPO_ROOT / "fixtures" / "replay").glob("*.json"):
        shutil.copyfile(f, fixtures_dst / f.name)

    return ws


class FakeToolchainRunner:
    """
    Deterministic offline command runner simulating venv, pip, npm, node, and DB init
    inside an isolated temporary workspace without touching network resources.
    """

    def __init__(self, ws: Path):
        self.ws = ws
        self.commands: List[List[str]] = []
        self.backend_installed = False

    def __call__(self, cmd: List[str], cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None, timeout: int = 300):
        self.commands.append(cmd)
        joined = " ".join(cmd)

        if len(cmd) >= 3 and cmd[1:3] == ["-m", "venv"]:
            if "--help" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "usage: venv", "")
            venv_bin = self.ws / ".venv" / "bin"
            if "--clear" in cmd and (self.ws / ".venv").exists():
                shutil.rmtree(self.ws / ".venv")
            venv_bin.mkdir(parents=True, exist_ok=True)
            py = venv_bin / "python"
            py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            py.chmod(0o755)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        if len(cmd) >= 3 and cmd[1] == "-c" and "ensurepip" in cmd[2]:
            return subprocess.CompletedProcess(cmd, 0, "", "")

        if cmd and ("node" in Path(cmd[0]).name or "npm" in Path(cmd[0]).name):
            if "-v" in cmd:
                ver = "v20.11.0" if "node" in Path(cmd[0]).name else "10.2.4"
                return subprocess.CompletedProcess(cmd, 0, ver + "\n", "")
            if len(cmd) > 1 and cmd[1] in ("ci", "install"):
                bin_dir = self.ws / "frontend" / "node_modules" / ".bin"
                bin_dir.mkdir(parents=True, exist_ok=True)
                vite = bin_dir / "vite"
                vite.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                vite.chmod(0o755)
                return subprocess.CompletedProcess(cmd, 0, "added 10 packages", "")
            if len(cmd) > 2 and cmd[1:3] == ["run", "build"]:
                dist = self.ws / "frontend" / "dist"
                dist.mkdir(parents=True, exist_ok=True)
                (dist / "index.html").write_text("<html></html>", encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "built in 1.0s", "")

        if len(cmd) >= 4 and cmd[1:4] == ["-m", "pip", "install"]:
            self.backend_installed = True
            return subprocess.CompletedProcess(cmd, 0, "Successfully installed malbox-ai-backend", "")

        if len(cmd) >= 3 and cmd[1] == "-c" and "ALIVE" in cmd[2]:
            return subprocess.CompletedProcess(cmd, 0, "ALIVE\n", "")

        if len(cmd) >= 3 and cmd[1] == "-c" and "pydantic_settings" in cmd[2]:
            if self.backend_installed:
                return subprocess.CompletedProcess(cmd, 0, "OK\n", "")
            return subprocess.CompletedProcess(cmd, 1, "", "ModuleNotFoundError: No module named 'fastapi'")

        if len(cmd) >= 3 and cmd[1] == "-c" and "init_db()" in cmd[2]:
            db_path = self.ws / "data" / "malbox.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db_path))
            try:
                for tbl in REQUIRED_DB_TABLES:
                    conn.execute(f"CREATE TABLE IF NOT EXISTS {tbl} (id TEXT PRIMARY KEY);")
                conn.commit()
            finally:
                conn.close()
            return subprocess.CompletedProcess(cmd, 0, "DB_INITIALIZED\n", "")

        return subprocess.CompletedProcess(cmd, 0, "", "")


def _fake_which(name: str) -> Optional[str]:
    mapping = {"node": "/usr/bin/node", "npm": "/usr/bin/npm"}
    return mapping.get(name)


def test_doctor_fresh_installation_and_check_mode_read_only(tmp_path):
    """Fresh workspace fails `--check` cleanly without mutations, then passes after default setup."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    # 1. Read-only --check fails on missing components and does NOT mutate workspace
    check_rep = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert check_rep["exit_code"] == 1
    assert check_rep["overall_status"] == "FAIL"
    assert not (ws / ".env").exists()
    assert not (ws / ".venv").exists()
    assert not (ws / "data").exists()

    # 2. Default doctor safely bootstraps Replay Mode workspace
    setup_rep = run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)
    assert setup_rep["exit_code"] == 0
    assert setup_rep["overall_status"] == "PASS"
    assert (ws / ".env").is_file()
    assert (ws / ".venv" / "bin" / "python").is_file()
    assert (ws / "frontend" / "node_modules" / ".bin" / "vite").is_file()
    assert (ws / "frontend" / "dist" / "index.html").is_file()
    assert (ws / "data" / "malbox.db").is_file()

    # Quarantine permissions are locked down (0700 on POSIX)
    if os.name == "posix":
        mode = (ws / "data" / "quarantine").stat().st_mode & 0o777
        assert mode == 0o700

    # Replay defaults enforced
    env_vals = parse_env_file(ws / ".env")
    assert env_vals["MALBOX_LIVE_MODE_ENABLED"].lower() == "false"
    assert env_vals["MALBOX_DEFAULT_SANDBOX_BACKEND"].lower() == "replay"
    assert env_vals["MALBOX_HOST"] == "127.0.0.1"

    # Never invokes sudo
    for cmd in runner.commands:
        assert "sudo" not in cmd


def test_doctor_repeated_invocation_preserves_secrets_and_data(tmp_path):
    """Re-running doctor/repair never overwrites user secrets, redact secrets in JSON, and preserves DB rows."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    # Inject custom user secret & DB row
    custom_secret = "sk-user-confidential-key-987654"
    env_text = (ws / ".env").read_text(encoding="utf-8") + f"\nMALBOX_AI_API_KEY={custom_secret}\nMALBOX_AI_PROVIDER=openai\n"
    (ws / ".env").write_text(env_text, encoding="utf-8")

    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    conn.execute("INSERT INTO samples (id) VALUES ('sample_keep_me');")
    conn.commit()
    conn.close()

    # Run doctor again in both default and explicit repair modes
    cmd_count_before = len(runner.commands)
    rep1 = run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)
    rep2 = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)

    assert rep1["exit_code"] == 0
    assert rep2["exit_code"] == 0
    assert (ws / ".env").read_text(encoding="utf-8") == env_text
    assert custom_secret not in json.dumps(rep2)

    # DB row remains completely intact
    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    rows = conn.execute("SELECT id FROM samples;").fetchall()
    conn.close()
    assert rows == [("sample_keep_me",)]

    # Pip/npm were NOT unnecessarily re-executed once already installed
    post_cmds = runner.commands[cmd_count_before:]
    assert not any("pip" in c for c in post_cmds)
    assert not any("ci" in c for c in post_cmds)


def test_doctor_partial_installation_repair(tmp_path):
    """Partial install (.env present without .venv or frontend node_modules) repairs without touching .env."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    custom_env = (
        "MALBOX_HOST=127.0.0.1\n"
        "MALBOX_PORT=8000\n"
        "MALBOX_LIVE_MODE_ENABLED=false\n"
        "MALBOX_DEFAULT_SANDBOX_BACKEND=replay\n"
        "MALBOX_SECRET_KEY=user-partial-secret-keep\n"
    )
    (ws / ".env").write_text(custom_env, encoding="utf-8")

    check_res = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert check_res["exit_code"] == 1
    by_id = {c["id"]: c for c in check_res["checks"]}
    assert by_id["env_config"]["status"] == "PASS"
    assert by_id["backend_venv"]["status"] == "FAIL"
    assert by_id["frontend_deps"]["status"] == "FAIL"

    repair_res = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)
    assert repair_res["exit_code"] == 0
    assert (ws / ".env").read_text(encoding="utf-8") == custom_env
    by_id_after = {c["id"]: c for c in repair_res["checks"]}
    assert by_id_after["backend_venv"]["status"] == "PASS"
    assert by_id_after["backend_venv"]["repaired"] is True
    assert by_id_after["frontend_deps"]["status"] == "PASS"


def test_doctor_missing_dependencies_and_optional_skips(tmp_path):
    """Missing Node/Python/fixtures fail cleanly; missing optional features (CAPE/Ghidra/OpenCode/AI) yield SKIP."""
    ws = _make_isolated_workspace(tmp_path)

    # 1. Missing node & npm -> FAIL by default, SKIP if skip_frontend=True
    node_fail = check_node_npm(skip_frontend=False, which_fn=lambda _: None)
    assert node_fail.status == CheckStatus.FAIL
    node_skip = check_node_npm(skip_frontend=True, which_fn=lambda _: None)
    assert node_skip.status == CheckStatus.SKIP

    # 2. Old Python 3.9 -> FAIL
    py_fail = check_python(version_info=(3, 9, 18))
    assert py_fail.status == CheckStatus.FAIL

    # 3. Missing fixture -> FAIL
    (ws / "fixtures" / "replay" / "ransomware_wannacry_mock.json").unlink()
    fix_fail = check_replay_fixtures(ws)
    assert fix_fail.status == CheckStatus.FAIL
    assert "ransomware_wannacry_mock" in fix_fail.details["missing"]

    # 4. Low disk space -> FAIL
    class LowDisk:
        free = 100 * 1024 * 1024  # 100 MB

    res_fail = check_resources(ws, disk_usage_fn=lambda _: LowDisk(), memory_fn=lambda: (4096, 2048))
    assert res_fail.status == CheckStatus.FAIL

    # 5. Optional tools absent -> SKIP (never FAIL)
    opt_results = check_optional_integrations(ws, environ={}, which_fn=lambda _: None)
    assert all(r.status == CheckStatus.SKIP for r in opt_results)


def test_doctor_unsafe_configuration_blocked(tmp_path, capsys):
    """Unsafe Live Mode (without operator token) fails doctor AND blocks start; 0.0.0.0 warns; --overwrite-env requires --yes."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    # Setup healthy first
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    # Inject unsafe Live Mode config
    (ws / ".env").write_text(
        "MALBOX_HOST=127.0.0.1\nMALBOX_LIVE_MODE_ENABLED=true\nMALBOX_OPERATOR_TOKEN=\n",
        encoding="utf-8",
    )

    rep = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert rep["exit_code"] == 1
    env_check = next(c for c in rep["checks"] if c["id"] == "env_config")
    assert env_check["status"] == "FAIL"
    assert "UNSAFE CONFIGURATION" in env_check["summary"]

    # `start` refuses to boot unsafe configuration
    start_res = start_services(ws, backend_only=True, environ={})
    assert start_res["exit_code"] == 1
    assert start_res["status"] == "blocked"

    # Public host binding 0.0.0.0 triggers WARN
    (ws / ".env").write_text(
        "MALBOX_HOST=0.0.0.0\nMALBOX_LIVE_MODE_ENABLED=false\nMALBOX_DEFAULT_SANDBOX_BACKEND=replay\n",
        encoding="utf-8",
    )
    warn_rep = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert warn_rep["exit_code"] == 0
    assert next(c for c in warn_rep["checks"] if c["id"] == "env_config")["status"] == "WARN"

    # --overwrite-env without --yes refuses in non-interactive test stdin
    rc = cli_main(["doctor", "--overwrite-env", "--json"], root_dir=ws)
    out = capsys.readouterr().out
    assert rc == 1
    assert "Refusing to overwrite" in out


def test_doctor_recovery_corrupt_venv_stale_pid_and_missing_tables(tmp_path):
    """Recovers from corrupt venv, stale PID files, missing DB schema tables, and loose quarantine perms."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    # Break workspace: corrupt empty .venv, stale PIDs, empty SQLite DB with no tables, loose quarantine
    (ws / ".venv").mkdir()
    (ws / ".malbox").mkdir()
    (ws / ".malbox" / "backend.pid").write_text(json.dumps({"pid": 9999999}), encoding="utf-8")
    (ws / ".malbox" / "frontend.pid").write_text("not-json", encoding="utf-8")

    (ws / "data" / "quarantine").mkdir(parents=True)
    if os.name == "posix":
        (ws / "data" / "quarantine").chmod(0o755)

    empty_db = ws / "data" / "malbox.db"
    sqlite3.connect(str(empty_db)).close()

    # Check sees missing tables WARN and broken venv FAIL
    pre_db = check_database(ws, environ={})
    assert pre_db.status == CheckStatus.WARN

    # Repair recovers everything cleanly
    rep = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)
    assert rep["exit_code"] == 0
    assert rep["overall_status"] == "PASS"
    assert not (ws / ".malbox" / "backend.pid").exists()
    assert not (ws / ".malbox" / "frontend.pid").exists()
    assert any("stale PID" in a for a in rep["actions_taken"])
    assert any(c == [sys.executable, "-m", "venv", "--clear", str(ws / ".venv")] for c in runner.commands)
    assert check_database(ws, environ={}).status == CheckStatus.PASS


def test_doctor_port_conflict_detection_and_lifecycle_stop(tmp_path):
    """Detects external TCP port conflict safely and manages real process stop lifecycle cleanly."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    # Bind ephemeral port to simulate conflict
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        busy_port = sock.getsockname()[1]

        (ws / ".env").write_text(
            f"MALBOX_HOST=127.0.0.1\nMALBOX_PORT={busy_port}\nMALBOX_LIVE_MODE_ENABLED=false\n",
            encoding="utf-8",
        )
        port_res = check_ports(ws, skip_frontend=True, environ={})
        assert port_res.status == CheckStatus.WARN
        assert str(busy_port) in port_res.summary

        start_res = start_services(ws, backend_only=True, environ={})
        assert start_res["exit_code"] == 1
        assert start_res["status"] == "port_conflict"

    # Test real managed dummy process stop & cleanup
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        pid_file = ws / ".malbox" / "backend.pid"
        pid_file.write_text(json.dumps({"pid": proc.pid, "pgid": proc.pid, "port": 18000}), encoding="utf-8")

        st = get_status(ws, environ={})
        assert st["backend"]["alive"] is True

        stop_res = stop_services(ws, timeout=5.0)
        assert stop_res["exit_code"] == 0
        assert stop_res["services"]["backend"] == "stopped_gracefully"
        assert not pid_file.exists()
        assert proc.wait(timeout=2.0) is not None
    finally:
        if proc.poll() is None:
            proc.kill()


def test_root_malbox_entrypoint_cli_json_invocation():
    """Verify root ./malbox executable works via portable shell invocation and emits valid JSON."""
    res_help = subprocess.run([str(REPO_ROOT / "malbox"), "--help"], cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
    assert res_help.returncode == 0
    assert "doctor" in res_help.stdout
    assert "start" in res_help.stdout

    res_check = subprocess.run(
        [str(REPO_ROOT / "malbox"), "doctor", "--check", "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(res_check.stdout)
    assert payload["mode"] == "check"
    assert payload["exit_code"] in (0, 1)
    assert {c["status"] for c in payload["checks"]}.issubset({"PASS", "WARN", "FAIL", "SKIP"})
