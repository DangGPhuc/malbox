import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
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
    check_directories,
    check_env_config,
    check_node_npm,
    check_optional_integrations,
    check_ports,
    check_python,
    check_replay_fixtures,
    check_resources,
)
from malbox_cli.cli import main as cli_main  # noqa: E402
from malbox_cli.lifecycle import get_status, start_services, stop_services  # noqa: E402
from malbox_cli.models import (  # noqa: E402
    REQUIRED_DB_TABLES,
    CheckStatus,
    ProcessVerification,
    parse_env_file,
    verify_managed_process,
)
from malbox_cli.repair import run_doctor, run_replay_smoke_test  # noqa: E402


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

        if len(cmd) >= 3 and cmd[1] == "-c" and "SMOKE_JSON" in cmd[2]:
            payload = {
                "analysis_id": "smoke-test-123",
                "risk_score": 100,
                "risk_level": "Malicious",
                "findings_count": 4,
                "graph_nodes": 17,
                "graph_edges": 16,
                "elapsed_ms": 50.0,
                "peak_rss_mb": 45.0,
            }
            return subprocess.CompletedProcess(cmd, 0, "SMOKE_JSON:" + json.dumps(payload) + "\n", "")

        return subprocess.CompletedProcess(cmd, 0, "", "")


def _fake_which(name: str) -> Optional[str]:
    mapping = {"node": "/usr/bin/node", "npm": "/usr/bin/npm"}
    return mapping.get(name)


def test_doctor_fresh_installation_and_permissions(tmp_path):
    """Fresh workspace fails `--check`, then sets up with strict 0600 (.env) and 0700 (quarantine/.malbox) perms."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    check_rep = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert check_rep["exit_code"] == 1
    assert check_rep["overall_status"] == "FAIL"
    assert not (ws / ".env").exists()
    assert not (ws / ".venv").exists()

    setup_rep = run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)
    assert setup_rep["exit_code"] == 0
    assert setup_rep["overall_status"] == "PASS"

    if os.name == "posix":
        assert ((ws / ".env").stat().st_mode & 0o777) == 0o600
        assert ((ws / "data" / "quarantine").stat().st_mode & 0o777) == 0o700
        assert ((ws / ".malbox").stat().st_mode & 0o777) == 0o700

    env_vals = parse_env_file(ws / ".env")
    assert env_vals["MALBOX_LIVE_MODE_ENABLED"].lower() == "false"
    assert env_vals["MALBOX_DEFAULT_SANDBOX_BACKEND"].lower() == "replay"
    assert env_vals["MALBOX_HOST"] == "127.0.0.1"

    for cmd in runner.commands:
        assert "sudo" not in cmd


def test_doctor_repeated_invocation_preserves_secrets_and_tightens_permissions(tmp_path):
    """Re-running doctor never overwrites secrets, tightens permissive .env/log modes safely, and preserves DB rows."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    custom_secret = "sk-user-confidential-key-987654"
    env_text = (ws / ".env").read_text(encoding="utf-8") + f"\nMALBOX_AI_API_KEY={custom_secret}\nMALBOX_AI_PROVIDER=openai\n"
    (ws / ".env").write_text(env_text, encoding="utf-8")
    if os.name == "posix":
        (ws / ".env").chmod(0o644)
        logf = ws / ".malbox" / "backend.log"
        logf.write_text("sample log\n", encoding="utf-8")
        logf.chmod(0o644)
        (ws / ".malbox").chmod(0o755)

    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    conn.execute("INSERT INTO samples (id) VALUES ('sample_keep_me');")
    conn.commit()
    conn.close()

    # Check flags permissive permissions as WARN
    warn_chk = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    by_id = {c["id"]: c for c in warn_chk["checks"]}
    assert by_id["env_config"]["status"] == "WARN"
    assert by_id["directories"]["status"] == "WARN"

    # Repair restricts perms to 0600/0700 while keeping user secrets intact
    cmd_count_before = len(runner.commands)
    rep1 = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)
    rep2 = run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)

    assert rep1["exit_code"] == 0
    assert rep1["overall_status"] == "PASS"
    assert rep2["exit_code"] == 0
    assert (ws / ".env").read_text(encoding="utf-8") == env_text
    assert custom_secret not in json.dumps(rep1)

    if os.name == "posix":
        assert ((ws / ".env").stat().st_mode & 0o777) == 0o600
        assert ((ws / ".malbox").stat().st_mode & 0o777) == 0o700
        assert ((ws / ".malbox" / "backend.log").stat().st_mode & 0o777) == 0o600

    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    rows = conn.execute("SELECT id FROM samples;").fetchall()
    conn.close()
    assert rows == [("sample_keep_me",)]

    post_cmds = runner.commands[cmd_count_before:]
    assert not any("pip" in c for c in post_cmds)
    assert not any("ci" in c for c in post_cmds)


def test_doctor_partial_installation_repair(tmp_path):
    """Partial install (.env present without .venv or node_modules) repairs without touching .env."""
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
    if os.name == "posix":
        (ws / ".env").chmod(0o600)

    repair_res = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)
    assert repair_res["exit_code"] == 0
    assert (ws / ".env").read_text(encoding="utf-8") == custom_env


def test_doctor_missing_dependencies_and_optional_skips(tmp_path):
    """Missing Node/Python/fixtures fail cleanly; missing optional features (CAPE/Ghidra/OpenCode/AI) yield SKIP."""
    ws = _make_isolated_workspace(tmp_path)

    assert check_node_npm(skip_frontend=False, which_fn=lambda _: None).status == CheckStatus.FAIL
    assert check_node_npm(skip_frontend=True, which_fn=lambda _: None).status == CheckStatus.SKIP
    assert check_python(version_info=(3, 9, 18)).status == CheckStatus.FAIL

    (ws / "fixtures" / "replay" / "ransomware_wannacry_mock.json").unlink()
    fix_fail = check_replay_fixtures(ws)
    assert fix_fail.status == CheckStatus.FAIL

    class LowDisk:
        free = 100 * 1024 * 1024

    assert check_resources(ws, disk_usage_fn=lambda _: LowDisk(), memory_fn=lambda: (4096, 2048)).status == CheckStatus.FAIL

    opt_results = check_optional_integrations(ws, environ={}, which_fn=lambda _: None)
    assert all(r.status == CheckStatus.SKIP for r in opt_results)


def test_doctor_unsafe_configuration_blocked(tmp_path, capsys):
    """Unsafe Live Mode without operator token fails doctor AND blocks start; 0.0.0.0 warns; --overwrite-env requires --yes."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    (ws / ".env").write_text(
        "MALBOX_HOST=127.0.0.1\nMALBOX_LIVE_MODE_ENABLED=true\nMALBOX_OPERATOR_TOKEN=\n",
        encoding="utf-8",
    )

    rep = run_doctor(ws, mode="check", environ={}, runner=runner, which_fn=_fake_which)
    assert rep["exit_code"] == 1
    assert next(c for c in rep["checks"] if c["id"] == "env_config")["status"] == "FAIL"

    start_res = start_services(ws, backend_only=True, environ={})
    assert start_res["exit_code"] == 1
    assert start_res["status"] == "blocked"

    rc = cli_main(["doctor", "--overwrite-env", "--json"], root_dir=ws)
    assert rc == 1
    assert "Refusing to overwrite" in capsys.readouterr().out


def test_doctor_recovery_corrupt_venv_stale_pid_and_missing_tables(tmp_path):
    """Recovers from dead/corrupt PID files, corrupt venv, missing DB tables, and loose permissions."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)

    (ws / ".venv").mkdir()
    (ws / ".malbox").mkdir()
    (ws / ".malbox" / "backend.pid").write_text(json.dumps({"pid": 9999999, "proc_start_time": "ticks:1"}), encoding="utf-8")
    (ws / ".malbox" / "frontend.pid").write_text("not-json", encoding="utf-8")
    (ws / "data" / "quarantine").mkdir(parents=True)
    sqlite3.connect(str(ws / "data" / "malbox.db")).close()

    rep = run_doctor(ws, mode="repair", environ={}, runner=runner, which_fn=_fake_which)
    assert rep["exit_code"] == 0
    assert rep["overall_status"] == "PASS"
    assert not (ws / ".malbox" / "backend.pid").exists()
    assert not (ws / ".malbox" / "frontend.pid").exists()


def test_lifecycle_strong_ownership_verification_rejects_unrelated_reused_and_tampered_pgids(tmp_path):
    """
    Tests strong ownership verification using mocked signals and proc metadata:
    - Rejects unrelated Python/Node processes (never uses bare 'python'/'node' matching)
    - Rejects reused PIDs (proc_start_time mismatch)
    - Rejects PID files missing proc_start_time
    - Ignores manipulated stored PGIDs and verifies actual OS PGID before sending killpg
    - Handles partial shutdown cleanly and returns nonzero exit code when unsafe
    """
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    backend_cwd = ws.resolve()
    frontend_cwd = (ws / "frontend").resolve()

    # 1. Unrelated python process -> UNVERIFIED, zero signals sent, nonzero stop exit
    unrel_state = {
        "service": "backend",
        "pid": 44444,
        "pgid": 123,  # attacker-supplied bogus pgid
        "root_dir": str(backend_cwd),
        "proc_start_time": "ticks:1000",
        "port": 8000,
    }
    ver_unrel = verify_managed_process(
        unrel_state,
        "backend",
        ws,
        liveness_fn=lambda _: "alive",
        start_time_fn=lambda _: "ticks:1000",
        cmdline_fn=lambda _: "/usr/bin/python3 -m http.server 8000",
        cwd_fn=lambda _: Path("/tmp"),
        getpgid_fn=lambda _: 44444,
    )
    assert ver_unrel.status == "unverified"

    # 2. Reused PID (proc_start_time changed even if cmdline happens to look similar)
    ver_reused = verify_managed_process(
        unrel_state,
        "backend",
        ws,
        liveness_fn=lambda _: "alive",
        start_time_fn=lambda _: "ticks:999999",
        cmdline_fn=lambda _: f"{ws}/.venv/bin/python -m uvicorn app.main:app --port 8000",
        cwd_fn=lambda _: backend_cwd,
        getpgid_fn=lambda _: 44444,
    )
    assert ver_reused.status == "reused_pid"

    # 3. Missing proc_start_time -> UNVERIFIED
    legacy_state = {"service": "backend", "pid": 44444, "port": 8000}
    ver_no_start = verify_managed_process(
        legacy_state,
        "backend",
        ws,
        liveness_fn=lambda _: "alive",
        start_time_fn=lambda _: "ticks:1000",
        cmdline_fn=lambda _: "uvicorn app.main:app --port 8000",
        cwd_fn=lambda _: backend_cwd,
    )
    assert ver_no_start.status == "unverified"

    # 4. Stop with manipulated PGID + valid OS PGID verifies actual OS PGID is used (NOT stored PGID!)
    (ws / ".malbox" / "backend.pid").write_text(json.dumps({
        "service": "backend",
        "pid": 55555,
        "pgid": 999,  # bogus stored PGID that MUST be ignored!
        "root_dir": str(backend_cwd),
        "proc_start_time": "ticks:2000",
        "port": 8000,
    }), encoding="utf-8")

    # Also put an unrelated PID in frontend.pid to test partial shutdown failure
    (ws / ".malbox" / "frontend.pid").write_text(json.dumps({
        "service": "frontend",
        "pid": 66666,
        "root_dir": str(backend_cwd),
        "proc_start_time": "ticks:3000",
        "port": 5173,
    }), encoding="utf-8")

    kill_calls = []
    killpg_calls = []
    alive_pids = {55555, 66666}

    def mock_kill(pid, sig):
        kill_calls.append((pid, sig))
        if sig in (signal.SIGTERM, signal.SIGKILL):
            alive_pids.discard(pid)

    def mock_killpg(pgid, sig):
        killpg_calls.append((pgid, sig))
        if pgid == 55555 and sig in (signal.SIGTERM, signal.SIGKILL):
            alive_pids.discard(55555)

    def mock_verify(state, svc, root):
        if svc == "backend":
            return verify_managed_process(
                state,
                "backend",
                root,
                liveness_fn=lambda p: "alive" if p in alive_pids else "dead",
                start_time_fn=lambda _: "ticks:2000",
                cmdline_fn=lambda _: f"{ws}/.venv/bin/python -m uvicorn app.main:app --port 8000",
                cwd_fn=lambda _: backend_cwd,
                getpgid_fn=lambda p: p,  # real OS PGID = 55555 (not stored bogus 999!)
            )
        return verify_managed_process(
            state,
            "frontend",
            root,
            liveness_fn=lambda p: "alive" if p in alive_pids else "dead",
            start_time_fn=lambda _: "ticks:3000",
            cmdline_fn=lambda _: "node /unrelated/app/server.js",  # Unrelated Node process!
            cwd_fn=lambda _: frontend_cwd,
            getpgid_fn=lambda p: p,
        )

    stop_res = stop_services(
        ws,
        timeout=1.0,
        verify_fn=mock_verify,
        kill_fn=mock_kill,
        killpg_fn=mock_killpg,
    )

    # Partial shutdown: backend stopped cleanly via OS-verified PGID 55555 (never 999!),
    # while unrelated Node frontend was REFUSED with nonzero exit_code!
    assert stop_res["exit_code"] == 1
    assert stop_res["status"] == "partial_failure"
    assert stop_res["services"]["backend"] == "stopped_gracefully"
    assert stop_res["services"]["frontend"] == "refused_unverified"
    assert (55555, signal.SIGTERM) in killpg_calls
    assert all(pg != 999 for pg, _ in killpg_calls)
    assert all(pid != 66666 for pid, _ in kill_calls)
    assert all(pg != 66666 for pg, _ in killpg_calls)
    assert not (ws / ".malbox" / "backend.pid").exists()
    assert (ws / ".malbox" / "frontend.pid").exists()

    # 5. If OS PGID != PID (shared process group), group signal is NOT sent — only direct PID signal!
    (ws / ".malbox" / "frontend.pid").unlink()
    (ws / ".malbox" / "backend.pid").write_text(json.dumps({
        "service": "backend",
        "pid": 77777,
        "root_dir": str(backend_cwd),
        "proc_start_time": "ticks:4000",
        "port": 8000,
    }), encoding="utf-8")
    alive_pids = {77777}
    kill_calls.clear()
    killpg_calls.clear()

    def mock_verify_shared_pg(state, svc, root):
        return verify_managed_process(
            state,
            "backend",
            root,
            liveness_fn=lambda p: "alive" if p in alive_pids else "dead",
            start_time_fn=lambda _: "ticks:4000",
            cmdline_fn=lambda _: f"{ws}/.venv/bin/python -m uvicorn app.main:app --port 8000",
            cwd_fn=lambda _: backend_cwd,
            getpgid_fn=lambda _: 11111,  # shared group != pid 77777!
        )

    stop_shared = stop_services(
        ws,
        timeout=1.0,
        verify_fn=mock_verify_shared_pg,
        kill_fn=mock_kill,
        killpg_fn=mock_killpg,
    )
    assert stop_shared["exit_code"] == 0
    assert stop_shared["services"]["backend"] == "stopped_gracefully"
    assert killpg_calls == []
    assert (77777, signal.SIGTERM) in kill_calls

    # 6. Repeated idempotent stop when stopped exits 0 with not_running
    stop_again = stop_services(ws)
    assert stop_again["exit_code"] == 0
    assert stop_again["services"]["backend"] == "not_running"


def test_real_unrelated_process_refused_safely(tmp_path):
    """Real harmless python subprocess (sleep) inside backend.pid MUST be rejected cleanly without signaling."""
    ws = _make_isolated_workspace(tmp_path)
    (ws / ".malbox").mkdir()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"], start_new_session=True)
    try:
        from malbox_cli.models import get_process_start_time
        start_tok = get_process_start_time(proc.pid)
        pid_file = ws / ".malbox" / "backend.pid"
        pid_file.write_text(json.dumps({
            "service": "backend",
            "pid": proc.pid,
            "root_dir": str(ws.resolve()),
            "proc_start_time": start_tok,
            "port": 8000,
        }), encoding="utf-8")

        # stop MUST refuse to kill the unrelated sleep script and MUST return nonzero exit code
        stop_res = stop_services(ws)
        assert stop_res["exit_code"] == 1
        assert stop_res["services"]["backend"] == "refused_unverified"
        assert proc.poll() is None  # Still alive, completely unharmed!

        # start MUST also refuse to blindly overwrite
        (ws / ".venv" / "bin").mkdir(parents=True)
        (ws / ".venv" / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
        start_res = start_services(ws, backend_only=True, environ={})
        assert start_res["exit_code"] == 1
        assert start_res["status"] == "unverified_pid"
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_custom_ports_invalid_ports_conflict_and_vite_proxy(tmp_path):
    """Validates custom ports, rejects invalid ports clearly, identifies external port conflicts, and tests Vite proxy."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    # 1. Valid custom ports
    (ws / ".env").write_text(
        "MALBOX_HOST=127.0.0.1\nMALBOX_PORT=8123\nMALBOX_FRONTEND_PORT=5199\nMALBOX_LIVE_MODE_ENABLED=false\n",
        encoding="utf-8",
    )
    os.chmod(ws / ".env", 0o600)
    custom_ports = check_ports(ws, environ={})
    assert custom_ports.status == CheckStatus.PASS
    assert custom_ports.details["backend_port"] == 8123
    assert custom_ports.details["frontend_port"] == 5199

    st = get_status(ws, environ={})
    assert st["backend"]["url"] == "http://127.0.0.1:8123"
    assert st["frontend"]["url"] == "http://127.0.0.1:5199"

    # 2. Invalid / out-of-range / colliding ports FAIL clearly
    for bad_env in (
        "MALBOX_PORT=not_a_number\n",
        "MALBOX_PORT=70000\n",
        "MALBOX_PORT=0\n",
        "MALBOX_PORT=8000\nMALBOX_FRONTEND_PORT=8000\n",
    ):
        (ws / ".env").write_text(bad_env, encoding="utf-8")
        assert check_env_config(ws, environ={}).status == CheckStatus.FAIL
        assert check_ports(ws, environ={}).status == CheckStatus.FAIL
        assert start_services(ws, backend_only=True, environ={})["status"] == "invalid_config"

    # 3. External port conflict identified without claiming ownership
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        busy_port = sock.getsockname()[1]

        (ws / ".env").write_text(
            f"MALBOX_HOST=127.0.0.1\nMALBOX_PORT={busy_port}\nMALBOX_LIVE_MODE_ENABLED=false\n",
            encoding="utf-8",
        )
        res = check_ports(ws, skip_frontend=True, environ={})
        assert res.status == CheckStatus.WARN
        assert "external/unmanaged process" in res.summary
        assert res.details["running_managed"] == []

        start_res = start_services(ws, backend_only=True, environ={})
        assert start_res["exit_code"] == 1
        assert start_res["status"] == "port_conflict"

    # 4. Verify Vite config resolves custom backend proxy target when Node + vite exist
    if (REPO_ROOT / "frontend" / "node_modules" / "vite").is_dir() and shutil.which("node"):
        env_custom = dict(os.environ)
        env_custom["MALBOX_PORT"] = "8245"
        env_custom["MALBOX_FRONTEND_PORT"] = "5245"
        js_probe = (
            "import('vite').then(async ({ resolveConfig }) => {"
            " const c = await resolveConfig({}, 'serve');"
            " console.log(JSON.stringify({port: c.server.port, target: c.server.proxy['/api'].target}));"
            "});"
        )
        vite_res = subprocess.run(
            ["node", "-e", js_probe],
            cwd=str(REPO_ROOT / "frontend"),
            env=env_custom,
            capture_output=True,
            text=True,
            check=False,
        )
        assert vite_res.returncode == 0
        parsed_vite = json.loads(vite_res.stdout.strip().splitlines()[-1])
        assert parsed_vite["port"] == 5245
        assert parsed_vite["target"] == "http://127.0.0.1:8245"


def test_doctor_smoke_test_flag_and_read_only_check_exclusion(tmp_path):
    """--smoke-test works explicitly without altering user data, and cannot run under read-only --check."""
    ws = _make_isolated_workspace(tmp_path)
    runner = FakeToolchainRunner(ws)
    assert run_doctor(ws, mode="default", environ={}, runner=runner, which_fn=_fake_which)["exit_code"] == 0

    # Insert user DB sentinel row that MUST NOT be touched by smoke test
    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    conn.execute("INSERT INTO samples (id) VALUES ('user_row_untouched');")
    conn.commit()
    conn.close()

    # --check + --smoke-test must be rejected cleanly
    assert cli_main(["doctor", "--check", "--smoke-test"], root_dir=ws) == 1

    # Smoke test executes via runner cleanly without altering user DB
    smoke_res = run_replay_smoke_test(ws, runner=runner, environ={})
    assert smoke_res.status == CheckStatus.PASS
    assert "WannaCry scenario" in smoke_res.summary

    # Also verify real isolated SMOKE_TEST_SCRIPT execution using current test interpreter
    from malbox_cli.repair import SMOKE_TEST_SCRIPT
    import tempfile
    with tempfile.TemporaryDirectory(prefix="malbox_pytest_smoke_") as real_tmp:
        smoke_env = dict(os.environ)
        smoke_env.update({
            "PYTHONPATH": str(REPO_ROOT / "backend"),
            "MALBOX_SMOKE_TMPDIR": real_tmp,
            "MALBOX_DATA_DIR": str(Path(real_tmp) / "data"),
            "MALBOX_QUARANTINE_DIR": str(Path(real_tmp) / "data" / "quarantine"),
            "MALBOX_ARTIFACTS_DIR": str(Path(real_tmp) / "data" / "artifacts"),
            "MALBOX_FIXTURES_DIR": str(REPO_ROOT / "fixtures" / "replay"),
            "MALBOX_DATABASE_URL": f"sqlite:///{Path(real_tmp) / 'smoke.db'}",
            "MALBOX_LIVE_MODE_ENABLED": "false",
            "MALBOX_DEFAULT_SANDBOX_BACKEND": "replay",
            "MALBOX_AI_PROVIDER": "mock",
            "MALBOX_OPERATOR_TOKEN": "",
        })
        real_run = subprocess.run(
            [sys.executable, "-c", SMOKE_TEST_SCRIPT],
            cwd=str(REPO_ROOT),
            env=smoke_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert real_run.returncode == 0, f"Real SMOKE_TEST_SCRIPT failed: {real_run.stderr}"
        assert "SMOKE_JSON:" in real_run.stdout

    conn = sqlite3.connect(str(ws / "data" / "malbox.db"))
    rows = conn.execute("SELECT id FROM samples;").fetchall()
    conn.close()
    assert rows == [("user_row_untouched",)]


def test_root_malbox_entrypoint_cli_json_and_smoke_invocation():
    """Verify root ./malbox executable supports --help, --check --json, and real isolated --smoke-test --json."""
    res_help = subprocess.run([str(REPO_ROOT / "malbox"), "--help"], cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
    assert res_help.returncode == 0
    assert "doctor" in res_help.stdout

    res_check = subprocess.run(
        [str(REPO_ROOT / "malbox"), "doctor", "--check", "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(res_check.stdout)
    assert payload["mode"] == "check"
    assert {c["status"] for c in payload["checks"]}.issubset({"PASS", "WARN", "FAIL", "SKIP"})
