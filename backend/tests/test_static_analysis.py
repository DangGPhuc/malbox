from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import struct
import subprocess
import sys
import threading
import time
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "ghidra_scripts"
CLI_PARENT = REPO_ROOT / "scripts"
if str(CLI_PARENT) not in sys.path:
    sys.path.insert(0, str(CLI_PARENT))

from malbox_cli.checks import check_optional_integrations
from malbox_cli.models import CheckStatus

from app.ai.intelligence_helper import build_deterministic_proposed_intelligence
from app.core.config import settings
from app.models.analysis import Analysis, AnalysisStatus
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.schemas.intelligence import AIProviderMetadata
from app.schemas.report import RiskAssessment
from app.schemas.static_analysis import (
    DecompiledFunction,
    FunctionCallRelationship,
    FunctionMetadata,
    ImportedSymbol,
    ProgramMetadata,
    StaticAnalysisProvenance,
    StaticAnalysisResult,
    StaticAnalysisTruncation,
    StaticStringEvidence,
    make_static_function_id,
)
from app.services.intelligence.bundle_builder import EvidenceBundleBuilder
from app.services.intelligence.validator import EvidenceValidator
from app.services.static_analysis.containment import (
    CgroupMemorySupport,
    check_vm_memory_headroom,
    get_available_memory_mb,
)
from app.services.static_analysis.ghidra_adapter import (
    GhidraIsolationError,
    GhidraStaticAnalyzer,
    build_ghidra_headless_args,
    build_ghidra_sandbox_command,
    prepare_isolated_project_workspace,
    validate_sample_for_static_analysis,
)
from app.services.static_analysis.ranker import rank_functions
from app.services.static_analysis.version_check import (
    locate_ghidra_home,
    parse_java_major_version,
    validate_ghidra_runtime,
)
from app.services.static_analysis.worker import (
    StaticAnalysisBusyError,
    StaticAnalysisSubmissionError,
    StaticAnalysisWorkerManager,
    prepare_result_for_persistence,
    static_worker_manager,
)
from sqlalchemy.orm import sessionmaker

from app.services.submission.pe_parser import parse_pe_metadata


def _build_minimal_pe32() -> bytes:
    """Builds a minimal harmless PE32 x86 binary with 1 trivial .text function (never executed)."""
    buf = bytearray(1024)
    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    # PE signature + COFF header at 0x80
    pe_off = 0x80
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x014C, 1, 0, 0, 0, 224, 0x0102)
    # Optional Header Standard + Windows fields (PE32 0x010B)
    opt_off = pe_off + 24
    struct.pack_into(
        "<HBBIIIIII",
        buf,
        opt_off,
        0x010B,
        1,
        0,
        0x200,
        0,
        0,
        0x1000,
        0x1000,
        0x1000,
    )
    struct.pack_into(
        "<IIIHHHHHHIIIIHHIIIIII",
        buf,
        opt_off + 28,
        0x00400000,  # ImageBase
        0x1000,      # SectionAlignment
        0x0200,      # FileAlignment
        6, 0, 0, 0, 6, 0, 0,
        0x2000,      # SizeOfImage
        0x0200,      # SizeOfHeaders
        0,
        3,           # IMAGE_SUBSYSTEM_WINDOWS_CUI
        0,
        0x100000, 0x1000, 0x100000, 0x1000,
        0,
        16,
    )
    # Section header (.text) at opt_off + 224
    sec_off = opt_off + 224
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        buf,
        sec_off + 8,
        0x200,       # VirtualSize
        0x1000,      # VirtualAddress
        0x200,       # SizeOfRawData
        0x200,       # PointerToRawData
        0, 0, 0, 0,
        0x60000020,  # CODE | EXECUTE | READ
    )
    # Minimal x86 function: push ebp; mov ebp, esp; mov eax, 42; pop ebp; ret
    buf[0x200 : 0x200 + 10] = bytes.fromhex("55 89 e5 b8 2a 00 00 00 5d c3")
    return bytes(buf)


def _write_pe_sample(directory: Path, name: str = "sample.bin") -> tuple[Path, str, bytes]:
    data = _build_minimal_pe32()
    p = directory / name
    p.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    return p, sha, data


def _make_fake_ghidra_install(root: Path, version: str = "12.1.4", min_java: int = 21) -> Path:
    gh = root / "ghidra"
    (gh / "support").mkdir(parents=True, exist_ok=True)
    (gh / "Ghidra").mkdir(parents=True, exist_ok=True)
    ah = gh / "support" / "analyzeHeadless"
    ah.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ah.chmod(0o755)
    (gh / "Ghidra" / "application.properties").write_text(
        f"application.version={version}\napplication.java.min={min_java}\n",
        encoding="utf-8",
    )
    return gh


def _make_fake_jdk(root: Path) -> Path:
    jh = root / "jdk"
    (jh / "bin").mkdir(parents=True, exist_ok=True)
    for tool in ("java", "javac"):
        p = jh / "bin" / tool
        p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        p.chmod(0o755)
    return jh


def _mock_runtime(ghidra_home: Path, jdk_home: Path, version: str = "12.1.4"):
    return validate_ghidra_runtime(
        configured_home=str(ghidra_home),
        env={"JAVA_HOME": str(jdk_home)},
        runner=lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0], returncode=0, stdout="", stderr='openjdk version "25.0.4.1" 2026-01-20'
        ),
    )


def _extract_output_path_from_bwrap_cmd(cmd: list[str], job_dir: Path) -> Path:
    # Sandbox mounts job_dir to /work and sets output path /work/output/facts.json
    idx = cmd.index("-postScript")
    container_out = Path(cmd[idx + 2])
    rel = container_out.relative_to("/work")
    return job_dir / rel


def _mock_cg_support(supported: bool = True) -> CgroupMemorySupport:
    if not supported:
        return CgroupMemorySupport(supported=False, reason="systemd-run unavailable in test")
    return CgroupMemorySupport(
        supported=True,
        backend="systemd_cgroup_v2",
        runner_bin="/usr/bin/systemd-run",
        systemctl_bin=None,
        host_env={"XDG_RUNTIME_DIR": "/run/user/1000"},
    )


def _patch_valid_preflights(monkeypatch, rt, *, with_cgroup: bool = True, avail_mb: int = 4096):
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.validate_ghidra_runtime",
        lambda configured_home=None: rt,
    )
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.check_os_sandbox_support",
        lambda backend="bwrap": (True, "/usr/bin/bwrap", None),
    )
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.check_vm_memory_headroom",
        lambda min_available_mb, mem_reader=None: (avail_mb >= min_available_mb, avail_mb, "ok" if avail_mb >= min_available_mb else "Insufficient available VM memory"),
    )
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.check_cgroup_memory_support",
        lambda *a, **kw: _mock_cg_support(with_cgroup),
    )


def _fake_popen_writer(payload: object, *, stdout_bytes: bytes = b"INFO ok\n", returncode: int = 0):
    class _FakeProc:
        def __init__(self, cmd, cwd=None, **kwargs):
            self.pid = 424242
            self.returncode = returncode
            job_dir = Path(cwd)
            out_path = _extract_output_path_from_bwrap_cmd(cmd, job_dir)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(payload, bytes):
                out_path.write_bytes(payload)
            elif isinstance(payload, str):
                out_path.write_text(payload, encoding="utf-8")
            elif payload is not None:
                out_path.write_text(json.dumps(payload), encoding="utf-8")
            self.stdout = io.BytesIO(stdout_bytes)
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    return _FakeProc


# ---------------------------------------------------------------------------
# 1. Missing Ghidra installation -> UNAVAILABLE
# ---------------------------------------------------------------------------
def test_missing_ghidra_installation_returns_unavailable(tmp_path):
    sample_path, sha, data = _write_pe_sample(tmp_path)
    assert parse_pe_metadata(data)["is_valid_pe"] is True

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(tmp_path / "does_not_exist"),
        workspace_root=tmp_path / "ws",
        scripts_dir=SCRIPTS_DIR,
    )
    res = analyzer.analyze_sample("smp-1", sample_path, sha)
    assert res.status == "UNAVAILABLE"
    assert res.provenance.binary_executed is False
    assert any("does not exist" in e.lower() or "unavailable" in e.lower() for e in res.errors)


# ---------------------------------------------------------------------------
# 2. Wrong Java version / missing javac -> UNAVAILABLE + Doctor WARN
# ---------------------------------------------------------------------------
def test_wrong_java_version_and_doctor_warning(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path, version="12.1.4", min_java=21)
    jdk = _make_fake_jdk(tmp_path)

    assert parse_java_major_version('openjdk version "25.0.4.1"') == 25
    assert parse_java_major_version('java version "1.8.0_392"') == 8

    def fake_java17_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr='openjdk version "17.0.9" 2023-10-17'
        )

    rt_bad = validate_ghidra_runtime(
        configured_home=str(gh),
        env={"JAVA_HOME": str(jdk)},
        runner=fake_java17_runner,
    )
    assert rt_bad.ok is False
    assert rt_bad.java_major == 17
    assert "requires JDK 21+" in (rt_bad.error or "")

    # Missing javac (JRE only) is also rejected
    (jdk / "bin" / "javac").unlink()
    rt_no_javac = validate_ghidra_runtime(
        configured_home=str(gh),
        env={"JAVA_HOME": str(jdk)},
        runner=fake_java17_runner,
    )
    assert rt_no_javac.ok is False
    assert "javac" in (rt_no_javac.error or "").lower()

    # Adapter propagates UNAVAILABLE when validate_ghidra_runtime fails
    sample_path, sha, _ = _write_pe_sample(tmp_path)
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.validate_ghidra_runtime",
        lambda configured_home=None: rt_bad,
    )
    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws",
        scripts_dir=SCRIPTS_DIR,
    )
    res = analyzer.analyze_sample("smp-java", sample_path, sha)
    assert res.status == "UNAVAILABLE"
    assert "JDK 21+" in res.errors[0]

    # Doctor reports WARN when Ghidra is enabled with incompatible JDK
    jdk = _make_fake_jdk(tmp_path / "jdk2")
    ws = tmp_path / "repo_ws"
    ws.mkdir()
    opt_checks = check_optional_integrations(
        ws,
        environ={"MALBOX_GHIDRA_ENABLED": "true", "MALBOX_GHIDRA_HOME": str(gh)},
        which_fn=lambda tool: str(jdk / "bin" / tool) if tool in ("java", "javac") else None,
        runner=fake_java17_runner,
    )
    gh_check = next(c for c in opt_checks if c.id == "opt_ghidra")
    assert gh_check.status == CheckStatus.WARN
    assert "JDK 21+" in gh_check.summary or "17" in gh_check.summary


# ---------------------------------------------------------------------------
# 3. Invalid executable format (non-PE) -> FAILED without running subprocess
# ---------------------------------------------------------------------------
def test_invalid_executable_format_fails(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)

    bad_file = tmp_path / "not_a_pe.sh"
    bad_bytes = b"#!/bin/sh\necho harmless_text\n"
    bad_file.write_bytes(bad_bytes)
    sha = hashlib.sha256(bad_bytes).hexdigest()

    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.validate_ghidra_runtime", lambda configured_home=None: rt)
    popen_mock = MagicMock()
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", popen_mock)

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws",
        scripts_dir=SCRIPTS_DIR,
    )
    res = analyzer.analyze_sample("smp-nonpe", bad_file, sha)
    assert res.status == "FAILED"
    assert "PE" in res.errors[0]
    popen_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Sample SHA-256 mismatch -> FAILED without running subprocess
# ---------------------------------------------------------------------------
def test_sample_sha256_mismatch_fails(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, _, _ = _write_pe_sample(tmp_path)

    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.validate_ghidra_runtime", lambda configured_home=None: rt)
    popen_mock = MagicMock()
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", popen_mock)

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws",
        scripts_dir=SCRIPTS_DIR,
    )
    res = analyzer.analyze_sample("smp-hash", sample_path, "0" * 64)
    assert res.status == "FAILED"
    assert "SHA-256" in res.errors[0]
    popen_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Unsafe paths & symlinks fail closed
# ---------------------------------------------------------------------------
def test_unsafe_paths_and_symlinks_fail_closed(tmp_path):
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    sym_sample = tmp_path / "sym_sample.bin"
    sym_sample.symlink_to(sample_path)
    with pytest.raises(GhidraIsolationError, match="symlink"):
        validate_sample_for_static_analysis(sym_sample, sha, 1024 * 1024)

    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    sym_dir = tmp_path / "sym_dir"
    sym_dir.symlink_to(real_dir)
    inner_sample, inner_sha, _ = _write_pe_sample(real_dir)
    with pytest.raises(GhidraIsolationError, match="symlinked directory"):
        validate_sample_for_static_analysis(sym_dir / inner_sample.name, inner_sha, 1024 * 1024)

    with pytest.raises(GhidraIsolationError, match="traversal"):
        validate_sample_for_static_analysis(tmp_path / ".." / sample_path.name, sha, 1024 * 1024)

    sym_ws = tmp_path / "sym_ws"
    sym_ws.symlink_to(real_dir)
    with pytest.raises(GhidraIsolationError, match="symlink"):
        prepare_isolated_project_workspace(sym_ws, "job1234", sha)

    with pytest.raises(GhidraIsolationError, match="traversal"):
        prepare_isolated_project_workspace(tmp_path / ".." / "ws", "job1234", sha)

    _, rel_err = locate_ghidra_home("relative/ghidra")
    assert rel_err is not None
    _, trav_err = locate_ghidra_home("/usr/share/../ghidra")
    assert trav_err is not None


# ---------------------------------------------------------------------------
# 6. Workspace isolation & refusing project reuse across mismatched hashes
# ---------------------------------------------------------------------------
def test_workspace_isolation_and_project_reuse_mismatch_refused(tmp_path, monkeypatch):
    ws_root = tmp_path / "ghidra_ws"
    sha_a = "a" * 64
    sha_b = "b" * 64

    job_dir, proj_name = prepare_isolated_project_workspace(ws_root, "jobabcd1", sha_a)
    assert proj_name == "malbox_jobabcd1"
    assert not job_dir.name.startswith(".")
    assert (job_dir / "malbox_project_manifest.json").is_file()
    if os.name == "posix":
        assert (ws_root.stat().st_mode & 0o777) == 0o700
        assert (job_dir.stat().st_mode & 0o777) == 0o700

    # Same job + mismatched SHA-256 must fail closed
    with pytest.raises(GhidraIsolationError, match="mismatched sample SHA-256"):
        prepare_isolated_project_workspace(ws_root, "jobabcd1", sha_b)

    # Missing manifest fails closed
    (job_dir / "malbox_project_manifest.json").unlink()
    with pytest.raises(GhidraIsolationError, match="lacks provenance manifest"):
        prepare_isolated_project_workspace(ws_root, "jobabcd1", sha_a)

    # Adapter cleans up job_dir automatically after failure/completion
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha_real, _ = _write_pe_sample(tmp_path)
    _patch_valid_preflights(monkeypatch, rt)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _fake_popen_writer({"status": "COMPLETED", "functions": []}))

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=ws_root,
        scripts_dir=SCRIPTS_DIR,
    )
    analyzer.analyze_sample("smp-clean", sample_path, sha_real, job_id="jobclean123")
    assert not (ws_root / "ghidra_job_jobclean123").exists()


# ---------------------------------------------------------------------------
# 7. Exact bwrap & analyzeHeadless command array & airgap isolation checks
# ---------------------------------------------------------------------------
def test_bwrap_and_analyze_headless_command_construction(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    captured: dict = {}

    class _CaptureProc:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["kwargs"] = kwargs
            out_path = _extract_output_path_from_bwrap_cmd(cmd, Path(kwargs["cwd"]))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text('{"status": "COMPLETED", "functions": []}', encoding="utf-8")
            self.pid = 5151
            self.returncode = 0
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    _patch_valid_preflights(monkeypatch, rt, with_cgroup=True)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _CaptureProc)

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws",
        scripts_dir=SCRIPTS_DIR,
        max_memory_mb=768,
        max_heap_mb=512,
        max_cpu=1,
        timeout_seconds=90,
    )
    res = analyzer.analyze_sample("smp-cmd", sample_path, sha)
    assert res.status == "COMPLETED"
    assert res.provenance.os_sandbox == "bwrap"
    assert res.provenance.memory_limit_backend == "systemd_cgroup_v2"
    assert res.provenance.memory_limit_mb == 768
    assert res.provenance.heap_limit_mb == 512
    assert res.provenance.process_exit_code == 0

    cmd = captured["cmd"]
    kwargs = captured["kwargs"]
    assert cmd[0] == "/usr/bin/systemd-run"
    assert "MemoryMax=768M" in cmd
    assert "MemorySwapMax=0" in cmd
    assert "CPUQuota=100%" in cmd
    assert "OOMPolicy=kill" in cmd
    assert "/usr/bin/bwrap" in cmd
    for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"):
        assert flag in cmd
    heap_idx = cmd.index("GHIDRA_HEADLESS_MAXMEM")
    assert cmd[heap_idx - 1] == "--setenv"
    assert cmd[heap_idx + 1] == "512m"
    assert "/input/sample.bin" in cmd
    assert "/ghidra_scripts" in cmd
    assert "-readOnly" in cmd
    assert "-deleteProject" in cmd
    assert "-analysisTimeoutPerFile" in cmd
    assert "-max-cpu" in cmd
    assert "ExportProgramFacts.java" in cmd
    # Never expose repo source or user home directly into bwrap
    assert str(REPO_ROOT / "backend") not in cmd
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert set(kwargs["env"].keys()).issubset({"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"})
    assert kwargs["start_new_session"] is True


# ---------------------------------------------------------------------------
# 8. Timeout triggers process group termination & TIMED_OUT + cleanup
# ---------------------------------------------------------------------------
def test_timeout_terminates_process_group_and_cleans_workspace(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)
    ws_root = tmp_path / "ws_timeout"

    killed_calls = []

    class _HangingProc:
        def __init__(self, cmd, **kwargs):
            self.pid = 77777
            self.returncode = None
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    _patch_valid_preflights(monkeypatch, rt, with_cgroup=True)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _HangingProc)
    monkeypatch.setattr(
        GhidraStaticAnalyzer,
        "_terminate_process_group",
        staticmethod(lambda proc, **kwargs: killed_calls.append(proc.pid)),
    )

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=ws_root,
        scripts_dir=SCRIPTS_DIR,
        timeout_seconds=1,
    )
    res = analyzer.analyze_sample("smp-to", sample_path, sha, job_id="jobtimeout1")
    assert res.status == "TIMED_OUT"
    assert 77777 in killed_calls
    assert not (ws_root / "ghidra_job_jobtimeout1").exists()


# ---------------------------------------------------------------------------
# 9. Hard max_output_bytes rejection and immediate FAIL on stream overflow
# ---------------------------------------------------------------------------
def test_output_caps_and_hard_max_output_bytes_rejection(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    _patch_valid_preflights(monkeypatch, rt, with_cgroup=True)

    # Oversized facts.json fails closed
    oversized_bytes = b"{" + b" " * 5000 + b"}"
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer(oversized_bytes),
    )
    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_cap",
        scripts_dir=SCRIPTS_DIR,
        max_output_bytes=2048,
    )
    res_over = analyzer.analyze_sample("smp-over", sample_path, sha)
    assert res_over.status == "FAILED"
    assert "exceeded hard cap" in res_over.errors[0]

    # Excessive console stdout terminates owned PGID cleanly and classifies as FAILED
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer({"status": "COMPLETED", "functions": []}, stdout_bytes=b"A" * 8000),
    )
    analyzer_stream = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_stream",
        scripts_dir=SCRIPTS_DIR,
        max_output_bytes=4096,
        max_stream_bytes=4096,
        kill_grace_seconds=0.05,
    )
    res_stream = analyzer_stream.analyze_sample("smp-stream", sample_path, sha)
    assert res_stream.status == "FAILED"
    assert "exceeded bounded limit" in res_stream.errors[0]


# ---------------------------------------------------------------------------
# 10. Normalization: deterministic IDs, call_graph, xrefs, strings, non-execution
# ---------------------------------------------------------------------------
def test_normalization_function_ids_call_graph_xrefs_and_non_execution(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    raw_export = {
        "status": "COMPLETED",
        "program_metadata": {
            "program_name": "sample.bin",
            "executable_format": "PE",
            "language_id": "x86:LE:32:default",
            "architecture": "x86",
            "endianness": "little",
            "address_size": 32,
            "image_base": "0x00400000",
            "entry_points": ["0x00401000"],
            "total_functions_discovered": 2,
            "total_imports": 1,
            "total_exports": 1,
            "total_strings": 1,
        },
        "imports": [{"library": "KERNEL32.DLL", "name": "VirtualAlloc", "address": "0x00405000"}],
        "exports": ["DllMain"],
        "strings": [
            {
                "address": "0x00404010",
                "value": "http://example.invalid/stage2",
                "length": 29,
                "section": ".rdata",
                "ref_func_addresses": ["0x00401000"],
            }
        ],
        "functions": [
            {
                "entry_address": "0x00401000",
                "name": "entry",
                "size_bytes": 128,
                "basic_block_count": 5,
                "is_thunk": False,
                "is_external": False,
                "imported_api_calls": ["VirtualAlloc"],
                "called_addresses": ["0x00401100"],
                "caller_addresses": [],
                "string_refs": ["http://example.invalid/stage2"],
                "xref_in_count": 1,
                "xref_out_count": 3,
            },
            {
                "entry_address": "0x00401100",
                "name": "helper_sub",
                "size_bytes": 32,
                "basic_block_count": 1,
                "is_thunk": False,
                "is_external": False,
                "called_addresses": [],
                "caller_addresses": ["0x00401000"],
                "xref_in_count": 1,
                "xref_out_count": 0,
            },
        ],
        "call_graph": [
            {
                "caller_address": "0x00401000",
                "caller_name": "entry",
                "callee_address": "0x00401100",
                "callee_name": "helper_sub",
                "is_external_import": False,
                "call_site_address": "0x00401020",
            },
            {
                "caller_address": "0x00401000",
                "caller_name": "entry",
                "callee_address": "0x00405000",
                "callee_name": "KERNEL32.DLL::VirtualAlloc",
                "is_external_import": True,
                "call_site_address": "0x00401010",
            },
        ],
        "cross_references": [
            {
                "from_address": "0x00401015",
                "to_address": "0x00404010",
                "ref_type": "DATA",
                "from_function_address": "0x00401000",
                "target_symbol": "s_http",
            }
        ],
        "decompiled_functions": [],
    }

    _patch_valid_preflights(monkeypatch, rt)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _fake_popen_writer(raw_export))

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_norm",
        scripts_dir=SCRIPTS_DIR,
    )
    res = analyzer.analyze_sample("smp-norm", sample_path, sha, analysis_id="ana-norm")
    assert res.status == "COMPLETED"
    assert res.provenance.binary_executed is False
    assert all(fn.is_executed is False for fn in res.functions)

    expected_entry_id = make_static_function_id(sha, "0x401000")
    expected_helper_id = make_static_function_id(sha, "0x401100")
    assert expected_entry_id == f"func:{sha[:16]}:0x401000"
    assert {f.function_id for f in res.functions} == {expected_entry_id, expected_helper_id}
    assert res.call_graph[0].caller_function_id == expected_entry_id
    assert res.call_graph[0].callee_function_id == expected_helper_id
    assert res.call_graph[1].is_external_import is True
    assert res.call_graph[1].callee_function_id is None
    assert res.cross_references[0].from_function_id == expected_entry_id
    assert res.strings[0].referencing_function_ids == [expected_entry_id]


# ---------------------------------------------------------------------------
# 11. Deterministic ranking heuristic & thunk demotion
# ---------------------------------------------------------------------------
def test_rank_functions_deterministic_weights_and_thunk_demotion():
    sha = "d" * 64
    fid_high = make_static_function_id(sha, "0x401000")
    fid_thunk = make_static_function_id(sha, "0x401050")
    fid_benign = make_static_function_id(sha, "0x401090")

    funcs = [
        FunctionMetadata(
            function_id=fid_benign,
            entry_address="0x401090",
            name="tiny_helper",
            size_bytes=16,
            basic_block_count=1,
        ),
        FunctionMetadata(
            function_id=fid_thunk,
            entry_address="0x401050",
            name="VirtualAlloc_thunk",
            size_bytes=6,
            basic_block_count=1,
            is_thunk=True,
            imported_api_calls=["VirtualAlloc"],
        ),
        FunctionMetadata(
            function_id=fid_high,
            entry_address="0x401000",
            name="injector_routine",
            size_bytes=320,
            basic_block_count=10,
            imported_api_calls=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            called_function_ids=[fid_benign],
            xref_in_count=2,
            string_refs=["http://c2.invalid/gate.php"],
        ),
    ]

    ranked1, findings1 = rank_functions(funcs, [], [])
    ranked2, findings2 = rank_functions(funcs, [], [])
    assert [f.function_id for f in ranked1] == [f.function_id for f in ranked2]
    assert [f.rank_score for f in ranked1] == [f.rank_score for f in ranked2]
    assert ranked1[0].function_id == fid_high
    assert ranked1[0].rank_score > ranked1[1].rank_score
    # Thunk stub penalized (VirtualAlloc 4.0 * 0.25 = 1.0) and omitted from findings
    thunk_out = next(f for f in ranked1 if f.function_id == fid_thunk)
    assert thunk_out.rank_score == 1.0
    assert all(fd.function_id != fid_thunk for fd in findings1)
    assert len(findings1) == 1
    assert "do not prove malicious intent" in findings1[0].disclaimer


# ---------------------------------------------------------------------------
# 12. Selective decompilation caps, truncation & status handling
# ---------------------------------------------------------------------------
def test_selective_decompilation_limits_and_statuses(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    long_code = "void f1(void) { " + ("x++; " * 50) + "}"
    raw_export = {
        "status": "COMPLETED",
        "functions": [{"entry_address": "0x401000", "name": "f1", "size_bytes": 100}],
        "decompiled_functions": [
            {"entry_address": "0x401000", "name": "f1", "decompile_status": "OK", "pseudocode": long_code},
            {"entry_address": "0x401010", "name": "f2", "decompile_status": "TIMED_OUT", "pseudocode": ""},
            {"entry_address": "0x401020", "name": "f3", "decompile_status": "OK", "pseudocode": "int f3(){return 1;}"},
        ],
    }

    _patch_valid_preflights(monkeypatch, rt)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _fake_popen_writer(raw_export))

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_dec",
        scripts_dir=SCRIPTS_DIR,
        max_decompile_functions=2,
        max_pseudocode_chars=40,
        max_output_bytes=16384,
    )
    res = analyzer.analyze_sample("smp-dec", sample_path, sha)
    assert res.status == "PARTIAL"
    assert res.is_partial is True
    assert len(res.decompiled_functions) == 2
    assert res.decompiled_functions[0].truncated is True
    assert "/* [TRUNCATED] */" in res.decompiled_functions[0].pseudocode
    assert res.decompiled_functions[1].decompile_status == "TIMED_OUT"
    assert res.truncation.decompiled_omitted_cap >= 1

    # Also verify byte budget SKIPPED_CAP enforcement
    res_budget = analyzer._normalize_and_rank_result(
        raw_json={
            "status": "COMPLETED",
            "functions": [],
            "decompiled_functions": [
                {"entry_address": "0x401000", "name": "big1", "decompile_status": "OK", "pseudocode": "A" * 2048},
                {"entry_address": "0x401010", "name": "big2", "decompile_status": "OK", "pseudocode": "B" * 2048},
            ],
        },
        raw_output_bytes=4500,
        pe_meta={},
        sample_id="smp-b",
        sample_sha256=sha,
        analysis_id=None,
        provenance=StaticAnalysisProvenance(sample_id="smp-b", sample_sha256=sha, os_sandbox="bwrap"),
        stream_overflow=False,
    )
    # Second exceeds max(2048, max_output_bytes//2) = 8192? Lower max_output_bytes=4096 in a fresh analyzer:
    analyzer_small = GhidraStaticAnalyzer(enabled=True, max_output_bytes=4096, max_pseudocode_chars=3000)
    res_budget = analyzer_small._normalize_and_rank_result(
        raw_json={
            "status": "COMPLETED",
            "functions": [],
            "decompiled_functions": [
                {"entry_address": "0x401000", "name": "big1", "decompile_status": "OK", "pseudocode": "A" * 1800},
                {"entry_address": "0x401010", "name": "big2", "decompile_status": "OK", "pseudocode": "B" * 1800},
            ],
        },
        raw_output_bytes=4000,
        pe_meta={},
        sample_id="smp-b",
        sample_sha256=sha,
        analysis_id=None,
        provenance=StaticAnalysisProvenance(sample_id="smp-b", sample_sha256=sha, os_sandbox="bwrap"),
        stream_overflow=False,
    )
    assert res_budget.decompiled_functions[1].decompile_status == "SKIPPED_CAP"


# ---------------------------------------------------------------------------
# 13. Malformed Ghidra JSON output -> FAILED
# ---------------------------------------------------------------------------
def test_malformed_ghidra_json_fails_cleanly(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    _patch_valid_preflights(monkeypatch, rt)
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _fake_popen_writer("{broken json"))

    analyzer = GhidraStaticAnalyzer(
        enabled=True, ghidra_home=str(gh), workspace_root=tmp_path / "ws_mal", scripts_dir=SCRIPTS_DIR
    )
    res = analyzer.analyze_sample("smp-mal", sample_path, sha)
    assert res.status == "FAILED"
    assert "Malformed JSON" in res.errors[0]


# ---------------------------------------------------------------------------
# 14. Partial analysis failure -> PARTIAL & is_partial=True
# ---------------------------------------------------------------------------
def test_partial_analysis_result_sets_partial_status(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    _patch_valid_preflights(monkeypatch, rt)
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer(
            {
                "status": "PARTIAL",
                "truncated": True,
                "program_metadata": {"total_functions_discovered": 100},
                "functions": [{"entry_address": "0x401000", "name": "entry", "size_bytes": 32}],
                "errors": ["Decompiler channel restarted on 1 function"],
            }
        ),
    )

    analyzer = GhidraStaticAnalyzer(
        enabled=True, ghidra_home=str(gh), workspace_root=tmp_path / "ws_part", scripts_dir=SCRIPTS_DIR
    )
    res = analyzer.analyze_sample("smp-part", sample_path, sha)
    assert res.status == "PARTIAL"
    assert res.is_partial is True
    assert res.truncation.functions_omitted == 99
    assert len(res.errors) == 1


# ---------------------------------------------------------------------------
# 15. Replay pipeline backward compatibility when Ghidra is unconfigured/unavailable
# ---------------------------------------------------------------------------
def test_replay_pipeline_backward_compatible_with_static_unavailable(client, db_session):
    pe_bytes = _build_minimal_pe32()
    res = client.post(
        "/api/v1/samples",
        files={"file": ("wannacry_compat.exe", io.BytesIO(pe_bytes), "application/octet-stream")},
    )
    assert res.status_code == 201
    sample = res.json()

    ana_res = client.post(
        "/api/v1/analyses?run_sync=true",
        json={
            "sample_id": sample["id"],
            "backend_type": "replay",
            "profile": "standard",
            "replay_scenario_id": "ransomware_wannacry_mock",
            "timeout_seconds": 60,
        },
    )
    assert ana_res.status_code == 201
    analysis = ana_res.json()
    assert analysis["status"] == AnalysisStatus.COMPLETED.value

    rep = client.get(f"/api/v1/analyses/{analysis['id']}/report").json()
    assert rep["risk_score"] >= 80

    static_res = client.get(f"/api/v1/analyses/{analysis['id']}/static-analysis")
    assert static_res.status_code == 200
    assert static_res.json()["status"] == "UNAVAILABLE"

    risk = RiskAssessment.model_validate(rep["full_report"]["risk_assessment"])
    bundle = EvidenceBundleBuilder(db_session).build(analysis["id"], risk_assessment=risk)
    assert bundle.static_analysis.status == "not_available"


# ---------------------------------------------------------------------------
# 16. Intelligence bridge: verified static IDs allowed, pseudocode never leaked
# ---------------------------------------------------------------------------
def test_intelligence_bridge_evidence_validation_and_no_pseudocode_leak(db_session):
    pe_bytes = _build_minimal_pe32()
    sha = hashlib.sha256(pe_bytes).hexdigest()
    sample = Sample(
        sha256=sha,
        sha1=hashlib.sha1(pe_bytes).hexdigest(),
        md5=hashlib.md5(pe_bytes).hexdigest(),
        file_name="static_bridge.exe",
        file_size=len(pe_bytes),
        is_pe=True,
        quarantine_path="/tmp/unused_bridge.bin",
    )
    db_session.add(sample)
    db_session.flush()

    analysis = Analysis(
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(analysis)
    db_session.flush()

    fn_id = make_static_function_id(sha, "0x401000")
    static_res = StaticAnalysisResult(
        status="COMPLETED",
        provenance=StaticAnalysisProvenance(
            analysis_id=analysis.id,
            sample_id=sample.id,
            sample_sha256=sha,
            ghidra_version="12.1.4",
            os_sandbox="bwrap",
        ),
        program_metadata=ProgramMetadata(
            program_name="static_bridge.exe",
            executable_format="PE",
            architecture="x86",
            address_size=32,
            total_functions_discovered=1,
            total_imports=1,
        ),
        functions=[
            FunctionMetadata(
                function_id=fn_id,
                entry_address="0x401000",
                name="verified_payload_setup",
                size_bytes=120,
                basic_block_count=4,
                imported_api_calls=["VirtualAlloc"],
                rank_score=4.0,
            )
        ],
        decompiled_functions=[
            DecompiledFunction(
                function_id=fn_id,
                entry_address="0x401000",
                name="verified_payload_setup",
                pseudocode="void verified_payload_setup(void) { /* SECRET_DECOMPILED_PSEUDOCODE_TOKEN */ }",
                pseudocode_bytes=78,
            )
        ],
        truncation=StaticAnalysisTruncation(functions_discovered=1, functions_included=1, decompiled_included=1),
    )

    db_session.add(
        StaticAnalysisRecord(
            sample_id=sample.id,
            analysis_id=analysis.id,
            sample_sha256=sha,
            status="COMPLETED",
            ghidra_version="12.1.4",
            result_json=static_res.model_dump(mode="json"),
        )
    )
    db_session.commit()

    bundle = EvidenceBundleBuilder(db_session).build(
        analysis.id, risk_assessment=RiskAssessment(score=75, level="Suspicious")
    )
    assert bundle.static_analysis.status == "available"
    assert bundle.static_analysis.decompiled_count == 1
    assert bundle.static_analysis.decompiled_omitted_for_external_ai is True
    assert fn_id in bundle.valid_evidence_ids
    assert "SECRET_DECOMPILED_PSEUDOCODE_TOKEN" not in bundle.model_dump_json()

    proposed = {
        "executive_assessment": "Replay scenario 'ransomware_wannacry_mock' combined with verified static function verified_payload_setup.",
        "behavioral_narrative": "Static disassembly recovered verified_payload_setup without executing binary.",
        "timeline_interpretations": [],
        "technical_claims": [
            {
                "claim_id": "CLM-STATIC-OK",
                "classification": "FACT",
                "claim_text": "Static function verified_payload_setup references imported API VirtualAlloc.",
                "supporting_evidence_ids": [fn_id],
                "confidence": 0.9,
                "caveats": [],
            },
            {
                "claim_id": "CLM-STATIC-INF",
                "classification": "INFERENCE",
                "claim_text": "Verified static function verified_payload_setup may prepare an allocation buffer.",
                "supporting_evidence_ids": [fn_id],
                "confidence": 0.7,
                "caveats": [],
            },
            {
                "claim_id": "CLM-STATIC-FAB",
                "classification": "FACT",
                "claim_text": "Fabricated function sub_deadbeef steals keys via RtlEncryptMemory.",
                "supporting_evidence_ids": ["func:0000000000000000:0xdeadbeef"],
                "confidence": 0.9,
                "caveats": [],
            },
        ],
        "ioc_interpretations": [],
        "confidence_assessment": {
            "overall_confidence": 0.7,
            "evidence_completeness": "medium",
            "rationale": "Replay telemetry + verified Ghidra metadata",
        },
        "contradictions_or_gaps": [],
        "limitations": [],
        "recommended_follow_up_actions": [],
    }
    meta = AIProviderMetadata(
        mode="mock",
        provider="mock",
        model="deterministic",
        tokens_used=0,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    validated = EvidenceValidator().validate_and_finalize(
        proposed, bundle, meta, build_deterministic_proposed_intelligence
    )
    by_id = {c.claim_id: c for c in validated.technical_claims}
    assert by_id["CLM-STATIC-OK"].validation_status == "VERIFIED"
    assert by_id["CLM-STATIC-INF"].support_category == "ANALYST_INFERENCE"
    assert by_id["CLM-STATIC-INF"].requires_human_review is True
    assert by_id["CLM-STATIC-FAB"].validation_status == "REJECTED"


# ---------------------------------------------------------------------------
# 17. API auth + single-worker 409 Conflict check + completion flow
# ---------------------------------------------------------------------------
def test_static_analysis_api_single_worker_409_conflict_and_auth(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", True)
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "static-test-secret")
    monkeypatch.setattr(
        "app.services.static_analysis.worker.SessionLocal",
        sessionmaker(autocommit=False, autoflush=False, bind=db_session.get_bind()),
    )

    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    monkeypatch.setattr("app.api.v1.static_analysis.validate_ghidra_runtime", lambda configured_home=None: rt)
    monkeypatch.setattr(
        "app.api.v1.static_analysis.check_vm_memory_headroom",
        lambda min_available_mb: (True, 4096, "ok"),
    )
    monkeypatch.setattr(
        "app.api.v1.static_analysis.check_os_sandbox_support",
        lambda backend="bwrap": (True, "/usr/bin/bwrap", None),
    )
    monkeypatch.setattr(
        "app.api.v1.static_analysis.check_cgroup_memory_support",
        lambda: _mock_cg_support(True),
    )

    pe_path, sha, _ = _write_pe_sample(tmp_path)
    sample = Sample(
        sha256=sha,
        sha1="1" * 40,
        md5="2" * 32,
        file_name="worker_test.exe",
        file_size=len(_build_minimal_pe32()),
        is_pe=True,
        quarantine_path=str(pe_path),
    )
    db_session.add(sample)
    db_session.flush()
    analysis = Analysis(
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(analysis)
    db_session.commit()

    started_ev = threading.Event()
    release_ev = threading.Event()

    def _slow_analyze(self, sample_id, sample_path, expected_sha256, analysis_id=None, job_id=None, cancel_event=None, allow_disabled=False):
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return StaticAnalysisResult(
            status="COMPLETED",
            provenance=StaticAnalysisProvenance(
                analysis_id=analysis_id,
                sample_id=sample_id,
                sample_sha256=expected_sha256,
                ghidra_version="12.1.4",
                os_sandbox="bwrap",
            ),
            truncation=StaticAnalysisTruncation(),
        )

    monkeypatch.setattr(GhidraStaticAnalyzer, "analyze_sample", _slow_analyze)

    try:
        # Unauthenticated request rejected with 401
        unauth = client.post(f"/api/v1/analyses/{analysis.id}/static-analysis")
        assert unauth.status_code == 401

        # First authorized trigger queued -> 202
        headers = {"X-Reporting-Token": "static-test-secret"}
        res1 = client.post(f"/api/v1/analyses/{analysis.id}/static-analysis", headers=headers)
        assert res1.status_code == 202
        assert res1.json()["status"] == "QUEUED"
        assert started_ev.wait(timeout=3.0)

        # Second concurrent trigger rejected -> 409 Conflict
        res2 = client.post(f"/api/v1/analyses/{analysis.id}/static-analysis", headers=headers)
        assert res2.status_code == 409
    finally:
        release_ev.set()
        for _ in range(50):
            if not static_worker_manager.is_busy():
                break
            time.sleep(0.05)

    # Stored result readable via GET without triggering execution
    get_res = client.get(f"/api/v1/analyses/{analysis.id}/static-analysis")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "COMPLETED"
    sample_res = client.get(f"/api/v1/samples/{sample.id}/static-analysis")
    assert sample_res.status_code == 200
    assert sample_res.json()["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# 18. Disabled-by-default blocks trigger (403), adapter returns SKIPPED, Doctor SKIPs
# ---------------------------------------------------------------------------
def test_disabled_by_default_policy_blocks_trigger_and_doctor_skips(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", False)
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "static-test-secret")

    pe_path, sha, _ = _write_pe_sample(tmp_path)
    sample = Sample(
        sha256=sha,
        sha1="3" * 40,
        md5="4" * 32,
        file_name="disabled_test.exe",
        file_size=len(_build_minimal_pe32()),
        is_pe=True,
        quarantine_path=str(pe_path),
    )
    db_session.add(sample)
    db_session.flush()
    analysis = Analysis(
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(analysis)
    db_session.commit()

    analyzer = GhidraStaticAnalyzer()
    assert analyzer.analyze_sample(sample.id, pe_path, sha).status == "SKIPPED"

    trigger_res = client.post(
        f"/api/v1/analyses/{analysis.id}/static-analysis",
        headers={"X-Reporting-Token": "static-test-secret"},
    )
    assert trigger_res.status_code == 403

    get_res = client.get(f"/api/v1/analyses/{analysis.id}/static-analysis")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "UNAVAILABLE"

    ws = tmp_path / "repo_skip"
    ws.mkdir()
    opt_checks = check_optional_integrations(
        ws,
        environ={"MALBOX_GHIDRA_ENABLED": "false"},
        which_fn=lambda _: None,
    )
    gh_check = next(c for c in opt_checks if c.id == "opt_ghidra")
    assert gh_check.status == CheckStatus.SKIP


# ---------------------------------------------------------------------------
# 19. Opt-in real Ghidra Headless + ExportProgramFacts.java + bwrap + cgroup smoke test
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    os.environ.get("MALBOX_RUN_LIVE_GHIDRA_TEST") != "1",
    reason="Opt-in live Ghidra headless smoke test; set MALBOX_RUN_LIVE_GHIDRA_TEST=1 to execute.",
)
def test_live_ghidra_bwrap_smoke_opt_in(tmp_path):
    sample_path, sha, _ = _write_pe_sample(tmp_path, "minimal_stub.exe")
    ws_root = tmp_path / "live_ghidra_ws"
    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=os.environ.get("MALBOX_GHIDRA_HOME", ""),
        workspace_root=ws_root,
        scripts_dir=SCRIPTS_DIR,
        max_memory_mb=1280,
        max_heap_mb=512,
        min_available_memory_mb=1024,
        max_cpu=1,
        timeout_seconds=90,
        max_functions=50,
        max_decompile_functions=3,
        max_pseudocode_chars=4096,
        max_output_bytes=262144,
    )
    res = analyzer.analyze_sample(
        sample_id="live-smoke-pe32",
        sample_path=sample_path,
        expected_sha256=sha,
        analysis_id="live-smoke-ana",
        job_id="livesmoke01",
    )
    assert res.status in ("COMPLETED", "PARTIAL"), f"Live Ghidra failed: {res.errors}"
    assert res.provenance.binary_executed is False
    assert res.provenance.os_sandbox == "bwrap"
    assert res.provenance.memory_limit_backend == "systemd_cgroup_v2"
    assert res.provenance.memory_limit_mb == 1280
    assert res.provenance.heap_limit_mb == 512
    assert res.provenance.process_exit_code == 0
    assert res.program_metadata is not None
    assert res.program_metadata.address_size == 32
    assert len(res.functions) >= 1
    assert all(fn.is_executed is False for fn in res.functions)
    assert not (ws_root / "ghidra_job_livesmoke01").exists()
    print("LIVE_GHIDRA_RESULT:", json.dumps(res.model_dump(mode="json"), indent=2))


# ---------------------------------------------------------------------------
# 20. Task 1: Strict exit-code integrity & nonzero return handling
# ---------------------------------------------------------------------------
def test_exit_code_integrity_nonzero_never_completed_and_distinguishes_cases(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)
    _patch_valid_preflights(monkeypatch, rt)

    analyzer = GhidraStaticAnalyzer(
        enabled=True, ghidra_home=str(gh), workspace_root=tmp_path / "ws_rc", scripts_dir=SCRIPTS_DIR
    )

    # Case A: rc=1 + valid-looking COMPLETED JSON -> MUST fail, never COMPLETED
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer(
            {
                "status": "COMPLETED",
                "functions": [{"entry_address": "0x401000", "name": "entry", "size_bytes": 16}],
            },
            returncode=1,
        ),
    )
    res_rc1 = analyzer.analyze_sample("smp-rc1", sample_path, sha, job_id="jobrc001")
    assert res_rc1.status == "FAILED"
    assert res_rc1.is_partial is False
    assert res_rc1.provenance.process_exit_code == 1
    assert "exited nonzero (rc=1)" in res_rc1.errors[0]
    assert not (tmp_path / "ws_rc" / "ghidra_job_jobrc001").exists()

    # Case B: rc=1 + PARTIAL JSON -> JSON must NOT override process failure
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer(
            {"status": "PARTIAL", "errors": ["Decompiler crashed"], "functions": []},
            returncode=1,
        ),
    )
    res_rc1_part = analyzer.analyze_sample("smp-rc1p", sample_path, sha, job_id="jobrc002")
    assert res_rc1_part.status == "FAILED"
    assert res_rc1_part.provenance.process_exit_code == 1
    assert "facts.json reported status=PARTIAL" in res_rc1_part.errors[0]

    # Case C: rc=0 + FAILED JSON -> FAILED
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer({"status": "FAILED", "errors": ["Program load aborted"]}, returncode=0),
    )
    res_rc0_fail = analyzer.analyze_sample("smp-rc0f", sample_path, sha, job_id="jobrc003")
    assert res_rc0_fail.status == "FAILED"
    assert "Program load aborted" in res_rc0_fail.errors[0]

    # Case D: rc=0 + missing output -> FAILED
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer(None, returncode=0),
    )
    res_missing = analyzer.analyze_sample("smp-miss", sample_path, sha, job_id="jobrc004")
    assert res_missing.status == "FAILED"
    assert "without producing facts.json" in res_missing.errors[0]


# ---------------------------------------------------------------------------
# 21. Task 2: Immediate overflow kill, SIGTERM grace -> SIGKILL, safe PGID guard
# ---------------------------------------------------------------------------
def test_stream_overflow_immediate_kill_grace_period_and_sigkill_escalation(tmp_path, monkeypatch):
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)
    _patch_valid_preflights(monkeypatch, rt)

    class _NoisyStream:
        def __init__(self, proc):
            self._proc = proc

        def read(self, size=4096):
            if self._proc.poll() is not None:
                return b""
            time.sleep(0.01)
            return b"X" * size

        def close(self):
            pass

    signals_sent: list[tuple[str, int, int]] = []

    class _StubbornProc:
        def __init__(self, cmd, **kwargs):
            self.pid = 88888
            self.returncode = None
            self.waited = False
            self.stdout = _NoisyStream(self)
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.waited = True
            return self.returncode

    last_proc: list[_StubbornProc] = []

    def _make_stubborn(cmd, **kwargs):
        p = _StubbornProc(cmd, **kwargs)
        last_proc.append(p)
        return p

    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", _make_stubborn)
    monkeypatch.setattr(os, "getpgrp", lambda: 1000)
    monkeypatch.setattr(os, "getpgid", lambda pid: 88888)

    def _fake_killpg(pgid, sig):
        signals_sent.append(("killpg", pgid, sig))
        if sig == signal.SIGKILL and last_proc:
            last_proc[-1].returncode = -9

    monkeypatch.setattr(os, "killpg", _fake_killpg)

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_ov",
        scripts_dir=SCRIPTS_DIR,
        timeout_seconds=30,  # Must abort well before 30s!
        max_stream_bytes=8192,
        kill_grace_seconds=0.1,
    )
    t0 = time.monotonic()
    res = analyzer.analyze_sample("smp-ov", sample_path, sha, job_id="jobov01")
    elapsed = time.monotonic() - t0

    assert elapsed < 3.0
    assert res.status == "FAILED"
    assert "exceeded bounded limit" in res.errors[0]
    assert last_proc and last_proc[0].waited is True
    assert ("killpg", 88888, signal.SIGTERM) in signals_sent
    assert ("killpg", 88888, signal.SIGKILL) in signals_sent
    assert signals_sent.index(("killpg", 88888, signal.SIGTERM)) < signals_sent.index(("killpg", 88888, signal.SIGKILL))
    assert not (tmp_path / "ws_ov" / "ghidra_job_jobov01").exists()

    # Safety guard: NEVER call os.killpg if getpgid returns foreign/own process group
    signals_sent.clear()
    pid_kills: list[tuple[int, int]] = []

    class _GracefulProc:
        def __init__(self):
            self.pid = 99999
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    gp = _GracefulProc()
    monkeypatch.setattr(os, "getpgrp", lambda: 5555)
    monkeypatch.setattr(os, "getpgid", lambda pid: 5555)  # Unsafe: matches own pgrp!

    def _fake_kill(pid, sig):
        pid_kills.append((pid, sig))
        if sig == signal.SIGTERM:
            gp.returncode = -15

    monkeypatch.setattr(os, "kill", _fake_kill)
    GhidraStaticAnalyzer._terminate_process_group(gp, grace_seconds=0.2)
    assert not any(call[0] == "killpg" for call in signals_sent)
    assert pid_kills == [(99999, signal.SIGTERM)]  # Graceful exit skips SIGKILL


# ---------------------------------------------------------------------------
# 22. Task 3: Available-RAM preflight & fail-closed cgroup containment checks
# ---------------------------------------------------------------------------
def test_vm_memory_headroom_and_cgroup_containment_fail_closed(tmp_path, monkeypatch):
    memfile = tmp_path / "meminfo"
    memfile.write_text("MemTotal:        8000000 kB\nMemAvailable:     512000 kB\n", encoding="utf-8")
    assert get_available_memory_mb(memfile) == 500
    ok_mem, avail, msg = check_vm_memory_headroom(1280, mem_reader=lambda: get_available_memory_mb(memfile))
    assert ok_mem is False
    assert avail == 500
    assert "500 MiB" in msg

    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    sample_path, sha, _ = _write_pe_sample(tmp_path)

    # Insufficient RAM -> UNAVAILABLE without launching subprocess
    _patch_valid_preflights(monkeypatch, rt, with_cgroup=True, avail_mb=400)
    popen_mock = MagicMock()
    monkeypatch.setattr("app.services.static_analysis.ghidra_adapter.subprocess.Popen", popen_mock)

    analyzer = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_mem",
        scripts_dir=SCRIPTS_DIR,
        min_available_memory_mb=1280,
    )
    res_low = analyzer.analyze_sample("smp-lowmem", sample_path, sha)
    assert res_low.status == "UNAVAILABLE"
    assert "Insufficient available VM memory" in res_low.errors[0]
    popen_mock.assert_not_called()

    # Cgroup unavailable with require_cgroup_memory_limit=True -> UNAVAILABLE (fail closed)
    _patch_valid_preflights(monkeypatch, rt, with_cgroup=False, avail_mb=4096)
    res_nocg = analyzer.analyze_sample("smp-nocg", sample_path, sha)
    assert res_nocg.status == "UNAVAILABLE"
    assert "cgroup v2" in res_nocg.errors[0]
    popen_mock.assert_not_called()

    # Explicit opt-out require_cgroup_memory_limit=False runs with warning & memory_limit_backend="none"
    monkeypatch.setattr(
        "app.services.static_analysis.ghidra_adapter.subprocess.Popen",
        _fake_popen_writer({"status": "COMPLETED", "functions": []}),
    )
    analyzer_optout = GhidraStaticAnalyzer(
        enabled=True,
        ghidra_home=str(gh),
        workspace_root=tmp_path / "ws_optout",
        scripts_dir=SCRIPTS_DIR,
        require_cgroup_memory_limit=False,
    )
    res_opt = analyzer_optout.analyze_sample("smp-optout", sample_path, sha)
    assert res_opt.status == "COMPLETED"
    assert res_opt.provenance.memory_limit_backend == "none"
    assert any("cgroup memory containment disabled" in w for w in res_opt.warnings)


# ---------------------------------------------------------------------------
# 23. Task 5: Ancestor symlink traversal & DB persistence size gating
# ---------------------------------------------------------------------------
def test_ancestor_symlink_rejection_and_persistence_size_bound(tmp_path):
    real_base = tmp_path / "real_base"
    real_base.mkdir()
    sample_path, sha, _ = _write_pe_sample(real_base)

    sym_anc = tmp_path / "sym_ancestor"
    sym_anc.symlink_to(real_base)

    # Ancestor symlink two levels above nested workspace/sample must fail closed
    with pytest.raises(GhidraIsolationError, match="symlink"):
        prepare_isolated_project_workspace(sym_anc / "nested" / "ws", "jobanc01", sha)

    nested_dir = real_base / "sub" / "quarantine"
    nested_dir.mkdir(parents=True)
    inner_sample, inner_sha, _ = _write_pe_sample(nested_dir)
    with pytest.raises(GhidraIsolationError, match="symlink"):
        validate_sample_for_static_analysis(sym_anc / "sub" / "quarantine" / inner_sample.name, inner_sha, 1024 * 1024)
    _, gh_sym_err = locate_ghidra_home(str(sym_anc / "ghidra"))
    assert gh_sym_err is not None and "symlink" in gh_sym_err.lower()

    # Persistence gate shrinks oversized pseudocode gracefully while staying valid
    fn_id = make_static_function_id(sha, "0x401000")
    huge_res = StaticAnalysisResult(
        status="COMPLETED",
        provenance=StaticAnalysisProvenance(sample_id="s1", sample_sha256=sha, os_sandbox="bwrap"),
        functions=[FunctionMetadata(function_id=fn_id, entry_address="0x401000", name="big_fn")],
        decompiled_functions=[
            DecompiledFunction(
                function_id=fn_id,
                entry_address="0x401000",
                name="big_fn",
                pseudocode="Z" * 30000,
                pseudocode_bytes=30000,
            )
        ],
        truncation=StaticAnalysisTruncation(functions_discovered=1, functions_included=1, decompiled_included=1),
    )
    bounded = prepare_result_for_persistence(huge_res, max_persisted_bytes=16384)
    assert len(bounded.model_dump_json().encode("utf-8")) <= 16384
    assert bounded.status == "PARTIAL"
    assert bounded.decompiled_functions[0].decompile_status == "SKIPPED_CAP"


# ---------------------------------------------------------------------------
# 24. Task 4: Worker lifecycle (failed submission, cancellation, shutdown, 503 API)
# ---------------------------------------------------------------------------
def test_worker_lifecycle_startup_shutdown_failed_submission_and_cancellation(client, db_session, tmp_path, monkeypatch):
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db_session.get_bind())
    monkeypatch.setattr("app.services.static_analysis.worker.SessionLocal", session_factory)

    pe_path, sha, _ = _write_pe_sample(tmp_path)
    sample = Sample(
        sha256=sha,
        sha1="5" * 40,
        md5="6" * 32,
        file_name="lifecycle.exe",
        file_size=len(_build_minimal_pe32()),
        is_pe=True,
        quarantine_path=str(pe_path),
    )
    db_session.add(sample)
    db_session.commit()

    mgr = StaticAnalysisWorkerManager()
    mgr.start()

    # 1. Executor submission failure MUST mark DB FAILED and clear active job ID (no stuck QUEUED!)
    bad_exec = MagicMock()
    bad_exec.submit.side_effect = RuntimeError("executor boom")
    monkeypatch.setattr(mgr, "_get_executor", lambda: bad_exec)

    with pytest.raises(StaticAnalysisSubmissionError):
        mgr.submit_job(db=db_session, sample=sample, analysis_id=None)

    assert mgr.is_busy() is False
    assert mgr.active_job_id() is None
    row_after_fail = db_session.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.sample_id == sample.id).first()
    assert row_after_fail is not None
    assert row_after_fail.status == "FAILED"
    assert "executor boom" in (row_after_fail.error_message or "")

    # 1b. Repeated sequential submissions reuse worker cleanly
    class _FastOkAnalyzer(GhidraStaticAnalyzer):
        def analyze_sample(self, sample_id, sample_path, expected_sha256, analysis_id=None, job_id=None, cancel_event=None, allow_disabled=False):
            return StaticAnalysisResult(
                status="COMPLETED",
                provenance=StaticAnalysisProvenance(analysis_id=analysis_id, sample_id=sample_id, sample_sha256=expected_sha256, os_sandbox="bwrap"),
                truncation=StaticAnalysisTruncation(),
            )

    mgr_seq = StaticAnalysisWorkerManager()
    mgr_seq.start()
    for _idx in range(2):
        r_seq = mgr_seq.submit_job(db=db_session, sample=sample, analyzer=_FastOkAnalyzer(enabled=True))
        for _ in range(40):
            if not mgr_seq.is_busy():
                break
            time.sleep(0.02)
        db_session.expire_all()
        db_row = db_session.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == r_seq.id).first()
        assert db_row is not None and db_row.status == "COMPLETED"
    mgr_seq.stop(wait_seconds=1.0)

    # 2. Active job cancelled cleanly during shutdown (`stop()`) and rejects subsequent submissions until `start()`
    mgr2 = StaticAnalysisWorkerManager()
    mgr2.start()
    entered_ev = threading.Event()
    saw_cancel_ev = threading.Event()

    class _CancelAwareAnalyzer(GhidraStaticAnalyzer):
        def analyze_sample(self, sample_id, sample_path, expected_sha256, analysis_id=None, job_id=None, cancel_event=None, allow_disabled=False):
            entered_ev.set()
            assert cancel_event is not None
            assert cancel_event.wait(timeout=3.0)
            saw_cancel_ev.set()
            return StaticAnalysisResult(
                status="FAILED",
                provenance=StaticAnalysisProvenance(analysis_id=analysis_id, sample_id=sample_id, sample_sha256=expected_sha256, os_sandbox="bwrap"),
                truncation=StaticAnalysisTruncation(),
                errors=["Cancelled by shutdown"],
            )

    rec2 = mgr2.submit_job(db=db_session, sample=sample, analyzer=_CancelAwareAnalyzer(enabled=True))
    assert entered_ev.wait(timeout=2.0)
    interrupted = mgr2.stop(wait_seconds=3.0)
    assert interrupted >= 1
    assert saw_cancel_ev.is_set()
    assert mgr2.is_busy() is False

    db_session.expire_all()
    rec2_db = db_session.query(StaticAnalysisRecord).filter(StaticAnalysisRecord.id == rec2.id).first()
    assert rec2_db is not None
    assert rec2_db.status == "FAILED"

    with pytest.raises(StaticAnalysisSubmissionError, match="shutting down"):
        mgr2.submit_job(db=db_session, sample=sample, analyzer=_CancelAwareAnalyzer(enabled=True))

    # 3. API 503 preflight when cgroup containment or VM RAM headroom fails
    monkeypatch.setattr(settings, "GHIDRA_ENABLED", True)
    monkeypatch.setattr(settings, "REPORTING_AUTH_TOKEN", "static-test-secret")
    monkeypatch.setattr(settings, "GHIDRA_REQUIRE_CGROUP_MEMORY_LIMIT", True)
    gh = _make_fake_ghidra_install(tmp_path)
    jdk = _make_fake_jdk(tmp_path)
    rt = _mock_runtime(gh, jdk)
    analysis = Analysis(
        sample_id=sample.id,
        status=AnalysisStatus.COMPLETED.value,
        backend_type="replay",
        replay_scenario_id="ransomware_wannacry_mock",
    )
    db_session.add(analysis)
    db_session.commit()

    monkeypatch.setattr("app.api.v1.static_analysis.validate_ghidra_runtime", lambda configured_home=None: rt)
    monkeypatch.setattr("app.api.v1.static_analysis.check_vm_memory_headroom", lambda min_available_mb: (False, 300, "Insufficient available VM memory"))
    resp_503_ram = client.post(
        f"/api/v1/analyses/{analysis.id}/static-analysis",
        headers={"X-Reporting-Token": "static-test-secret"},
    )
    assert resp_503_ram.status_code == 503
    assert "Insufficient" in resp_503_ram.json()["detail"]

    monkeypatch.setattr("app.api.v1.static_analysis.check_vm_memory_headroom", lambda min_available_mb: (True, 4096, "ok"))
    monkeypatch.setattr("app.api.v1.static_analysis.check_os_sandbox_support", lambda backend="bwrap": (True, "/usr/bin/bwrap", None))
    monkeypatch.setattr("app.api.v1.static_analysis.check_cgroup_memory_support", lambda: _mock_cg_support(False))
    resp_503_cg = client.post(
        f"/api/v1/analyses/{analysis.id}/static-analysis",
        headers={"X-Reporting-Token": "static-test-secret"},
    )
    assert resp_503_cg.status_code == 503
    assert "cgroup" in resp_503_cg.json()["detail"].lower()
