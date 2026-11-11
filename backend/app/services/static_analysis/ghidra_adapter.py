from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.ai.opencode_sandbox import check_os_sandbox_support
from app.core.config import settings
from app.core.security import redact_sensitive_text
from app.schemas.static_analysis import (
    CrossReference,
    DecompiledFunction,
    FunctionCallRelationship,
    FunctionMetadata,
    ImportedSymbol,
    ProgramMetadata,
    StaticAnalysisProvenance,
    StaticAnalysisResult,
    StaticAnalysisStatus,
    StaticAnalysisTruncation,
    StaticStringEvidence,
    make_static_function_id,
    make_static_string_id,
    normalize_entry_address,
)
from app.services.static_analysis.ranker import rank_functions
from app.services.static_analysis.version_check import GhidraRuntimeValidation, validate_ghidra_runtime
from app.services.submission.pe_parser import parse_pe_metadata


_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{4,64}$")


class GhidraIsolationError(RuntimeError):
    """Raised when mandatory path, hash, symlink, or OS sandbox checks fail closed."""


def _compute_file_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _has_hidden_component(rel_path: Path) -> bool:
    return any(part.startswith(".") for part in rel_path.parts if part not in (".", ".."))


def validate_sample_for_static_analysis(
    sample_path: Path,
    expected_sha256: str,
    max_sample_bytes: int,
) -> Tuple[Path, int, Dict[str, Any]]:
    """
    Validates quarantined binary before passing read-only to Ghidra:
    rejects symlinks, traversal, missing/oversized files, SHA-256 mismatch, and non-PE binaries.
    Never executes the binary.
    """
    if not sample_path or ".." in sample_path.parts:
        raise GhidraIsolationError("Unsafe sample path (contains traversal or empty specification).")
    if sample_path.is_symlink():
        raise GhidraIsolationError(f"Refusing symlinked sample file: {sample_path}")
    # Also reject symlinked immediate directory holding sample (e.g. forged quarantine dir)
    if sample_path.parent.is_symlink():
        raise GhidraIsolationError(f"Refusing sample inside symlinked directory: {sample_path.parent}")
    if not sample_path.exists() or not sample_path.is_file():
        raise GhidraIsolationError(f"Sample binary does not exist as a regular file: {sample_path}")

    size_bytes = sample_path.stat().st_size
    if size_bytes <= 0:
        raise GhidraIsolationError("Sample file is empty (0 bytes).")
    if size_bytes > max_sample_bytes:
        raise GhidraIsolationError(
            f"Sample size ({size_bytes} bytes) exceeds GHIDRA_MAX_SAMPLE_BYTES ({max_sample_bytes} bytes)."
        )

    actual_sha = _compute_file_sha256(sample_path).lower()
    if actual_sha != (expected_sha256 or "").strip().lower():
        raise GhidraIsolationError(
            f"Sample SHA-256 verification failed: expected '{expected_sha256[:16]}...', got '{actual_sha[:16]}...'."
        )

    with open(sample_path, "rb") as f:
        sample_bytes = f.read()

    pe_meta = parse_pe_metadata(sample_bytes)
    if not pe_meta.get("is_valid_pe", False):
        reason = pe_meta.get("warning") or "File is not a valid PE executable."
        raise GhidraIsolationError(f"Invalid executable format for static PE analysis: {reason}")

    return sample_path.resolve(), size_bytes, pe_meta


def prepare_isolated_project_workspace(
    workspace_root: Path,
    job_id: str,
    sample_sha256: str,
) -> Tuple[Path, str]:
    """
    Creates an isolated, non-hidden, permission-restricted per-analysis workspace and enforces
    a sample SHA-256 project manifest so mismatched samples never share Ghidra projects.
    """
    if not _SAFE_ID_RE.match(job_id):
        raise GhidraIsolationError(f"Unsafe static analysis job identifier: '{job_id}'")
    if ".." in workspace_root.parts:
        raise GhidraIsolationError("GHIDRA_WORKSPACE_ROOT contains unsafe traversal segments.")
    if workspace_root.is_symlink():
        raise GhidraIsolationError("GHIDRA_WORKSPACE_ROOT cannot be a symlink.")

    workspace_root.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace_root, 0o700)

    resolved_root = workspace_root.resolve()
    job_dir_name = f"ghidra_job_{job_id}"
    if job_dir_name.startswith("."):
        raise GhidraIsolationError("Project directory name cannot start with '.'.")

    job_dir = resolved_root / job_dir_name
    manifest_path = job_dir / "malbox_project_manifest.json"

    if job_dir.exists():
        if job_dir.is_symlink():
            raise GhidraIsolationError("Refusing symlinked Ghidra project workspace.")
        if not manifest_path.is_file():
            raise GhidraIsolationError(
                "Existing Ghidra workspace lacks provenance manifest; refusing project reuse."
            )
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise GhidraIsolationError(f"Corrupt Ghidra project manifest: {exc}") from exc
        if manifest.get("sample_sha256") != sample_sha256.lower():
            raise GhidraIsolationError(
                "Refusing Ghidra project reuse across mismatched sample SHA-256."
            )
    else:
        job_dir.mkdir(parents=True, exist_ok=False)

    os.chmod(job_dir, 0o700)

    # Create non-hidden subdirectories cleanly (Ghidra treats dot paths as hidden)
    for sub in ("project", "home", "cfg", "cache", "tmp", "output"):
        sub_path = job_dir / sub
        sub_path.mkdir(parents=True, exist_ok=True)
        os.chmod(sub_path, 0o700)

    rel_proj = (job_dir / "project").relative_to(resolved_root)
    if _has_hidden_component(rel_proj):
        raise GhidraIsolationError("Hidden path components detected in Ghidra project location.")

    manifest_data = {
        "job_id": job_id,
        "sample_sha256": sample_sha256.lower(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    os.chmod(manifest_path, 0o600)

    project_name = f"malbox_{job_id[:16]}"
    return job_dir, project_name


def build_ghidra_headless_args(
    analyze_headless_path: str,
    project_location: str,
    project_name: str,
    sample_input_path: str,
    scripts_dir: str,
    output_json_path: str,
    max_functions: int,
    max_decompile_functions: int,
    per_func_timeout: int,
    max_pseudocode_chars: int,
    max_output_bytes: int,
    analysis_timeout_per_file: int,
    max_cpu: int,
) -> List[str]:
    """Builds the strict non-shell analyzeHeadless argument vector."""
    return [
        analyze_headless_path,
        project_location,
        project_name,
        "-import",
        sample_input_path,
        "-readOnly",
        "-scriptPath",
        scripts_dir,
        "-postScript",
        "ExportProgramFacts.java",
        output_json_path,
        str(max_functions),
        "200",
        "400",
        "AUTO_TOP",
        str(max_decompile_functions),
        str(per_func_timeout),
        str(max_pseudocode_chars),
        str(max_output_bytes),
        "-analysisTimeoutPerFile",
        str(analysis_timeout_per_file),
        "-max-cpu",
        str(max(1, min(4, max_cpu))),
        "-deleteProject",
    ]


def build_ghidra_sandbox_command(
    resolved_bwrap: str,
    runtime: GhidraRuntimeValidation,
    job_dir: Path,
    sample_file: Path,
    scripts_dir: Path,
    max_memory_mb: int,
    max_cpu: int,
    headless_args: List[str],
) -> Tuple[List[str], Dict[str, str]]:
    """
    Confines analyzeHeadless inside Linux Bubblewrap namespaces (--unshare-all --unshare-net)
    with read-only system libs, Ghidra installation, script directory, and single sample file,
    plus an isolated RW /work directory and stripped environment.
    """
    assert runtime.ghidra_home is not None
    assert runtime.analyze_headless is not None

    resolved_ghidra = runtime.ghidra_home.resolve()
    ghidra_in_usr = str(resolved_ghidra).startswith("/usr/")
    sandbox_ghidra_root = str(resolved_ghidra) if ghidra_in_usr else "/opt/ghidra"
    sandbox_headless = f"{sandbox_ghidra_root}/support/analyzeHeadless"

    # Rewrite paths inside headless_args to match sandbox mount points cleanly
    sanitized_args = [
        sandbox_headless,
        "/work/project",
        headless_args[2],
        "-import",
        "/input/sample.bin",
        "-readOnly",
        "-scriptPath",
        "/ghidra_scripts",
        *headless_args[8:],
    ]

    java_opts = (
        f"-XX:MaxMetaspaceSize=256m "
        f"-XX:ReservedCodeCacheSize=128m "
        f"-Dapplication.settingsdir=/work/cfg "
        f"-Dapplication.cachedir=/work/cache "
        f"-Dapplication.tempdir=/work/tmp "
        f"-Djava.io.tmpdir=/work/tmp "
        f"-Duser.home=/work/home "
        f"-Dcpu.core.override={max(1, min(4, max_cpu))} "
        f"-Dcpu.core.limit={max(1, min(4, max_cpu))}"
    )

    env_vars: Dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/work/home",
        "XDG_CONFIG_HOME": "/work/cfg",
        "XDG_CACHE_HOME": "/work/cache",
        "TMPDIR": "/work/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GHIDRA_HEADLESS_MAXMEM": f"{max(256, min(4096, max_memory_mb))}m",
        "GHIDRA_HEADLESS_JAVA_OPTIONS": java_opts,
    }
    if runtime.java_home is not None:
        env_vars["JAVA_HOME"] = str(runtime.java_home.resolve())

    cmd: List[str] = [
        resolved_bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind-try",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf",
        "--ro-bind-try",
        "/etc/ld.so.conf.d",
        "/etc/ld.so.conf.d",
        "--ro-bind-try",
        "/etc/alternatives",
        "/etc/alternatives",
        "--ro-bind-try",
        "/etc/nsswitch.conf",
        "/etc/nsswitch.conf",
        "--ro-bind-try",
        "/etc/localtime",
        "/etc/localtime",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "67108864",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/work",
        "--dir",
        "/input",
        "--dir",
        "/ghidra_scripts",
        "--bind",
        str(job_dir.resolve()),
        "/work",
        "--ro-bind",
        str(sample_file.resolve()),
        "/input/sample.bin",
        "--ro-bind",
        str(scripts_dir.resolve()),
        "/ghidra_scripts",
        "--chdir",
        "/work",
        "--clearenv",
    ]

    # Bind /etc/java-* configuration directories cleanly so OpenJDK finds security/logging props
    for etc_java in sorted(Path("/etc").glob("java*")):
        cmd.extend(["--ro-bind-try", str(etc_java), str(etc_java)])

    if not ghidra_in_usr:
        cmd.extend(["--ro-bind", str(resolved_ghidra), "/opt/ghidra"])

    if runtime.java_home is not None and not str(runtime.java_home.resolve()).startswith("/usr/"):
        java_res = str(runtime.java_home.resolve())
        cmd.extend(["--ro-bind", java_res, java_res])

    for k, v in sorted(env_vars.items()):
        cmd.extend(["--setenv", k, v])

    cmd.append("--")
    cmd.extend(sanitized_args)
    return cmd, env_vars


class GhidraStaticAnalyzer:
    """
    Safe, optional, resource-bounded Ghidra Headless adapter for non-executing static PE analysis.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        ghidra_home: Optional[str] = None,
        workspace_root: Optional[Path] = None,
        scripts_dir: Optional[Path] = None,
        max_memory_mb: Optional[int] = None,
        max_cpu: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
        max_sample_bytes: Optional[int] = None,
        max_functions: Optional[int] = None,
        max_decompile_functions: Optional[int] = None,
        max_pseudocode_chars: Optional[int] = None,
        max_output_bytes: Optional[int] = None,
    ) -> None:
        self.enabled = settings.GHIDRA_ENABLED if enabled is None else enabled
        self.ghidra_home = ghidra_home if ghidra_home is not None else settings.GHIDRA_HOME
        self.workspace_root = Path(workspace_root) if workspace_root is not None else Path(settings.GHIDRA_WORKSPACE_ROOT)
        self.scripts_dir = Path(scripts_dir) if scripts_dir is not None else Path(settings.GHIDRA_SCRIPTS_DIR)
        self.max_memory_mb = int(max_memory_mb if max_memory_mb is not None else settings.GHIDRA_MAX_MEMORY_MB)
        self.max_cpu = int(max_cpu if max_cpu is not None else settings.GHIDRA_MAX_CPU)
        self.timeout_seconds = int(timeout_seconds if timeout_seconds is not None else settings.GHIDRA_TIMEOUT_SECONDS)
        self.max_sample_bytes = int(max_sample_bytes if max_sample_bytes is not None else settings.GHIDRA_MAX_SAMPLE_BYTES)
        self.max_functions = int(max_functions if max_functions is not None else settings.GHIDRA_MAX_FUNCTIONS)
        self.max_decompile_functions = int(
            max_decompile_functions
            if max_decompile_functions is not None
            else settings.GHIDRA_MAX_DECOMPILE_FUNCTIONS
        )
        self.max_pseudocode_chars = int(
            max_pseudocode_chars if max_pseudocode_chars is not None else settings.GHIDRA_MAX_PSEUDOCODE_CHARS
        )
        self.max_output_bytes = int(max_output_bytes if max_output_bytes is not None else settings.GHIDRA_MAX_OUTPUT_BYTES)

    def analyze_sample(
        self,
        sample_id: str,
        sample_path: Path,
        expected_sha256: str,
        analysis_id: Optional[str] = None,
        job_id: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        allow_disabled: bool = False,
    ) -> StaticAnalysisResult:
        started_dt = datetime.now(timezone.utc)
        t_start = time.monotonic()
        effective_job_id = job_id or uuid.uuid4().hex[:16]

        def _make_provenance(
            ghidra_ver: Optional[str] = None,
            java_ver: Optional[str] = None,
            sandbox_label: str = "bwrap",
        ) -> StaticAnalysisProvenance:
            return StaticAnalysisProvenance(
                analysis_id=analysis_id,
                sample_id=sample_id,
                sample_sha256=expected_sha256.lower(),
                ghidra_version=ghidra_ver,
                java_version=java_ver,
                started_at=started_dt.isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat(),
                execution_duration_ms=max(0, int((time.monotonic() - t_start) * 1000)),
                project_isolated=True,
                os_sandbox=sandbox_label,
            )

        def _error_result(
            status_val: StaticAnalysisStatus,
            msg: str,
            ghidra_ver: Optional[str] = None,
            java_ver: Optional[str] = None,
            sandbox_label: str = "none",
        ) -> StaticAnalysisResult:
            safe_msg = redact_sensitive_text(msg, max_chars=400)
            return StaticAnalysisResult(
                status=status_val,
                provenance=_make_provenance(ghidra_ver, java_ver, sandbox_label=sandbox_label),
                truncation=StaticAnalysisTruncation(
                    max_output_bytes=self.max_output_bytes,
                    max_functions=self.max_functions,
                    max_decompile_functions=self.max_decompile_functions,
                ),
                errors=[safe_msg],
                warnings=[],
                is_partial=(status_val == "PARTIAL"),
            )

        # 1. Policy check
        if not self.enabled and not allow_disabled:
            return _error_result(
                "SKIPPED",
                "Ghidra headless static analysis is disabled (MALBOX_GHIDRA_ENABLED=false).",
            )

        # 2. Script directory validation
        scripts_resolved = self.scripts_dir.resolve()
        if not scripts_resolved.is_dir() or not (scripts_resolved / "ExportProgramFacts.java").is_file():
            return _error_result(
                "UNAVAILABLE",
                f"ExportProgramFacts.java script not found in {scripts_resolved}.",
            )

        # 3. Validate installed Ghidra & compatible JDK (read-only)
        runtime = validate_ghidra_runtime(configured_home=self.ghidra_home)
        if not runtime.ok or runtime.analyze_headless is None:
            return _error_result(
                "UNAVAILABLE",
                runtime.error or "Ghidra Headless or compatible JDK is unavailable.",
                ghidra_ver=runtime.ghidra_version,
                java_ver=runtime.java_version,
            )

        # 4. Validate quarantined sample integrity, size, symlinks & PE format
        try:
            validated_sample, _, pe_meta = validate_sample_for_static_analysis(
                sample_path=Path(sample_path),
                expected_sha256=expected_sha256,
                max_sample_bytes=self.max_sample_bytes,
            )
        except GhidraIsolationError as exc:
            return _error_result(
                "FAILED",
                str(exc),
                ghidra_ver=runtime.ghidra_version,
                java_ver=runtime.java_version,
            )

        # 5. Mandatory OS namespace boundary preflight (fail closed)
        sb_ok, resolved_bwrap, sb_reason = check_os_sandbox_support("bwrap")
        if not sb_ok or not resolved_bwrap:
            return _error_result(
                "UNAVAILABLE",
                f"Required Bubblewrap OS isolation unavailable for Ghidra (fail closed): {sb_reason}",
                ghidra_ver=runtime.ghidra_version,
                java_ver=runtime.java_version,
            )

        # 6. Prepare isolated, non-hidden, manifest-bound per-job Ghidra project directory
        job_dir: Optional[Path] = None
        try:
            job_dir, project_name = prepare_isolated_project_workspace(
                workspace_root=self.workspace_root,
                job_id=effective_job_id,
                sample_sha256=expected_sha256,
            )
        except GhidraIsolationError as exc:
            return _error_result(
                "FAILED",
                str(exc),
                ghidra_ver=runtime.ghidra_version,
                java_ver=runtime.java_version,
                sandbox_label="bwrap",
            )

        try:
            per_file_timeout = max(10, min(self.timeout_seconds, max(15, self.timeout_seconds - 10)))
            per_func_timeout = max(2, min(20, per_file_timeout // 3))
            headless_args = build_ghidra_headless_args(
                analyze_headless_path=str(runtime.analyze_headless),
                project_location="/work/project",
                project_name=project_name,
                sample_input_path="/input/sample.bin",
                scripts_dir="/ghidra_scripts",
                output_json_path="/work/output/facts.json",
                max_functions=self.max_functions,
                max_decompile_functions=self.max_decompile_functions,
                per_func_timeout=per_func_timeout,
                max_pseudocode_chars=self.max_pseudocode_chars,
                max_output_bytes=self.max_output_bytes,
                analysis_timeout_per_file=per_file_timeout,
                max_cpu=self.max_cpu,
            )

            cmd, env_vars = build_ghidra_sandbox_command(
                resolved_bwrap=resolved_bwrap,
                runtime=runtime,
                job_dir=job_dir,
                sample_file=validated_sample,
                scripts_dir=scripts_resolved,
                max_memory_mb=self.max_memory_mb,
                max_cpu=self.max_cpu,
                headless_args=headless_args,
            )

            proc = subprocess.Popen(
                cmd,
                cwd=str(job_dir),
                env={},
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=self._make_rlimit_preexec(),
            )

            stdout_b, stderr_b, stream_overflow, timed_out, cancelled = self._collect_bounded_output(
                proc=proc,
                timeout=float(self.timeout_seconds),
                cancel_event=cancel_event,
            )

            if cancelled:
                return _error_result(
                    "FAILED",
                    "Static analysis job cancelled while executing.",
                    ghidra_ver=runtime.ghidra_version,
                    java_ver=runtime.java_version,
                    sandbox_label="bwrap",
                )

            if timed_out:
                return _error_result(
                    "TIMED_OUT",
                    f"Ghidra headless static analysis exceeded {self.timeout_seconds}s timeout and process group was terminated.",
                    ghidra_ver=runtime.ghidra_version,
                    java_ver=runtime.java_version,
                    sandbox_label="bwrap",
                )

            output_file = job_dir / "output" / "facts.json"
            if not output_file.is_file():
                err_tail = redact_sensitive_text(
                    (stderr_b.decode("utf-8", errors="replace") or stdout_b.decode("utf-8", errors="replace"))[-400:],
                    max_chars=300,
                )
                return _error_result(
                    "FAILED",
                    f"Ghidra headless finished (rc={proc.returncode}) without producing facts.json ({err_tail or 'no output'}).",
                    ghidra_ver=runtime.ghidra_version,
                    java_ver=runtime.java_version,
                    sandbox_label="bwrap",
                )

            raw_size = output_file.stat().st_size
            if raw_size > self.max_output_bytes:
                return _error_result(
                    "FAILED",
                    f"Exported Ghidra output exceeded hard cap ({raw_size} > {self.max_output_bytes} bytes).",
                    ghidra_ver=runtime.ghidra_version,
                    java_ver=runtime.java_version,
                    sandbox_label="bwrap",
                )

            try:
                raw_text = output_file.read_text(encoding="utf-8")
                parsed_json = json.loads(raw_text)
            except Exception as exc:
                return _error_result(
                    "FAILED",
                    f"Malformed JSON emitted by Ghidra export script: {type(exc).__name__}",
                    ghidra_ver=runtime.ghidra_version,
                    java_ver=runtime.java_version,
                    sandbox_label="bwrap",
                )

            return self._normalize_and_rank_result(
                raw_json=parsed_json,
                raw_output_bytes=raw_size,
                pe_meta=pe_meta,
                sample_id=sample_id,
                sample_sha256=expected_sha256.lower(),
                analysis_id=analysis_id,
                provenance=_make_provenance(runtime.ghidra_version, runtime.java_version, sandbox_label="bwrap"),
                stream_overflow=stream_overflow,
            )

        except Exception as exc:
            return _error_result(
                "FAILED",
                f"Unexpected static analysis adapter failure ({type(exc).__name__}): {exc}",
                ghidra_ver=runtime.ghidra_version,
                java_ver=runtime.java_version,
                sandbox_label="bwrap",
            )
        finally:
            if job_dir is not None and job_dir.exists():
                shutil.rmtree(job_dir, ignore_errors=True)

    def _make_rlimit_preexec(self):
        cpu_limit = max(5, int(self.timeout_seconds))

        def _apply() -> None:
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            # Allow bounded project database writes up to 256 MiB per file
            max_file = 256 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_file, max_file))

        return _apply

    def _collect_bounded_output(
        self,
        proc: subprocess.Popen,
        timeout: float,
        cancel_event: Optional[threading.Event] = None,
    ) -> Tuple[bytes, bytes, bool, bool, bool]:
        out_chunks: List[bytes] = []
        err_chunks: List[bytes] = []
        limit = max(4096, self.max_output_bytes)
        state = {"total": 0, "overflowed": False}
        lock = threading.Lock()

        def _drain(stream, bucket: List[bytes]) -> None:
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    with lock:
                        if state["total"] + len(chunk) <= limit:
                            state["total"] += len(chunk)
                            bucket.append(chunk)
                        else:
                            state["overflowed"] = True
                            break
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks), daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks), daemon=True)
        t_out.start()
        t_err.start()

        timed_out = False
        cancelled = False
        deadline = time.monotonic() + max(0.5, float(timeout))

        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                self._terminate_process_group(proc.pid)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                self._terminate_process_group(proc.pid)
                break
            time.sleep(0.05)

        t_out.join(timeout=1.5)
        t_err.join(timeout=1.5)
        if proc.poll() is None:
            self._terminate_process_group(proc.pid)
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass

        return b"".join(out_chunks), b"".join(err_chunks), state["overflowed"], timed_out, cancelled

    @staticmethod
    def _terminate_process_group(pid: int) -> None:
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pgid, sig)
            except OSError:
                try:
                    os.kill(pid, sig)
                except OSError:
                    pass

    def _normalize_and_rank_result(
        self,
        raw_json: Any,
        raw_output_bytes: int,
        pe_meta: Dict[str, Any],
        sample_id: str,
        sample_sha256: str,
        analysis_id: Optional[str],
        provenance: StaticAnalysisProvenance,
        stream_overflow: bool,
    ) -> StaticAnalysisResult:
        if not isinstance(raw_json, dict):
            return StaticAnalysisResult(
                status="FAILED",
                provenance=provenance,
                truncation=StaticAnalysisTruncation(
                    max_output_bytes=self.max_output_bytes,
                    max_functions=self.max_functions,
                    max_decompile_functions=self.max_decompile_functions,
                ),
                errors=["Ghidra JSON root is not an object."],
            )

        raw_status = str(raw_json.get("status") or "COMPLETED").upper()
        errors: List[str] = [str(e) for e in (raw_json.get("errors") or [])]
        warnings: List[str] = [str(w) for w in (raw_json.get("warnings") or [])]
        if stream_overflow:
            warnings.append("Ghidra console stdout/stderr exceeded buffer cap and was truncated.")

        if raw_status == "FAILED":
            return StaticAnalysisResult(
                status="FAILED",
                provenance=provenance,
                truncation=StaticAnalysisTruncation(
                    output_bytes=raw_output_bytes,
                    max_output_bytes=self.max_output_bytes,
                    max_functions=self.max_functions,
                    max_decompile_functions=self.max_decompile_functions,
                ),
                errors=errors or ["Ghidra script reported failure status."],
                warnings=warnings,
                is_partial=False,
            )

        raw_prog = raw_json.get("program_metadata") or {}
        if not isinstance(raw_prog, dict):
            raw_prog = {}

        raw_imports = raw_json.get("imports") or []
        imports = [
            ImportedSymbol(
                library=str(item.get("library") or "UNKNOWN"),
                name=str(item.get("name") or "unknown"),
                address=normalize_entry_address(item["address"]) if item.get("address") else None,
                ordinal=item.get("ordinal"),
            )
            for item in raw_imports[:400]
            if isinstance(item, dict)
        ]

        exports = [str(e) for e in (raw_json.get("exports") or [])[:200]]

        raw_strings = raw_json.get("strings") or []
        strings: List[StaticStringEvidence] = []
        for s_item in raw_strings[:200]:
            if not isinstance(s_item, dict) or not s_item.get("address"):
                continue
            addr = normalize_entry_address(str(s_item.get("address")))
            ref_fids = [
                make_static_function_id(sample_sha256, str(fa))
                for fa in (s_item.get("ref_func_addresses") or [])[:16]
            ]
            val = str(s_item.get("value") or "")[:240]
            strings.append(
                StaticStringEvidence(
                    string_id=make_static_string_id(sample_sha256, addr),
                    address=addr,
                    value=val,
                    length=int(s_item.get("length") or len(val)),
                    section=s_item.get("section"),
                    referencing_function_ids=ref_fids,
                )
            )

        raw_funcs = raw_json.get("functions") or []
        total_discovered = int(raw_prog.get("total_functions_discovered") or len(raw_funcs))
        capped_funcs = raw_funcs[: self.max_functions]
        func_omitted = max(0, total_discovered - len(capped_funcs))

        addr_to_fid: Dict[str, str] = {}
        functions: List[FunctionMetadata] = []
        for f_item in capped_funcs:
            if not isinstance(f_item, dict) or not f_item.get("entry_address"):
                continue
            addr = normalize_entry_address(str(f_item.get("entry_address")))
            fid = make_static_function_id(sample_sha256, addr)
            addr_to_fid[addr] = fid

        for f_item in capped_funcs:
            if not isinstance(f_item, dict) or not f_item.get("entry_address"):
                continue
            addr = normalize_entry_address(str(f_item.get("entry_address")))
            fid = addr_to_fid[addr]
            called_fids = [
                addr_to_fid.get(normalize_entry_address(str(ca)), make_static_function_id(sample_sha256, str(ca)))
                for ca in (f_item.get("called_addresses") or [])[:50]
            ]
            caller_fids = [
                addr_to_fid.get(normalize_entry_address(str(ca)), make_static_function_id(sample_sha256, str(ca)))
                for ca in (f_item.get("caller_addresses") or [])[:50]
            ]
            functions.append(
                FunctionMetadata(
                    function_id=fid,
                    entry_address=addr,
                    name=str(f_item.get("name") or f"FUN_{addr[2:]}"),
                    size_bytes=max(0, int(f_item.get("size_bytes") or 0)),
                    basic_block_count=f_item.get("basic_block_count"),
                    is_thunk=bool(f_item.get("is_thunk", False)),
                    is_external=bool(f_item.get("is_external", False)),
                    is_executed=False,
                    calling_convention=f_item.get("calling_convention"),
                    signature=f_item.get("signature"),
                    imported_api_calls=[str(x) for x in (f_item.get("imported_api_calls") or [])[:40]],
                    called_function_ids=called_fids,
                    caller_function_ids=caller_fids,
                    string_refs=[str(x)[:200] for x in (f_item.get("string_refs") or [])[:25]],
                    xref_in_count=max(0, int(f_item.get("xref_in_count") or 0)),
                    xref_out_count=max(0, int(f_item.get("xref_out_count") or 0)),
                )
            )

        call_graph: List[FunctionCallRelationship] = []
        for c_item in (raw_json.get("call_graph") or [])[:1500]:
            if not isinstance(c_item, dict) or not c_item.get("caller_address"):
                continue
            c_addr = normalize_entry_address(str(c_item.get("caller_address")))
            callee_addr = normalize_entry_address(str(c_item["callee_address"])) if c_item.get("callee_address") else None
            is_ext = bool(c_item.get("is_external_import", False))
            call_graph.append(
                FunctionCallRelationship(
                    caller_function_id=make_static_function_id(sample_sha256, c_addr),
                    caller_address=c_addr,
                    caller_name=str(c_item.get("caller_name") or c_addr),
                    callee_function_id=(
                        None if (is_ext or not callee_addr) else make_static_function_id(sample_sha256, callee_addr)
                    ),
                    callee_address=callee_addr,
                    callee_name=str(c_item.get("callee_name") or callee_addr or "unknown"),
                    is_external_import=is_ext,
                    call_site_address=c_item.get("call_site_address"),
                )
            )

        cross_refs: List[CrossReference] = []
        for x_item in (raw_json.get("cross_references") or [])[:400]:
            if not isinstance(x_item, dict) or not x_item.get("from_address") or not x_item.get("to_address"):
                continue
            from_fn_addr = x_item.get("from_function_address")
            to_fn_addr = x_item.get("to_function_address")
            cross_refs.append(
                CrossReference(
                    from_address=normalize_entry_address(str(x_item.get("from_address"))),
                    to_address=normalize_entry_address(str(x_item.get("to_address"))),
                    ref_type=str(x_item.get("ref_type") or "REF"),
                    from_function_id=make_static_function_id(sample_sha256, str(from_fn_addr)) if from_fn_addr else None,
                    to_function_id=make_static_function_id(sample_sha256, str(to_fn_addr)) if to_fn_addr else None,
                    target_symbol=x_item.get("target_symbol"),
                )
            )

        # Authoritative deterministic function ranking
        ranked_functions, ranked_findings = rank_functions(functions, call_graph, strings)

        # Selective bounded decompilation enforcement
        raw_decomp = raw_json.get("decompiled_functions") or []
        decomp_list: List[DecompiledFunction] = []
        total_decomp_bytes = 0
        decomp_errors_or_timeouts = False
        decomp_cap_triggered = int(raw_json.get("decompiled_skipped_cap") or 0) > 0

        for d_item in raw_decomp:
            if not isinstance(d_item, dict) or not d_item.get("entry_address"):
                continue
            if len(decomp_list) >= self.max_decompile_functions:
                decomp_cap_triggered = True
                break
            d_addr = normalize_entry_address(str(d_item.get("entry_address")))
            d_status = str(d_item.get("decompile_status") or "OK").upper()
            if d_status not in ("OK", "TIMED_OUT", "ERROR", "SKIPPED_CAP"):
                d_status = "ERROR"
            if d_status in ("TIMED_OUT", "ERROR"):
                decomp_errors_or_timeouts = True

            code = str(d_item.get("pseudocode") or "")
            truncated_flag = bool(d_item.get("truncated", False))
            if len(code) > self.max_pseudocode_chars:
                code = code[: self.max_pseudocode_chars] + "\n/* [TRUNCATED] */"
                truncated_flag = True

            code_bytes = len(code.encode("utf-8"))
            if total_decomp_bytes + code_bytes > max(2048, self.max_output_bytes // 2):
                decomp_list.append(
                    DecompiledFunction(
                        function_id=make_static_function_id(sample_sha256, d_addr),
                        entry_address=d_addr,
                        name=str(d_item.get("name") or d_addr),
                        pseudocode="",
                        pseudocode_bytes=0,
                        truncated=True,
                        decompile_status="SKIPPED_CAP",
                        error_message="Skipped due to decompilation output byte budget.",
                    )
                )
                decomp_cap_triggered = True
                continue

            total_decomp_bytes += code_bytes
            decomp_list.append(
                DecompiledFunction(
                    function_id=make_static_function_id(sample_sha256, d_addr),
                    entry_address=d_addr,
                    name=str(d_item.get("name") or d_addr),
                    pseudocode=code,
                    pseudocode_bytes=code_bytes,
                    truncated=truncated_flag,
                    decompile_status=d_status,  # type: ignore[arg-type]
                    error_message=d_item.get("error_message"),
                )
            )

        program_meta = ProgramMetadata(
            program_name=str(raw_prog.get("program_name") or "sample.bin"),
            executable_format=raw_prog.get("executable_format") or pe_meta.get("subsystem"),
            language_id=raw_prog.get("language_id"),
            architecture=raw_prog.get("architecture") or pe_meta.get("machine_type"),
            endianness=raw_prog.get("endianness"),
            address_size=raw_prog.get("address_size"),
            image_base=raw_prog.get("image_base") or pe_meta.get("image_base"),
            entry_points=[normalize_entry_address(str(ep)) for ep in (raw_prog.get("entry_points") or [])],
            total_functions_discovered=total_discovered,
            total_imports=int(raw_prog.get("total_imports") or len(imports)),
            total_exports=int(raw_prog.get("total_exports") or len(exports)),
            total_strings=int(raw_prog.get("total_strings") or len(strings)),
        )

        is_partial = (
            raw_status == "PARTIAL"
            or bool(raw_json.get("truncated"))
            or func_omitted > 0
            or decomp_cap_triggered
            or decomp_errors_or_timeouts
            or bool(errors)
        )
        final_status: StaticAnalysisStatus = "PARTIAL" if is_partial else "COMPLETED"

        truncation = StaticAnalysisTruncation(
            truncated=is_partial,
            functions_discovered=total_discovered,
            functions_included=len(ranked_functions),
            functions_omitted=func_omitted,
            decompiled_requested=int(raw_json.get("decompiled_requested") or len(raw_decomp)),
            decompiled_included=sum(1 for d in decomp_list if d.decompile_status == "OK"),
            decompiled_omitted_cap=max(
                0,
                int(raw_json.get("decompiled_skipped_cap") or 0)
                + max(0, len(raw_decomp) - len(decomp_list)),
            ),
            strings_included=len(strings),
            strings_omitted=max(0, program_meta.total_strings - len(strings)),
            output_bytes=raw_output_bytes,
            max_output_bytes=self.max_output_bytes,
            max_functions=self.max_functions,
            max_decompile_functions=self.max_decompile_functions,
        )

        return StaticAnalysisResult(
            status=final_status,
            provenance=provenance,
            program_metadata=program_meta,
            functions=ranked_functions,
            call_graph=call_graph,
            cross_references=cross_refs,
            imports=imports,
            exports=exports,
            strings=strings,
            decompiled_functions=decomp_list,
            ranked_findings=ranked_findings,
            truncation=truncation,
            errors=errors,
            warnings=warnings,
            is_partial=is_partial,
        )
