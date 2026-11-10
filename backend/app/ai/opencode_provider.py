import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.ai.intelligence_helper import build_deterministic_proposed_intelligence
from app.ai.mock_provider import MockLLMProvider
from app.ai.opencode_sandbox import (
    ApprovedProviderProxy,
    build_bwrap_command,
    check_os_sandbox_support,
    parse_approved_provider_target,
    resolve_executable,
)
from app.ai.provider import LLMProvider
from app.core.config import settings
from app.core.security import redact_sensitive_text
from app.schemas.intelligence import (
    AIProviderMetadata,
    IntelligenceReport,
    VerifiedEvidenceBundle,
)
from app.services.intelligence.rules_loader import load_report_analyst_rules
from app.services.intelligence.validator import EvidenceValidator


TESTED_OPENCODE_VERSION = "2.1.4"
MIN_SUPPORTED_OPENCODE_VERSION = (2, 0, 0)
MAX_EXCLUSIVE_OPENCODE_VERSION = (3, 0, 0)

_DISALLOWED_TOOL_NAMES = {
    "shell",
    "bash",
    "edit",
    "write",
    "patch",
    "multiedit",
    "webfetch",
    "websearch",
    "external_directory",
    "subagent",
    "task",
    "skill",
    "mcp",
    "glob",
    "grep",
    "list",
    "todowrite",
}

_FALLBACK_AGENT_SPEC = """---
description: Restricted read-only evidence-grounded malware intelligence report analyst (OpenCode v2.1.4)
mode: primary
permissions:
  - action: "*"
    resource: "*"
    effect: deny
  - action: shell
    resource: "*"
    effect: deny
  - action: bash
    resource: "*"
    effect: deny
  - action: edit
    resource: "*"
    effect: deny
  - action: external_directory
    resource: "*"
    effect: deny
  - action: webfetch
    resource: "*"
    effect: deny
  - action: subagent
    resource: "*"
    effect: deny
  - action: read
    resource: "./evidence_bundle.json"
    effect: allow
---
Analyze only ./evidence_bundle.json and return ONLY valid AIProposedIntelligence JSON.
"""


class OpenCodeExecutionError(RuntimeError):
    """Raised internally when isolated OpenCode execution fails or violates policy."""


def parse_opencode_semver(version_output: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"(?:^|\s)v?(\d+)\.(\d+)\.(\d+)(?:\s|$|[-+])", version_output or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_supported_opencode_version(ver: Optional[Tuple[int, int, int]]) -> bool:
    if ver is None:
        return False
    return MIN_SUPPORTED_OPENCODE_VERSION <= ver < MAX_EXCLUSIVE_OPENCODE_VERSION


class OpenCodeReportProvider(LLMProvider):
    """
    Restricted, opt-in OpenCode CLI reporting adapter (supported OpenCode V2, tested on 2.1.4).
    Executes solely inside an independently enforced Bubblewrap (bwrap) OS namespace sandbox
    with read-only evidence mounts, zero host home/repository exposure, airgapped or
    allowlisted-proxy network confinement, POSIX resource caps, and active cancellation.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        external_consent: Optional[bool] = None,
        binary: Optional[str] = None,
        sandbox_binary: Optional[str] = None,
        agent_name: Optional[str] = None,
        model: Optional[str] = None,
        allow_network: Optional[bool] = None,
        allowed_provider_url: Optional[str] = None,
        timeout: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
        max_cpu_seconds: Optional[int] = None,
        max_memory_mb: Optional[int] = None,
        max_data_mb: Optional[int] = None,
        provider_api_key: Optional[str] = None,
        provider_env_name: Optional[str] = None,
    ) -> None:
        self.enabled = settings.OPENCODE_ENABLED if enabled is None else enabled
        self.external_consent = (
            settings.REPORTING_EXTERNAL_AI_CONSENT if external_consent is None else external_consent
        )
        self.binary = binary if binary is not None else settings.OPENCODE_BIN
        self.sandbox_binary = (
            sandbox_binary if sandbox_binary is not None else settings.OPENCODE_SANDBOX_BIN
        )
        self.agent_name = agent_name if agent_name is not None else settings.OPENCODE_AGENT_NAME
        self.model = model if model is not None else settings.OPENCODE_MODEL
        self.allow_network = (
            settings.OPENCODE_ALLOW_NETWORK if allow_network is None else allow_network
        )
        self.allowed_provider_url = (
            allowed_provider_url
            if allowed_provider_url is not None
            else (settings.OPENCODE_ALLOWED_PROVIDER_URL or settings.AI_BASE_URL)
        )
        self.timeout = float(timeout if timeout is not None else settings.OPENCODE_TIMEOUT_SECONDS)
        self.max_output_bytes = int(
            max_output_bytes if max_output_bytes is not None else settings.OPENCODE_MAX_OUTPUT_BYTES
        )
        self.max_cpu_seconds = int(
            max_cpu_seconds if max_cpu_seconds is not None else settings.OPENCODE_MAX_CPU_SECONDS
        )
        self.max_memory_mb = int(
            max_memory_mb if max_memory_mb is not None else settings.OPENCODE_MAX_MEMORY_MB
        )
        self.max_data_mb = int(
            max_data_mb if max_data_mb is not None else settings.OPENCODE_MAX_DATA_MB
        )
        self.provider_api_key = (
            provider_api_key if provider_api_key is not None else settings.OPENCODE_PROVIDER_API_KEY
        )
        self.provider_env_name = (
            provider_env_name if provider_env_name is not None else settings.OPENCODE_PROVIDER_ENV_NAME
        )
        self.last_call_meta: Dict[str, Any] = {}

    def generate_plan(self, sample_metadata: Dict[str, Any], available_profiles: list) -> Dict[str, Any]:
        return MockLLMProvider().generate_plan(sample_metadata, available_profiles)

    def evaluate_observations(
        self, sample_metadata: Dict[str, Any], telemetry_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        return MockLLMProvider().evaluate_observations(sample_metadata, telemetry_summary)

    def generate_executive_summary(
        self, sample_metadata: Dict[str, Any], findings_summary: Dict[str, Any], timeline: list
    ) -> str:
        return MockLLMProvider().generate_executive_summary(sample_metadata, findings_summary, timeline)

    def generate_intelligence_report(
        self,
        bundle: VerifiedEvidenceBundle,
        rules_text: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> IntelligenceReport:
        now_iso = datetime.now(timezone.utc).isoformat()
        secrets_to_redact = self._collect_secrets_for_redaction()
        model_label = self.model or f"opencode:{self.agent_name}"
        detected_version = TESTED_OPENCODE_VERSION

        try:
            if not self.enabled:
                raise OpenCodeExecutionError("OpenCode adapter is disabled by configuration.")
            if not self.external_consent:
                raise OpenCodeExecutionError(
                    "External evidence transmission consent is not enabled for OpenCode."
                )

            sb_ok, resolved_bwrap, sb_reason = check_os_sandbox_support(self.sandbox_binary)
            if not sb_ok or not resolved_bwrap:
                raise OpenCodeExecutionError(
                    sb_reason or "Mandatory Bubblewrap OS sandbox is unavailable (fail closed)."
                )

            resolved_bin = self._resolve_binary(self.binary)
            if not resolved_bin:
                raise OpenCodeExecutionError("OpenCode CLI executable could not be located.")

            agent_markdown = self._load_and_validate_agent_markdown()

            if self.allow_network:
                allowed_host, allowed_port = parse_approved_provider_target(
                    self.allowed_provider_url
                )
                net_target: Optional[Tuple[str, int]] = (allowed_host, allowed_port)
            else:
                net_target = None

            detected_version = self._verify_cli_version(
                resolved_bwrap=resolved_bwrap,
                resolved_bin=resolved_bin,
                cancel_event=cancel_event,
            )

            content, tokens_used = self._execute_sandboxed(
                resolved_bwrap=resolved_bwrap,
                resolved_bin=resolved_bin,
                agent_markdown=agent_markdown,
                bundle=bundle,
                rules_text=rules_text,
                net_target=net_target,
                cancel_event=cancel_event,
            )

            provider_meta = AIProviderMetadata(
                mode="opencode_enriched",
                provider="opencode",
                model=model_label,
                tokens_used=tokens_used,
                fallback_used=False,
                fallback_reason=None,
                rules_version="2.0",
                generated_at=now_iso,
            )
            report = EvidenceValidator().validate_and_finalize(
                raw_output=content,
                bundle=bundle,
                provider_meta=provider_meta,
                fallback_fn=build_deterministic_proposed_intelligence,
            )
            self.last_call_meta = {
                "provider": report.provider_metadata.provider,
                "model": report.provider_metadata.model,
                "tokens_used": report.provider_metadata.tokens_used,
                "fallback": report.provider_metadata.fallback_used,
                "fallback_reason": report.provider_metadata.fallback_reason,
                "cli_version": detected_version,
                "tested_opencode_version": TESTED_OPENCODE_VERSION,
                "os_sandbox": "bwrap",
            }
            return report

        except Exception as exc:
            safe_reason = redact_sensitive_text(
                f"{type(exc).__name__}: {str(exc)}",
                extra_secrets=secrets_to_redact,
                max_chars=180,
            )
            fallback_proposed = build_deterministic_proposed_intelligence(bundle)
            provider_meta = AIProviderMetadata(
                mode="mock_fallback",
                provider="mock_fallback",
                model=model_label,
                tokens_used=0,
                fallback_used=True,
                fallback_reason=safe_reason,
                rules_version="2.0",
                generated_at=now_iso,
            )
            report = EvidenceValidator().validate_and_finalize(
                raw_output=fallback_proposed,
                bundle=bundle,
                provider_meta=provider_meta,
                fallback_fn=build_deterministic_proposed_intelligence,
            )
            self.last_call_meta = {
                "provider": "mock_fallback",
                "model": model_label,
                "tokens_used": 0,
                "fallback": True,
                "fallback_reason": safe_reason,
                "cli_version": detected_version,
                "tested_opencode_version": TESTED_OPENCODE_VERSION,
                "os_sandbox": "bwrap",
            }
            return report

    def _collect_secrets_for_redaction(self) -> List[str]:
        candidates = [
            self.provider_api_key,
            settings.AI_API_KEY,
            settings.REPORTING_AUTH_TOKEN,
            settings.OPERATOR_TOKEN,
            settings.SECRET_KEY,
            settings.CAPE_API_TOKEN,
        ]
        return [s for s in candidates if s]

    @staticmethod
    def _resolve_binary(bin_spec: str) -> Optional[str]:
        return resolve_executable(bin_spec, fallback_dir=Path.home() / ".opencode" / "bin")

    def _load_and_validate_agent_markdown(self) -> str:
        repo_root = Path(__file__).resolve().parents[3]
        spec_path = repo_root / ".opencode" / "agents" / f"{self.agent_name}.md"
        if spec_path.is_file():
            try:
                content = spec_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise OpenCodeExecutionError(f"Unable to read agent specification: {exc}") from exc
        elif self.agent_name == "report-analyst":
            content = _FALLBACK_AGENT_SPEC
        else:
            raise OpenCodeExecutionError(f"Requested OpenCode agent '{self.agent_name}' does not exist.")

        # Validate frontmatter before invoking OpenCode: must be primary mode and deny dangerous tools
        if not re.search(r"(?m)^mode:\s*primary\s*$", content):
            raise OpenCodeExecutionError(
                f"OpenCode agent '{self.agent_name}' must declare 'mode: primary' for direct invocation."
            )
        lowered = content.lower()
        for required_deny in ("shell", "edit", "external_directory", "webfetch", "subagent"):
            if required_deny not in lowered or "deny" not in lowered:
                raise OpenCodeExecutionError(
                    f"OpenCode agent '{self.agent_name}' missing explicit '{required_deny}' deny rule."
                )
        return content

    def _verify_cli_version(
        self,
        resolved_bwrap: str,
        resolved_bin: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> str:
        with tempfile.TemporaryDirectory(prefix="malbox_oc_ver_") as raw_tmp:
            tmpdir = Path(raw_tmp)
            os.chmod(tmpdir, 0o700)
            (tmpdir / ".opencode" / "agents").mkdir(parents=True, exist_ok=True)
            (tmpdir / "opencode.json").write_text("{}", encoding="utf-8")
            (tmpdir / "evidence_bundle.json").write_text("{}", encoding="utf-8")

            cmd = build_bwrap_command(
                resolved_bwrap=resolved_bwrap,
                resolved_opencode=resolved_bin,
                tmpdir=tmpdir,
                sandbox_env={
                    "PATH": "/opt/opencode:/usr/bin:/bin",
                    "HOME": "/sandbox",
                    "XDG_CONFIG_HOME": "/sandbox/.xdg/config",
                    "XDG_DATA_HOME": "/sandbox/.xdg/data",
                    "XDG_STATE_HOME": "/sandbox/.xdg/state",
                    "XDG_CACHE_HOME": "/sandbox/.xdg/cache",
                    "NO_COLOR": "1",
                },
                inner_args=["--version"],
                max_tmpfs_bytes=settings.OPENCODE_MAX_SANDBOX_TMPFS_BYTES,
                allow_network=False,
            )

            proc = subprocess.Popen(
                cmd,
                cwd=str(tmpdir),
                env={},
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=self._make_rlimit_preexec(),
            )
            stdout_b, stderr_b, overflowed, timed_out, cancelled = self._collect_bounded_output(
                proc=proc,
                timeout=min(5.0, self.timeout),
                cancel_event=cancel_event,
            )
            if cancelled:
                raise OpenCodeExecutionError("OpenCode CLI version check cancelled.")
            if timed_out or overflowed or proc.returncode != 0:
                raise OpenCodeExecutionError("OpenCode CLI --version check failed inside sandbox.")

            ver_text = (stdout_b or stderr_b).decode("utf-8", errors="replace").strip()
            parsed = parse_opencode_semver(ver_text)
            if not is_supported_opencode_version(parsed):
                raise OpenCodeExecutionError(
                    f"Unsupported OpenCode CLI version '{ver_text[:60]}'; requires v2.x."
                )
            return ".".join(str(x) for x in parsed)

    def _build_locked_opencode_config(self) -> Dict[str, Any]:
        deny_actions = [
            "*",
            "shell",
            "bash",
            "edit",
            "write",
            "patch",
            "multiedit",
            "external_directory",
            "webfetch",
            "websearch",
            "subagent",
            "task",
            "skill",
            "mcp",
            "glob",
            "grep",
            "list",
            "todowrite",
        ]
        permissions = [{"action": act, "resource": "*", "effect": "deny"} for act in deny_actions]
        permissions.append({"action": "read", "resource": "./evidence_bundle.json", "effect": "allow"})

        # Disable privileged built-in agents so fallback to 'build'/'plan'/'general'/'explore' is blocked
        disabled_builtins: Dict[str, Dict[str, bool]] = {
            name: {"disable": True}
            for name in ("build", "plan", "general", "explore")
            if name != self.agent_name
        }
        return {
            "$schema": "https://opencode.ai/config.json",
            "default_agent": self.agent_name,
            "agent": disabled_builtins,
            "permissions": permissions,
        }

    def _build_sandbox_env(self) -> Dict[str, str]:
        env: Dict[str, str] = {
            "PATH": "/opt/opencode:/usr/bin:/bin",
            "HOME": "/sandbox",
            "TMPDIR": "/tmp",
            "XDG_CONFIG_HOME": "/sandbox/.xdg/config",
            "XDG_DATA_HOME": "/sandbox/.xdg/data",
            "XDG_STATE_HOME": "/sandbox/.xdg/state",
            "XDG_CACHE_HOME": "/sandbox/.xdg/cache",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
        }
        key = self.provider_api_key
        env_name = (self.provider_env_name or "").strip()
        if (
            self.allow_network
            and key
            and env_name
            and re.fullmatch(r"[A-Z][A-Z0-9_]{2,64}", env_name)
            and not env_name.startswith("MALBOX_")
        ):
            env[env_name] = key
        return env

    def _make_rlimit_preexec(self):
        cpu_limit = max(2, self.max_cpu_seconds)
        mem_bytes = max(256, self.max_memory_mb) * 1024 * 1024
        data_bytes = max(128, self.max_data_mb) * 1024 * 1024

        def _apply_limits() -> None:
            import resource

            limits = [
                (resource.RLIMIT_CPU, cpu_limit),
                (resource.RLIMIT_AS, mem_bytes),
                (resource.RLIMIT_DATA, data_bytes),
                (resource.RLIMIT_FSIZE, 1048576),
                (resource.RLIMIT_NOFILE, 256),
            ]
            for r_id, target in limits:
                try:
                    _, hard = resource.getrlimit(r_id)
                    cap = target if hard == resource.RLIM_INFINITY else min(target, hard)
                    resource.setrlimit(r_id, (cap, hard if hard != resource.RLIM_INFINITY else cap))
                except (ValueError, OSError):
                    pass
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (ValueError, OSError):
                pass

        return _apply_limits

    def _execute_sandboxed(
        self,
        resolved_bwrap: str,
        resolved_bin: str,
        agent_markdown: str,
        bundle: VerifiedEvidenceBundle,
        rules_text: Optional[str],
        net_target: Optional[Tuple[str, int]],
        cancel_event: Optional[threading.Event] = None,
    ) -> Tuple[str, int]:
        with tempfile.TemporaryDirectory(prefix="malbox_oc_") as raw_tmp:
            tmpdir = Path(raw_tmp)
            os.chmod(tmpdir, 0o700)

            agents_dir = tmpdir / ".opencode" / "agents"
            agents_dir.mkdir(parents=True, exist_ok=True)

            agent_path = agents_dir / f"{self.agent_name}.md"
            agent_path.write_text(agent_markdown, encoding="utf-8")
            os.chmod(agent_path, 0o400)
            os.chmod(agents_dir, 0o500)
            os.chmod(tmpdir / ".opencode", 0o500)

            cfg_path = tmpdir / "opencode.json"
            cfg_path.write_text(json.dumps(self._build_locked_opencode_config(), indent=2), encoding="utf-8")
            os.chmod(cfg_path, 0o400)

            bundle_path = tmpdir / "evidence_bundle.json"
            bundle_path.write_text(bundle.model_dump_json(), encoding="utf-8")
            os.chmod(bundle_path, 0o400)

            # Verify no overlap with sensitive host paths
            resolved_tmp = tmpdir.resolve()
            for forbidden in (
                Path(settings.WORKSPACE_ROOT).resolve(),
                Path(settings.QUARANTINE_DIR).resolve(),
                Path(settings.DATA_DIR).resolve(),
                Path.home().resolve(),
            ):
                if resolved_tmp == forbidden:
                    raise OpenCodeExecutionError("Temporary workspace resolved to forbidden directory.")

            sandbox_env = self._build_sandbox_env()
            effective_rules = rules_text or load_report_analyst_rules()
            prompt_msg = (
                "Analyze ONLY ./evidence_bundle.json and follow these non-executable rules.\n"
                "Return ONLY a single valid JSON object matching AIProposedIntelligence.\n\n"
                + effective_rules[:3000]
            )

            inner_args = [
                "run",
                "--standalone",
                "--format",
                "json",
                "--agent",
                self.agent_name,
                "--file",
                "evidence_bundle.json",
            ]
            if self.model:
                inner_args.extend(["--model", self.model])
            inner_args.append(prompt_msg)

            def _run_subprocess(sock_path: Optional[Path]) -> Tuple[bytes, bytes, bool, bool, bool, int]:
                cmd = build_bwrap_command(
                    resolved_bwrap=resolved_bwrap,
                    resolved_opencode=resolved_bin,
                    tmpdir=tmpdir,
                    sandbox_env=sandbox_env,
                    inner_args=inner_args,
                    max_tmpfs_bytes=settings.OPENCODE_MAX_SANDBOX_TMPFS_BYTES,
                    allow_network=(net_target is not None),
                    egress_socket_path=sock_path,
                )
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(resolved_tmp),
                    env={},
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    preexec_fn=self._make_rlimit_preexec(),
                )
                out_b, err_b, ov, to, canc = self._collect_bounded_output(
                    proc=proc,
                    timeout=self.timeout,
                    cancel_event=cancel_event,
                )
                rc = proc.returncode if proc.returncode is not None else -9
                return out_b, err_b, ov, to, canc, rc

            try:
                if net_target is not None:
                    sock_path = tmpdir / "egress.sock"
                    with ApprovedProviderProxy(sock_path, net_target[0], net_target[1]):
                        stdout_bytes, stderr_bytes, overflowed, timed_out, cancelled, rc = _run_subprocess(
                            sock_path
                        )
                else:
                    stdout_bytes, stderr_bytes, overflowed, timed_out, cancelled, rc = _run_subprocess(
                        None
                    )
            finally:
                # Restore permissions briefly if needed so TemporaryDirectory cleanup removes 0400/0500 items cleanly
                for p in (agent_path, cfg_path, bundle_path):
                    if p.exists():
                        try:
                            os.chmod(p, 0o600)
                        except OSError:
                            pass
                for d in (agents_dir, tmpdir / ".opencode"):
                    if d.exists():
                        try:
                            os.chmod(d, 0o700)
                        except OSError:
                            pass

            if cancelled:
                raise OpenCodeExecutionError("OpenCode subprocess cancelled due to request timeout.")
            if timed_out:
                raise OpenCodeExecutionError(
                    f"OpenCode subprocess timed out after {self.timeout}s."
                )
            if overflowed:
                raise OpenCodeExecutionError(
                    f"OpenCode subprocess output exceeded {self.max_output_bytes} bytes."
                )

            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")

            if rc != 0:
                err_hint = stderr_text.strip() or stdout_text.strip() or f"exit_code={rc}"
                raise OpenCodeExecutionError(
                    f"OpenCode CLI failed ({rc}): {err_hint}"
                )

            return self._parse_opencode_jsonl(stdout_text, expected_agent=self.agent_name)

    def _collect_bounded_output(
        self,
        proc: subprocess.Popen,
        timeout: float,
        cancel_event: Optional[threading.Event] = None,
    ) -> Tuple[bytes, bytes, bool, bool, bool]:
        out_chunks: List[bytes] = []
        err_chunks: List[bytes] = []
        state = {"total": 0, "overflowed": False, "killed_overflow": False}
        lock = threading.Lock()
        limit = max(1024, self.max_output_bytes)

        def _drain(stream, bucket: List[bytes]) -> None:
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    kill_now = False
                    with lock:
                        if state["total"] + len(chunk) > limit:
                            state["overflowed"] = True
                            if not state["killed_overflow"]:
                                state["killed_overflow"] = True
                                kill_now = True
                        else:
                            state["total"] += len(chunk)
                            bucket.append(chunk)
                    if kill_now:
                        self._terminate_process_group(proc.pid)
                        break
                    if state["overflowed"]:
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
        deadline = time.monotonic() + max(0.2, float(timeout))

        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                self._terminate_process_group(proc.pid)
                break
            if state["overflowed"]:
                self._terminate_process_group(proc.pid)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                self._terminate_process_group(proc.pid)
                break
            time.sleep(min(0.05, remaining))

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

    @staticmethod
    def _parse_opencode_jsonl(
        stdout_text: str,
        expected_agent: Optional[str] = None,
    ) -> Tuple[str, int]:
        text_fragments: List[str] = []
        total_tokens = 0
        parsed_events = 0
        saw_step_start = False
        saw_step_finish = False

        for raw_line in stdout_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError as exc:
                raise OpenCodeExecutionError(f"Malformed OpenCode JSONL event: {exc}") from exc

            if not isinstance(evt, dict):
                raise OpenCodeExecutionError("Malformed OpenCode JSONL line: expected JSON object.")

            parsed_events += 1
            ev_type = str(evt.get("type") or "").strip().lower()
            part = evt.get("part") if isinstance(evt.get("part"), dict) else {}

            # Reject silent agent fallback if event carries an explicit differing agent identity
            ev_agent = evt.get("agent") or part.get("agent")
            if expected_agent and ev_agent and str(ev_agent) != expected_agent:
                raise OpenCodeExecutionError(
                    f"Unexpected agent fallback detected: expected '{expected_agent}', saw '{ev_agent}'."
                )

            if ev_type == "error":
                err_obj = evt.get("error") or part.get("error") or evt.get("message")
                if isinstance(err_obj, dict):
                    err_msg = err_obj.get("message") or err_obj.get("type") or "OpenCode error event"
                else:
                    err_msg = str(err_obj or "OpenCode error event")
                raise OpenCodeExecutionError(str(err_msg))

            if ev_type == "step_start":
                saw_step_start = True

            if ev_type == "tool_use":
                tool_name = str(part.get("tool") or evt.get("tool") or "").strip().lower()
                if tool_name in _DISALLOWED_TOOL_NAMES:
                    raise OpenCodeExecutionError(
                        f"Disallowed OpenCode tool invocation detected: '{tool_name}'"
                    )
                if tool_name and tool_name != "read":
                    raise OpenCodeExecutionError(
                        f"Unexpected OpenCode tool invocation rejected: '{tool_name}'"
                    )
                if tool_name == "read":
                    inp = part.get("input") or evt.get("input") or {}
                    target = str(
                        inp.get("filePath") or inp.get("path") or inp.get("file") or ""
                    )
                    if target and Path(target).name != "evidence_bundle.json":
                        raise OpenCodeExecutionError(
                            "OpenCode attempted to read a file other than evidence_bundle.json."
                        )

            if ev_type == "text":
                fragment = part.get("text") or evt.get("text") or evt.get("content") or ""
                if isinstance(fragment, str) and fragment:
                    text_fragments.append(fragment)

            if ev_type == "step_finish":
                saw_step_finish = True
                tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else evt.get("tokens")
                if isinstance(tokens, dict):
                    if isinstance(tokens.get("total"), int):
                        total_tokens += max(0, tokens["total"])
                    else:
                        total_tokens += max(
                            0,
                            int(tokens.get("input", 0) or 0) + int(tokens.get("output", 0) or 0),
                        )

        if parsed_events == 0:
            raise OpenCodeExecutionError("OpenCode produced zero JSONL events.")

        if saw_step_start and not saw_step_finish:
            raise OpenCodeExecutionError(
                "Incomplete OpenCode JSONL response stream: missing step_finish completion event."
            )

        combined = "".join(text_fragments).strip()
        if not combined:
            raise OpenCodeExecutionError("OpenCode event stream yielded empty assistant output.")

        if combined.startswith("```"):
            combined = re.sub(r"^```(?:json)?\s*", "", combined, flags=re.IGNORECASE)
            combined = re.sub(r"\s*```$", "", combined).strip()

        return combined, total_tokens
