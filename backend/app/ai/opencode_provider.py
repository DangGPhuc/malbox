import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.ai.intelligence_helper import build_deterministic_proposed_intelligence
from app.ai.mock_provider import MockLLMProvider
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
mode: subagent
permissions:
  - action: "*"
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


def check_posix_isolation_support() -> Tuple[bool, Optional[str]]:
    """
    Verifies OS primitives required for isolated OpenCode invocation:
    POSIX process groups (killpg), strict directory mode enforcement (0700),
    and resource limits module availability.
    """
    if os.name != "posix":
        return False, "POSIX OS isolation primitives (process groups, 0700 workspace, rlimits) are required."
    if not hasattr(os, "killpg") or not hasattr(os, "getpgid"):
        return False, "Process group isolation (os.killpg/getpgid) is unavailable."
    try:
        import resource  # noqa: F401
    except ImportError:
        return False, "POSIX resource limit controls are unavailable."
    return True, None


class OpenCodeReportProvider(LLMProvider):
    """
    Restricted, opt-in OpenCode CLI reporting adapter (tested with OpenCode v2.1.4).
    Executes inside a locked-down temporary directory containing ONLY the agent spec
    and sanitized VerifiedEvidenceBundle JSON, with stripped env and hard resource bounds.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        external_consent: Optional[bool] = None,
        binary: Optional[str] = None,
        agent_name: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
        max_cpu_seconds: Optional[int] = None,
        provider_api_key: Optional[str] = None,
        provider_env_name: Optional[str] = None,
    ) -> None:
        self.enabled = settings.OPENCODE_ENABLED if enabled is None else enabled
        self.external_consent = (
            settings.REPORTING_EXTERNAL_AI_CONSENT if external_consent is None else external_consent
        )
        self.binary = binary if binary is not None else settings.OPENCODE_BIN
        self.agent_name = agent_name if agent_name is not None else settings.OPENCODE_AGENT_NAME
        self.model = model if model is not None else settings.OPENCODE_MODEL
        self.timeout = float(timeout if timeout is not None else settings.OPENCODE_TIMEOUT_SECONDS)
        self.max_output_bytes = int(
            max_output_bytes if max_output_bytes is not None else settings.OPENCODE_MAX_OUTPUT_BYTES
        )
        self.max_cpu_seconds = int(
            max_cpu_seconds if max_cpu_seconds is not None else settings.OPENCODE_MAX_CPU_SECONDS
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
    ) -> IntelligenceReport:
        now_iso = datetime.now(timezone.utc).isoformat()
        secrets_to_redact = self._collect_secrets_for_redaction()
        model_label = self.model or f"opencode:{self.agent_name}"

        try:
            if not self.enabled:
                raise OpenCodeExecutionError("OpenCode adapter is disabled by configuration.")
            if not self.external_consent:
                raise OpenCodeExecutionError(
                    "External evidence transmission consent is not enabled for OpenCode."
                )

            iso_ok, iso_reason = check_posix_isolation_support()
            if not iso_ok:
                raise OpenCodeExecutionError(iso_reason or "OS isolation requirements unmet.")

            resolved_bin = self._resolve_binary(self.binary)
            if not resolved_bin:
                raise OpenCodeExecutionError("OpenCode CLI executable could not be located.")

            content, tokens_used = self._execute_isolated(
                resolved_bin=resolved_bin,
                bundle=bundle,
                rules_text=rules_text,
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
                "tested_opencode_version": TESTED_OPENCODE_VERSION,
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
                "tested_opencode_version": TESTED_OPENCODE_VERSION,
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
        if not bin_spec or ".." in bin_spec:
            return None
        candidate = Path(bin_spec)
        if candidate.is_absolute():
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
            return None
        if "/" in bin_spec or "\\" in bin_spec:
            return None
        found = shutil.which(bin_spec)
        if not found:
            home_local = Path.home() / ".opencode" / "bin" / bin_spec
            if home_local.is_file() and os.access(home_local, os.X_OK):
                return str(home_local)
        return found

    def _load_agent_markdown(self) -> str:
        repo_root = Path(__file__).resolve().parents[3]
        spec_path = repo_root / ".opencode" / "agents" / "report-analyst.md"
        if spec_path.is_file():
            try:
                content = spec_path.read_text(encoding="utf-8")
                if content.strip():
                    return content
            except OSError:
                pass
        return _FALLBACK_AGENT_SPEC

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
        cfg: Dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "permissions": permissions,
        }
        return cfg

    def _build_sanitized_env(self, tmpdir: Path, resolved_bin: str) -> Dict[str, str]:
        bin_dir = str(Path(resolved_bin).resolve().parent)
        safe_path = f"{bin_dir}:/usr/local/bin:/usr/bin:/bin"
        env: Dict[str, str] = {
            "PATH": safe_path,
            "HOME": str(tmpdir),
            "TMPDIR": str(tmpdir / "tmp"),
            "XDG_CONFIG_HOME": str(tmpdir / "xdg_config"),
            "XDG_DATA_HOME": str(tmpdir / "xdg_data"),
            "XDG_STATE_HOME": str(tmpdir / "xdg_state"),
            "XDG_CACHE_HOME": str(tmpdir / "xdg_cache"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
        }
        key = self.provider_api_key
        env_name = (self.provider_env_name or "").strip()
        if (
            key
            and env_name
            and re.fullmatch(r"[A-Z][A-Z0-9_]{2,64}", env_name)
            and not env_name.startswith("MALBOX_")
        ):
            env[env_name] = key
        return env

    def _make_rlimit_preexec(self):
        cpu_limit = max(2, self.max_cpu_seconds)

        def _apply_limits() -> None:
            import resource

            try:
                _, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)
                cap_cpu = cpu_limit if hard_cpu == resource.RLIM_INFINITY else min(cpu_limit, hard_cpu)
                resource.setrlimit(resource.RLIMIT_CPU, (cap_cpu, cap_cpu))
            except (ValueError, OSError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (ValueError, OSError):
                pass
            try:
                _, hard_fsize = resource.getrlimit(resource.RLIMIT_FSIZE)
                max_fsize = 1048576
                cap_fsize = max_fsize if hard_fsize == resource.RLIM_INFINITY else min(max_fsize, hard_fsize)
                resource.setrlimit(resource.RLIMIT_FSIZE, (cap_fsize, cap_fsize))
            except (ValueError, OSError):
                pass

        return _apply_limits

    def _execute_isolated(
        self,
        resolved_bin: str,
        bundle: VerifiedEvidenceBundle,
        rules_text: Optional[str],
    ) -> Tuple[str, int]:
        with tempfile.TemporaryDirectory(prefix="malbox_oc_") as raw_tmp:
            tmpdir = Path(raw_tmp)
            os.chmod(tmpdir, 0o700)

            for sub in ("tmp", "xdg_config", "xdg_data", "xdg_state", "xdg_cache"):
                d = tmpdir / sub
                d.mkdir(parents=True, exist_ok=True)
                os.chmod(d, 0o700)

            agents_dir = tmpdir / ".opencode" / "agents"
            agents_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(tmpdir / ".opencode", 0o700)
            os.chmod(agents_dir, 0o700)

            agent_path = agents_dir / f"{self.agent_name}.md"
            agent_path.write_text(self._load_agent_markdown(), encoding="utf-8")
            os.chmod(agent_path, 0o400)

            cfg_path = tmpdir / "opencode.json"
            cfg_path.write_text(json.dumps(self._build_locked_opencode_config(), indent=2), encoding="utf-8")
            os.chmod(cfg_path, 0o400)

            bundle_path = tmpdir / "evidence_bundle.json"
            bundle_path.write_text(bundle.model_dump_json(), encoding="utf-8")
            os.chmod(bundle_path, 0o400)

            # Verify no workspace directory overlap with Malbox repository or quarantine
            resolved_tmp = tmpdir.resolve()
            for forbidden in (
                Path(settings.WORKSPACE_ROOT).resolve(),
                Path(settings.QUARANTINE_DIR).resolve(),
                Path(settings.DATA_DIR).resolve(),
                Path.home().resolve(),
            ):
                if resolved_tmp == forbidden:
                    raise OpenCodeExecutionError("Temporary workspace resolved to forbidden directory.")

            safe_env = self._build_sanitized_env(tmpdir, resolved_bin)

            effective_rules = rules_text or load_report_analyst_rules()
            prompt_msg = (
                "Analyze ONLY ./evidence_bundle.json and follow these non-executable rules.\n"
                "Return ONLY a single valid JSON object matching AIProposedIntelligence.\n\n"
                + effective_rules[:3000]
            )

            cmd = [
                resolved_bin,
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
                cmd.extend(["--model", self.model])
            cmd.append(prompt_msg)

            proc = subprocess.Popen(
                cmd,
                cwd=str(resolved_tmp),
                env=safe_env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=self._make_rlimit_preexec(),
            )

            stdout_bytes, stderr_bytes, overflowed, timed_out = self._collect_bounded_output(proc)
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

            if proc.returncode != 0:
                err_hint = stderr_text.strip() or stdout_text.strip() or f"exit_code={proc.returncode}"
                raise OpenCodeExecutionError(
                    f"OpenCode CLI failed ({proc.returncode}): {err_hint}"
                )

            return self._parse_opencode_jsonl(stdout_text)

    def _collect_bounded_output(
        self, proc: subprocess.Popen
    ) -> Tuple[bytes, bytes, bool, bool]:
        out_chunks: List[bytes] = []
        err_chunks: List[bytes] = []
        state = {"total": 0, "overflowed": False}
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
                    with lock:
                        if state["total"] + len(chunk) > limit:
                            state["overflowed"] = True
                            break
                        state["total"] += len(chunk)
                        bucket.append(chunk)
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
        try:
            proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_group(proc.pid)
        finally:
            if state["overflowed"]:
                self._terminate_process_group(proc.pid)

        t_out.join(timeout=1.5)
        t_err.join(timeout=1.5)
        if proc.poll() is None:
            self._terminate_process_group(proc.pid)
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass

        return b"".join(out_chunks), b"".join(err_chunks), state["overflowed"], timed_out

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
    def _parse_opencode_jsonl(stdout_text: str) -> Tuple[str, int]:
        text_fragments: List[str] = []
        total_tokens = 0
        parsed_events = 0

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

            if ev_type == "error":
                err_msg = evt.get("error") or part.get("error") or evt.get("message") or "OpenCode error event"
                raise OpenCodeExecutionError(str(err_msg))

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

        combined = "".join(text_fragments).strip()
        if not combined:
            raise OpenCodeExecutionError("OpenCode event stream yielded empty assistant output.")

        # Strip optional markdown code fences if emitted around final JSON
        if combined.startswith("```"):
            combined = re.sub(r"^```(?:json)?\s*", "", combined, flags=re.IGNORECASE)
            combined = re.sub(r"\s*```$", "", combined).strip()

        return combined, total_tokens
