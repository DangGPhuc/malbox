# MALBOX-AI — OpenCode Restricted Reporting Adapter (Phase 2B.1)

## 1. Purpose and Scope

`OpenCodeReportProvider` ([`opencode_provider.py`](file:///home/kali/Documents/malbox/backend/app/ai/opencode_provider.py)) provides an **optional, opt-in, disabled-by-default** adapter for running an external OpenCode agent over a verified evidence bundle cleanly separated from the Malbox repository, quarantine directory, and user secrets.

- OpenCode is **not** required to install, bootstrap (`./malbox doctor`), start, or use Malbox in Replay Mode or direct LLM mode.
- **Pinned Tested Version**: `opencode v2.1.4` (`TESTED_OPENCODE_VERSION = "2.1.4"`).

---

## 2. Permission Model & Agent Policy (`.opencode/agents/report-analyst.md`)

The repository ships a restricted subagent specification at [`.opencode/agents/report-analyst.md`](file:///home/kali/Documents/malbox/.opencode/agents/report-analyst.md) using OpenCode v2 `permissions` rules (`action`, `resource`, `effect` where last matching rule wins):

1. Catch-all deny: `{ action: "*", resource: "*", effect: "deny" }`.
2. Explicit tool denials across `"*"`: `shell`, `bash`, `edit`, `write`, `patch`, `multiedit`, `external_directory`, `webfetch`, `websearch`, `subagent`, `task`, `skill`, `mcp`, `glob`, `grep`, `list`, `todowrite`.
3. Sole permitted read path: `{ action: "read", resource: "./evidence_bundle.json", effect: "allow" }`.

Additionally, the adapter writes a workspace-local `opencode.json` (`0o400`) inside the ephemeral temp directory repeating the same deny-by-default `permissions` policy before invoking `opencode run --standalone --format json --agent report-analyst --file evidence_bundle.json`.

> **Important Security Boundary Note**: Agent tool permissions are application-layer policy controls inside OpenCode and do **not** provide OS-level isolation by themselves. OS-level confinement is enforced by the adapter's subprocess boundary below.

---

## 3. Defense-in-Depth Subprocess Isolation

`OpenCodeReportProvider` enforces the following controls on every invocation:

1. **POSIX Capability Preflight (`check_posix_isolation_support`)**: Fails closed cleanly (falling back to deterministic offline reporting without spawning a subprocess) if POSIX process groups (`os.killpg`/`os.getpgid`) or `resource` limits are unavailable.
2. **Ephemeral `0o700` Temporary Workspace**:
   - Created via `tempfile.TemporaryDirectory(prefix="malbox_oc_")` (`0o700`), verified distinct from `WORKSPACE_ROOT`, `QUARANTINE_DIR`, `DATA_DIR`, and `Path.home()`.
   - Populated solely with read-only (`0o400`) `.opencode/agents/report-analyst.md`, locked-down `opencode.json`, and `evidence_bundle.json` (containing only the sanitized, bounded `VerifiedEvidenceBundle` — never raw sample binaries).
   - Deleted deterministically on completion or failure.
3. **Allowlisted Subprocess Environment**:
   - Built from an empty dict (`shell=False`, `stdin=subprocess.DEVNULL`), exposing only `PATH`, isolated `HOME`/`TMPDIR`/`XDG_*` pointing inside the temp workspace, `LANG`/`LC_ALL`, `NO_COLOR`, and (when explicitly configured via `MALBOX_OPENCODE_PROVIDER_API_KEY`) a single non-`MALBOX_*` model credential env var (`MALBOX_OPENCODE_PROVIDER_ENV_NAME`).
   - Host secrets (`MALBOX_OPERATOR_TOKEN`, `MALBOX_REPORTING_AUTH_TOKEN`, `MALBOX_SECRET_KEY`, `MALBOX_CAPE_API_TOKEN`, cloud keys, GitHub tokens, and arbitrary host `os.environ` vars) are never inherited.
4. **Resource Limits, Bounded Stream Capture & PGID Termination**:
   - Child runs in its own session (`start_new_session=True`) with POSIX `RLIMIT_CPU`, `RLIMIT_CORE=0`, and `RLIMIT_FSIZE=1 MiB`.
   - Incremental `stdout`/`stderr` reader terminates the entire process group (`os.killpg` `SIGTERM` -> `SIGKILL`) immediately if output exceeds `MALBOX_OPENCODE_MAX_OUTPUT_BYTES` (default `262144` bytes) or wall-clock `MALBOX_OPENCODE_TIMEOUT_SECONDS` (default `30s`) elapses.
5. **Event-Stream & Output Validation**:
   - `_parse_opencode_jsonl()` validates NDJSON lines, blocks any unexpected or disallowed `tool_use` event (including any `read` outside `evidence_bundle.json`), extracts text and token counts, passes the JSON payload through `EvidenceValidator`, and redacts secrets/paths via `redact_sensitive_text()`.
   - Any missing binary, policy violation, timeout, oversized stream, malformed JSONL, or schema/authority conflict falls back to deterministic `MockLLMProvider` output labeled `mode="mock_fallback"`, `provider="mock_fallback"`, `fallback_used=True`.

---

## 4. Configuration Flags

All settings default to disabled/offline-safe:

```env
MALBOX_OPENCODE_ENABLED=false
MALBOX_REPORTING_EXTERNAL_AI_CONSENT=false
MALBOX_OPENCODE_BIN=opencode
MALBOX_OPENCODE_AGENT_NAME=report-analyst
MALBOX_OPENCODE_MODEL=
MALBOX_OPENCODE_TIMEOUT_SECONDS=30.0
MALBOX_OPENCODE_MAX_OUTPUT_BYTES=262144
MALBOX_OPENCODE_MAX_CPU_SECONDS=25
MALBOX_OPENCODE_PROVIDER_API_KEY=
MALBOX_OPENCODE_PROVIDER_ENV_NAME=OPENAI_API_KEY
```

