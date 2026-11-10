# MALBOX-AI — OpenCode Restricted Reporting Adapter (Phase 2B.1)

## 1. Purpose and Scope

`OpenCodeReportProvider` ([`opencode_provider.py`](file:///home/kali/Documents/malbox/backend/app/ai/opencode_provider.py)) provides an **optional, opt-in, disabled-by-default** adapter for running an external OpenCode CLI agent over a verified evidence bundle isolated from the Malbox repository, quarantine directory, user home directory, and host secrets.

- OpenCode is **not** required to install, bootstrap (`./malbox doctor`), start, or use Malbox in Replay Mode, deterministic reporting, or direct HTTP LLM mode.
- **Tested Baseline & Dynamic Version Check**: Verified against `opencode v2.1.4` (`TESTED_OPENCODE_VERSION = "2.1.4"`, `MIN_SUPPORTED_OPENCODE_VERSION = (2, 0, 0)`, `MAX_EXCLUSIVE_OPENCODE_VERSION = (3, 0, 0)`). Every execution dynamically validates `opencode --version` inside Bubblewrap (`parse_opencode_semver()`) and fails closed on unparseable output or incompatible versions (`< 2.0.0` or `>= 3.0.0`).

---

## 2. Primary Agent Execution Mode & Permission Policy

The repository defines the restricted analyst agent at [`.opencode/agents/report-analyst.md`](file:///home/kali/Documents/malbox/.opencode/agents/report-analyst.md):

1. **Primary Mode (`mode: primary`)**: Enables direct `opencode run --standalone --format json --agent report-analyst --file evidence_bundle.json` execution cleanly without falling back to a default privileged agent.
2. **Built-In Privileged Agents Disabled**: Inside the ephemeral workspace, `_build_locked_opencode_config()` writes `opencode.json` (`0o400`) setting `"default_agent": "report-analyst"` and `"disable": true` for `"build"`, `"plan"`, `"general"`, and `"explore"`. Attempts to invoke `--agent build` are rejected by the CLI (`Agent not found`).
3. **Deny-by-Default Tool Permissions (`permissions` list)**:
   - Catch-all deny: `{ action: "*", resource: "*", effect: "deny" }`.
   - Explicit tool denials across `"*"`: `shell`, `bash`, `edit`, `write`, `patch`, `multiedit`, `external_directory`, `webfetch`, `websearch`, `subagent`, `task`, `skill`, `mcp`, `glob`, `grep`, `list`, `todowrite`.
   - Sole permitted read path: `{ action: "read", resource: "./evidence_bundle.json", effect: "allow" }`.

> **Defense-in-Depth Note**: Agent markdown rules and `opencode.json` permissions constrain OpenCode's own tool loop at the application layer, while **Bubblewrap (`bwrap`)** enforces kernel-level filesystem, namespace, capability, environment, and network isolation independently.

---

## 3. Genuine OS Security Boundary (`bwrap` + `ApprovedProviderProxy`)

Implemented in [`opencode_sandbox.py`](file:///home/kali/Documents/malbox/backend/app/ai/opencode_sandbox.py):

1. **Fail-Closed OS Sandbox Preflight (`check_os_sandbox_support`)**:
   - Checks POSIX Linux platform, `geteuid() == getuid()` (refuses SUID privilege escalation mismatch), executable `bwrap`, `os.killpg`/`os.getpgid`, POSIX `resource` module, and runs an actual `bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL ... /bin/true` probe.
   - If Bubblewrap or unprivileged user namespaces are unavailable, `OpenCodeReportProvider` fails closed without spawning `opencode` (falling back deterministically when offline fallback applies, or failing health readiness). Replay Mode, deterministic reporting, and direct HTTP LLM mode remain unaffected.
2. **Minimal Namespace & Filesystem Isolation (`build_bwrap_command`)**:
   - Flags: `--unshare-all`, `--die-with-parent`, `--new-session`, `--cap-drop ALL`, `--clearenv`, `--chdir /sandbox`, and explicit `"--"` before inner binary arguments.
   - Mounts only read-only system libs (`/usr`, `/lib`, `/lib64`, `/bin`), minimal selective `/etc` trust/resolver files (`ld.so.*`, `ssl`, `ca-certificates`, `pki`, `nsswitch.conf`, `localtime`), `--proc /proc`, `--dev /dev`, and size-bounded `--tmpfs` (`/tmp` and `/sandbox/.xdg` bounded by `OPENCODE_MAX_SANDBOX_TMPFS_BYTES = 16 MiB`).
   - Mounts `opencode` executable read-only (`--ro-bind`) at `/opt/opencode/opencode` and workspace artifacts read-only at `/sandbox/evidence_bundle.json`, `/sandbox/opencode.json`, and `/sandbox/.opencode`.
   - The Malbox repository (`WORKSPACE_ROOT`), `QUARANTINE_DIR`, `DATA_DIR`, user `$HOME`, and host `/etc` secrets are **never mounted**.
3. **Egress Network Control (`ApprovedProviderProxy`)**:
   - Default (`MALBOX_OPENCODE_ALLOW_NETWORK=false`): full network namespace isolation (`--unshare-net` with zero egress sockets).
   - Approved provider egress (`MALBOX_OPENCODE_ALLOW_NETWORK=true`): `parse_approved_provider_target()` validates `MALBOX_OPENCODE_ALLOWED_PROVIDER_URL`. `ApprovedProviderProxy` binds a host Unix domain socket (`0o600`) mounted inside the still-`--unshare-net` sandbox and exposes a local loopback HTTP proxy forwarder that relays **only** HTTP/CONNECT destinations matching the exact approved `(host, port)`, returning `403 Forbidden` for all other destinations.
4. **POSIX Resource Limits, Cancel Propagation & Process-Group Teardown**:
   - `preexec_fn` applies `RLIMIT_CPU` (`OPENCODE_MAX_CPU_SECONDS`), `RLIMIT_AS` (`OPENCODE_MAX_MEMORY_MB`), `RLIMIT_DATA` (`OPENCODE_MAX_DATA_MB`), `RLIMIT_CORE=0`, and `RLIMIT_FSIZE=1 MiB` cleanly inside a new session (`start_new_session=True`).
   - `_collect_bounded_output()` monitors `cancel_event`, output size limit (`OPENCODE_MAX_OUTPUT_BYTES`), and wall-clock timeout (`OPENCODE_TIMEOUT_SECONDS`), immediately terminating the process group (`os.killpg` `SIGTERM` -> `SIGKILL`).
   - **Scope / Host Limitation**: Environments where unprivileged Linux user namespaces are disabled by kernel/seccomp policy cannot run OpenCode and fail closed cleanly. Host environments without `systemd` user scopes rely on `bwrap` namespace isolation, `--die-with-parent`, POSIX `RLIMIT_*`, bounded tmpfs, and `os.killpg` rather than systemd cgroups.
5. **Strict JSONL & Authority Validation (`_parse_opencode_jsonl`)**:
   - Rejects OpenCode v2 error objects (`event["error"]`), incomplete streams (`step_start` without `step_finish`), unexpected `agent` identifiers, disallowed `tool_use` events, and out-of-workspace `read` paths; validates proposed claims strictly through `EvidenceValidator`; redacts sensitive patterns via `redact_sensitive_text()`.

---

## 4. Configuration Flags

All settings default to disabled / offline / airgapped:

```env
MALBOX_OPENCODE_ENABLED=false
MALBOX_REPORTING_EXTERNAL_AI_CONSENT=false
MALBOX_OPENCODE_BIN=opencode
MALBOX_OPENCODE_SANDBOX_BIN=bwrap
MALBOX_OPENCODE_AGENT_NAME=report-analyst
MALBOX_OPENCODE_MODEL=
MALBOX_OPENCODE_ALLOW_NETWORK=false
MALBOX_OPENCODE_ALLOWED_PROVIDER_URL=
MALBOX_OPENCODE_TIMEOUT_SECONDS=30.0
MALBOX_OPENCODE_MAX_OUTPUT_BYTES=262144
MALBOX_OPENCODE_MAX_CPU_SECONDS=25
MALBOX_OPENCODE_MAX_MEMORY_MB=2048
MALBOX_OPENCODE_MAX_DATA_MB=512
MALBOX_OPENCODE_MAX_SANDBOX_TMPFS_BYTES=16777216
MALBOX_OPENCODE_PROVIDER_API_KEY=
MALBOX_OPENCODE_PROVIDER_ENV_NAME=OPENAI_API_KEY
```
