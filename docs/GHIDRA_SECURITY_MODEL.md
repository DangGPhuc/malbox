# MALBOX-AI — Ghidra Static Analysis Security Model

Processing untrusted malware binaries inside a complex disassembler and decompiler introduces parser, symlink, resource exhaustion, and data-exfiltration attack surfaces. [`ghidra_adapter.py`](../backend/app/services/static_analysis/ghidra_adapter.py) and [`ExportProgramFacts.java`](../ghidra_scripts/ExportProgramFacts.java) implement defense-in-depth fail-closed controls.

---

## 1. Strictly Non-Executing Analysis Guarantee

- Uploaded binaries are **never executed** by Malbox or Ghidra (`StaticAnalysisProvenance.binary_executed` and `FunctionMetadata.is_executed` are schema-locked to `Literal[False]`).
- `analyzeHeadless` is invoked with `-readOnly` and imports binaries strictly as dead data bytes into an ephemeral Ghidra project database.
- [`validate_sample_for_static_analysis()`](../backend/app/services/static_analysis/ghidra_adapter.py) and [`has_symlink_ancestor()`](../backend/app/services/static_analysis/containment.py) validate every sample and workspace path **before** launching Ghidra:
  1. Rejects empty paths and any `..` traversal components.
  2. Rejects symlinked files, symlinked parent directories, and symlinked ancestor directories along sample, workspace, and configured `GHIDRA_HOME` paths.
  3. Rejects empty files and binaries larger than `MALBOX_GHIDRA_MAX_SAMPLE_BYTES` (default `16 MiB`).
  4. Re-computes `SHA-256` byte-by-byte and rejects any hash mismatch against `Sample.sha256`.
  5. Validates the binary header via `parse_pe_metadata()` so non-PE files fail closed without launching a JVM.

---

## 2. Fail-Closed Bubblewrap OS Isolation

Every live Ghidra subprocess MUST run inside Linux Bubblewrap (`bwrap`). If `check_os_sandbox_support("bwrap")` fails, static analysis fails closed (`status="UNAVAILABLE"`) rather than falling back to unconfined host execution.

Containment flags applied in `build_ghidra_sandbox_command()`:
- `--unshare-all`: Unshares user, IPC, PID, UTS, cgroup, and **network namespaces** (complete network airgap).
- `--die-with-parent` & `--new-session` & `start_new_session=True`: Ensures sandbox children cannot outlive the backend or escape process-group cleanup.
- `--cap-drop ALL`: Drops all Linux capabilities inside the sandbox.
- `--clearenv`: Clears host environment variables (preventing secret leakage from `.env`, API tokens, or shell credentials).
- **Minimal Read-Only Mounts**: Only OS libraries (`/usr`, `/lib`, `/lib64`, `/bin`, `/etc/alternatives`, `/etc/java*`), Ghidra installation, `/ghidra_scripts`, and the single sample bound read-only at `/input/sample.bin`. Host repository source (`backend/`, `frontend/`), `.env`, SQLite DB, and user `$HOME` are **never** mounted.
- **Writable Isolation**: Only the per-job directory at `/work` (plus bounded 64 MiB `--tmpfs /tmp`) is writable.

---

## 3. Project Workspace Isolation & Reuse Prevention

Ghidra ignores dot-prefixed project directories and risks cross-contaminating analyses if project folders are reused:
- [`prepare_isolated_project_workspace()`](../backend/app/services/static_analysis/ghidra_adapter.py) enforces `0700` permissions on `MALBOX_GHIDRA_WORKSPACE_ROOT` and per-job workspace `ghidra_job_<job_id>`, rejecting symlinks, `..` traversal, and hidden `.`-prefixed path segments.
- A manifest (`malbox_project_manifest.json`, `0600`) binds each workspace to its `job_id` and `sample_sha256`. Existing directories lacking a manifest or matching a different SHA-256 raise `GhidraIsolationError`.
- In addition to `-deleteProject` passed to `analyzeHeadless`, the adapter removes `job_dir` unconditionally inside a `finally` block (including after failures or timeouts).

---

## 4. Resource Exhaustion, Process-Tree Memory Budget & Termination Controls

- **Single-Concurrency Queue & Multi-Worker Lock**: [`StaticAnalysisWorkerManager`](../backend/app/services/static_analysis/worker.py) enforces `max_workers=1`, rejects concurrent triggers with `HTTP 409 Conflict`, rejects failed executor submissions immediately (never leaving jobs `QUEUED`), recovers interrupted rows on startup, cancels active Ghidra subprocesses on backend shutdown (`stop()`), and coordinates across multi-worker processes sharing `GHIDRA_WORKSPACE_ROOT` via non-blocking POSIX `fcntl.flock` (`malbox_static_worker.lock`). Single-worker Uvicorn (`--workers 1`) remains the supported production deployment for Kali VMs.
- **Process-Tree Cgroup v2 Memory Containment & VM Headroom Preflight** ([`containment.py`](../backend/app/services/static_analysis/containment.py)):
  - Before invoking Java, `check_vm_memory_headroom()` reads `/proc/meminfo` (`MemAvailable`) and fails closed (`UNAVAILABLE`) if available host RAM falls below `MALBOX_GHIDRA_MIN_AVAILABLE_MEMORY_MB` (default `1280 MiB`).
  - Rather than relying on ineffective `RLIMIT_RSS` or broken HotSpot `RLIMIT_AS`, Ghidra runs wrapped in unprivileged `systemd-run --user --scope` cgroup v2 controls (`MemoryHigh`, `MemoryMax=1280M`, `MemorySwapMax=0`, `CPUQuota=100%`, `TasksMax=128`, `OOMPolicy=kill`) bounding the **entire process tree** (JVM heap + Metaspace `192m` + CodeCache `96m` + native C++ `decompile` children) without `sudo` or privilege escalation.
  - When `MALBOX_GHIDRA_REQUIRE_CGROUP_MEMORY_LIMIT=true` (default), unsupported hosts fail closed (`UNAVAILABLE`) rather than running unconfined JVMs.
- **JVM, POSIX Rlimits & Immediate Stream/Exit Enforcement**:
  - Conservative heap default `MALBOX_GHIDRA_MAX_HEAP_MB=512` (`GHIDRA_HEADLESS_MAXMEM=512m`) clamped inside `GHIDRA_MAX_MEMORY_MB`, `-max-cpu` (`1..4`), `RLIMIT_CPU`, `RLIMIT_CORE=0`, and `RLIMIT_FSIZE=256 MiB`.
  - **Exit-Code Integrity**: Nonzero subprocess return codes NEVER produce `COMPLETED` and NEVER let `facts.json` status override process failure; partial exports (`status="PARTIAL"`) are accepted only from `rc == 0` runs that preserve verified schemas and truncation metadata.
  - **Immediate Console Overflow Termination**: `_collect_bounded_output()` monitors `MALBOX_GHIDRA_MAX_STREAM_BYTES` (`256 KiB`), immediately wakes the monitor on overflow, signals **only** the verified owned child PGID (`pgid == proc.pid != os.getpgrp()`) with `SIGTERM`, waits a bounded grace period before `SIGKILL` escalation, reaps cleanly, closes pipes so reader threads cannot block, tears down transient systemd scope units, and returns `FAILED`.
- **Persistence Byte Gate**: `prepare_result_for_persistence()` strictly re-validates `StaticAnalysisResult` schemas and bounds JSON payload size (`MALBOX_GHIDRA_MAX_PERSISTED_RESULT_BYTES`, `1 MiB`) prior to SQLite writes.

---

## 5. Authorization & External AI Data Protection

- Triggering static analysis (`POST /api/v1/analyses/{id}/static-analysis`) requires `MALBOX_GHIDRA_ENABLED=true` and constant-time (`hmac.compare_digest`) validation of the `X-Reporting-Token` header against `MALBOX_REPORTING_AUTH_TOKEN`. Read-only `GET` endpoints never trigger Ghidra.
- **Pseudocode Exfiltration Prevention**: [`intelligence_bridge.py`](../backend/app/services/static_analysis/intelligence_bridge.py) sanitizes function names/APIs via `sanitize_untrusted_input_for_ai()` and sets `decompiled_omitted_for_external_ai=True`. Recovered pseudocode stays local on the backend and is never placed into `VerifiedEvidenceBundle` or forwarded automatically to external AI providers.

---

## 6. Known Limitations

1. **Parser Complexity**: While isolated in Bubblewrap without network access or write access outside `/work`, malformed PE headers still exercise Ghidra's Java/C++ loaders inside the sandbox.
2. **Packed / Obfuscated Binaries**: UPX-packed, virtualized, or heavily obfuscated executables may yield small function counts, thunk stubs, or `TIMED_OUT`/`PARTIAL` decompiler results without dynamic unpacking.
3. **Host-Specific Isolation**: Linux Bubblewrap requires unprivileged user namespaces and `systemd-run --user` requires a delegated cgroup v2 `memory` controller (verified on Kali Linux host; CI runners and headless containers lacking user cgroups fail closed when `MALBOX_GHIDRA_REQUIRE_CGROUP_MEMORY_LIMIT=true` and execute mocked unit tests).
4. **Single Uvicorn Worker Model**: In-process queue accounting assumes Uvicorn `--workers 1`; multi-worker deployments must still respect the shared workspace file lock (`HTTP 409`/`FAILED` on contention).
5. **Heuristic Signals Only**: `FunctionAnalysisFinding.rank_score` surfaces suspicious static API/string patterns for analyst triage and does not assert maliciousness or runtime execution.

