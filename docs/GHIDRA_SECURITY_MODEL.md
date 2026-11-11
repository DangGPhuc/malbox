# MALBOX-AI — Ghidra Static Analysis Security Model

Processing untrusted malware binaries inside a complex disassembler and decompiler introduces parser, symlink, resource exhaustion, and data-exfiltration attack surfaces. [`ghidra_adapter.py`](../backend/app/services/static_analysis/ghidra_adapter.py) and [`ExportProgramFacts.java`](../ghidra_scripts/ExportProgramFacts.java) implement defense-in-depth fail-closed controls.

---

## 1. Strictly Non-Executing Analysis Guarantee

- Uploaded binaries are **never executed** by Malbox or Ghidra (`StaticAnalysisProvenance.binary_executed` and `FunctionMetadata.is_executed` are schema-locked to `Literal[False]`).
- `analyzeHeadless` is invoked with `-readOnly` and imports binaries strictly as dead data bytes into an ephemeral Ghidra project database.
- [`validate_sample_for_static_analysis()`](../backend/app/services/static_analysis/ghidra_adapter.py) validates every sample **before** launching Ghidra:
  1. Rejects empty paths and any `..` traversal components.
  2. Rejects symlinked files (`sample_path.is_symlink()`) and files inside symlinked quarantine directories (`sample_path.parent.is_symlink()`).
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

## 4. Resource Exhaustion, Caps & Timeout Enforcement

- **Single-Concurrency Queue**: [`StaticAnalysisWorkerManager`](../backend/app/services/static_analysis/worker.py) enforces `max_workers=1` and returns `HTTP 409 Conflict` if another job is active, plus recovers interrupted `QUEUED`/`RUNNING` DB records cleanly on server startup.
- **JVM & POSIX Rlimits**:
  - `GHIDRA_HEADLESS_MAXMEM` (default `1024m`), `-XX:MaxMetaspaceSize=256m`, `-XX:ReservedCodeCacheSize=128m`, `-max-cpu` (clamped `1..4`).
  - `RLIMIT_CPU` bound to `timeout_seconds`, `RLIMIT_CORE=0` (no core dumps of untrusted buffers), and `RLIMIT_FSIZE=256 MiB`.
- **Two-Layer Timeouts & Process-Group Kill**:
  - Ghidra receives `-analysisTimeoutPerFile` and `ExportProgramFacts.java` sets a per-function decompiler timeout via `DecompInterface`.
  - If wall-clock execution exceeds `MALBOX_GHIDRA_TIMEOUT_SECONDS`, `_terminate_process_group()` sends `SIGTERM` followed by `SIGKILL` to the entire OS process group (`os.killpg`) so headless JVMs and C++ `decompile` helpers cannot orphan.
- **Export & Console Truncation Guards**:
  - [`ExportProgramFacts.java`](../ghidra_scripts/ExportProgramFacts.java) writes using built-in string serialization (zero third-party JAR dependencies), truncates long strings/pseudocode, respects `maxFunctions`, `maxDecompileFunctions`, and byte budgets.
  - Adapter rejects `facts.json` larger than `MALBOX_GHIDRA_MAX_OUTPUT_BYTES` (`FAILED`) and drains stdout/stderr via a bounded reader.

---

## 5. Authorization & External AI Data Protection

- Triggering static analysis (`POST /api/v1/analyses/{id}/static-analysis`) requires `MALBOX_GHIDRA_ENABLED=true` and constant-time (`hmac.compare_digest`) validation of the `X-Reporting-Token` header against `MALBOX_REPORTING_AUTH_TOKEN`. Read-only `GET` endpoints never trigger Ghidra.
- **Pseudocode Exfiltration Prevention**: [`intelligence_bridge.py`](../backend/app/services/static_analysis/intelligence_bridge.py) sanitizes function names/APIs via `sanitize_untrusted_input_for_ai()` and sets `decompiled_omitted_for_external_ai=True`. Recovered pseudocode stays local on the backend and is never placed into `VerifiedEvidenceBundle` or forwarded automatically to external AI providers.

---

## 6. Known Limitations

1. **Parser Complexity**: While isolated in Bubblewrap without network access or write access outside `/work`, malformed PE headers still exercise Ghidra's Java/C++ loaders inside the sandbox.
2. **Packed / Obfuscated Binaries**: UPX-packed, virtualized, or heavily obfuscated executables may yield small function counts, thunk stubs, or `TIMED_OUT`/`PARTIAL` decompiler results without dynamic unpacking.
3. **Host-Specific Isolation**: Linux Bubblewrap requires unprivileged user namespaces on the host Linux kernel (verified on Kali host; CI runners without `bwrap`/Ghidra run the unit suite with mocked subprocess execution).
4. **Heuristic Signals Only**: `FunctionAnalysisFinding.rank_score` surfaces suspicious static API/string patterns for analyst triage and does not assert maliciousness or runtime execution.

