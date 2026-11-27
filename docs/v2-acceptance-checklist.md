# MalBox v2.0 Controlled 3-VM Acceptance Checklist

Use this checklist on your physical / virtualized 3-VM lab (**Machine 1: Kali**, **Machine 2: REMnux**, **Machine 3: REMWin Windows 10 x64** or Windows 11 x64) after pulling `develop/malbox-v2` and before merging into `main`.

> **Safety Reminder:** Perform all online tool installations first, then disconnect VMs from any bridged/NAT adapter onto `malbox-net1` (`10.10.10.0/24`) and `malbox-net2` (`10.10.20.0/24`) **before** taking the `CLEAN` snapshot or executing any test sample.

---

## 1. Pre-Flight Network & Environment Checks

- [ ] Verify Machine 1 IP `10.10.10.10` (`malbox-net1` only, no default Internet gateway).
- [ ] Verify Machine 2 NIC1 `10.10.10.20` (`malbox-net1`) & NIC2 `10.10.20.20` (`malbox-net2`), and confirm `sysctl net.ipv4.ip_forward` equals `0`.
- [ ] Verify Machine 3 IP `10.10.20.30` (`malbox-net2` only), confirming `workspace/.dirty_state` is absent before snapshot creation.
- [ ] On Machine 3 (`machine3-sandbox`) in a PowerShell window where local scripts are permitted, run:
  ```powershell
  .\setup.ps1 -CheckOnly
  ```
  *(Note: `SNAPSHOT_STATE=NO_DIRTY_MARKER` is reported here in `setup_report.json`; do not disable Windows security policies.)*
  Confirm `LOCAL_READINESS` is `READY` (or documented `LIMITED` only for intentionally omitted optional components like `WinPmem`, `Detect It Easy`, `Volatility 3`), `Ghidra` + `JDK` compatibility passes with `GhidraExport.java` (`runtime_verified` / functional export stays `PENDING` until a live sample run), and `MalBox MCP` registers all 16 tools.
- [ ] Take / verify the `CLEAN` snapshot on Machine 3.

---

## 2. Service Startup & Cross-VM Control Path

- [ ] On Machine 3, launch Sandbox listener via wrapper:
  ```cmd
  cd C:\path\to\malbox\machine3-sandbox
  run_sandbox.bat
  ```
  Confirm `[SANDBOX] Server started on 0.0.0.0:8001.` and `[SANDBOX] Waiting for sample...` appear on stdout.
- [ ] On Machine 2, launch Gateway relay via wrapper:
  ```bash
  cd ~/malbox/machine2-gateway
  ./run_gateway.sh
  ```
  Run `bash setup.sh --check-only` on Machine 2 and Machine 1; confirm Machine 1 reports `NETWORK_READINESS=CONTROL_PATH_READY`.

---

## 3. End-to-End Harmless Sample Run

Submit a **harmless** PE test binary (e.g., compiled benign Win32 console binary or safe Sysinternals test binary):

- [ ] On Machine 1 (`machine1-client`), run:
  ```bash
  source .venv/bin/activate
  doctor /path/to/harmless_sample.exe
  # Or with `--verbose` to log live Sandbox stages on Machine 1
  ```
- [ ] Confirm normal terminal flow:
  - Machine 1 prints `[CLIENT] Checking gateway connection...`, `[OK] Gateway connected.`, `[CLIENT] Uploading sample...`, `[OK] Sample submitted (Job ID: ...).`, `[CLIENT] Waiting for analysis...`.
  - Under `--verbose` (or `/jobs/<id>` polling), stages progress through `preparing_workspace -> static_analysis -> ghidra_analysis -> awaiting_local_approval -> dynamic_observation -> finalizing_evidence -> packaging_evidence -> returning_evidence`.
- [ ] On Machine 3 terminal, confirm `[SANDBOX] Awaiting local analysis approval...` and the approval prompt `[SANDBOX] Approve dynamic execution for ... [y/N]:` appear (when `require_local_approval: true`), approve locally (`y`), and confirm `[SANDBOX] Dynamic observation started.` and `[SANDBOX] Observation completed.` finish cleanly.
- [ ] On Machine 1, confirm `[OK] Evidence received.`, `[OK] Saved to ...`, `[CLIENT] Analysis completed.`, and that evidence extracts cleanly under `evidence/<job_id>/` (mode `0o750` on POSIX) without path-traversal or manifest verification errors.

---

## 4. Artifact Verification (v2 Features)

Inspect extracted `evidence/<job_id>/`:

- [ ] `static/hashes.json`: contains `file_identification` (`declared_extension`, `format_family`, `format_mismatch`, `supported_static_capabilities`).
- [ ] `static/yara.json`: lists `rule_file_metadata` with SHA-256 digests and engine version.
- [ ] `static/die.json`: present if `diec.exe` installed; otherwise verify absent `detect_it_easy` remained `unavailable` without marking mandatory job status failed or partial.
- [ ] `ghidra/functions.json` & `ghidra/decompiled/`: populated using `GhidraExport.java` without PyGhidra/Jython errors, with `export_assessment` and truncation booleans (`functions_truncated`, `imports_truncated`, etc.) matching actual output.
- [ ] `dynamic/network/connections.json` & `dns.json`: entries categorized into `sample_related_traffic` / `control_traffic` / `background_traffic` / `unattributed_traffic`.
- [ ] `dynamic/eventlogs/events_summary.json`: includes `sysmon_config_provenance` (`schemaversion`, `sha256`), normalized UTC timestamps, deduplication counts, and `missing_channels`.
- [ ] `attack_mapping.json`: each technique cites real structured artifact paths and distinguishes `static_capability_indicator`, `observed_event`, and `correlated_observation`.
- [ ] `manifest.json`: `evidence_file_inventory` matches extracted files and excludes `manifest.json` under explicit `manifest_self_reference`, `collector_role_summary` separates mandatory/conditional/optional collectors, and `excluded_or_omitted_files` lists excluded `raw/procmon.pml` (when `include_raw_pml: false`).
- [ ] On Machine 3 locally, verify MalBox MCP server queries `evidence/<job_id>/` successfully (`get_static_analysis`, `get_ghidra_results`, `get_evidence_summary`).

---

## 5. Snapshot Dirty-State Gate & Optional Features / Negative Tests

- [ ] After job completion, verify submitting a second `doctor` job from Machine 1 is rejected (`HTTP 409`, `RESTORE_REQUIRED`) until Machine 3 snapshot is restored.
- [ ] **Optional Format Mismatch Test (Static-Only Declined Execution):** Submit a text file renamed `mismatch_test.exe` and decline dynamic approval (`N`); confirm `file_identification.format_mismatch=true`, `ghidra` reports `skipped` (`unsupported_sample_format`), and `dynamic_execution_status=skipped`.
- [ ] **Optional INetSim Gateway Test & Failure Isolation:** Enable `inetsim` on Machine 2 + `"inetsim_diagnostics_enabled": true` + `"fetch_gateway_network_diagnostics": true` on Machine 1; verify `gateway_network_diagnostics.json` arrives alongside unmodified Sandbox ZIP (and confirm temporarily misconfiguring `inetsim_log_dir` does not block verified Sandbox ZIP delivery).
- [ ] **Optional Canary Fixtures Test:** Enable `"canary_fixtures_enabled": true` on clean snapshot; confirm `dynamic/filesystem/canary_integrity.json` records hashes and integrity verification (`malbox_canary_note.txt`, `malbox_canary_matrix.csv`, `malbox_canary_sample.log`).
- [ ] **Status Note:** Controlled 3-VM Windows acceptance testing has **not** yet been completed in this development review and must be executed by the operator on the isolated lab VMs before merging `develop/malbox-v2` into `main`.
- [ ] Revert Machine 3 VM to `CLEAN` snapshot after acceptance tests finish.
