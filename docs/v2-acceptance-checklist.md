# MalBox v2.0 Controlled 3-VM Acceptance Checklist

Use this checklist on your physical / virtualized 3-VM lab (**Machine 1: Kali**, **Machine 2: REMnux**, **Machine 3: REMWin Windows 10 x64** or Windows 11 x64) after pulling `develop/malbox-v2` and before merging into `main`.

> **Safety Reminder:** Perform all online tool installations first, then disconnect VMs from any bridged/NAT adapter onto `malbox-net1` (`10.10.10.0/24`) and `malbox-net2` (`10.10.20.0/24`) **before** taking the `CLEAN` snapshot or executing any test sample.

---

## 1. Pre-Flight Network & Environment Checks

- [ ] Verify Machine 1 IP `10.10.10.10` (`malbox-net1` only, no default Internet gateway).
- [ ] Verify Machine 2 NIC1 `10.10.10.20` (`malbox-net1`) & NIC2 `10.10.20.20` (`malbox-net2`), and confirm `sysctl net.ipv4.ip_forward` equals `0`.
- [ ] Verify Machine 3 IP `10.10.20.30` (`malbox-net2` only), confirming `workspace/.dirty_state` is absent before snapshot creation.
- [ ] On Machine 3 (`machine3-sandbox`), run:
  ```powershell
  Set-ExecutionPolicy -Scope Process Bypass
  .\setup.ps1 -CheckOnly
  ```
  Confirm `LOCAL_READINESS` is `READY` (or documented `LIMITED` only for intentionally omitted optional components like `WinPmem`, `Detect It Easy`, `Volatility 3`), `Ghidra` + `JDK` compatibility passes with `GhidraExport.java`, and `MalBox MCP` registers all 16 tools.
- [ ] Take / verify the `CLEAN` snapshot on Machine 3.

---

## 2. Service Startup & Cross-VM Control Path

- [ ] On Machine 3, launch Sandbox listener via wrapper:
  ```cmd
  cd C:\path\to\malbox\machine3-sandbox
  run_sandbox.bat
  ```
  Confirm `[SANDBOX] Listening on 0.0.0.0:8001` and `SNAPSHOT_STATE=NO_DIRTY_MARKER`.
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
  ```
- [ ] Confirm terminal prints progression stages:
  `received -> static_analysis -> ghidra_analysis -> awaiting_local_approval -> dynamic_observation -> returning_evidence`.
- [ ] On Machine 3 terminal, confirm local approval prompt appears (when `require_local_approval: true`), approve locally, and confirm observation completes cleanly.
- [ ] On Machine 1, confirm evidence ZIP extracts cleanly under `evidence/<job_id>/` (mode `0o750` on POSIX) without path-traversal or manifest errors.

---

## 4. Artifact Verification (v2 Features)

Inspect extracted `evidence/<job_id>/`:

- [ ] `static/hashes.json`: contains `file_identification` (`declared_extension`, `format_family`, `format_mismatch`, `supported_static_capabilities`).
- [ ] `static/yara.json`: lists `rule_file_metadata` with SHA-256 digests and engine version.
- [ ] `static/die.json`: present if `diec.exe` installed; otherwise verify absent `detect_it_easy` remained `unavailable` without marking mandatory job status failed.
- [ ] `ghidra/functions.json` & `ghidra/decompiled/`: populated using `GhidraExport.java` without PyGhidra/Jython errors.
- [ ] `dynamic/network/connections.json` & `dns.json`: entries categorized into `sample_related_traffic` / `control_traffic` / `background_traffic` / `unattributed_traffic`.
- [ ] `dynamic/eventlogs/events_summary.json`: includes `sysmon_config_provenance` (`schemaversion`, `sha256`), normalized UTC timestamps, deduplication counts, and `missing_channels`.
- [ ] `attack_mapping.json`: each technique cites real structured artifact paths and distinguishes `static_capability_indicator`, `observed_event`, and `correlated_observation`.
- [ ] `manifest.json`: `evidence_file_inventory` matches extracted files and `excluded_or_omitted_files` lists excluded `raw/procmon.pml` (when `include_raw_pml: false`).
- [ ] On Machine 3 locally, verify MalBox MCP server queries `evidence/<job_id>/` successfully (`get_static_analysis`, `get_evidence_summary`).

---

## 5. Snapshot Dirty-State Gate & Optional Features Verification

- [ ] After job completion, verify submitting a second `doctor` job from Machine 1 is rejected (`HTTP 409`, `RESTORE_REQUIRED`) until Machine 3 snapshot is restored.
- [ ] **Optional Format Mismatch Test (Static-Only Declined Execution):** Submit a text file renamed `mismatch_test.exe` and decline dynamic approval (`N`); confirm `file_identification.format_mismatch=true` and `dynamic_execution_status=skipped`.
- [ ] **Optional INetSim Gateway Test:** Enable `inetsim` on Machine 2 + `"inetsim_diagnostics_enabled": true` + `"fetch_gateway_network_diagnostics": true` on Machine 1; verify `gateway_network_diagnostics.json` arrives alongside unmodified Sandbox ZIP.
- [ ] **Optional Canary Fixtures Test:** Enable `"canary_fixtures_enabled": true` on clean snapshot; confirm `dynamic/filesystem/canary_integrity.json` records hashes and integrity verification.
- [ ] Revert Machine 3 VM to `CLEAN` snapshot after acceptance tests finish.
