# MalBox v2.0 Analysis Coverage & Evidence Capabilities

This document summarizes what MalBox v2.0 collects, how telemetry is classified, and where explicit analytical boundaries remain.

---

## 1. File Identification & Static Properties

- **Artifact:** `static/hashes.json`, `static/pe_info.json`, `static/imports.json`, `static/exports.json`
- **Capabilities:**
  - Cryptographic digests (`md5`, `sha1`, `sha256`), byte size, and Shannon file entropy (`file_metadata`).
  - Offline header/magic-byte identification (`identify_file_format`): PE/COFF (validated via `e_lfanew`), ELF, Mach-O/Java Class, ZIP vs OOXML (`docx`/`xlsx`/`pptx`) vs JAR, PDF, OLE2 Compound File, Windows LNK, RTF, and UTF-8/UTF-16 script/text heuristics.
  - Declared-extension vs detected-header mismatch detection (`format_mismatch` and `format_mismatch_reason`).
  - Supported capability declaration (`supported_static_capabilities`) and honest non-PE limitation reporting (`unsupported_format_limitations`).
  - For valid PE binaries: `pefile` architecture, timestamps, section entropies, Authenticode/signature directory presence, imported DLLs/APIs, and exported symbols.
- **Limitations:** Non-PE files (scripts, PDF, OOXML, OLE2, LNK, raw blobs) do not undergo recursive archive extraction, VBA macro deobfuscation, PDF JavaScript stream decoding, or LNK target parsing inside core static collectors.

## 2. Strings & Offline IOC Candidate Extraction

- **Artifact:** `static/floss.json`, `static/strings.txt`
- **Capabilities:**
  - Executes Mandiant `FLOSS` (`floss.exe`) offline with Python ASCII/UTF-16 string extraction fallback.
  - Normalizes URL, domain, IPv4, path, and registry-key candidates (`extract_indicators_from_lines`), filtering IPv4 scope (`private_rfc1918`, `loopback`, `link_local`, `public_routable`) and suppressing noisy `.com` Windows filename collisions (e.g., `command.com`, `mode.com`).
- **Limitations:** Static strings are **unverified offline candidates** and frequently include benign toolchain paths, library messages, or decoy strings. Dynamic observation is required before treating any candidate as active behavior.

## 3. Disassembly & Decompilation

- **Artifact:** `ghidra/functions.json`, `ghidra/disassembly.txt`, `ghidra/decompiled/*.c`
- **Capabilities:**
  - Automated NSA `Ghidra` Headless export via zero-dependency `GhidraExport.java` (compatible with Ghidra 10.x / 11.x / 12.x without PyGhidra or Jython requirements) with legacy `ghidra_export.py` retained for fallback reference.
  - Exports bounded function lists (`total_function_count`, `functions_truncated`), assembly disassembly, and C decompiler pseudo-code.
- **Limitations:** Obfuscated binaries, heavy packers, stripped code, or non-binary script inputs may yield sparse or incomplete decompilation. Automated `GhidraMCP` GUI integration is optional and remains unverified unless manually started inside Ghidra GUI.

## 4. Capability, YARA & Packer/Compiler Signatures

- **Artifacts:** `static/capa.json`, `static/yara.json`, `static/die.json` (optional)
- **Capabilities:**
  - Mandiant `capa` maps binary code features against local `capa-rules` and preserves ATT&CK/MBC metadata.
  - YARA (`yara-python` preferred, `yara64.exe` CLI fallback) records local rule file SHA-256 provenance (`rule_file_metadata`), per-file compile errors (`failed_rule_files`), engine version, and match/string truncation booleans.
  - Optional Detect It Easy (`diec.exe -j`) provides non-executing compiler, linker, and packer/protector indicators (`static/die.json`). Missing optional DIE does not degrade job `final_status` (`optional_static`).
- **Limitations:** Local YARA rules (`scripts/yara_rules/`) and DIE detections are strictly offline heuristic indicators and are never treated as standalone proof of execution or maliciousness.

## 5. Process & Behavior Monitoring

- **Artifacts:** `dynamic/process/processes.json`, `dynamic/process/process_tree.json`, `dynamic/process/process_events.json`
- **Capabilities:**
  - Launches approved sample strictly inside `workspace/<job_id>/run/` with clean termination tracking (`termination_report`).
  - Tracks root PID and child lineage via `psutil` polling, expanded using Sysmon Event ID 1 parent-child linkage and optional Procmon CSV correlation.

## 6. Filesystem & Optional Canary Monitoring

- **Artifacts:** `dynamic/filesystem/changes.json`, `dynamic/filesystem/canary_integrity.json` (optional when `canary_fixtures_enabled: true`)
- **Capabilities:**
  - Correlates Sysmon file events (EID 11/23) and Procmon file operations scoped to tracked sample PIDs and run directory.
  - Records bounded dropped executable artifact metadata (hashes and extension flags) rather than dumping arbitrary live filesystem copies.
  - Optional deterministic benign canary fixtures (`malbox_canary_note.txt`, `malbox_canary_matrix.csv`, `malbox_canary_sample.log`) detect before/after modification or deletion (`canary_integrity.json`).
- **Limitations:** `raw/procmon.pml` is excluded from returned ZIPs by default (`include_raw_pml: false`) to prevent large archive bloat while retaining bounded exported CSV rows (`max_procmon_export_rows: 15000`).

## 7. Registry & Persistence Monitoring

- **Artifact:** `dynamic/registry/changes.json`
- **Capabilities:**
  - Collects tracked-PID registry create/set/rename/delete operations from Sysmon (EID 12/13/14) and Procmon, flagging common autorun/persistence key matches (`persistence_indicators`).
- **Limitations:** Procmon kernel driver capture requires Administrator elevation; unprivileged sandbox runs rely on Sysmon Event Log readability.

## 8. Network & Optional Gateway Diagnostics

- **Artifacts:** `dynamic/network/connections.json`, `dynamic/network/dns.json`, `dynamic/network/capture.pcapng` (Sandbox); optional `retained_evidence/gateway_netdiag_<job_id>.json` (Gateway)
- **Capabilities:**
  - Captures Internal Network 2 packets via Wireshark `dumpcap.exe` (when Npcap is configured) and parses DNS queries via `tshark.exe`.
  - Classifies connections and DNS queries into `sample_related_traffic`, `control_traffic`, `background_traffic`, and `unattributed_traffic` without deleting packet evidence.
  - Optional Gateway INetSim diagnostics (`inetsim_diagnostics_enabled: false` by default) expose time-windowed simulated service logs via separate Gateway endpoint `/jobs/<job_id>/network-diagnostics` without modifying the signed Sandbox ZIP archive.
- **Limitations:** In an air-gapped lab (`ip_forward=0`), external C2 servers are unreachable and encrypted TLS payloads remain opaque beyond SNI/DNS/metadata.

## 9. Memory & Forensics Telemetry

- **Artifacts:** `dynamic/memory/memory_usage.json`, `dynamic/memory/dumps/`, `dynamic/memory/volatility/`
- **Capabilities:**
  - Periodic `psutil` system and per-PID RAM usage polling (`memory_monitor`).
  - Optional user-mode `procdump64.exe` minidumps for tracked live PIDs remaining at the end of the observation window.
  - Optional `winpmem_enabled: false` physical RAM acquisition and offline `Volatility 3` (`pslist`, `pstree`, `cmdline`, `netscan`, `malfind`) using pre-cached local symbols.

## 10. Event Logs, Sysmon Provenance & Evidence-Backed ATT&CK Correlation

- **Artifacts:** `dynamic/eventlogs/*.evtx`, `dynamic/eventlogs/events_summary.json`, `attack_mapping.json`
- **Capabilities:**
  - Exports Windows Event Logs (`Sysmon`, `System`, `Application`, `Security`, `PowerShell`, `Defender`) scoped from `dynamic_window_utc` without clearing host logs.
  - Normalizes EVTX timestamps to UTC ISO-8601 (`time_created` + `time_created_raw`), deduplicates via `(channel, EventRecordID)`, records per-channel access/missing/truncation status, and records SHA-256 + `schemaversion` provenance of `configs/sysmon.xml`.
  - When `enable_attack_mapping: true`, `collectors/attack_mapping.py` builds `attack_mapping.json` mapping techniques with explicit evidence references and separating `static_capability_indicator`, `observed_event`, `correlated_observation` (static + dynamic agreement), and `unverified_hypothesis`.
- **Limitations:** Single static indicators or YARA matches never establish runtime confirmation. All ATT&CK mappings require human analyst review against the underlying cited artifacts.
