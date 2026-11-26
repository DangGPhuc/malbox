# MalBox v2.0 Changelog

Changes implemented on branch `develop/malbox-v2` on top of baseline commit `7c76260a285871e7d70645df96341db3e491b800`. All v1 HTTP endpoints, default IPs/ports (`10.10.10.10`, `10.10.10.20:8000`, `10.10.20.20`, `10.10.20.30:8001`), stage names, core terminal log banners, and the 16-tool MalBox MCP server interface remain backward-compatible.

---

## Sprint 1 — Evidence Quality & Ghidra Compatibility (`d0f795d`)

- **Zero-Dependency Ghidra Headless Export (`machine3-sandbox/scripts/GhidraExport.java`):** Replaced reliance on PyGhidra/Python headless bridges with a pure Java `GhidraScript` compatible with Ghidra 10.x / 11.x / 12.x (`config.json`: `"ghidra_export_script": "GhidraExport.java"`). Added `application.java.min` parsing in `readiness.py` (`get_ghidra_props`) and `total_function_count` / `functions_truncated` tracking in `ghidra_analysis.py` and `mcp/tools.py`. Legacy `scripts/ghidra_export.py` remains retained as reference.
- **Static IOC Normalization & Hygiene (`machine3-sandbox/collectors/static_analysis.py`):** Improved offline URL, domain, IPv4 scope classification, path/registry extraction, and common `.com` executable filename suppression (`COMMON_COM_EXECUTABLES`), recording extraction confidence details without inventing confirmations.
- **Context-Aware Network Classification (`machine3-sandbox/collectors/network_monitor.py`):** Added `classify_connections` and `classify_dns_queries` categorizing traffic into `sample_related_traffic`, `control_traffic`, `background_traffic`, and `unattributed_traffic` while preserving raw captures.
- **Archive & Procmon Size Hygiene (`machine3-sandbox/analyzer.py`, `collectors/filesystem_monitor.py`, `collectors/memory_monitor.py`):** Added `include_raw_pml: false`, `max_raw_pml_mb: 200`, `max_procmon_export_rows: 15000`, disk-space checks before CSV export, unified `_should_archive_file` / `_build_inventory` / `_package_evidence_zip`, `excluded_or_omitted_files` reporting in `manifest.json`, and accurate `disabled_by_config` status handling for optional `WinPmem`.

---

## Sprint 2 — Deployment Reliability & Evidence Protection (`07591b9`)

- **REMWin Windows 10 x64 & Windows 11 x64 Support (`machine3-sandbox/readiness.py`, `setup.ps1`):** Generalized `windows_version_compat` to validate Windows 10 x64 (`build >= 10240`) and Windows 11 x64 (`build >= 22000`) consistently.
- **Startup Wrapper Scripts (`machine2-gateway/run_gateway.sh`, `machine3-sandbox/run_sandbox.bat`):** Added deterministic `.venv`-verified launch wrappers exiting non-zero cleanly when virtualenvs or configs are missing.
- **Optional Canary Fixtures & Evidence Permissions (`machine3-sandbox/collectors/filesystem_monitor.py`, `analyzer.py`, `gateway.py`, `doctor.py`):** Added opt-in (`canary_fixtures_enabled: false`) benign workspace canary files (`canary_integrity.json`) and restricted POSIX evidence directory modes (`0o750`).
- **Bounded Relay Errors & Defensive Archive Verification (`machine2-gateway/gateway.py`, `machine1-client/doctor.py`):** Added bounded failure classifications (`connection_timeout`, `service_unavailable`, `unexpected_http_response`, `interrupted_job`, `evidence_unavailable`), Gateway pre-acknowledge ZIP integrity and size (`max_evidence_archive_mb: 512`) verification, and Client `safe_extract_zip` (path traversal, backslash, and ZIP-bomb byte guards) + `verify_extracted_manifest`.

---

## Sprint 3 — Isolated Network Diagnostics & Provenance (`38dda77`)

- **Optional Gateway INetSim Diagnostics (`machine2-gateway/inetsim_diagnostics.py`):** Added read-only binary/unit/config/log inspection (`collect_gateway_inetsim_diagnostics`) and time-windowed, query-string/credential-redacted session evidence collection (`collect_session_inetsim_evidence`), opt-in via `machine2-gateway/config.json` (`inetsim_diagnostics_enabled: false`).
- **Readiness Integration (`machine2-gateway/readiness.py`):** Added `inetsim_optional` check reporting configured vs active local INetSim status without altering mandatory local gateway readiness (`READY` vs `LIMITED`).
- **Separate Gateway Evidence Provenance (`machine2-gateway/gateway.py`, `machine1-client/doctor.py`, `docs/network-setup.md`):** Persisted gateway diagnostics outside Sandbox ZIPs at `retained_evidence/gateway_netdiag_<job_id>.json`, served via `GET /jobs/<job_id>/network-diagnostics`, optionally fetched by Machine 1 (`fetch_gateway_network_diagnostics: false`) as `<evidence_dir>/gateway_network_diagnostics.json`.

---

## Sprint 4 — Static Depth, EVTX Provenance, ATT&CK Mapping & Docs (`7755de1`+)

- **Static File Identification & Format Mismatch (`machine3-sandbox/collectors/static_analysis.py`):** Added `identify_file_format` detecting magic headers (`PE/COFF`, `ELF`, `Mach-O/Class`, `ZIP`, `OOXML`, `JAR`, `PDF`, `OLE2`, `LNK`, `RTF`, text/scripts), declaring `format_mismatch` against extensions, and documenting supported capabilities and non-PE limitations in `static/hashes.json` and `static/pe_info.json`.
- **Optional Detect It Easy & YARA Provenance (`machine3-sandbox/collectors/static_analysis.py`, `config.json`, `readiness.py`):** Added opt-in `detect_it_easy` collector (`static/die.json`, `optional_static` classification so absent `diec.exe` never falsely degrades job `final_status`) and upgraded `_analyze_yara` with per-rule-file SHA-256 metadata, explicit `failed_rule_files`, engine version, and match/string truncation booleans.
- **EVTX Provenance, Normalization & Deduplication (`machine3-sandbox/collectors/eventlog_monitor.py`):** Added `inspect_sysmon_config_provenance` (SHA-256 + `schemaversion`), UTC ISO-8601 `normalize_event_timestamp`, `EventRecordID`-based deduplication in `parse_evtx_xml_detailed`, `max_records` truncation tracking, and `channel_status_reason` / `missing_channels` diagnostics.
- **Evidence-Backed MITRE ATT&CK Correlation (`machine3-sandbox/collectors/attack_mapping.py`, `analyzer.py`, `mcp/tools.py`):** Added conservative `build_attack_mapping` writing `attack_mapping.json` (when `enable_attack_mapping: true`), surfacing findings in `summary.json`, `report.md` Section 10, and `EvidenceStore.get_evidence_summary` / `get_static_analysis`.
- **v2 Documentation Suite:** Added `docs/analysis-coverage.md`, `docs/scope-and-limitations.md`, `docs/v2-changelog.md`, and `docs/v2-acceptance-checklist.md`.
