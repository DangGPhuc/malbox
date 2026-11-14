# Malbox-AI — Gate 0 Live Sandbox Audit & Remediation Matrix

**Document Reference:** `docs/audit/LIVE_CAPE_REMEDIATION.md`  
**Audited Branch:** `fix/live-cape-portability-ui-redesign` (based on `audit/v02-release-candidate` @ `63551e2`)  
**Audit Date:** 2026-11-14  
**Primary Input Defect Reports:**
- `AUDIT_LIVE_SANDBOX_FIXES_AND_PORTABILITY.md` (Field evaluation report)
- `LIVE_SANDBOX_GAPS_AND_AUDIT.md` (Telemetry & Guest instrumentation report)
- `DESIGN.md` (Notion-inspired warm-light design system specification)

---

## 1. Executive Summary & Verification Methodology

All defect claims from field reports were audited against the actual source code of `malbox-ai`.
Each problem was categorized by architectural layer:
1. **Malbox Application Defects:** Bugs in API contracts, JSON parsing, race conditions, or rule coverage.
2. **CAPE Configuration Problems:** Misaligned server settings (e.g. `resultserver` IP, machine tags, freespace).
3. **VirtualBox / Guest OS Limitations:** Network persistence, Python syntax compatibility, firewall policies.
4. **Missing Telemetry Instrumentation:** Lack of in-guest API hooking (`capemon.dll`) or fake network services (`inetsim`).
5. **UI / UX Deficiencies:** Visual hierarchy, accessibility, and theme support.

---

## 2. Gate 0 Defect Audit Matrix

| Issue ID | Category | Reported Problem | Actual Source Code Evidence | Reproducibility | Severity | Root Cause | Proposed Fix | Regression Test Requirement | Security Implications |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| **ISSUE-01** | Malbox App Defect | Task status parsing always returns `unknown`, causing 60s timeout | `backend/app/services/sandbox/cape.py:122-124`: `task_info = resp.json().get("data", {}).get("task", {})` | 100% on standard CAPEv2 REST API (`/apiv2/tasks/view/<id>/`) | **High (P0)** | Real CAPEv2 returns flat JSON `{"error": false, "data": {"id": 1, "status": "running"}}` while mock test provided wrapped `{"data": {"task": {...}}}`. | Extract `data_obj = resp.json().get("data", {})`; use `data_obj.get("task")` if dict, otherwise `data_obj`. | `test_cape_get_task_status_flat_and_wrapped_formats` | Prevents denial-of-service / false timeout on live analyses. |
| **ISSUE-02** | Malbox App Defect | Task rejected on submission with `Check Tags help` error | `backend/app/services/sandbox/cape.py:90`: `"tags": profile` unconditionally injected | 100% when CAPE VM does not have matching tag | **High (P1)** | Conflates Malbox analysis profile (e.g. `standard`, `ransomware_focus`) with machine tags in `virtualbox.conf`. | Only send `tags` if profile is non-standard and mapped; allow explicit optional tag mapping. | `test_cape_submission_tags_handling_standard_and_custom` | Avoids submission failures when running against standard guest VMs. |
| **ISSUE-03** | Malbox App Defect | Race condition between `completed` and `reported` returns empty report | `backend/app/services/sandbox/cape.py:129-130`: `"completed": "collecting"`, `"reported": "completed"`. In `pipeline_worker.py:170`: `if curr_status in ["completed", "reported"]:` triggers fetch before `report.json` is generated. | 100% during slow post-processing | **High (P0)** | When CAPE VM halts, status is `completed`, but `process.py` has not finished writing `report.json`. API returns `{"error": true, "error_value": "No reports created..."}`. | In `pipeline_worker.py`, only accept `reported` (or verify report endpoint ready) before transitioning out of RUNNING; in `collect_results()`, check `resp.json().get("error")` and retry with backoff. | `test_cape_completed_before_reported_race_retry` | Prevents swallowing errors and falsely declaring zero-finding clean reports. |
| **ISSUE-04** | Malbox App Defect | Swallowed API error payloads in `collect_results()` | `backend/app/services/sandbox/cape.py:151-155`: checks `resp.status_code != 200`, but CAPE returns HTTP 200 with `{"error": true, "error_value": "..."}` | 100% on pending reports | **High (P1)** | Endpoint errors return HTTP 200 with JSON error envelope. `_transform_cape_report()` receives error dict, extracts empty lists, and returns 0 events. | Explicitly check `resp_json.get("error")` and raise `RuntimeError` or `ReportNotReadyError` on error envelopes. | `test_cape_report_error_true_with_http_200_raises` | Prevents corrupting telemetry database with fake clean state. |
| **ISSUE-05** | Malbox App Defect | Incomplete analysis evaluated as 0/100 "No Suspicious Behavior" | `backend/app/workers/pipeline_worker.py`: if `processes` is empty due to analyzer crash, still scores 0/100 and completes as normal. | 100% on analyzer crash | **High (P1)** | Absence of telemetry instrumentation is conflated with benign execution. | Implement evidence-quality/telemetry completeness classification (`COMPLETE`, `PARTIAL`, `INCOMPLETE`, `UNVERIFIED`). Flag analyzer crashes as `INCOMPLETE` with warnings. | `test_incomplete_telemetry_quality_contract` | Eliminates dangerous false negatives in intelligence reporting. |
| **ISSUE-06** | Malbox App Defect | Rule engine gap: No rules for dropped binaries or process memory injection | `backend/app/services/detection/rules.py`: Only 7 rules (Shadow copy, Mass encryption, Registry run, PowerShell, Browser creds, C2 HTTP, SMB probe). | 100% on Crypter / Dropper / Injector malware | **Medium (P2)** | Crypter samples (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `CreateRemoteThread`, dropped `.bin`/`.exe`) match 0 rules, scoring 0/100. | Add `RULE_DROPPED_EXECUTABLE_PAYLOAD` (T1027/T1105) and `RULE_PROCESS_INJECTION_TECHNIQUE` (T1055) with contextual thresholds and benign negative tests. | `test_dropped_executable_and_process_injection_rules` | Accurately scores droppers and injectors without false positives. |
| **ISSUE-07** | Malbox App Defect | Doctor CLI does not verify live CAPE connectivity | `scripts/malbox_cli/checks.py:872-887`: Only checks if `MALBOX_LIVE_MODE_ENABLED=true` string exists in `.env`. | 100% in Doctor CLI | **Low (P3)** | No active HTTP probe to CAPE API URL when Live Mode is enabled. | Add active read-only connectivity and version check via `CapeSandboxBackend.check_readiness()` with short timeout; report `READY`, `UNREACHABLE`, `UNAUTHORIZED`, etc. | `test_doctor_cape_connectivity_and_readiness` | Provides clear feedback to operators before running live tasks. |
| **ISSUE-08** | VirtualBox / Host Network | Host-Only IP lost after host reboot | Host OS ephemeral IP assignment via `ip addr add` | Common across Linux reboots | **Host Infra** | Linux does not persist ad-hoc `ip` commands across reboots. | Document persistent VirtualBox command: `vboxmanage hostonlyif ipconfig <INTF> --ip <IP> --netmask <NM>`. | Documented in `docs/setup/virtualbox-isolated-network.md` | Ensures stable network link without modifying systemd globally. |
| **ISSUE-09** | CAPE Config | `[resultserver] ip` hardcoded to specific subnet | `cuckoo.conf` `[resultserver] ip` set to static IP | 100% when host IP subnet changes | **CAPE Infra** | Resultserver fails with `[Errno 99] Cannot assign requested address`. | Document setting `ip = 0.0.0.0` or matching host-only gateway IP in documentation templates. | Documented in `docs/setup/cape-integration.md` | Allows flexible multi-NIC and multi-machine setups. |
| **ISSUE-10** | Guest VM Runtime | `analyzer.py` crashes on Python <= 3.5 | In-guest `analyzer.py` utilizes modern f-strings (`f"..."`) and type annotations | 100% on old Windows VMs (Python 3.5) | **Guest Infra** | Python 3.5 syntax error aborts analyzer immediately. | Document mandatory Python 3.10+ requirement for guest VMs in setup guide. | Documented in `docs/setup/cape-integration.md` | Standardizes guest VM preparation across different lab machines. |
| **ISSUE-11** | UI / UX Deficiency | Monolithic dark-mode UI with dense tables and high visual fatigue | `frontend/src/index.css`, `frontend/src/App.tsx`, `ReportPage.tsx` | 100% across all pages | **UX Redesign** | Existing UI uses dark cyberpunk theme (`#070a12`, `#0b1120`) with heavy borders and lack of warm editorial feel. | Implement Notion-inspired design system (`#f6f5f4` canvas, `#ffffff` cards, `#0075de` CTA, 12px radii, clean typography, light/dark theme switch). | Frontend component tests, visual layout tests | Enhances forensic readability, cognitive focus, and accessibility. |

---

## 3. Baseline Verification Summary

Prior to initiating Phase A implementation:
- **Backend Test Suite:** 139 passed, 1 skipped (`.venv/bin/pytest backend/tests/`).
- **Frontend Test Suite:** 39 passed across 4 files (`cd frontend && npm test`).
- **TypeScript Strict Compilation:** 0 errors (`npm run typecheck`).
- **Production Bundle:** Built cleanly (`npm run build`).
- **Branch:** `fix/live-cape-portability-ui-redesign` cleanly branched from `63551e2`.
