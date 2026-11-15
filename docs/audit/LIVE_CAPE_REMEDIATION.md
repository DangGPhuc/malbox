# Malbox-AI — Gate 0 Live Sandbox Audit & Remediation Matrix

**Document Reference:** `docs/audit/LIVE_CAPE_REMEDIATION.md`  
**Audited Branch:** `fix/live-cape-portability-ui-redesign`  
**Baseline Commit SHA:** `63551e2fa626e24d3368a00d7020235d1e0cd45f`  
**Phase A Commit SHA:** `17d3516` (`fix(cape): repair pipeline contract and enforce task/report integrity`)  
**Phase B Commit SHA:** `a8170d7` (`fix(detection): preserve evidence quality and contextual live findings`)  
**Phase C Commit:** `feat(ui): finalize forensic workspace shell and evidence-aware UX`  
**Audit Date:** 2026-11-15  

---

## 1. Executive Summary & Verification Methodology

All defect claims from field reports (`AUDIT_LIVE_SANDBOX_FIXES_AND_PORTABILITY.md`, `LIVE_SANDBOX_GAPS_AND_AUDIT.md`, `DESIGN.md`) were audited against the actual source code of `malbox-ai` and remediated in three sequential phases:

1. **Phase A (Live CAPE Pipeline Blockers):** Repaired pipeline/adapter contract mismatch, task/report identity verification, monotonic polling deadline, and readiness probing.
2. **Phase B (Detection Quality & Telemetry Ceilings):** Implemented strict contextual process injection correlation, verified write requirements for dropped executables, calibrated risk levels by telemetry completeness, extracted memory dumped payloads into artifacts rather than forging fake filesystem writes, and enforced hard telemetry ceilings.
3. **Phase C (Notion-Inspired Forensic Workspace Shell & UX):** Implemented collapsible sidebar, compact top header with breadcrumbs and persistent active case pill, canonical backend risk classifications on Dashboard, 5-step guided submission wizard with backend/sample reset, generation-fenced async analysis switching, Cytoscape concrete theme color resolution, zero external font network requests, and real Chromium visual verification across 7 views, 3 viewports, and light/dark modes.

---

## 2. Gate 0 Defect Audit & Resolution Matrix

| Issue ID | Category | Reported Problem | Root Cause in Baseline | Phase & Resolution | Verification Evidence |
|:---|:---|:---|:---|:---|:---|
| **ISSUE-01** | Malbox App Defect | Task status parsing always returns `unknown`, causing 60s timeout | Flat JSON from real CAPEv2 (`{"error": false, "data": {"id": 1, "status": "running"}}`) unhandled | **Phase A:** Check both flat and wrapped `data.get("task")` formats | `test_cape_get_task_status_flat_and_wrapped_formats` PASSED |
| **ISSUE-02** | Malbox App Defect | Task rejected on submission with `Check Tags help` error | Profile unconditionally injected into `tags` parameter | **Phase A:** Default `CAPE_PROFILE_TAG_MAP` empty; strict validation of `ALLOWED_SUBMISSION_OPTIONS` | `test_cape_profile_tag_mapping_empty_by_default` PASSED |
| **ISSUE-03** | Malbox App Defect | Race condition between `completed` and `reported` returns empty report | Fetch triggered before `report.json` finished writing | **Phase A:** In `collect_results()`, check `resp.json().get("error")` and retry with monotonic deadline | `test_cape_completed_before_reported_race_retry` PASSED |
| **ISSUE-04** | Malbox App Defect | Swallowed API error payloads in `collect_results()` | HTTP 200 returned by CAPE with `{"error": true, ...}` | **Phase A:** Explicitly check `resp_json.get("error")` and raise `RuntimeError` | `test_cape_report_error_envelope_with_http_200_raises` PASSED |
| **ISSUE-05** | Malbox App Defect | Incomplete analysis evaluated as 0/100 "No Suspicious Behavior" | Absence of telemetry instrumentation conflated with clean execution | **Phase B:** Telemetry completeness contract (`COMPLETE`, `PARTIAL`, `INCOMPLETE`, `UNVERIFIED`). Incomplete produces `Analysis Incomplete — Inconclusive` with low confidence. | `test_incomplete_telemetry_quality_contract_prevents_false_clean` PASSED |
| **ISSUE-06** | Malbox App Defect | Rule engine gap: No rules for dropped binaries or process memory injection | Crypter/dropper samples scored 0/100 | **Phase B:** Added `RULE_DROPPED_EXECUTABLE_PAYLOAD` (requiring verified write action) and `RULE_PROCESS_INJECTION_TECHNIQUE` (source/target PID correlation, executable protection, temporal ordering $\Delta t \le 60s$, API success) | `test_process_injection_rule_positive_and_negative`, `test_dropped_executable_rule_positive_and_negative` PASSED |
| **ISSUE-07** | Malbox App Defect | Doctor CLI does not verify live CAPE connectivity | Only checked string in `.env` | **Phase A:** Added `_probe_cape_readiness` using `CapeSandboxBackend.check_readiness()` with `guest_vms_total`, `guest_vms_available`, `confinement_verified: False` | `./malbox doctor --check` PASSED |
| **ISSUE-08** | VirtualBox / Host Network | Host-Only IP lost after host reboot | Ephemeral IP assignment | **Phase A Documentation:** Documented persistent `vboxmanage hostonlyif ipconfig` in setup guides | Verified in `docs/setup/virtualbox-isolated-network.md` |
| **ISSUE-09** | CAPE Config | `[resultserver] ip` hardcoded to specific subnet | Hardcoded IP causes `Errno 99` | **Phase A Documentation:** Documented `ip = 0.0.0.0` or host-only gateway IP in documentation templates | Verified in `docs/setup/cape-integration.md` |
| **ISSUE-10** | Guest VM Runtime | `analyzer.py` crashes on Python <= 3.5 | Modern f-strings & type annotations in guest code | **Phase A Documentation:** Documented Python 3.10+ requirement for guest VMs | Verified in `docs/setup/cape-integration.md` |
| **ISSUE-11** | UI / UX Deficiency | Monolithic dark-mode UI with dense tables and high visual fatigue | Monolithic dark cyberpunk theme (`#070a12`) | **Phase C:** Notion-inspired forensic design system: `#f6f5f4` canvas, `#ffffff` cards, `#0075de` CTA, collapsible sidebar, compact header, breadcrumbs, persistent active case pill, light/dark theme switch | 46 frontend tests PASSED; 20 real Chromium screenshots verified |

---

## 3. Phase A Detailed Verification (`17d3516`)
- `backend/app/core/config.py`: Added `CAPE_PROFILE_TAG_MAP: Dict[str, str] = Field(default_factory=dict)`, `CAPE_DEFAULT_MACHINE: str = ""`, `CAPE_DEFAULT_NETWORK_ROUTE: str = ""`.
- `backend/app/services/sandbox/cape.py`:
  - Enforced strict value validation for `ALLOWED_SUBMISSION_OPTIONS` (`timeout`, `enforce_timeout`, `tags`, `machine`, `package`, `priority`, `options`, `custom`, `clock`).
  - Readiness probe verifies JSON envelope and extracts VM counts with `confinement_verified: False`.
  - Task ID mismatch and sample SHA-256 mismatch reject payload with `ValueError`.
  - Monotonic polling deadline prevents infinite hanging; 401/403 fails immediately without blind retries.
  - Single task POST prevents remote duplicate task creation.
- `backend/app/workers/pipeline_worker.py`:
  - Removed forwarding of internal planning fields (`requested_artifacts`, `telemetry_focus`) to CAPE transport options.
  - Maps `not_found` and `unauthorized` to `AnalysisStatus.FAILED`.
- End-to-end regression test: `test_cape_pipeline_worker_e2e_regression_mocked_http` verified full pipeline execution to `COMPLETED` without sending internal planning options.

---

## 4. Phase B Detailed Verification (`a8170d7`)
- `backend/app/services/detection/engine.py`:
  - `RULE_PROCESS_INJECTION_TECHNIQUE`: Correlates allocation/write and thread creation by source and target PID; verifies API call success; checks executable memory protection; validates temporal ordering ($T_{alloc/write} \le T_{thread}$, $\Delta t \le 60s$); rejects self/local calls, failed APIs, and standalone `NtProtectVirtualMemory`/`NtCreateThreadEx`.
  - `RULE_DROPPED_EXECUTABLE_PAYLOAD`: Requires explicit `write`/`create`/`modify` action; rejects reads; ignores `.bin` without verified PE metadata; ignores benign text/log/config writes.
  - Telemetry completeness calibration: `INCOMPLETE`/`UNVERIFIED` produce `Analysis Incomplete — Inconclusive` with confidence 0.20–0.35, preventing false "Clean" verdicts.
  - Version tagged as `ENGINE_VERSION = "0.2.2"`.
- `backend/app/services/sandbox/cape.py`:
  - Hard telemetry ceilings: 100 max processes, 500 calls/process, 2000 total calls, 500 filesystem, 500 registry, 200 network events.
  - Extracted in-memory dumped payloads (`payloads`) into `artifacts` as `type="memory_dump_payload"`, `is_extracted_memory_payload=True`, NOT manufactured into `filesystem` as fake file writes.
  - Records truncation counts in metadata and notes.

---

## 5. Phase C Detailed Verification (Current)
- **Zero External Fonts (C1):** Removed Google Fonts `@import` and `<link rel="preconnect">` requests; system font stacks ensure complete offline operation.
- **Application Shell (C2):**
  - Collapsible desktop sidebar (250px to 68px) with global navigation (Dashboard, Analyses/Cases, Submit Sample) and active case navigation (Workspace, Timeline, Graph, Static, Correlation, Report).
  - Compact header with sidebar toggle, breadcrumbs, persistent active analysis pill with quick exit, health status, and accessible light/dark theme switch.
  - URL hash synchronization and browser Back/Forward navigation support via `window.addEventListener('hashchange', ...)`.
- **Dashboard Risk & Evidence Semantics (C3):**
  - Canonical backend thresholds: Malicious $\ge 80$, Suspicious $50-79$, Low $20-49$, Incomplete/Review partitioned separately.
  - Mutually exclusive severity distribution totaling 100% of cases.
  - Breakdown of Replay scenarios vs Live samples.
  - System readiness strip driven by live `api.getHealth()` probe.
- **Submission Wizard (C4):**
  - Guided 5-step flow with Replay default.
  - Actual CAPE availability probe disables live submission with clear notice when `MALBOX_LIVE_MODE_ENABLED=false`.
  - State reset on backend or sample switch clears operator approval and token.
  - Explicit notification that guest VM confinement must be verified by operator on host-only networks.
- **Report & Evidence UX (C5):**
  - Reusable `AnalysisHeader` component unifying sample filename, SHA-256, Analysis ID, Replay/Live origin, Lifecycle status, Evidence completeness, Risk score/verdict, and AI confidence/provider across all investigation screens.
  - Cytoscape concrete theme color resolution for HTML5 canvas in `BehaviorGraphPage`, `StaticCallGraphPanel`, and `CorrelationRelationshipView`.
- **Asynchronous Analysis Switching (C6):**
  - `generationRef` fencing on `WorkspacePage` and `BehaviorGraphPage` eliminates race conditions and prevents late responses from overwriting active data.
  - Old polling timers cleared immediately; non-overlapping polling enforced.
- **Real Browser Visual Verification (C7):**
  - 20 real screenshots captured with headless Chromium across 7 core pages, 3 viewports (Desktop 1440×900, Laptop 1024×768, Mobile 390×844), in both light and dark themes.
  - Artifacts stored in `docs/screenshots/`.
