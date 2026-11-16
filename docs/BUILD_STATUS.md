# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.2.2-live-first-platform  
**Active Branch:** `fix/live-cape-portability-ui-redesign`  
**Baseline Commit SHA:** `63551e2fa626e24d3368a00d7020235d1e0cd45f`  
**Status:** **OPERATIONAL — PRODUCTION LIVE-FIRST SUSPICIOUS FILE ANALYSIS PLATFORM**  
**Release Documents:**
- [`docs/architecture/live-first-analysis.md`](architecture/live-first-analysis.md) — Live-First Suspicious File Analysis Architecture
- [`docs/architecture/malware-classification.md`](architecture/malware-classification.md) — 17-Category Malware Classification Taxonomy
- [`docs/setup/cape-integration.md`](setup/cape-integration.md) — CAPE Sandbox v2 Production Integration Guide
- [`docs/setup/virtualbox-isolated-network.md`](setup/virtualbox-isolated-network.md) — Persistent VirtualBox Host-Only Network Configuration Guide
- [`docs/ui/DESIGN_SYSTEM.md`](ui/DESIGN_SYSTEM.md) — Notion-Inspired Forensic Design System Reference
- [`docs/ui/UX_REDESIGN_REPORT.md`](ui/UX_REDESIGN_REPORT.md) — Comprehensive UX Redesign & Workspace Modernization Report

---

## 1. Feature Completion Matrix & Readiness Classification

| Subsystem | Readiness | Verification Evidence | Operational Details |
| :--- | :--- | :--- | :--- |
| **PE Submission & Intake** | **VERIFIED** | `test_submission.py`, `test_live_first_defaults.py` | Single-action file analysis intake. Quarantined with 0400 read-only permissions; SHA-256 deduplicated; preflight metadata extracted. |
| **Execution Safety Gate** | **VERIFIED** | `test_safety_and_lifecycle.py` | Live-mode safety policy enforcement; explicit analyst safety confirmation; fail-closed operator token boundary (`MALBOX_OPERATOR_TOKEN`). |
| **Reliable Job Lifecycle** | **VERIFIED** | `test_safety_and_lifecycle.py` | Persistent `JobQueueManager`, bounded concurrency=1, crash recovery, terminal state protection, race-free cancellation. |
| **Ghidra Headless Decompilation** | **VERIFIED** | `test_static_analysis.py` (26/26 PASSED) | Automatic static trigger with Bubblewrap sandbox containment; ranking of high-risk functions; graceful fallback if disabled. |
| **CAPE Sandbox Integration** | **VERIFIED** | `test_cape_adapter.py` (17/17 PASSED) | Automatic package routing (`dll` vs `exe`), bounded polling lifecycle, crash detection, 50MB report cap, 100MB artifact cap. |
| **17-Category Malware Classification Engine** | **VERIFIED** | `test_malware_classification.py` (7/7 PASSED) | 17-category taxonomy with deterministic scoring rules, CONFIRMED/SUSPECTED status, multi-label handling, unsupported category flagging. |
| **Deterministic Rule Engine (v0.2.2)** | **VERIFIED** | `test_detection_rules.py` (14/14 PASSED) | Contextual thresholds for ransomware, shadow copy deletion, persistence, PowerShell, credential vaults, C2 HTTP, and SMB probes. |
| **Cytoscape.js Behavior Graph** | **VERIFIED** | `test_telemetry_integrity.py`, `BehaviorGraphPage.tsx` | Process instance identity (`proc_{ev.id}`), temporal PID reuse resolution, API call event filtering (API calls are not processes). |
| **Evidence Correlation Engine & Explorer** | **VERIFIED** | `test_evidence_correlation.py` (19/19 PASSED) | Bounded deterministic $O(F+E)$ correlation connecting Ghidra code observations with runtime dynamic events. HMAC-signed trace key. |
| **Evidence-Grounded AI Intelligence** | **VERIFIED** | `test_intelligence_engine.py`, `test_opencode_and_hardening.py` | Bounded evidence bundle, claim/fact verification, dedicated `X-Reporting-Token` authorization, zero external calls on mount. |
| **Doctor CLI & Safe Intake Smoke Test** | **VERIFIED** | `test_doctor_cli.py` (13/13 PASSED) | Idempotent diagnostics distinguishing app install, CAPE configuration, API reachability, and guest VM readiness. Safe non-executing intake smoke test. |
| **Notion-Inspired Single-Action UI** | **VERIFIED** | Vitest (`47/47 PASSED`), `tsc --noEmit`, `vite build`, `npm audit` (`0 vulnerabilities`) | Single-action suspicious file upload, CAPE readiness badge, real active threat statistics on Dashboard, and Malware Classification section. |

---

## 2. Test Execution Outcomes

### Backend (`pytest` 9.2.0)
- **Backend Test Suite:** **171 passed, 1 skipped** (`test_live_ghidra_bwrap_smoke_opt_in` skipped by default unless `MALBOX_RUN_LIVE_GHIDRA_TEST=1`)

### Frontend (`tsc --noEmit` + `vitest` 4.1.12 + `vite` 6.4.6)
- **Frontend Unit Tests:** **47/47 PASSED** across 5 test suites (`DesignSystemAndTheme.test.tsx` [8], `CorrelationPage.test.tsx` [10], `ReportPage.test.tsx` [11], `EnrichmentFlow.test.tsx` [4], `StaticAnalysisPage.test.tsx` [14])
- **TypeScript Strict Check:** `npm run typecheck` PASSED (0 errors)
- **Production Build:** `npm run build` PASSED (clean bundle in 1.69s)
- **Dependency Audit Baseline:** `npm audit` $\rightarrow$ 0 vulnerabilities

### Doctor & Safe Intake Smoke Test
- `./malbox doctor --check`: 13 PASS, 0 WARN, 0 FAIL, 2 SKIP
- `./malbox doctor --smoke-test`: 14 PASS, 0 WARN, 0 FAIL, 2 SKIP (Sample intake verified, 0400 permissions verified, DB persistence confirmed)

### Real Browser Visual Verification
- 20 real screenshots captured with headless Chromium across desktop (1440×900), laptop (1024×768), and mobile (390×844) viewports in light and dark themes. Archived in `docs/ui/screenshots/` and `docs/screenshots/`.
