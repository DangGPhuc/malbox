# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.2.2-live-first-safety-hardened  
**Active Branch:** `fix/live-cape-portability-ui-redesign`  
**Baseline Commit SHA:** `5021959`  
**Status:** **OPERATIONAL — COMPLETE AUTOMATED PROVISIONING & PRODUCTION LIVE-FIRST PLATFORM**  
**CI Run:** [https://github.com/DangGPhuc/malbox/actions/runs/44761351446](https://github.com/DangGPhuc/malbox/actions/runs/44761351446) (PASS: Backend 272 passed, Frontend 51 passed)
**Release Documents:**
- [`docs/deployment/REMNUX_VIRTUALBOX_INSTALLATION_GUIDE.md`](deployment/REMNUX_VIRTUALBOX_INSTALLATION_GUIDE.md) — Complete Step-by-Step Installation Guide for REMnux Gateway & REMWin VirtualBox Lab
- [`docs/deployment/REMNUX_VIRTUALBOX_LAB.md`](deployment/REMNUX_VIRTUALBOX_LAB.md) — Deployment Profile Specification for Dual-Interface Peer-VM Architecture
- [`docs/architecture/ADR_REMNUX_VIRTUALBOX_GATEWAY.md`](architecture/ADR_REMNUX_VIRTUALBOX_GATEWAY.md) — ADR-008: Deterministic REMnux Gateway and REMWin Automated Sandbox Architecture
- [`docs/deployment/OPERATOR_INSTALLATION_GUIDE.md`](deployment/OPERATOR_INSTALLATION_GUIDE.md) — Complete Automated Operator Installation & Provisioning Guide
- [`docs/deployment/UNINSTALL_AND_ROLLBACK.md`](deployment/UNINSTALL_AND_ROLLBACK.md) — Teardown, State Reset, and Complete Uninstall Guide
- [`docs/architecture/live-first-analysis.md`](architecture/live-first-analysis.md) — Live-First Suspicious File Analysis Architecture & Confinement Gate
- [`docs/architecture/malware-classification.md`](architecture/malware-classification.md) — 17-Category Evidence-Grounded Malware Classification Taxonomy
- [`docs/setup/cape-integration.md`](setup/cape-integration.md) — CAPE Sandbox v2 Production Integration & Isolation Attestation Guide
- [`docs/setup/virtualbox-isolated-network.md`](setup/virtualbox-isolated-network.md) — Persistent VirtualBox Host-Only Network Configuration Guide
- [`docs/ui/DESIGN_SYSTEM.md`](ui/DESIGN_SYSTEM.md) — Notion-Inspired Forensic Design System Reference
- [`docs/ui/UX_REDESIGN_REPORT.md`](ui/UX_REDESIGN_REPORT.md) — Comprehensive UX Redesign & Workspace Modernization Report

---

## 1. Feature Completion Matrix & Safety Hardening Classification

| Subsystem | Readiness | Verification Evidence | Operational Details |
| :--- | :--- | :--- | :--- |
| **REMnux Gateway & VirtualBox Peer-VM Lab** | **VERIFIED** | `test_remnux_virtualbox_gateway.py` (20/20 PASSED) | Peer-VM execution topology (`REMNUX_VIRTUALBOX_LAB`). Dual-network isolation (`vboxnet0` 192.168.56.0/24 + `malbox-sandbox` 10.77.0.0/24). Physical host controller with HMAC replay defense, VM allowlist, and clean snapshot cycling. Constrained MCP tool server. Non-negotiable invariant: ZERO AI outside Kali. |
| **Mandatory CAPE Confinement Gate** | **VERIFIED** | `test_cape_confinement_gate.py` (8/8 PASSED) | Fail-closed isolation contract (`verify_cape_confinement`). Requires explicit operator attestation (`cape_isolation_attestation.json`), unexpired timestamp, and safe route allowlist (`drop`, `none`, `isolated`). Configured route name never implies verified isolation. |
| **Ghidra / CAPE Sequential Synchronization** | **VERIFIED** | `test_ghidra_sequential_cleanup.py` (3/3 PASSED) | Pipeline waits for Ghidra completion before CAPE detonation. On Ghidra timeout, enforces process group termination via `cancel_active(wait_seconds)`. If Ghidra process remains active, transitions to `FAILED` and blocks CAPE. Accurately records `TIMED_OUT`. |
| **Bounded CAPE Transport & Monotonic Deadlines** | **VERIFIED** | `test_cape_transport_deadline.py` (6/6 PASSED) | Strict monotonic deadline spanning polling, report retrieval, and artifact streaming. Eliminates artificial 5s deadline extension. Bounded streaming bodies (50 MB report, 100 MB artifact). 200 MB free disk space check. Guaranteed `.tmp` file cleanup on failure. |
| **Strict Classification Evidence Integrity** | **VERIFIED** | `test_classification_evidence_integrity.py` (6/6 PASSED), `test_malware_classification.py` (16/16 PASSED) | Complete elimination of synthetic placeholder IDs (`EVENT:*`, `PE:*`). Resolves all evidence IDs against persisted SQLite records for the specific `analysis_id`. Fences cross-analysis references. Requires verified remote threads for Injector, linked transfers for Downloader, and evasive flags for Launcher. Constrains confidence under partial telemetry. |
| **Frontend Authorization & Confinement UX** | **VERIFIED** | `DesignSystemAndTheme.test.tsx` (8/8 PASSED), `SubmitPage.tsx` | Single-action Analyze File workflow. Displays explicit blocked state when guest network isolation is unverified. Operator tokens are strictly transient in-memory React state (zero storage in `localStorage` or `sessionStorage`). Duplicate submission prevention. |
| **PE Submission & Quarantine Intake** | **VERIFIED** | `test_submission.py` (6/6 PASSED) | Single-action file analysis intake. Quarantined with `0400` read-only permissions; SHA-256 deduplicated; preflight PE triage. |
| **Execution Safety Gate & Lifecycle** | **VERIFIED** | `test_safety_and_lifecycle.py` (14/14 PASSED) | Live-mode safety policy enforcement; explicit analyst safety confirmation; fail-closed operator token boundary (`MALBOX_OPERATOR_TOKEN`). Persistent `JobQueueManager`. |
| **Ghidra Headless Decompilation** | **VERIFIED** | `test_static_analysis.py` (26/26 PASSED) | Automatic static trigger with Bubblewrap sandbox containment; ranking of high-risk functions; graceful fallback if disabled. |
| **CAPE Sandbox Dynamic Detonation** | **VERIFIED** | `test_cape_adapter.py` (17/17 PASSED) | Automatic package routing (`dll` vs `exe`), bounded polling lifecycle, crash detection, 50MB report cap, 100MB artifact cap. |
| **Deterministic Rule Engine** | **VERIFIED** | `test_detection_rules.py` (12/12 PASSED) | Contextual thresholds for ransomware, shadow copy deletion, persistence, PowerShell, credential vaults, C2 HTTP, and SMB probes. |
| **Cytoscape.js Behavior Graph** | **VERIFIED** | `test_telemetry_integrity.py` (7/7 PASSED), `BehaviorGraphPage.tsx` | Process instance identity (`proc_{ev.id}`), temporal PID reuse resolution, API call event filtering (API calls are not processes). |
| **Evidence Correlation Engine & Explorer** | **VERIFIED** | `test_evidence_correlation.py` (19/19 PASSED) | Bounded deterministic $O(F+E)$ correlation connecting Ghidra code observations with runtime dynamic events. HMAC-signed trace key. |
| **Evidence-Grounded AI Intelligence** | **VERIFIED** | `test_intelligence_engine.py` (13/13 PASSED), `test_opencode_and_hardening.py` (13/13 PASSED) | Bounded evidence bundle, claim/fact verification, dedicated `X-Reporting-Token` authorization, zero external calls on mount. |
| **Automated Provisioning & Hardware Discovery** | **VERIFIED** | `test_automated_provisioning.py` (13/13 PASSED) | Hardware detection, Profile A/B/C recommendation, core setup, Ghidra detection/containment, AI model catalog, CAPE installer scripts, guest templates, isolation evidence collector, and minimal benign PE acceptance. |
| **7-Tier Infrastructure Readiness Dashboard** | **VERIFIED** | `InfrastructurePage.test.tsx` (3/3 PASSED), `test_health.py` | 7 core tiers (Application, Static, AI, CAPE, Guest, Confinement, Detonation), 8 subsystem cards, copyable CLI remediation commands. Never treats `APPLICATION_READY` as `DETONATION_READY`. |
| **Doctor CLI & Safe Intake Smoke Test** | **VERIFIED** | `test_doctor_cli.py` (13/13 PASSED) | Idempotent diagnostics distinguishing app install, CAPE configuration, API reachability, and guest VM readiness. Safe non-executing intake smoke test. |

---

## 2. Test Execution Outcomes

### Backend (`pytest` 9.2.0)
- **Full Backend Test Suite:** **292 passed, 1 skipped** in 59.12s
  * `test_remnux_virtualbox_gateway.py`: 20 passed
  * `test_automated_provisioning.py`: 13 passed
  * `test_cape_confinement_gate.py`: 8 passed
  * `test_ghidra_sequential_cleanup.py`: 3 passed
  * `test_cape_transport_deadline.py`: 6 passed
  * `test_classification_evidence_integrity.py`: 6 passed
  * `test_cape_adapter.py`: 17 passed
  * `test_malware_classification.py`: 16 passed
  * `test_evidence_correlation.py`: 19 passed
  * `test_static_analysis.py`: 26 passed, 1 skipped (`test_live_ghidra_bwrap_smoke_opt_in`)
  * `test_pipeline_e2e_integration.py`: 6 passed
  * `test_replay_pipeline.py`: 5 passed
  * `test_intelligence_engine.py`: 13 passed
  * `test_opencode_and_hardening.py`: 13 passed
  * `test_detection_rules.py`: 12 passed
  * `test_doctor_cli.py`: 13 passed
  * `test_safety_and_lifecycle.py`: 14 passed
  * `test_submission.py`: 6 passed
  * `test_pe_parser.py`: 5 passed
  * `test_live_first_defaults.py`: 5 passed
  * `test_ai_orchestration.py`: 5 passed
  * `test_real_ai_provider.py`: 6 passed
  * `test_telemetry_integrity.py`: 7 passed
  * `test_health.py`: 3 passed
  * `test_product_completion.py`: 24 passed

### Frontend (`vitest` 4.1.12 + `tsc` + `vite` 6.4.6)
- **Frontend Unit Tests:** **51/51 PASSED** across 6 test suites (`DesignSystemAndTheme.test.tsx` [9], `CorrelationPage.test.tsx` [10], `ReportPage.test.tsx` [11], `EnrichmentFlow.test.tsx` [4], `StaticAnalysisPage.test.tsx` [14], `InfrastructurePage.test.tsx` [3])
- **TypeScript Strict Check:** `tsc` PASSED (0 errors)
- **Production Build:** `vite build` PASSED (clean bundle in 2.43s)
- **Dependency Audit Baseline:** `npm audit` $\rightarrow$ 0 vulnerabilities

### Doctor & Safe Intake Smoke Test
- `./malbox doctor --smoke-test`: 14 PASS, 1 WARN (CAPE offline - expected on unattached host), 0 FAIL, 1 SKIP. Quarantined with 0400 permissions, DB persistence verified.
