# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.2.2-live-integrity-ux-final  
**Active Branch:** `fix/live-cape-portability-ui-redesign`  
**Baseline Commit SHA:** `63551e2fa626e24d3368a00d7020235d1e0cd45f`  
**Phase A Commit SHA:** `17d3516` (`fix(cape): repair pipeline contract and enforce task/report integrity`)  
**Phase B Commit SHA:** `a8170d7` (`fix(detection): preserve evidence quality and contextual live findings`)  
**Phase C Commit:** `feat(ui): finalize forensic workspace shell and evidence-aware UX`  
**Status:** **OPERATIONAL — READY FOR REPLAY AND BENIGN LIVE ACCEPTANCE**  
**Release Documents:**
- [`LIVE_CAPE_REMEDIATION.md`](audit/LIVE_CAPE_REMEDIATION.md) — Gate 0 Live Sandbox Audit & Remediation Matrix (All 11 Issues Remediated)
- [`cape-integration.md`](setup/cape-integration.md) — CAPE Sandbox v2 Production Integration Guide
- [`virtualbox-isolated-network.md`](setup/virtualbox-isolated-network.md) — Persistent VirtualBox Host-Only Network Configuration Guide
- [`live-telemetry-integrity.md`](architecture/live-telemetry-integrity.md) — Live Telemetry Completeness & Evidence Integrity Architecture
- [`DESIGN_SYSTEM.md`](ui/DESIGN_SYSTEM.md) — Notion-Inspired Forensic Design System Reference
- [`UX_REDESIGN_REPORT.md`](ui/UX_REDESIGN_REPORT.md) — Comprehensive UX Redesign & Workspace Modernization Report

---

## 1. Feature Completion Matrix & Readiness Classification

| Subsystem | Readiness | Verification Evidence | Operational Details |
| :--- | :--- | :--- | :--- |
| **PE Submission & Triage** | **VERIFIED** | `test_pe_parser.py`, `test_submission.py` | Computes SHA-256, SHA-1, MD5; extracts imports/sections/entropy; isolates in quarantine (0400). |
| **Execution Safety Gate** | **VERIFIED** | `test_safety_and_lifecycle.py` | Strict enum validation, server policy check, per-task user approval, fail-closed operator token authorization with `compare_digest`. |
| **Reliable Job Lifecycle** | **VERIFIED** | `test_safety_and_lifecycle.py` | Persistent `JobQueueManager`, strict concurrency=1 (including `execute_sync`), crash recovery, terminal state protection, race-free cancellation. |
| **Replay Scenario API Contract**| **VERIFIED** | `test_replay_pipeline.py` | Synchronized `replay_scenario_id` contract across React frontend (`SubmitPage.tsx`, `client.ts`) and FastAPI backend. Independent execution of WannaCry and RedLine scenarios. No silent fallbacks. |
| **AI Analysis Orchestrator** | **VERIFIED** | `test_ai_orchestration.py`, `test_real_ai_provider.py` | Structured preflight planner, positive allowlist policy validation, RealLLMProvider (HTTP) + fallback to Mock, audit tracking with token metadata. |
| **Deterministic Rule Engine (v0.2.2)** | **VERIFIED** | `test_detection_rules.py` (14/14 PASSED) | Contextual thresholds for ransomware, shadow copy deletion, persistence, PowerShell, credential vaults, C2 HTTP, and SMB probes; strict contextual process memory injection (T1055) and dropped executable write verification (T1027/T1105). Calibrated risk levels by telemetry completeness. |
| **Cytoscape.js Behavior Graph**| **VERIFIED** | `test_telemetry_integrity.py`, `BehaviorGraphPage.tsx` | Unique process-instance identity (`proc_{ev.id}`), temporal PID reuse resolution, concrete theme color resolution for HTML5 canvas, generation-fenced async loading. |
| **Evidence Provenance & Reporting**| **VERIFIED** | `test_telemetry_integrity.py`, `test_intelligence_engine.py`, `export_html.py` | Non-fabricated environment metadata, explicit Replay provenance, synthetic mock artifact labeling (`is_synthetic`), XSS-safe HTML export with strict CSP. |
| **Evidence-Grounded AI Intelligence (v2.0)** | **VERIFIED** | `test_intelligence_engine.py`, `test_opencode_and_hardening.py`, `docs/architecture/intelligence-v2.md` | DB-bounded `VerifiedEvidenceBundle` with hard byte limit (`BundleSizeLimitError`), semantic claim/entity/category validation (`DETERMINISTIC_FACT`, `ANALYST_INFERENCE`, `UNCERTAIN_HYPOTHESIS`), dedicated `X-Reporting-Token` authorization. |
| **Restricted OpenCode Adapter (v2.1.4)** | **VERIFIED (HOST)** | `test_opencode_and_hardening.py`, `docs/ai/OPENCODE_INTEGRATION.md`, `.opencode/agents/report-analyst.md` | Optional, disabled-by-default `mode: primary` adapter with disabled privileged built-in agents, mandatory Bubblewrap (`bwrap`) Linux namespace isolation, dynamic CLI version verification. |
| **Doctor & Bootstrap CLI** | **VERIFIED** | `test_doctor_cli.py` (13/13 PASSED) | Idempotent `./malbox doctor/start/stop/status`, strong OS PID/PGID ownership verification, 0600 `.env` & 0700 `.malbox` permissions, active CAPE connectivity probe via `_probe_cape_readiness`. |
| **Notion-Inspired Forensic UI & Shell** | **VERIFIED** | Vitest (`46/46 PASSED`), `tsc --noEmit`, `vite build`, `npm audit` (`0 vulnerabilities`) | Warm paper canvas (`#f6f5f4`), pure white cards (`#ffffff`), hairline borders (`rgba(0,0,0,0.08)`), 12px corners, Notion Blue (`#0075de`) CTAs, light/dark theme switch, collapsible sidebar (250px to 68px), compact header with breadcrumbs and persistent active case pill, guided 5-step submission wizard, generation-fenced async analysis switching. |
| **Live CAPE Sandbox Backend** | **VERIFIED (PIPELINE & CONTRACT)** | `test_cape_adapter.py` (17/17 PASSED) | Pipeline contract separated from internal planning, options allowlist, flat/wrapped status parsing, task ID/SHA-256 validation, monotonic polling deadline, crash detection, hard telemetry ceilings, memory payload separation, and strict completeness contract. Real hypervisor guest VM requires live lab setup. |
| **Static Decompilation (Ghidra Phase 3A.1 & 3B UI + Gate 0)** | **VERIFIED** | `test_static_analysis.py` (26/26 PASSED), `StaticAnalysisPage.test.tsx` (14/14 PASSED) | Non-executing Ghidra Headless PE analyzer with Bubblewrap + `systemd-run --user` containment, Gate 0 generation/abort fencing, sticky `Pause Polling`, concrete theme color resolution for Cytoscape call graph. |
| **Evidence Correlation Engine & Explorer (Phase 4A, 4A.1 & 4B)** | **VERIFIED** | `test_evidence_correlation.py` (19/19 PASSED), `CorrelationPage.test.tsx` (10/10 PASSED) | Bounded deterministic `O(F+E)` correlation connecting verified Ghidra code observations with normalized dynamic events without equating API presence to runtime execution. Concrete theme color resolution. |

---

## 2. Test Execution Outcomes

### Backend (`pytest` 9.2.0)
- **Backend Test Suite:** **159 passed, 1 skipped** (`test_live_ghidra_bwrap_smoke_opt_in` skipped by default unless `MALBOX_RUN_LIVE_GHIDRA_TEST=1`)

### Frontend (`tsc --noEmit` + `vitest` 4.1.12 + `vite` 6.4.6)
- **Frontend Unit Tests:** **46/46 PASSED** across 5 test suites (`DesignSystemAndTheme.test.tsx` [7], `CorrelationPage.test.tsx` [10], `ReportPage.test.tsx` [11], `EnrichmentFlow.test.tsx` [4], `StaticAnalysisPage.test.tsx` [14])
- **TypeScript Strict Check:** `npm run typecheck` PASSED (0 errors)
- **Production Build:** `npm run build` PASSED (clean bundle in 1.82s)
- **Dependency Audit Baseline:** `npm audit` -> 0 vulnerabilities

### Doctor & Replay Smoke Test
- `./malbox doctor --check`: 13 PASS, 0 WARN, 0 FAIL, 2 SKIP
- `./malbox doctor --smoke-test`: 14 PASS, 0 WARN, 0 FAIL, 2 SKIP (WannaCry scenario, 5 findings, 18 graph nodes, 947.71 ms, 90.92 MB peak RSS)

### Real Browser Visual Verification
- 20 real screenshots captured with headless Chromium across 7 core pages, 3 viewports (1440×900, 1024×768, 390×844), light and dark themes. Archived in `docs/screenshots/`.
