# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.2.1-live-cape-ui-redesign  
**Active Branch:** `fix/live-cape-portability-ui-redesign`  
**Baseline Commit SHA:** `63551e2fa626e24d3368a00d7020235d1e0cd45f`  
**Status:** **OPERATIONAL — LIVE SANDBOX RELIABILITY & NOTION UI REDESIGN VERIFIED**  
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
| **AI Analysis Orchestrator** | **VERIFIED** | `test_ai_orchestration.py`, `test_real_ai_provider.py` | Structured preflight planner, positive allowlist policy validation, RealLLMProvider (HTTP) + fallback to Mock, audit tracking with token metadata. Follow-up classified as advisory recommendation. |
| **Deterministic Rule Engine** | **VERIFIED** | `test_detection_rules.py` (9/9 PASSED) | Contextual thresholds for ransomware, shadow copy deletion, persistence, PowerShell, credential vaults, C2 HTTP, and SMB probes; expanded with `RULE_DROPPED_EXECUTABLE_PAYLOAD` (T1027/T1105) and `RULE_PROCESS_INJECTION_TECHNIQUE` (T1055) with benign negative tests. |
| **Cytoscape.js Behavior Graph**| **VERIFIED** | `test_telemetry_integrity.py` | Unique process-instance identity (`proc_{ev.id}`), temporal PID reuse resolution, unattributed network activity isolated to `node_unattributed_network`, 100% grounded edges. |
| **Evidence Provenance & Reporting**| **VERIFIED** | `test_telemetry_integrity.py`, `test_intelligence_engine.py`, `export_html.py` | Non-fabricated environment metadata, explicit Replay provenance, synthetic mock artifact labeling (`is_synthetic`), XSS-safe HTML export with strict CSP. |
| **Evidence-Grounded AI Intelligence (v2.0)** | **VERIFIED** | `test_intelligence_engine.py`, `test_opencode_and_hardening.py`, `docs/architecture/intelligence-v2.md` | DB-bounded `VerifiedEvidenceBundle` with hard byte limit (`BundleSizeLimitError`), semantic claim/entity/category validation (`DETERMINISTIC_FACT`, `ANALYST_INFERENCE`, `UNCERTAIN_HYPOTHESIS`), dedicated `X-Reporting-Token` authorization, shared bounded `EnrichmentCoordinator` with timeout cancellation & true slot retention, stale-write fencing, and secret/path redaction. |
| **Restricted OpenCode Adapter (v2.1.4)** | **VERIFIED (HOST)** | `test_opencode_and_hardening.py`, `docs/ai/OPENCODE_INTEGRATION.md`, `.opencode/agents/report-analyst.md` | Optional, disabled-by-default `mode: primary` adapter with disabled privileged built-in agents, mandatory Bubblewrap (`bwrap`) Linux namespace isolation (`--unshare-all`, `--cap-drop ALL`, `--clearenv`, RO mounts, bounded tmpfs, `ApprovedProviderProxy`), dynamic CLI version verification, POSIX rlimits, JSONL stream guards, `killpg` cancellation, and truthful deterministic fallback. |
| **Doctor & Bootstrap CLI** | **VERIFIED** | `test_doctor_cli.py` (13/13 PASSED) | Idempotent `./malbox doctor/start/stop/status`, strong OS PID/PGID ownership verification, 0600 `.env` & 0700 `.malbox` permissions, active CAPE connectivity probe via stdlib `urllib.request`. |
| **Notion-Inspired Forensic UI** | **VERIFIED** | Vitest + React Testing Library (`42/42 PASSED`), `tsc --noEmit`, `vite build`, `npm audit` (`0 vulnerabilities`) | Warm paper canvas (`#f6f5f4`), pure white cards (`#ffffff`), hairline borders (`rgba(0,0,0,0.08)`), 12px corners, Notion Blue (`#0075de`) CTAs, light/dark theme switch with `localStorage` persistence, guided 5-step submission wizard, and responsive layout. |
| **Live CAPE Sandbox Backend** | **VERIFIED (ADAPTER & CONTRACT)** | `test_cape_adapter.py` (9/9 PASSED) | Flat and wrapped status parsing, options allowlist, graceful machine tag mapping, completed-before-reported race retry, error envelope handling, analyzer crash detection, and strict telemetry completeness quality gate (`COMPLETE`, `PARTIAL`, `INCOMPLETE`, `UNVERIFIED`). Real hypervisor guest VM requires live lab setup. |
| **Static Decompilation (Ghidra Phase 3A.1 & 3B UI + Gate 0)** | **VERIFIED (FOUNDATION + FUNCTION EXPLORER UI)** | `test_static_analysis.py`, `StaticAnalysisPage.test.tsx` | Optional, disabled-by-default (`MALBOX_GHIDRA_ENABLED=false`) non-executing Ghidra Headless PE analyzer (`binary_executed=False`) with mandatory Bubblewrap + `systemd-run --user` memory containment, Gate 0 generation/abort request fencing, sticky `Pause Polling`, preserved last-usable completed evidence over failed retries, sibling active-job fallback isolation, lazy-loaded `StaticAnalysisPage` UI. |
| **Evidence Correlation Engine & Explorer (Phase 4A, 4A.1 & 4B)** | **VERIFIED (PHASE 4B COMPLETE)** | `test_evidence_correlation.py`, `CorrelationPage.test.tsx` | Bounded deterministic `O(F+E)` correlation connecting verified Ghidra code observations (`func:`, `str:`, imports) with normalized dynamic events without equating API presence to runtime execution. HMAC-isolated `trace_auth` verification. |

---

## 2. Test Execution Outcomes

### Backend (`pytest` 9.2.0)
- **Backend Test Suite:** **148 passed, 1 skipped** (`test_live_ghidra_bwrap_smoke_opt_in` skipped by default unless `MALBOX_RUN_LIVE_GHIDRA_TEST=1`)

### Frontend (`tsc --noEmit` + `vitest` 4.1.12 + `vite` 6.4.6)
- **Frontend Unit Tests:** **42/42 PASSED** across 5 test suites (`DesignSystemAndTheme.test.tsx`, `CorrelationPage.test.tsx`, `ReportPage.test.tsx`, `EnrichmentFlow.test.tsx`, `StaticAnalysisPage.test.tsx`)
- **TypeScript Strict Check:** `npm run typecheck` PASSED (0 errors)
- **Production Build:** `npm run build` PASSED (clean bundle in 1.87s)
- **Dependency Audit Baseline:** `npm audit` -> 0 vulnerabilities (`vite@^6.4.6`, `vitest@^4.1.12`)
- **Opt-In Live Ghidra + Bubblewrap + Cgroup v2 Smoke Test (`MALBOX_RUN_LIVE_GHIDRA_TEST=1`):** **Verified in Phase 3B Gate 0 (`843947c`)** (Ghidra `12.1.4` + OpenJDK `25.0.4.1` + `ExportProgramFacts.java` inside `systemd-run --user --scope` + `bwrap` on harmless constructed PE32 stub with decompiler `entry` output verified; `binary_executed=False`)
- **Hosted `ubuntu-latest` CI Note:** Tests requiring host Linux `bwrap`/`opencode`/`ghidra` binaries (`test_real_bwrap_sandbox_and_real_opencode_cli_integration`, `test_live_ghidra_bwrap_smoke_opt_in`) skip cleanly when absent on hosted CI runners.

### Frontend (`tsc --noEmit` + `vitest` 4.1.12 + `vite` 6.4.6)
- **Frontend Unit Tests:** **39/39 PASSED** across `frontend/src/__tests__/CorrelationPage.test.tsx` (10), `frontend/src/__tests__/ReportPage.test.tsx` (11), `frontend/src/__tests__/EnrichmentFlow.test.tsx` (4), and `frontend/src/__tests__/StaticAnalysisPage.test.tsx` (14)
- **TypeScript Strict Check:** `npm run typecheck` PASSED (0 errors)
- **Production Build:** `npm run build` PASSED (lazy-loaded `StaticAnalysisPage` & split `cytoscape.esm` chunks)
- **Dependency Audit Baseline:** `npm audit` -> 0 vulnerabilities (`vite@^6.4.6`, `vitest@^4.1.12`)

### Test Breakdown by Subsystem
1. `backend/tests/test_ai_orchestration.py`: (5/5 PASSED)
2. `backend/tests/test_cape_adapter.py`: (3/3 PASSED)
3. `backend/tests/test_detection_rules.py`: (6/6 PASSED)
4. `backend/tests/test_doctor_cli.py`: (12/12 PASSED, including Phase 4B Gate 0 `MALBOX_TRACE_AUTH_KEY` policy & secret redaction; RC Gate 1 Phase 3/4 DB table health checks for `static_analysis_results` and `evidence_correlations`)
5. `backend/tests/test_evidence_correlation.py`: (19/19 PASSED, covering Phase 4A + Phase 4A.1 + Phase 4B Gate 0 trace-key isolation & HTML correlation export + RC Gate 0 coherent correlation selection & fenced async lookup)
6. `backend/tests/test_health.py`: (2/2 PASSED)
7. `backend/tests/test_intelligence_engine.py`: (13/13 PASSED)
8. `backend/tests/test_opencode_and_hardening.py`: (13/13 PASSED)
9. `backend/tests/test_pe_parser.py`: (5/5 PASSED)
10. `backend/tests/test_real_ai_provider.py`: (6/6 PASSED)
11. `backend/tests/test_replay_pipeline.py`: (5/5 PASSED)
   - `test_full_replay_analysis_pipeline` [PASSED]
   - `test_replay_scenario_wannacry_independent_of_profile` [PASSED]
   - `test_replay_scenario_redline_independent_of_profile` [PASSED]
   - `test_replay_scenario_alias_compatibility` [PASSED]
   - `test_replay_invalid_scenario_id_does_not_silently_fallback` [PASSED]
12. `backend/tests/test_safety_and_lifecycle.py`: (14/14 PASSED)
13. `backend/tests/test_static_analysis.py`: (26/26 unit PASSED, 1 opt-in live test skipped by default; Phase 4A Gate 0 regression checks verified)
14. `backend/tests/test_submission.py`: (3/3 PASSED)
15. `backend/tests/test_telemetry_integrity.py`: (7/7 PASSED)

---

## 3. Automated Performance & Memory Benchmark Summary

Measured via `scripts/benchmark_replay.py`:

### System Specifications Under Test
- **OS Platform:** Linux 7.1.5+kali-amd64 (x86_64)
- **Python Version:** CPython 3.14.7
- **CPU Cores:** 12 logical cores
- **Total System RAM:** ~7,627 MB
- **Environment:** Host Development / CI Baseline (Pre-VM Validation)

### Standard Replay Scenarios
| Scenario | Pipeline Latency | CPU Time | Scenario Peak Alloc | Process Peak RSS | Events | Graph Build |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WannaCry Ransomware** | 101.08 ms | 79.61 ms | 0.84 MB | 402.11 MB | 15 | 2.52 ms (17 nodes, 16 edges) |
| **RedLine Infostealer** | 134.11 ms | 112.23 ms | 0.16 MB | 402.11 MB | 12 | 3.18 ms (14 nodes, 13 edges) |

### Synthetic Telemetry Scaling (Sequential)
| Scale | Events Count | Normalization Duration | Ingestion Throughput | DB Write Time | Graph Build Time | Report Duration | Scenario Alloc |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 101 events | 48.91 ms | 2,065.1 ev/s | 1.89 ms | 21.04 ms (104 nodes) | 18.92 ms | 0.86 MB |
| **Medium** | 1,001 events | 158.45 ms | 6,317.6 ev/s | 7.78 ms | 82.63 ms (987 nodes) | 90.12 ms | 7.98 MB |
| **Large** | 10,001 events | 1,583.47 ms | 6,315.9 ev/s | 66.64 ms | 914.55 ms (8,970 nodes) | 1,056.20 ms | 74.47 MB |

### API Endpoint Response Latencies
| Endpoint | Method | Response Latency |
| :--- | :--- | :--- |
| `/api/v1/health` | GET | 17.47 ms |
| `/api/v1/samples` (Upload & Triage) | POST | 10.42 ms |
| `/api/v1/analyses` (Synchronous Replay Pipeline) | POST | 87.24 ms |
| `/api/v1/analyses/{id}` (Status Polling) | GET | 10.57 ms |
| `/api/v1/analyses/{id}/graph` (Cytoscape Elements) | GET | 15.03 ms |
| `/api/v1/analyses/{id}/report` (Structured Findings) | GET | 7.07 ms |
