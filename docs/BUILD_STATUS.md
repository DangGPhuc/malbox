# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.2.4-alpha (Phase 3A.1 Ghidra Runtime Hardening)  
**Active Branch:** `fix/phase3a-ghidra-runtime-hardening`  
**Status:** **OPERATIONAL — PHASE 3A.1 GHIDRA RUNTIME HARDENING & CONTAINMENT VERIFIED**

---

## 1. Feature Completion Matrix & Readiness Classification

| Subsystem | Readiness | Verification Evidence | Operational Details |
| :--- | :--- | :--- | :--- |
| **PE Submission & Triage** | **VERIFIED** | `test_pe_parser.py`, `test_submission.py` | Computes SHA-256, SHA-1, MD5; extracts imports/sections/entropy; isolates in quarantine (0400). |
| **Execution Safety Gate** | **VERIFIED** | `test_safety_and_lifecycle.py` | Strict enum validation, server policy check, per-task user approval, fail-closed operator token authorization with `compare_digest`. |
| **Reliable Job Lifecycle** | **VERIFIED** | `test_safety_and_lifecycle.py` | Persistent `JobQueueManager`, strict concurrency=1 (including `execute_sync`), crash recovery, terminal state protection, race-free cancellation. |
| **Replay Scenario API Contract**| **VERIFIED** | `test_replay_pipeline.py` | Synchronized `replay_scenario_id` contract across React frontend (`SubmitPage.tsx`, `client.ts`) and FastAPI backend. Independent execution of WannaCry and RedLine scenarios. No silent fallbacks. |
| **AI Analysis Orchestrator** | **VERIFIED** | `test_ai_orchestration.py`, `test_real_ai_provider.py` | Structured preflight planner, positive allowlist policy validation, RealLLMProvider (HTTP) + fallback to Mock, audit tracking with token metadata. Follow-up classified as advisory recommendation. |
| **Deterministic Rule Engine** | **VERIFIED** | `test_detection_rules.py` | Contextual thresholds (T1490, T1486, T1547.001, T1059.001, T1555.003, T1071.001, T1046); negative regression tests for lone ransom note and normal HTTP POST. |
| **Cytoscape.js Behavior Graph**| **VERIFIED** | `test_telemetry_integrity.py` | Unique process-instance identity (`proc_{ev.id}`), temporal PID reuse resolution, unattributed network activity isolated to `node_unattributed_network`, 100% grounded edges. |
| **Evidence Provenance & Reporting**| **VERIFIED** | `test_telemetry_integrity.py`, `test_intelligence_engine.py`, `export_html.py` | Non-fabricated environment metadata, explicit Replay provenance, synthetic mock artifact labeling (`is_synthetic`), XSS-safe HTML export with strict CSP. |
| **Evidence-Grounded AI Intelligence (v2.0)** | **VERIFIED** | `test_intelligence_engine.py`, `test_opencode_and_hardening.py`, `docs/architecture/intelligence-v2.md` | DB-bounded `VerifiedEvidenceBundle` with hard byte limit (`BundleSizeLimitError`), semantic claim/entity/category validation (`DETERMINISTIC_FACT`, `ANALYST_INFERENCE`, `UNCERTAIN_HYPOTHESIS`), dedicated `X-Reporting-Token` authorization, shared bounded `EnrichmentCoordinator` with timeout cancellation & true slot retention, stale-write fencing, and secret/path redaction. |
| **Restricted OpenCode Adapter (v2.1.4)** | **VERIFIED (HOST)** | `test_opencode_and_hardening.py`, `docs/ai/OPENCODE_INTEGRATION.md`, `.opencode/agents/report-analyst.md` | Optional, disabled-by-default `mode: primary` adapter with disabled privileged built-in agents, mandatory Bubblewrap (`bwrap`) Linux namespace isolation (`--unshare-all`, `--cap-drop ALL`, `--clearenv`, RO mounts, bounded tmpfs, `ApprovedProviderProxy`), dynamic CLI version verification, POSIX rlimits, JSONL stream guards, `killpg` cancellation, and truthful deterministic fallback. *Note: Real `bwrap` + `opencode` integration was skipped on `ubuntu-latest` CI and verified locally on Kali; independent Kali VM validation recommended before external use.* |
| **Doctor & Bootstrap CLI** | **VERIFIED** | `test_doctor_cli.py` | Idempotent `./malbox doctor/start/stop/status`, strong OS PID/PGID ownership verification, 0600 `.env` & 0700 `.malbox` permissions, offline Replay setup. |
| **Intelligence Report Web UI** | **VERIFIED** | Vitest + React Testing Library (`15/15 PASSED`), `tsc --noEmit`, `vite build`, `npm audit` (`0 vulnerabilities`) | Modular evidence-grounded dark-mode report dashboard (`frontend/src/components/IntelligenceReport/`), strict TypeScript contracts, Replay & synthetic artifact badges, FACT/INFERENCE/HYPOTHESIS + EvidenceExplorer, explicit in-memory `X-Reporting-Token` & external consent enrichment UX, print-friendly PDF & CSP-safe HTML exports, lazy-loaded Cytoscape graph, `auto`-mode consent enforcement, multi-page event lookup pagination, and full-report print state restoration. |
| **Live CAPE Sandbox Backend** | **PARTIAL** | `test_cape_adapter.py` | Fully implemented and unit-tested adapter with readiness checks, task polling, report transformation, and cancellation. Real hypervisor execution remains disabled by policy. |
| **Static Decompilation (Ghidra Phase 3A.1)** | **VERIFIED (HARDENED FOUNDATION)** | `test_static_analysis.py`, [`static-analysis-v1.md`](architecture/static-analysis-v1.md), [`GHIDRA_SETUP_GUIDE.md`](GHIDRA_SETUP_GUIDE.md), [`GHIDRA_SECURITY_MODEL.md`](GHIDRA_SECURITY_MODEL.md) | Optional, disabled-by-default (`MALBOX_GHIDRA_ENABLED=false`) non-executing Ghidra Headless PE analyzer (`binary_executed=False`) with mandatory Bubblewrap (`--unshare-all --cap-drop ALL --clearenv`) + unprivileged Linux cgroup v2 process-tree memory containment (`systemd-run --user MemoryMax=1280M`, `MemorySwapMax=0`, `GHIDRA_MAX_HEAP_MB=512`), VM `MemAvailable` preflight, strict subprocess exit-code integrity, immediate owned-PGID termination on stream overflow (`SIGTERM` grace -> `SIGKILL`), ancestor symlink rejection, shutdown cancellation propagation, persistence size gate, deterministic `rank_functions()` prioritization, and Intelligence bridge (`decompiled_omitted_for_external_ai=True`). Phase 3B UI views and Phase 4 correlation remain out of scope. |

---

## 2. Test Execution Outcomes

### Backend (`pytest` 9.2.0)
- **Local Host Default Suite (Kali, `bwrap` + `opencode v2.1.4`):** **116 passed, 1 skipped** (`test_live_ghidra_bwrap_smoke_opt_in` skipped by default unless `MALBOX_RUN_LIVE_GHIDRA_TEST=1`)
- **Opt-In Live Ghidra + Bubblewrap + Cgroup v2 Smoke Test (`MALBOX_RUN_LIVE_GHIDRA_TEST=1`):** **1 passed** (Ghidra `12.1.4` + OpenJDK `25.0.4.1` + `ExportProgramFacts.java` inside `systemd-run --user --scope` + `bwrap` on harmless constructed PE32 stub in 48.56s; `binary_executed=False`)
- **Hosted `ubuntu-latest` CI Note:** Tests requiring host Linux `bwrap`/`opencode`/`ghidra` binaries (`test_real_bwrap_sandbox_and_real_opencode_cli_integration`, `test_live_ghidra_bwrap_smoke_opt_in`) skip cleanly when absent on hosted CI runners.

### Frontend (`tsc --noEmit` + `vitest` 4.1.12 + `vite` 6.4.6)
- **Frontend Unit Tests:** **15/15 PASSED** across `frontend/src/__tests__/ReportPage.test.tsx` (11) and `frontend/src/__tests__/EnrichmentFlow.test.tsx` (4)
- **TypeScript Strict Check:** `npm run typecheck` PASSED (0 errors)
- **Production Build:** `npm run build` PASSED (1.67s)
- **Dependency Audit Baseline:** `npm audit` -> 0 vulnerabilities (`vite@^6.4.6`, `vitest@^4.1.12`)

### Test Breakdown by Subsystem
1. `backend/tests/test_ai_orchestration.py`: (5/5 PASSED)
2. `backend/tests/test_cape_adapter.py`: (3/3 PASSED)
3. `backend/tests/test_detection_rules.py`: (6/6 PASSED)
4. `backend/tests/test_doctor_cli.py`: (11/11 PASSED)
5. `backend/tests/test_health.py`: (2/2 PASSED)
6. `backend/tests/test_intelligence_engine.py`: (13/13 PASSED)
7. `backend/tests/test_opencode_and_hardening.py`: (13/13 PASSED)
8. `backend/tests/test_pe_parser.py`: (5/5 PASSED)
9. `backend/tests/test_real_ai_provider.py`: (6/6 PASSED)
10. `backend/tests/test_replay_pipeline.py`: (5/5 PASSED)
   - `test_full_replay_analysis_pipeline` [PASSED]
   - `test_replay_scenario_wannacry_independent_of_profile` [PASSED]
   - `test_replay_scenario_redline_independent_of_profile` [PASSED]
   - `test_replay_scenario_alias_compatibility` [PASSED]
   - `test_replay_invalid_scenario_id_does_not_silently_fallback` [PASSED]
11. `backend/tests/test_safety_and_lifecycle.py`: (14/14 PASSED)
12. `backend/tests/test_static_analysis.py`: (23/23 unit PASSED, 1 opt-in live test skipped by default; 1/1 live PASSED with `MALBOX_RUN_LIVE_GHIDRA_TEST=1`)
13. `backend/tests/test_submission.py`: (3/3 PASSED)
14. `backend/tests/test_telemetry_integrity.py`: (7/7 PASSED)

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
