# malbox-ai — Audit Remediation & Hardening Ledger

**Branch:** `audit/remediation-hardening`  
**Base Commit:** `181309e`  
**Date:** November 2026  
**Status:** Remediated & Verified (Phases 0 — 8 Completed)

---

## 1. Verified Defect & Remediation Summary

| Phase | Subsystem | Priority | Defect Description | Root Cause | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | Packaging | **P0** | `backend/pyproject.toml` missing `backend/README.md` & flat-layout discovery collision with empty `backend/fixtures`. | Missing readme file and missing package find directive in `pyproject.toml`. | **Fixed & Verified** |
| **1** | Safety Gate | **P0** | Inconsistent backend / mode gate allows `backend_type="cape"` with `live_mode=false` to bypass safety check; self-referential CAPE URL port 8000; missing operator auth. | API and Worker checked `live_mode` independently of `backend_type`; string backend without strict enum; CAPE URL defaulted to application port. | **Fixed & Verified** |
| **2** | Job Lifecycle | **P0** | BackgroundTasks used as queue; concurrency=1 not enforced; cancellation doesn't halt worker; premature CAPE report fetch; terminal states overwritten. | No durable queue; uncoordinated threading; missing CAPE status polling loop; missing state transition validation. | **Fixed & Verified** |
| **3** | AI Orchestrator| **P1** | `RealLLMProvider` was an empty mock proxy; blacklist validator instead of positive schema allowlist; no token/model/fallback tracking in audit trail. | Placeholder delegation in `llm_client.py`; negative key checking instead of positive schema allowlist. | **Fixed & Verified** |
| **4** | Telemetry | **P1** | Hardcoded OS/confinement in reports; process graph and tree sensitive to event order / PID reuse; potential ungrounded edges. | Lack of temporal instance identity for processes; static strings in report generator. | **Fixed & Verified** |
| **5** | Detection | **P1** | Overly broad single-event rules (any POST = exfil; any 445 = scanning); false "Clean" verdict on zero telemetry. | Lack of contextual behavioral thresholds; binary clean classification instead of absence of evidence disclaimer. | **Fixed & Verified** |
| **6** | Replay Mode | **P1** | Automatic canned fixture selection based on sample filename; unclear synthetic vs live provenance in reports and UI. | Dynamic selection heuristic conflates real sample with canned threat data; missing provenance banners. | **Fixed & Verified** |
| **7** | Security & UI | **P1** | Unescaped HTML in standalone report (XSS vector); frontend lacks live polling; synchronous blocking requests. | Lack of `html.escape()` and CSP meta in HTML generator; no interval polling in React workspace. | **Fixed & Verified** |
| **8** | QA & Benchmarks| **P1** | Missing CI workflow and automated VM resource benchmark script for resource-constrained evaluations. | Absence of `.github/workflows/ci.yml` and benchmark utility. | **Fixed & Verified** |

---

## 2. Detailed Remediation Details by Phase

### Phase 0 — Baseline Validation & Packaging
- **Defects Identified:**
  - `backend/pyproject.toml` declared `readme = "README.md"`, but no `README.md` existed in `backend/`.
  - Empty `backend/fixtures` directory caused setuptools flat-layout error: `Multiple top-level packages discovered in a flat-layout: ['app', 'fixtures']`.
- **Fixes Applied:**
  - Added dedicated `backend/README.md`.
  - Removed obsolete empty `backend/fixtures` directory.
  - Added `[tool.setuptools.packages.find]` with `include = ["app*"]` to `backend/pyproject.toml`.
  - Verified clean virtualenv editable install: `pip install -e "backend[dev]"` succeeded with code 0.

### Phase 1 — Critical Live Execution Safety Gate
- **Defects Identified:**
  - Submitting `backend_type="cape"` with `live_mode=false` bypassed endpoint safety checks.
  - `CAPE_API_URL` defaulted to `http://127.0.0.1:8000`, the application's own port.
  - Lack of operator authorization boundary on sensitive live detonation endpoints.
- **Fixes Applied:**
  - Introduced `SandboxBackendType` enum (`REPLAY`, `CAPE`).
  - Added Pydantic cross-field validator in `AnalysisCreate` enforcing:
    - `backend_type == 'cape'` requires `live_mode=True` and `approved_by_user=True`.
    - `backend_type == 'replay'` requires `live_mode=False`.
  - Added `X-Operator-Token` header check against `settings.OPERATOR_TOKEN` (HTTP 401 on missing/invalid token).
  - Changed default `CAPE_API_URL` to `http://127.0.0.1:8008`.
  - Enforced second pre-detonation readiness check in `PipelineWorker` before communicating with CAPE.

### Phase 2 — Reliable Analysis Job Lifecycle
- **Defects Identified:**
  - Direct execution via `BackgroundTasks` lacked durable queuing, state transition validation, and worker concurrency limits.
  - Immediate report retrieval from CAPE without polling task status (`pending`, `running`, `reported`).
  - Terminal states (`COMPLETED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `BLOCKED_BY_POLICY`) could be overwritten.
- **Fixes Applied:**
  - Created `JobQueueManager` enforcing `WORKER_CONCURRENCY=1`, background polling, and crash recovery (`recover_stale_jobs`).
  - Implemented `safe_update_status` validating transitions against `VALID_STATE_TRANSITIONS` and protecting terminal states.
  - Built bounded polling loop in `PipelineWorker` with cancellation event inspection at every stage.
  - Added external task ID persistence and graceful timeout handling.

### Phase 3 — Real AI Provider Implementation
- **Defects Identified:**
  - `RealLLMProvider` was delegating directly to `MockLLMProvider`.
  - `PolicyValidator` relied on a blacklist of keywords rather than strict positive schema allowlists.
  - Audit trail did not capture token usage, provider name, or fallback reasons.
- **Fixes Applied:**
  - Implemented full HTTP request client in `RealLLMProvider` using `httpx` connecting to OpenAI/Ollama-compatible `/chat/completions`.
  - Strict Pydantic model validation (`AnalysisPlan`, `FollowUpRecommendation`).
  - Fallback logic: If real LLM fails or times out, it gracefully falls back to `MockLLMProvider`, explicitly recording `provider: "mock_fallback"`, `tokens_used: 0`, and the exact exception in `OrchestrationRecord`.
  - Replaced negative keyword checks with strict positive allowlists for plan schema keys, profiles, artifacts, and duration bounds.

### Phase 4 — Telemetry Accuracy & Evidence Integrity
- **Defects Identified:**
  - Identifying processes solely by raw `pid: int` caused PID reuse collision.
  - Process tree crashed or misparented when child process events preceded parent events.
  - Report generator hardcoded `Windows 10 Pro 64-bit (Isolated Sandbox)`.
- **Fixes Applied:**
  - Process instances in `build_process_tree` are uniquely indexed by event ID and parented temporally using normalized UTC timestamps.
  - Out-of-order process events and cyclic PPID graphs are gracefully handled without crashing.
  - `ReportGenerator` ingests verified guest OS metadata from sandbox execution or reports `"Not reported by sandbox backend"`.
  - `build_behavior_graph` filters all edges to guarantee source and target node reference integrity.

### Phase 5 — Detection Rule Quality
- **Defects Identified:**
  - Single uncontextualized file writes or HTTP requests triggered critical rules (e.g., any POST = C2 exfil).
  - Empty behavioral findings yielded a false "Clean" safety guarantee.
- **Fixes Applied:**
  - Contextual rule thresholds:
    - `RULE_MASS_FILE_ENCRYPTION`: Requires ransom note + encrypted file OR multiple encrypted files (>=2).
    - `RULE_C2_HTTP_EXFILTRATION`: Requires POST to gate/beacon/upload endpoint.
    - `RULE_LATERAL_SMB_PROBE`: Requires multiple connection attempts or worm scanning context.
  - Zero-finding risk level updated to `"No Suspicious Behavior Observed"` with explicit limitations regarding bounded execution.

### Phase 6 — Replay Data Provenance
- **Defects Identified:**
  - Replay telemetry was heuristically bound by filename, conflating sample data with canned threat data.
  - Missing visual indicator distinguishing replay runs from live detonation.
- **Fixes Applied:**
  - Added explicit scenario selector (`ransomware_wannacry_mock`, `infostealer_redline_mock`) in UI and API.
  - Added `is_replay`, `backend_type`, `replay_scenario_id`, and `provenance_disclaimer` to `FullReportSchema` and `ReportResponse`.
  - Added prominent visual replay banner in HTML reports and React Workspace.

### Phase 7 — Report & Frontend Security
- **Defects Identified:**
  - Dynamic user-controlled strings (sample name, commands, findings) in HTML reports lacked escaping.
  - Workspace UI did not poll active jobs.
- **Fixes Applied:**
  - Applied `html.escape()` across all dynamic interpolated fields in `export_html.py`.
  - Added strict CSP `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:;">`.
  - Implemented 2-second interval polling in `WorkspacePage.tsx` stopping upon reaching terminal states.

### Phase 8 — Clean Install, CI & VM Benchmark Readiness
- **Defects Identified:**
  - Missing GitHub Actions CI workflow.
  - No automated VM resource evaluation benchmark.
- **Fixes Applied:**
  - Created `.github/workflows/ci.yml` running Python 3.12 pytest and Node 20 Vite build.
  - Created `scripts/benchmark_replay.py` measuring latency, CPU time, peak RSS memory, and forensic event counts.
  - Verified benchmark: ~60-100 ms total execution latency, under 385 MB peak memory.

---

## 3. Verification Test Suite Status
All 44 automated regression and unit tests pass with zero errors:
```
backend/tests/test_ai_orchestration.py: 5/5 PASSED
backend/tests/test_cape_adapter.py: 3/3 PASSED
backend/tests/test_detection_rules.py: 4/4 PASSED
backend/tests/test_health.py: 2/2 PASSED
backend/tests/test_pe_parser.py: 5/5 PASSED
backend/tests/test_real_ai_provider.py: 6/6 PASSED
backend/tests/test_replay_pipeline.py: 1/1 PASSED
backend/tests/test_safety_and_lifecycle.py: 10/10 PASSED
backend/tests/test_submission.py: 3/3 PASSED
backend/tests/test_telemetry_integrity.py: 5/5 PASSED
Total: 44 PASSED (100% pass rate)
```
Frontend Vite production build:
```
npm run build --prefix frontend
✓ built in 2.02s (0 errors)
```
