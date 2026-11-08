# malbox-ai — Audit Remediation & Hardening Ledger

**Branch:** `audit/remediation-hardening`  
**Base Commit:** `181309e` -> `e00a55f`  
**Date:** November 2026  
**Status:** **Remediated & Verified (Phases 0 — 8 Completed + Final CI Fix & Pre-VM Validation)**

---

## 1. Verified Defect & Remediation Summary

| Phase | Subsystem | Priority | Defect Description | Root Cause | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CI** | Reporting | **P0** | `NameError: name 'Optional' is not defined` in `generate_report()`. | Missing `Optional` in typing imports of `generator.py`. | **Fixed & Verified** |
| **0** | Packaging | **P0** | `backend/pyproject.toml` missing `backend/README.md` & flat-layout discovery collision with empty `backend/fixtures`. | Missing readme file and missing package find directive in `pyproject.toml`. | **Fixed & Verified** |
| **1** | Safety Gate | **P0** | Inconsistent backend / mode gate allows `backend_type="cape"` with `live_mode=false` to bypass safety check; self-referential CAPE URL port 8000; missing operator auth. | API and Worker checked `live_mode` independently of `backend_type`; string backend without strict enum; CAPE URL defaulted to application port. | **Fixed & Verified** |
| **2** | Security & Lifecycle | **P0** | Hardcoded default operator token; missing secret fails open or unchecked; public `run_sync` bypasses worker concurrency=1; replay scenario traversal; cancellation races with completion. | Permissive defaults in `config.py`; unmanaged thread execution in sync endpoint; lack of replay ID whitelist; unsynchronized state check. | **Fixed & Verified** |
| **3** | Analysis Logic | **P1** | Raw PID-only process node identity collapses reused PIDs; unattributed network events falsely linked to sample root; lone ransom note flags mass encryption; any HTTP POST flags C2; AI falsely claims unexecuted second pass. | Lack of process-instance IDs; missing unattributed network node; rule thresholds without multi-event corroboration; worker overwriting profile without second pass. | **Fixed & Verified** |
| **4** | Telemetry Scaling | **P1** | Benchmarks evaluated only 12-15 replay events; no verification on medium (1K) or large (10K) event streams. | Benchmark script tested only two static fixtures without synthetic dataset generator. | **Fixed & Verified** |
| **5** | CI Verification | **P0** | CI workflow lacked byte-compile validation, recursive module import checks, and comprehensive security regression tests. | Incomplete CI workflow definition. | **Fixed & Verified** |

---

## 2. Detailed Remediation Details by Subsystem

### CI Failure Fix & Packaging
- **Defects Identified:**
  - GitHub Actions and local execution failed with `NameError: name 'Optional' is not defined` at `backend/app/services/reporting/generator.py:27`.
  - `backend/pyproject.toml` declared `readme = "README.md"`, but no `README.md` existed in `backend/`.
- **Fixes Applied:**
  - Added `Optional` to `from typing import Dict, Any, List, Optional` in `backend/app/services/reporting/generator.py`.
  - Added dedicated `backend/README.md` and configured `find_packages(include=["app*"])`.
  - Verified with `python -m compileall -q backend/app backend/tests` (exited 0).
  - Verified recursive import check across all `backend/app` submodules (exited 0).

### Operator Authorization & Security Boundary
- **Defects Identified:**
  - `OPERATOR_TOKEN` previously had a hardcoded default string (`malbox-operator-secret-token-change-in-prod`).
  - If unconfigured, the system could fail open or allow unauthorized live malware execution.
  - Token comparison was vulnerable to timing side channels.
- **Fixes Applied:**
  - Changed default `OPERATOR_TOKEN: str = ""` in `config.py`.
  - Implemented fail-closed security boundary in `backend/app/api/v1/analyses.py`: If `settings.OPERATOR_TOKEN` is empty, Live Mode submissions and cancellations fail closed with HTTP 403 Forbidden.
  - Used constant-time token comparison: `hmac.compare_digest(x_operator_token, settings.OPERATOR_TOKEN)` for all live detonations and live cancellation operations.
  - Maintained `LIVE_MODE_ENABLED: bool = False` by default.

### Replay Scenario & Artifact Validation
- **Defects Identified:**
  - Arbitrary scenario IDs could be supplied, potentially traversing filesystem paths or silently falling back to mismatched fixtures.
- **Fixes Applied:**
  - Defined strict allowlist `REGISTERED_REPLAY_SCENARIOS = {"ransomware_wannacry_mock", "infostealer_redline_mock"}`.
  - Enforced regex check `^[a-zA-Z0-9_\-]+$` and path traversal rejection (`..`, `/`, `\`, null bytes) in both API endpoint and `ReplaySandboxBackend`.
  - Enforced path containment check `target_file.is_relative_to(fixtures_root)`.
  - Sanitized forensic artifact filenames: prevented directory traversal and path escapes during mock artifact generation.
  - Persisted resolved scenario ID and `fixture_version` in the analysis record and in `analysis_environment` report metadata.

### Worker Concurrency & Race-Free Cancellation
- **Defects Identified:**
  - Calling `POST /api/v1/analyses?run_sync=true` spawned an unmanaged `PipelineWorker` thread, bypassing the worker concurrency limit (`WORKER_CONCURRENCY=1`).
  - Cancellation requests could race with job completion.
  - Process crashes or restarts left jobs stranded in non-terminal states.
- **Fixes Applied:**
  - Added `_worker_lock = threading.Lock()` to `JobQueueManager`.
  - Routed synchronous requests through `job_queue_manager.execute_sync(analysis_id, db)`, acquiring `_worker_lock` and returning HTTP 429 if the slot is busy.
  - Protected cancellation state transitions: re-verified database status under lock to avoid racing with job completion.
  - Added `recover_stale_jobs(db)` recovering any non-terminal jobs to `FAILED` with descriptive error messages upon startup.

### Behavior Graph Evidence Provenance
- **Defects Identified:**
  - Process nodes used raw PID identity (`proc_{pid}`), causing collision and data corruption during PID reuse.
  - Out-of-order parent-child process events produced disconnected or misparented trees.
  - Network events without attributed processes were arbitrarily assigned to the sample root node.
- **Fixes Applied:**
  - Replaced raw PID IDs with unique process-instance identity: `proc_{ev.id}`.
  - Indexed all process instances with temporal intervals (`[spawn_time, end_time]`), resolving PID reuse and out-of-order parents deterministically.
  - Created dedicated `node_unattributed_network` ("Unattributed Network Traffic", type `NetworkTraffic`) for network events without verified process provenance, preventing false attribution to the sample root.
  - Strictly validated all graph edges: ensuring every edge references existing source/target nodes and links to real event IDs.

### Behavioral Detection Quality
- **Defects Identified:**
  - `RULE_MASS_FILE_ENCRYPTION` matched on a single ransom note with 0 encrypted files.
  - `RULE_C2_HTTP_EXFILTRATION` matched on ANY HTTP POST returning HTTP 200/201.
- **Fixes Applied:**
  - `RULE_MASS_FILE_ENCRYPTION`: Requires `(ransom_notes and encrypted_files) or len(encrypted_files) >= 2`. A single ransom note without encrypted files is no longer classified as mass file encryption.
  - `RULE_C2_HTTP_EXFILTRATION`: Requires HTTP POST combined with explicit C2 endpoint indicators (`gate`, `upload`, `beacon`, `panel`, `exfil`, `post.php`) or explicit exfiltration telemetry attributes. Normal API POSTs returning 200 are no longer flagged.
  - Added positive and negative regression tests for both rules in `test_detection_rules.py`.

### AI Orchestration Policy & Audit
- **Defects Identified:**
  - Approved plans did not pass parameters to sandbox execution.
  - Observation evaluation ran before detection scoring, receiving empty findings (`findings_count: 0`).
  - Worker previously mutated `analysis.profile` upon follow-up recommendation, falsely claiming an unexecuted second pass occurred.
  - Hardcoded `"Windows 10 x64 CAPE VM"` in CAPE adapter.
- **Fixes Applied:**
  - Passed approved plan parameters (`requested_artifacts`, `telemetry_focus`) to sandbox `submit_sample(options=...)`.
  - Moved deterministic `DetectionEngine` evaluation ahead of `ObservationEvaluator`, providing real findings, risk score, and rule IDs to the AI evaluator.
  - Follow-up dynamic pass recommendations are clearly classified as advisory recommendations for the operator; `analysis.profile` is NOT mutated without execution.
  - Removed hardcoded guest OS string from CAPE adapter; extracts real machine info or explicitly marks as `"Not reported by sandbox backend"`, and sets `confinement_verified=False`.

---

## 3. Verification Test Suite Status

All 52 automated regression and unit tests pass with zero errors:
```
backend/tests/test_ai_orchestration.py: 5/5 PASSED
backend/tests/test_cape_adapter.py: 3/3 PASSED
backend/tests/test_detection_rules.py: 6/6 PASSED
backend/tests/test_health.py: 2/2 PASSED
backend/tests/test_pe_parser.py: 5/5 PASSED
backend/tests/test_real_ai_provider.py: 6/6 PASSED
backend/tests/test_replay_pipeline.py: 1/1 PASSED
backend/tests/test_safety_and_lifecycle.py: 14/14 PASSED
backend/tests/test_submission.py: 3/3 PASSED
backend/tests/test_telemetry_integrity.py: 7/7 PASSED
======================== 52 passed, 1 warning in 10.44s ========================
```

Frontend production build:
```
cd frontend && npm run build
✓ 1491 modules transformed.
dist/index.html                   0.85 kB │ gzip:   0.49 kB
dist/assets/index-1H6TGCfN.css    3.05 kB │ gzip:   1.15 kB
dist/assets/index-_mae2sp5.js   644.62 kB │ gzip: 201.65 kB
✓ built in 2.35s
```
