# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.1.0  
**Active Branch:** `audit/remediation-hardening`  
**Audit & Remediation Date:** November 2026  
**Status:** **OPERATIONAL & PRODUCTION-READY (AUDIT REMEDIATION COMPLETED)**

---

## 1. Feature Completion Matrix

| Component | Status | Verification Evidence | Notes |
| :--- | :--- | :--- | :--- |
| **PE Submission & Triage** | **Completed** | `backend/tests/test_pe_parser.py`, `test_submission.py` | Computes SHA-256, SHA-1, MD5; extracts imports/sections/entropy; isolates in quarantine (0400). |
| **Execution Safety Gate** | **Completed** | `backend/tests/test_safety_and_lifecycle.py` | Strict enum validation, server policy check, per-task user approval, operator token authorization. |
| **Reliable Job Lifecycle** | **Completed** | `backend/tests/test_safety_and_lifecycle.py` | Persistent JobQueueManager, bounded concurrency=1, crash recovery, terminal state protection, status polling. |
| **AI Analysis Orchestrator** | **Completed** | `backend/tests/test_ai_orchestration.py`, `test_real_ai_provider.py` | Structured planner, positive allowlist policy validation, RealLLMProvider (HTTP) + fallback to Mock, token/audit tracking. |
| **Pluggable Sandbox Integration** | **Completed** | `backend/tests/test_replay_pipeline.py`, `test_cape_adapter.py` | `ReplaySandboxBackend` & `CapeSandboxBackend` (CAPE v2 API client) with polling and cancellation. |
| **Telemetry & Evidence Integrity**| **Completed** | `backend/tests/test_telemetry_integrity.py` | Temporal PID reuse handling, out-of-order event resilience, cycle prevention, verified non-fabricated OS metadata. |
| **Behavioral Detection & MITRE**| **Completed** | `backend/tests/test_detection_rules.py` | Contextual thresholds (T1490, T1486, T1547.001, T1059.001, T1555.003, T1071.001, T1046); "No Suspicious Behavior" verdict. |
| **Replay Data Provenance** | **Completed** | `backend/tests/test_replay_pipeline.py`, `scripts/benchmark_replay.py` | Explicit scenario selector (`ransomware_wannacry_mock`, `infostealer_redline_mock`), visual provenance badges in UI/reports. |
| **Cytoscape.js Behavior Graph**| **Completed** | Interactive frontend visualization & `/api/v1/analyses/{id}/graph` | 9 node types, 10 edge types, strict source/target integrity validation, suspicious node highlighting. |
| **Secure HTML Report Export** | **Completed** | `/api/v1/analyses/{id}/report/html` | Standalone HTML export with CSP `<meta>` tags, full `html.escape()`, and replay provenance banner. |
| **Web User Interface** | **Completed** | React 18 + TypeScript + Vite (`npm run build`) | Real-time interval polling, Replay scenario selection, Operator token gate, responsive dark UI. |

---

## 2. Test Execution Outcomes

- **Test Framework:** `pytest` 9.2.0 with `pytest-asyncio` & `starlette.testclient`
- **Total Test Cases:** 44
- **Passed:** 44 (100%)
- **Failed:** 0
- **Execution Time:** ~8.5 seconds

### Test Breakdown by Subsystem
1. `backend/tests/test_ai_orchestration.py`: (5/5 PASSED)
   - `test_policy_validator_allowlist` [PASSED]
   - `test_policy_validator_reject_host_command_injection` [PASSED]
   - `test_policy_validator_reject_unapproved_profile` [PASSED]
   - `test_policy_validator_clamp_excessive_timeout` [PASSED]
   - `test_ai_orchestration_audit_trail_recorded` [PASSED]
2. `backend/tests/test_cape_adapter.py`: (3/3 PASSED)
   - `test_cape_readiness_failure` [PASSED]
   - `test_cape_readiness_mocked` [PASSED]
   - `test_cape_submission_and_report_transform` [PASSED]
3. `backend/tests/test_detection_rules.py`: (4/4 PASSED)
   - `test_detection_engine_no_suspicious_behavior` [PASSED]
   - `test_detection_engine_ransomware_contextual_threshold` [PASSED]
   - `test_detection_engine_shadow_copy_deletion` [PASSED]
   - `test_detection_engine_c2_contextual_threshold` [PASSED]
4. `backend/tests/test_health.py`: (2/2 PASSED)
   - `test_health_endpoint` [PASSED]
   - `test_root_endpoint` [PASSED]
5. `backend/tests/test_pe_parser.py`: (5/5 PASSED)
   - `test_entropy_empty` [PASSED]
   - `test_entropy_uniform` [PASSED]
   - `test_entropy_low` [PASSED]
   - `test_parse_non_pe` [PASSED]
   - `test_parse_corrupted_pe` [PASSED]
6. `backend/tests/test_real_ai_provider.py`: (6/6 PASSED)
   - `test_real_llm_provider_generate_plan_success` [PASSED]
   - `test_real_llm_provider_network_failure_fallback` [PASSED]
   - `test_real_llm_provider_invalid_schema_fallback` [PASSED]
   - `test_real_llm_provider_evaluate_observations_success` [PASSED]
   - `test_policy_validator_positive_allowlist_unknown_keys` [PASSED]
   - `test_orchestration_audit_includes_llm_metadata` [PASSED]
7. `backend/tests/test_replay_pipeline.py`: (1/1 PASSED)
   - `test_full_replay_analysis_pipeline` [PASSED]
8. `backend/tests/test_safety_and_lifecycle.py`: (10/10 PASSED)
   - `test_safety_gate_cape_live_mode_false` [PASSED]
   - `test_safety_gate_cape_missing_approval` [PASSED]
   - `test_safety_gate_invalid_backend` [PASSED]
   - `test_safety_gate_replay_live_mode_true` [PASSED]
   - `test_safety_gate_live_disabled_by_policy` [PASSED]
   - `test_safety_gate_operator_token_required` [PASSED]
   - `test_terminal_state_protection` [PASSED]
   - `test_job_queue_recover_stale_jobs` [PASSED]
   - `test_cancellation_flow` [PASSED]
   - `test_cape_polling_lifecycle_mocked` [PASSED]
9. `backend/tests/test_submission.py`: (3/3 PASSED)
   - `test_upload_sample_deduplication` [PASSED]
   - `test_live_mode_safety_gate` [PASSED]
   - `test_create_and_retrieve_analysis` [PASSED]
10. `backend/tests/test_telemetry_integrity.py`: (5/5 PASSED)
    - `test_process_tree_pid_reuse` [PASSED]
    - `test_process_tree_out_of_order_events` [PASSED]
    - `test_process_tree_cycle_resilience` [PASSED]
    - `test_behavior_graph_strict_edge_integrity` [PASSED]
    - `test_reporting_no_fabricated_guest_os` [PASSED]

---

## 3. Automated VM Resource & Execution Benchmark

Measured via `scripts/benchmark_replay.py`:
```
========================================================
                 BENCHMARK SUMMARY TABLE                
========================================================
| Scenario                     | Pipeline   | CPU Time   | Peak RSS   | Events  |
|------------------------------|------------|------------|------------|---------|
| WannaCry Ransomware Scenario |  103.58 ms |   82.36 ms |  383.37 MB |      15 |
| RedLine Infostealer Scenario |   57.91 ms |   41.99 ms |  383.37 MB |      12 |
========================================================
```

---

## 4. Operational Prerequisites & Safety Boundaries

1. **Default Live Mode Disabled:**
   - `settings.LIVE_MODE_ENABLED = False` by default.
   - Any live detonation attempt without setting `MALBOX_LIVE_MODE_ENABLED=true` and providing `X-Operator-Token` is rejected with HTTP 403 / 401.
2. **CAPE Sandbox API URL Distinct from Application Server:**
   - `CAPE_API_URL` defaults to `http://127.0.0.1:8008`, preventing port collisions with FastAPI (port 8000).
3. **Replay Mode Isolation:**
   - 100% offline, deterministic, zero-network execution from curated forensic behavioral fixtures.
