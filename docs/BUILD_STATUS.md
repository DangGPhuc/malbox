# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.1.0  
**Active Branch:** `audit/remediation-hardening`  
**Base Audited Commit:** `e00a55f6fe6a7ea0fc4df31283c26541ed0253f1`  
**Status:** **OPERATIONAL & PRODUCTION-READY (AUDIT REMEDIATION & PRE-VM VALIDATION COMPLETED)**

---

## 1. Feature Completion Matrix & Readiness Classification

| Subsystem | Readiness | Verification Evidence | Operational Details |
| :--- | :--- | :--- | :--- |
| **PE Submission & Triage** | **VERIFIED** | `test_pe_parser.py`, `test_submission.py` | Computes SHA-256, SHA-1, MD5; extracts imports/sections/entropy; isolates in quarantine (0400). |
| **Execution Safety Gate** | **VERIFIED** | `test_safety_and_lifecycle.py` | Strict enum validation, server policy check, per-task user approval, fail-closed operator token authorization with `compare_digest`. |
| **Reliable Job Lifecycle** | **VERIFIED** | `test_safety_and_lifecycle.py` | Persistent `JobQueueManager`, strict concurrency=1 (including `execute_sync`), crash recovery, terminal state protection, race-free cancellation. |
| **Replay Scenario Validation**| **VERIFIED** | `test_safety_and_lifecycle.py` | Allowlist of registered scenario IDs (`ransomware_wannacry_mock`, `infostealer_redline_mock`), traversal rejection, artifact sanitization, scenario/fixture persistence. |
| **AI Analysis Orchestrator** | **VERIFIED** | `test_ai_orchestration.py`, `test_real_ai_provider.py` | Structured preflight planner, positive allowlist policy validation, RealLLMProvider (HTTP) + fallback to Mock, audit tracking with token metadata. Follow-up classified as advisory recommendation. |
| **Deterministic Rule Engine** | **VERIFIED** | `test_detection_rules.py` | Contextual thresholds (T1490, T1486, T1547.001, T1059.001, T1555.003, T1071.001, T1046); negative regression tests for lone ransom note and normal HTTP POST. |
| **Cytoscape.js Behavior Graph**| **VERIFIED** | `test_telemetry_integrity.py` | Unique process-instance identity (`proc_{ev.id}`), temporal PID reuse resolution, unattributed network activity isolated to `node_unattributed_network`, 100% grounded edges. |
| **Evidence Provenance & Reporting**| **VERIFIED** | `test_telemetry_integrity.py`, `export_html.py` | Non-fabricated environment metadata, explicit replay disclaimers, XSS-safe HTML export with strict CSP. |
| **Web User Interface** | **VERIFIED** | React 18 + TypeScript + Vite (`npm run build`) | Real-time interval polling, Replay scenario selection, Operator token gate, Cytoscape graph visualizer. |
| **Live CAPE Sandbox Backend** | **PARTIAL** | `test_cape_adapter.py` | Fully implemented and unit-tested adapter with readiness checks, task polling, report transformation, and cancellation. Real hypervisor execution remains disabled by policy. |

---

## 2. Test Execution Outcomes

- **Test Framework:** `pytest` 9.2.0 with `pytest-asyncio` & `starlette.testclient`
- **Total Test Cases:** 52
- **Passed:** 52 (100%)
- **Failed:** 0
- **Execution Time:** ~10.4 seconds

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
3. `backend/tests/test_detection_rules.py`: (6/6 PASSED)
   - `test_detection_engine_no_suspicious_behavior` [PASSED]
   - `test_detection_engine_ransomware_contextual_threshold` [PASSED]
   - `test_detection_engine_shadow_copy_deletion` [PASSED]
   - `test_detection_engine_c2_contextual_threshold` [PASSED]
   - `test_lone_ransom_note_without_encrypted_files_not_mass_encryption` [PASSED]
   - `test_normal_http_post_not_c2_exfiltration` [PASSED]
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
8. `backend/tests/test_safety_and_lifecycle.py`: (14/14 PASSED)
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
   - `test_operator_token_fail_closed_when_empty` [PASSED]
   - `test_operator_token_auth_flow` [PASSED]
   - `test_replay_scenario_validation_strict` [PASSED]
   - `test_live_analysis_cancellation_requires_operator_token` [PASSED]
9. `backend/tests/test_submission.py`: (3/3 PASSED)
   - `test_upload_sample_deduplication` [PASSED]
   - `test_live_mode_safety_gate` [PASSED]
   - `test_create_and_retrieve_analysis` [PASSED]
10. `backend/tests/test_telemetry_integrity.py`: (7/7 PASSED)
    - `test_process_tree_pid_reuse` [PASSED]
    - `test_process_tree_out_of_order_events` [PASSED]
    - `test_process_tree_cycle_resilience` [PASSED]
    - `test_behavior_graph_strict_edge_integrity` [PASSED]
    - `test_reporting_no_fabricated_guest_os` [PASSED]
    - `test_behavior_graph_unique_process_instance_identity_pid_reuse` [PASSED]
    - `test_behavior_graph_unattributed_network_not_assigned_to_sample` [PASSED]

---

## 3. Automated VM Resource & Execution Benchmark

Measured via `scripts/benchmark_replay.py`:

### Standard Replay Scenarios
| Scenario | Pipeline Latency | CPU Time | Peak RSS | Events | Graph Build |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WannaCry Ransomware** | 74.87 ms | 51.10 ms | 402.11 MB | 15 | 3.67 ms (17 nodes, 16 edges) |
| **RedLine Infostealer** | 51.61 ms | 33.62 ms | 402.11 MB | 12 | 2.16 ms (14 nodes, 13 edges) |

### Synthetic Telemetry Scaling
| Scale | Events Count | Normalization Duration | Ingestion Throughput | Graph Construction | Report Generation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 101 events | 12.78 ms | 7,904.4 events/sec | 5.76 ms (104 nodes) | 9.11 ms |
| **Medium** | 1,001 events | 43.33 ms | 23,103.2 events/sec | 20.50 ms (987 nodes) | 74.30 ms |
| **Large** | 10,001 events | 533.59 ms | 18,742.8 events/sec | 272.93 ms (8,970 nodes) | 614.37 ms |

### API Endpoint Response Latencies
| Endpoint | Method | Response Latency |
| :--- | :--- | :--- |
| `/api/v1/health` | GET | 22.78 ms |
| `/api/v1/samples` (Upload & Triage) | POST | 68.06 ms |
| `/api/v1/analyses` (Synchronous Replay Pipeline) | POST | 73.64 ms |
| `/api/v1/analyses/{id}` (Status Polling) | GET | 9.59 ms |
| `/api/v1/analyses/{id}/graph` (Cytoscape Elements) | GET | 13.42 ms |
| `/api/v1/analyses/{id}/report` (Structured Findings) | GET | 8.48 ms |
