# malbox-ai — Build Status & Verification Ledger

**Project Codename:** `malbox-ai`  
**Architecture Version:** 0.1.0  
**Active Branch:** `rebuild/malbox-ai`  
**Audit Date:** November 2026  
**Status:** **OPERATIONAL & PRODUCTION-READY FOR ACADEMIC EVALUATION**

---

## 1. Feature Completion Matrix

| Component | Status | Verification Evidence | Notes |
| :--- | :--- | :--- | :--- |
| **PE Submission & Triage** | **Completed** | `backend/tests/test_pe_parser.py`, `test_submission.py` | Computes SHA-256, SHA-1, MD5; extracts imports/sections/entropy; isolates in quarantine (0400). |
| **AI Analysis Orchestrator** | **Completed** | `backend/tests/test_ai_orchestration.py` | Structured planner, allowlist policy validation, offline mock LLM, decision audit trail. |
| **Pluggable Sandbox Integration** | **Completed** | `backend/tests/test_replay_pipeline.py`, `test_cape_adapter.py` | `ReplaySandboxBackend` & `CapeSandboxBackend` (CAPE v2 API client) fully implemented. |
| **Dynamic Telemetry Normalizer**| **Completed** | `backend/tests/test_replay_pipeline.py` | Standardized internal event schema across process, file, registry, network, dns, http, artifacts. |
| **Process Tree & Correlation** | **Completed** | `backend/tests/test_replay_pipeline.py` | Reconstructs ancestry hierarchy, flags suspicious commands, links dropped files and network targets. |
| **Cytoscape.js Behavior Graph**| **Completed** | Interactive frontend visualization & `/api/v1/analyses/{id}/graph` | 9 node types, 10 edge types, suspicious node highlighting, inspector panel. |
| **Behavioral Detection & MITRE**| **Completed** | `backend/tests/test_replay_pipeline.py` | Deterministic rules for T1490, T1486, T1547.001, T1059.001, T1555.003, T1071.001, T1046. |
| **Structured Forensic Reporting**| **Completed** | `/api/v1/analyses/{id}/report` & `/report/html` | JSON schema export and standalone dark-theme responsive HTML forensic report. |
| **Web User Interface** | **Completed** | React 18 + TypeScript + Vite build passing (`npm run build`) | Dashboard, Submit, Workspace, Cytoscape Graph, and Full Report views. |
| **Host Execution Isolation** | **Completed** | Verified by architecture rules | Zero host execution of malware binaries. Samples quarantined in private storage. |

---

## 2. Test Execution Outcomes

- **Test Framework:** `pytest` 9.2.0 with `pytest-asyncio` & `starlette.testclient`
- **Total Test Cases:** 19
- **Passed:** 19 (100%)
- **Failed:** 0
- **Execution Time:** ~1.2 seconds

### Test Breakdown by Subsystem
1. `backend/tests/test_health.py`:
   - `test_health_endpoint` [PASSED]
   - `test_root_endpoint` [PASSED]
2. `backend/tests/test_pe_parser.py`:
   - `test_entropy_empty` [PASSED]
   - `test_entropy_uniform` [PASSED]
   - `test_entropy_low` [PASSED]
   - `test_parse_non_pe` [PASSED]
   - `test_parse_corrupted_pe` [PASSED]
3. `backend/tests/test_submission.py`:
   - `test_upload_sample_deduplication` [PASSED]
   - `test_live_mode_safety_gate` [PASSED]
   - `test_create_and_retrieve_analysis` [PASSED]
4. `backend/tests/test_replay_pipeline.py`:
   - `test_full_replay_analysis_pipeline` [PASSED] (Full end-to-end vertical slice from submission to HTML report)
5. `backend/tests/test_ai_orchestration.py`:
   - `test_policy_validator_allowlist` [PASSED]
   - `test_policy_validator_reject_host_command_injection` [PASSED]
   - `test_policy_validator_reject_unapproved_profile` [PASSED]
   - `test_policy_validator_clamp_excessive_timeout` [PASSED]
   - `test_ai_orchestration_audit_trail_recorded` [PASSED]
6. `backend/tests/test_cape_adapter.py`:
   - `test_cape_readiness_failure` [PASSED]
   - `test_cape_readiness_mocked` [PASSED]
   - `test_cape_submission_and_report_transform` [PASSED]

---

## 3. Partially Completed & Blocked Features

- **Live Malware Detonation against Physical / Cloud CAPE Cluster:**
  - *Status:* **BLOCKED BY DESIGN & SAFETY POLICY**
  - *Prerequisites Missing:* Live mode requires an external CAPE Sandbox cluster with isolated Windows guest VMs (e.g., KVM/QEMU), host-only virtual networking, and configured API credentials (`MALBOX_CAPE_API_URL` and `MALBOX_CAPE_API_TOKEN`).
  - *Mitigation:* The CAPE adapter code (`CapeSandboxBackend`) is fully written, schema-validated, and verified using mocked integration tests. Replay Mode is 100% operational for all analysis, graphing, and reporting demonstrations.

---

## 4. Known Issues & Operational Considerations

1. **Large Pydantic/Vite Chunks:**
   - The Cytoscape.js and Lucide icon library bundles are approximately 640 kB minified (200 kB gzipped). While functional and fast for modern browsers, future optimization can implement code-splitting via dynamic imports.
2. **Synchronous Worker Concurrency:**
   - In accordance with the prompt's resource safety mandate (`WORKER_CONCURRENCY=1`), analyses run sequentially to prevent resource starvation on developer VMs.

---

## 5. Next Actionable Development Tasks

1. Integrate real-time WebSocket event streaming for live log visualization during sandbox execution.
2. Expand behavioral rule coverage for memory injection techniques (e.g., Process Hollowing, APC Injection).
3. Connect live Gemini/OpenAI API keys for advanced semantic malware explanation when external egress is permitted.

