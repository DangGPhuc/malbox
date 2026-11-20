# Malbox-AI v0.2 — Final Product Architecture & Code Gap Analysis

**Document Reference:** `docs/audit/FINAL_PRODUCT_GAP_ANALYSIS.md`  
**Date:** 2026-11-20  
**Repository:** `DangGPhuc/malbox`  
**Audited HEAD Commit:** `0166bbe7352f223a8d8e0d648eb3ebdd64ad304b`  
**Branch:** `fix/live-cape-portability-ui-redesign`  
**Auditor:** Principal Software Architect, Malware Analysis Engineer, AI Systems Engineer & QA Lead

---

## 1. Executive Summary

This document establishes the authoritative technical gap analysis and readiness matrix for transforming Malbox-AI into an operational, evidence-grounded, web-based malware analysis platform. Malbox is targeted for deployment on a physical (bare-metal) Kali Linux workstation with dynamic detonation delegated to a verified, isolated CAPE Sandbox v2 infrastructure (hosted on a dedicated hypervisor/controller or within an isolated service topology).

The evaluation is structured across all 17 critical subsystems. Deficiencies are classified under strict severity ratings:
- **P0 (Blocker):** Fundamental defect, false security assurance, data hazard, or execution safety risk that prohibits operational deployment.
- **P1 (Critical):** Incomplete production contract, unhandled error cascade, missing architectural requirement, or user-facing defect.
- **P2 (Enhancement/Technical Debt):** Maintenance, operational ergonomics, or non-blocking performance optimization.

---

## 2. Component Implementation & Gap Matrix

| Component | Subsystem | Implemented Behavior | Missing Behavior / Gaps | Proven Bugs & Risks | Priority | Acceptance Criteria |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **01** | **File Upload & Quarantine** | SHA-256 deduplication, unique UUID quarantine storage, 0o400 read-only file permissions, directory traversal protection. | File retention cleanup policies, automated quarantine quota enforcement. | If directory permissions are altered by operator, sample remains read-only but quota exhaustion could block intake. | P2 | Quarantine directory strictly 0o700, files 0o400, hash verified upon upload and before pipeline execution. |
| **02** | **Hashing & PE Triage** | SHA-256, SHA-1, MD5, PE structure parsing (`pefile`), section headers, entropy calculation, import/export tables, packing heuristics. | Support for non-PE formats (currently PE only; unsupported formats must fail closed with explicit reason). | Driver binaries (`.sys`) must be blocked by safety policy rather than detonated. Native driver check exists but requires robust verification. | P1 | Strict validation that non-PE samples or driver files are safely flagged and rejected from dynamic detonation. |
| **03** | **CAPE v2 Sandbox Adapter** | Authenticated REST API v2 (`/apiv2/`), task creation, status polling (`pending`/`running`/`completed`/`reported`), bounded streaming report retrieval, forensic PCAP streaming. | Machine tag mapping and secondary artifact recovery (e.g. memory dumps) if explicitly requested. | Real network failures during report fetch could trigger fallback in tests; must ensure fallback is strictly bounded by `MAX_REPORT_BYTES` in all environments. | P1 | All CAPE API interactions enforce monotonic deadlines, size bounds, strict cancellation checks, and identity verification. |
| **04** | **CAPE Readiness & Confinement** | Operator attestation verification, mandatory manual assertions (host-only, routing, firewall, clean snapshot), wildcard (`*`) rejection, permission check (no world-writable files). | Doctor CLI does not yet verify presence/validity of the attestation file or KVM/hypervisor capability in its matrix. | Unverified confinement must fail closed. False readiness if attestation is missing or expired. | P0 | Readiness probe reports `ready_for_analysis=False` and blocks submit button whenever attestation is missing, targets mismatch, or VM is unready. |
| **05** | **Ghidra Static Analysis** | Headless Ghidra execution in Bubblewrap (`bwrap`) sandbox, cgroups v2 memory limits (`MemoryMax`), process-tree termination on timeout, selective decompilation, function ranking. | Doctor does not verify user cgroup v2 delegation if configured. Pipeline handles missing Ghidra as `UNAVAILABLE` cleanly. | Long-running decompilation could stall pipeline if timeout kill does not terminate all child processes. Current process group SIGKILL escalation mitigates this. | P1 | Ghidra executes strictly in sandbox; timeouts cleanly clean up; unavailable Ghidra gracefully preserves triage and records `UNAVAILABLE`. |
| **06** | **Analysis Orchestration** | Sequential 10-stage pipeline: Preflight -> Planned -> Ghidra -> CAPE -> Normalizing -> Detection -> Correlation -> Classification -> AI -> Reporting. | Recovery of orphaned analyses on application restart (startup hook to mark stale `RUNNING` analyses as `FAILED` or recovered). | Unhandled server restart leaves analyses indefinitely in `RUNNING`. Concurrency between heavy Ghidra and CAPE jobs must remain strictly sequential. | P0 | Interrupted analyses recovered on restart; strict sequential execution; evidence preserved after partial stage failure. |
| **07** | **Telemetry Normalization** | Process tree reconstruction, PID reuse tracking with `(pid, timestamp)` instance tuples, cycle breaking, unattributed network traffic separation. | Extended registry hive normalization for complex WOW64 redirection. | Malicious circular process parentage could induce infinite loops if not bounded. Cycle detector in `process_tree.py` prevents this. | P1 | Monitored events normalized into structured entities with verifiable process lineage. |
| **08** | **Behavior Graph** | Cytoscape.js export schema, node/edge provenance, process-to-file and process-to-network edge linking. | Graph node expansion for deep registry subkeys beyond root keys. | Overly large graph payloads could impact browser memory. Handled by hard node/edge truncation bounds. | P2 | Visual graph reflects strictly verified process and telemetry interactions with truncation warnings when capped. |
| **09** | **Detection Rules** | 10 MITRE-aligned behavioral detection rules with temporal sequencing, API success checks, and false-positive guards. | Dynamic rule reloading without application restart. | Rule triggers without API success verification could flag benign attempts. Rule engine validates return values and remote PIDs. | P1 | Findings link to verified event IDs and MITRE ATT&CK techniques; no ungrounded findings. |
| **10** | **Evidence Correlation** | Bidirectional mapping between Ghidra static functions/APIs and dynamic events, call graph attribution, persistent correlation records. | Stale correlation invalidation when newer static or dynamic analysis records are registered. | Out-of-sync correlation when static analysis times out after dynamic analysis finishes. Handled by monotonic sequence check. | P1 | Static-dynamic correlation resolves clicked function deep-links and highlights observed dynamic behaviors. |
| **11** | **Malware Classification** | 17-category taxonomy, multi-label assignment, strict Downloader correlation (network GET matched to saved binary), Injector validated sequences, `INCOMPLETE` confidence capping ($\le 0.65$). | Category override by operator. | Benign installers flagged as Downloaders if network GET is unlinked to dropped binary. Prevented by strict basename/path correlation. | P0 | Classification grounded in verified findings; confidence clipped under partial telemetry; unsupported categories flagged `UNSUPPORTED`. |
| **12** | **AI Evidence Bundle** | Structured `VerifiedEvidenceBundle` containing hashes, PE metadata, static functions, process relationships, IOCs, findings, limitations, and truncation bounds. | Real-time streaming tokenization for large decompiled code excerpts. | Excessive bundle size causing LLM context window overflow. Handled by deterministic truncation and redaction. | P1 | Bundle contains strictly verified, bounded evidence IDs without raw binary bytes or unsanitized prompt injection vectors. |
| **13** | **AI Inference Providers** | `RealLLMProvider` (OpenAI-compatible / Ollama / local), `OpenCodeReportProvider` (CLI v2.1.4), `MockLLMProvider`. | Silent fallback from Real LLM to Mock LLM masks provider failures as actual AI output. Must explicitly mark AI `UNAVAILABLE` on provider failure. | `RealLLMProvider` previously fell back silently to `MockLLMProvider`, violating the requirement to never present mock output as real AI analysis. | P0 | Provider abstraction supports Local (Ollama/llama.cpp) and External AI (with consent); failure marks AI `UNAVAILABLE` and offers non-AI technical report without silent mock spoofing. |
| **14** | **Intelligence Report** | 18-section structured report, epistemic claim classification (`FACT`, `INFERENCE`, `HYPOTHESIS`), evidence ID citations, confidence/gap analysis. | Interactive re-analysis / regeneration with alternative AI prompt profiles. | Hallucinated threat claims or invented family names without explicit signature. Prevented by `EvidenceValidator` reject/downgrade rules. | P0 | Every claim grounded in verified evidence IDs; executive summary and technical sections clearly separate facts from inferences. |
| **15** | **Frontend UX** | Notion-inspired layout, single `Analyze File` workflow, dynamic stage progress, Function Explorer, Cytoscape graph, disabled submit button when unready. | Real-time WebSocket stage updates (currently HTTP polling). | Attempting submission when CAPE or isolation is unverified. Fixed by disabling submit button and rendering exact missing prerequisites. | P1 | Clean single-action intake; real-time stage progress; interactive evidence navigation; standalone HTML/JSON export. |
| **16** | **CLI, Doctor & Setup Assistant** | Doctor CLI (`./malbox doctor`), service lifecycle (`start`, `stop`, `status`). | Missing `./malbox setup` subcommand (`--check`, `--plan`, `--ghidra`, `--cape`, `--ai`, `--verify`); missing `./malbox logs`; Doctor lacks comprehensive 8-tier status matrix. | Operator executing real malware without independently verifying network isolation or virtualization prerequisites. | P0 | Doctor outputs complete 8-state matrix; `./malbox setup` provides idempotent, non-destructive guided setup plans. |
| **17** | **Database & Persistence** | SQLite with WAL mode, SQLAlchemy ORM, transactional commits, quarantine path tracking. | Automated vacuum and periodic backup tooling. | SQLite lock contention during simultaneous background worker writes and API queries. Handled by scoped sessions and WAL mode. | P1 | Database maintains integrity across restarts; historical reports and sample records are preserved permanently. |

---

## 3. High-Priority Defect & Gap Resolution Roadmap

### 3.1 P0 Findings (Must resolve before operational acceptance)
1. **P0-1: Silent Mock Fallback in AI Provider:**
   - *Problem:* `RealLLMProvider` and `run_bounded_llm_intelligence` catch exceptions and fall back to `MockLLMProvider` or `mock_fallback` mode without marking AI analysis as `UNAVAILABLE`.
   - *Fix:* When a real AI provider fails, do not generate synthetic mock claims. Record `ai_status = "UNAVAILABLE"`, preserve all deterministic findings and classifications, and render an authoritative non-AI forensic technical report with a one-click "Retry AI Analysis" option.
2. **P0-2: Missing Guided Setup Assistant (`./malbox setup`):**
   - *Problem:* Operators have no automated way to generate deployment plans, configure Ghidra/cgroups, verify CAPE connectivity, or configure local/external AI providers without manually editing files.
   - *Fix:* Implement `./malbox setup` with `--check`, `--plan`, `--ghidra`, `--cape`, `--ai`, and `--verify` commands supporting dry-run and configuration backups.
3. **P0-3: Doctor Readiness Matrix Incompleteness:**
   - *Problem:* Doctor does not evaluate hardware CPU virtualization (`/dev/kvm`, VMX/SVM flags), operator isolation attestation status, target machine/route binding, or local AI inference endpoints.
   - *Fix:* Extend `checks.py` to evaluate the complete matrix and categorize each subsystem into: `INSTALLED`, `CONFIGURED`, `REACHABLE`, `VERIFIED`, `READY`, `DEGRADED`, `BLOCKED`, `UNSUPPORTED`.
4. **P0-4: Orphaned Analysis Recovery on Backend Startup:**
   - *Problem:* If the backend is abruptly restarted while an analysis is in `RUNNING` or `QUEUED`, the task remains permanently stuck.
   - *Fix:* Add an application startup check in `main.py` that transitions orphaned active analyses to `FAILED` with error "Analysis interrupted by server restart; static triage preserved."

### 3.2 P1 Findings
1. **P1-1: Dedicated Deployment Documentation:**
   - *Problem:* Missing dedicated bare-metal Kali installation, Windows guest provisioning, network isolation checklist, and AI provider setup guides.
   - *Fix:* Author `docs/deployment/KALI_BARE_METAL.md`, `CAPE_SINGLE_HOST.md`, `CAPE_DISTRIBUTED.md`, `WINDOWS_GUEST_SETUP.md`, `NETWORK_ISOLATION_CHECKLIST.md`, `AI_PROVIDER_SETUP.md`, and `HARDWARE_REQUIREMENTS.md`.
2. **P1-2: Multi-Stage AI Analytical Investigation Pipeline:**
   - *Problem:* Current AI prompt treats analysis as a monolithic single-prompt pass rather than the 4-analyst sequential stages (Static Code -> Dynamic Behavior -> Threat Classification -> Report Composer).
   - *Fix:* Structure the intelligence prompt and schemas to explicitly encompass Analyst A, B, C, and D reasoning stages while enforcing strict context limits.

---

## 4. Verification & Testing Strategy

1. **Unit & Security Regression Gate:**
   - Verify all existing 221 backend tests and 47 frontend tests remain 100% green.
   - Add new tests for `./malbox setup`, the enhanced Doctor matrix, AI provider failure states (UNAVAILABLE without mock spoofing), and startup orphan recovery.
2. **Mocked End-to-End Pipeline Gate:**
   - Test full pipeline intake -> Ghidra -> CAPE -> detection -> classification -> AI report with mocked backends.
3. **Safe Real-World Integration Gate:**
   - Verify benign PE triage, local OpenCode/Ollama CLI detection, and report generation in Kali host environment.
