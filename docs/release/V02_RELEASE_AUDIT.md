# Malbox-AI v0.2 — Release Candidate Verification Audit

**Codename:** `malbox-ai`  
**Architecture Version:** `0.2.0-rc1`  
**Branch:** `audit/v02-release-candidate`  
**Audited Commit SHA:** `2841fe724ef6a83b7f3470e400575f5575250c47`  
**Audit Timestamp:** 2026-11-12T02:30:00Z  
**Host Environment:** Kali GNU/Linux Rolling (x86_64), Linux 7.1.5+kali-amd64  
**Audit Verdict:** **READY FOR OPERATOR ACCEPTANCE TEST**

---

## 1. Executive Summary & Scope

This audit document represents the final full-system verification for Malbox-AI v0.2.
The release encompasses all capabilities delivered across Phases 1 through 4:

1. **Phase 1: Deterministic PE Triage & Replay Engine:** Safe parsing of PE headers, sections, imports, and entropy without execution; repeatable deterministic playback of WannaCry and RedLine telemetry.
2. **Phase 2: Evidence-Grounded AI Intelligence & Safety Gate:** Bounded `VerifiedEvidenceBundle` with hard byte limits, semantic claim validation (FACT / INFERENCE / HYPOTHESIS), `X-Reporting-Token` ephemeral authorization, Bubblewrap-isolated OpenCode adapter with deterministic fallback.
3. **Phase 3: Ghidra Headless Static Analysis & Function Explorer:** Resource-bounded, bwrap-isolated static analysis of PE binaries with deterministic call graph ranking, selective decompilation, and function explorer UI.
4. **Phase 4: Evidence-Grounded Static/Dynamic Correlation Engine & Explorer:** Deterministic cross-layer correlation linking static code capabilities with runtime telemetry, authenticated HMAC trace verification, strict Replay synthetic provenance separation (`DIRECTLY_OBSERVED = 0`), and interactive Correlation Explorer UI.
5. **Release Candidate Gates (Gate 0 & Gate 1):** Coherent correlation source selection (`resolveCoherentCorrelationAssessment`), fenced async event pagination (`runBoundedEventLookup`), unmount lifecycle guards across all frontend views, and Doctor CLI Phase 3/4 database schema verification.

---

## 2. Test Execution & Verification Matrix

All tests listed below were executed on the Kali host against audited commit `2841fe724ef6a83b7f3470e400575f5575250c47`:

| Test Suite / Component | Classification | Tested Commit | Result | Duration | Notes |
|:---|:---|:---|:---:|:---:|:---|
| `backend/tests/test_pe_parser.py` (5 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.8s | PE header parsing, section hashing, imports, entropy |
| `backend/tests/test_submission.py` (3 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.4s | Deduplication, live mode safety gate, analysis retrieval |
| `backend/tests/test_safety_and_lifecycle.py` (14 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 2.5s | Operator tokens, job queue recovery, terminal states |
| `backend/tests/test_replay_pipeline.py` (5 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 1.8s | WannaCry & RedLine scenarios, synthetic invariants |
| `backend/tests/test_ai_orchestration.py` (5 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.9s | Policy validator, command injection blocks, audit trail |
| `backend/tests/test_real_ai_provider.py` (6 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 1.1s | HTTP LLM provider, fallback to Mock, allowlist |
| `backend/tests/test_detection_rules.py` (6 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.8s | MITRE ATT&CK contextual scoring, regression invariants |
| `backend/tests/test_telemetry_integrity.py` (7 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 1.2s | Process tree PID reuse, strict graph edge integrity |
| `backend/tests/test_intelligence_engine.py` (13 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 3.4s | Claim verification, byte caps, XSS safety, token auth |
| `backend/tests/test_opencode_and_hardening.py` (13 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 7.8s | Includes real `bwrap` + `opencode` CLI integration test |
| `backend/tests/test_cape_adapter.py` (3 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.5s | Mocked CAPE adapter readiness, task polling, transform |
| `backend/tests/test_doctor_cli.py` (12 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 2.1s | Permissions (0600/0700), process isolation, DB checks |
| `backend/tests/test_evidence_correlation.py` (19 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 6.7s | HMAC trace auth, streaming fingerprints, HTML export |
| `backend/tests/test_static_analysis.py` (26 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 6.6s | Function ranking, decompilation caps, bwrap sandbox |
| `backend/tests/test_health.py` (2 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 0.2s | `/health` and root API health endpoints |
| `test_live_ghidra_bwrap_smoke_opt_in` | CURRENT_RC (Host) | `2841fe7` | **SKIP** | — | Opt-in test requiring `MALBOX_RUN_LIVE_GHIDRA_TEST=1` |
| **Backend Total** | **CURRENT_RC (Host)** | `2841fe7` | **139 PASS / 1 SKIP** | **61.3s** | **100% of non-opt-in tests passing** |
| `frontend/src/__tests__/ReportPage.test.tsx` (11 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 4.2s | Intelligence report, async lookup paging, print hook |
| `frontend/src/__tests__/CorrelationPage.test.tsx` (10 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 6.0s | Correlation Explorer, Gate 0.1 & 0.2 coherence/fencing |
| `frontend/src/__tests__/StaticAnalysisPage.test.tsx` (14 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 4.7s | Ghidra function explorer, decompilation viewer |
| `frontend/src/__tests__/EnrichmentFlow.test.tsx` (4 tests) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 1.7s | Ephemeral token auth, error retry, consent UI |
| **Frontend Total** | **CURRENT_RC (Host)** | `2841fe7` | **39 PASS** | **8.9s** | **4 test files, 100% passing** |
| Frontend TypeScript (`tsc --noEmit`) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 7.1s | 0 errors in strict mode |
| Frontend Production Build (`npm run build`) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 4.1s | 1529 modules, 7 chunks generated cleanly |
| Frontend Dependency Audit (`npm audit`) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 5.8s | 0 vulnerabilities found |
| Doctor CLI Check (`./malbox doctor --check`) | CURRENT_RC (Host) | `2841fe7` | **PASS / WARN** | 2.1s | PASS=12, WARN=1 (legacy SQLite DB schema), SKIP=2 |
| Doctor Smoke Test (`./malbox doctor --smoke-test`) | CURRENT_RC (Host) | `2841fe7` | **PASS** | 4.2s | WannaCry replay verified (4 findings, 17 graph nodes) |

---

## 3. Discovered Findings & Resolution Log

### Fixed During Release Candidate Cycle

1. **[RC Gate 0] Incoherent Correlation Assessment Mixing:**
   - *Impact:* Previously, live correlation result counts could be mixed with snapshot provenance metadata when switching analyses or recomputing.
   - *Resolution:* Implemented `resolveCoherentCorrelationAssessment()` in `frontend/src/components/IntelligenceReport/utils.ts` and `_render_correlation_html_section()` in `backend/app/services/reporting/export_html.py`. Exactly one source is selected with explicit provenance and `superseded_snapshot` disclosure.
   - *Commit:* `82ebafb`

2. **[RC Gate 0] Unfenced Async Evidence Lookups:**
   - *Impact:* Rapid clicking or analysis switching could allow late `/events` responses to contaminate current view.
   - *Resolution:* Created `frontend/src/utils/eventLookup.ts` with `runBoundedEventLookup()` enforcing epoch, click-sequence monotonic guards, and a 5-page hard cap.
   - *Commit:* `82ebafb`

3. **[RC Gate 1] Doctor CLI Omission of Phase 3/4 DB Schema Tables:**
   - *Impact:* `REQUIRED_DB_TABLES` only checked baseline Phase 1 tables. Missing `static_analysis_results` or `evidence_correlations` would go undetected by `./malbox doctor --check`.
   - *Resolution:* Added both table names to `REQUIRED_DB_TABLES` in `scripts/malbox_cli/models.py`.
   - *Commit:* `52452a0`

4. **[RC Gate 1] Unmounted Component State Updates:**
   - *Impact:* Navigating away from `WorkspacePage` or `BehaviorGraphPage` during polling emitted React unmounted-component warnings.
   - *Resolution:* Added `mountedRef = useRef(true)` guards and interval cleanup in both pages.
   - *Commit:* `52452a0`

5. **[RC Fix] Dynamic Timestamp Inversion in Correlation History Test:**
   - *Impact:* `test_27_bounded_history_retrieval_across_large_history_and_replay_invariance` hardcoded a fixed timestamp `2026-11-11T23:00:00Z` which fell into the past during UTC date rollover on 2026-11-12, causing assertion failure against `now_utc`.
   - *Resolution:* Updated test fixture to use `datetime.now(timezone.utc) + timedelta(days=1)`.
   - *Commit:* `2841fe7`

### Open Findings & Operational Caveats (P2 / Advisory)

- **[P2 - Informational] Legacy SQLite Database Schema Warning:**
  - *Observation:* Running `./malbox doctor --check` against an existing `data/malbox.db` created during Phase 1/2 emits `[WARN] missing schema tables: evidence_correlations, static_analysis_results`.
  - *Mitigation:* Documented operator instruction: run `./malbox doctor --repair` on upgrade, which safely runs `init_db()` to create missing tables without dropping existing data.
  - *Severity:* P2 (Non-blocking; clean installs automatically initialize all tables).

- **[P2 - Informational] Empty-Live Correlation Supersession Banner:**
  - *Observation:* If a live correlation recomputation legitimately yields 0 findings, it supersedes a prior non-empty snapshot. The UI and JSON export prominently disclose this via `supersededSnapshot: { priorFindingsCount, fingerprint }`.
  - *Mitigation:* Intended architectural behavior; verified by `CorrelationPage.test.tsx` test 0.1.

---

## 4. Verification Distinctions: Host vs. CI vs. Mocks

To ensure complete audit integrity, test execution environments are explicitly classified:

1. **Host Integration Tests (Kali GNU/Linux):**
   - `test_real_bwrap_sandbox_and_real_opencode_cli_integration`: Executed against actual `/usr/bin/bwrap` and `/home/kali/.opencode/bin/opencode`. Result: **PASS**.
   - `Doctor CLI Lifecycle`: Executed against actual POSIX process groups, local file permissions (0600 `.env`, 0700 `data/quarantine`). Result: **PASS**.
   - `Doctor Smoke Test`: Executed end-to-end replay through full Python pipeline. Result: **PASS**.

2. **GitHub Actions CI Runner (`ubuntu-latest`):**
   - CI environment lacks host-installed OpenCode CLI and Ghidra Headless binaries.
   - The test harness detects binary absence and cleanly marks host-specific tests as **SKIP**, ensuring CI remains green without false negatives.

3. **Opt-in Live Ghidra Integration:**
   - `test_live_ghidra_bwrap_smoke_opt_in` is marked **SKIP** by default unless the environment variable `MALBOX_RUN_LIVE_GHIDRA_TEST=1` is provided. This enforces the project's zero-unauthorized-code-execution security invariant.

---

## 5. Security & Risk Assessment

- **Execution Safety Gate:** Hard fail-closed enforcement. Real binary execution remains disabled (`MALBOX_LIVE_MODE_ENABLED=false`).
- **Trace Signing Key Isolation:** `MALBOX_TRACE_AUTH_KEY` is cryptographically separated from `MALBOX_SECRET_KEY`. Default/weak keys reject trace validation. Replay events can never claim `DIRECTLY_OBSERVED` execution.
- **Sandboxing:** OpenCode and Ghidra operate under strict Bubblewrap Linux namespaces (`--unshare-all`, `--cap-drop ALL`, read-only bind mounts, memory cgroup caps).
- **Injection Protection:** HTML export uses `_esc()` on all untrusted and model-generated strings. Cytoscape JSON escapes node and edge labels.

---

## 6. Final Release Verdict

**Verdict:** **READY FOR OPERATOR ACCEPTANCE TEST**

**Justification:**
- All 139 core backend tests and 39 frontend unit tests are passing on HEAD `2841fe7`.
- TypeScript strict typecheck and Vite production build pass cleanly with 0 errors.
- Dependency audit confirms 0 security vulnerabilities.
- Zero open P0 or P1 defects.
- All release documents, operator checklists, and known limitations are fully delivered.
