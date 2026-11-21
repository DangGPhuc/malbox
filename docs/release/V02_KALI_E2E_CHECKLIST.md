# Malbox-AI v0.2 — Kali Host E2E Verification Checklist & Runbook

**Audited Commit SHA:** `2841fe724ef6a83b7f3470e400575f5575250c47`  
**Execution Date:** 2026-11-12  
**Platform:** Kali GNU/Linux Rolling (x86_64) — Kernel 7.1.5+kali-amd64  
**Target Architecture:** Full Malbox-AI Platform (Backend FastAPI + Frontend React/TypeScript)

---

## 1. Environment Metadata & Preflight Telemetry

Before executing E2E tests, the Kali host environment was inspected using non-destructive read-only commands:

| Parameter | Observed Host Value | Required Specification | Status |
|:---|:---|:---|:---:|
| **Operating System** | Kali GNU/Linux Rolling (x86_64) | Linux (x86_64, POSIX compatible) | **PASS** |
| **Linux Kernel** | 7.1.5+kali-amd64 | >= 5.15 | **PASS** |
| **Python Runtime** | 3.14.7 (`/usr/bin/python3`) | >= 3.10 | **PASS** |
| **Virtualenv** | `.venv/` (Python 3.14.7) | Isolated virtual environment | **PASS** |
| **Node.js** | v24.19.0 (`/usr/bin/node`) | >= 18.0.0 | **PASS** |
| **npm** | 12.0.2 (`/usr/bin/npm`) | >= 9.0.0 | **PASS** |
| **Java / OpenJDK** | OpenJDK 25.0.4.1 (build 25.0.4.1+1-1-Debian) | >= 17 (for Ghidra 12+) | **PASS** |
| **Ghidra Headless** | 12.1.4 (`/usr/share/ghidra/support/analyzeHeadless`) | >= 11.0 (Headless Analyzer) | **PASS** |
| **OpenCode CLI** | v2.1.4 (`/home/kali/.opencode/bin/opencode`) | Optional (v2.x) | **PASS** |
| **Bubblewrap** | 0.11.0 (`/usr/bin/bwrap`) | >= 0.7.0 (Linux user namespaces) | **PASS** |
| **systemd User Mode** | State: `running`, 252 loaded units | Active user session (cgroup v2) | **PASS** |
| **System Memory** | 7.4 GiB Total, 2.0 GiB Available, 7.7 GiB Swap | >= 4 GiB Total, >= 1.5 GiB Avail | **PASS** |
| **Disk Storage** | 460 GiB total, 54 GiB available (88% used) | >= 10 GiB available | **PASS** |
| **Orphaned Processes** | None detected (`java`, `ghidra`, `opencode`, `uvicorn`) | Clean process table | **PASS** |

---

## 2. Sequential Verification Runbook & Evidence Log

### Step 1: Python Import & App Assembly Preflight
- **Command:** `.venv/bin/python -c "import app.main; print('IMPORT_OK')"`
- **Expected Result:** Immediate `IMPORT_OK` output, exit code 0.
- **Observed Result:** `IMPORT_OK` (exit code 0, 1.8s).
- **Status:** **PASS**

### Step 2: Doctor System & Environment Audit
- **Command:** `./malbox doctor --check`
- **Expected Result:** Summary `WARN` or `PASS` with 0 failures. (Legacy database emits `WARN` noting missing Phase 3/4 tables if unmigrated).
- **Observed Result:**
  ```text
  malbox-ai Doctor (check mode) — Root: /home/kali/Documents/malbox
  ========================================================================
  [PASS]  Operating System: Supported OS detected: Kali GNU/Linux Rolling (x86_64)
  [PASS]  Python Runtime & venv: Python 3.14.7 with venv support available (/usr/bin/python3)
  [PASS]  Node.js & npm: Node.js v24.19.0 and npm 12.0.2 available
  [PASS]  Disk Space & RAM: Disk free: 54641 MB; Memory: 2900 MB free / 7627 MB total
  [PASS]  Configuration (.env) & Safety Policy: Safe Replay Mode defaults active (Live Mode disabled).
  [PASS]  Runtime & Quarantine Directories: Data, artifacts, runtime, and quarantine directories initialized.
  [PASS]  Virtualenv & Backend Dependencies: .venv healthy and all packages import cleanly.
  [PASS]  Frontend Dependencies & Build: Frontend dependencies and production bundle verified.
  [WARN]  Database Health: SQLite file exists, but missing schema tables: evidence_correlations, static_analysis_results.
  [PASS]  Replay Mode Fixtures: All 2 registered Replay scenarios valid.
  [PASS]  Network Port Availability: Ports clear (backend :8000, frontend :5173).
  [SKIP]  Optional: CAPE Sandbox: Optional live CAPE Sandbox disabled in Replay Mode.
  [PASS]  Optional: Ghidra Headless: Optional Ghidra 12.1.4 & JDK 25 verified (/usr/share/ghidra; bwrap=ok, cgroup_mem=ok).
  [PASS]  Optional: OpenCode CLI: Optional OpenCode CLI detected at /home/kali/.opencode/bin/opencode.
  [SKIP]  Optional: External AI Credentials: Using deterministic MockLLMProvider.
  ========================================================================
  Summary: WARN | PASS=12 WARN=1 FAIL=0 SKIP=2
  ```
- **Status:** **PASS**

### Step 3: Isolated Replay Smoke Test
- **Command:** `./malbox doctor --smoke-test`
- **Expected Result:** Full Replay analysis executes in memory without modifying production database.
- **Observed Result:**
  ```text
  [PASS]  Replay Pipeline Smoke Test: Isolated Replay E2E verified (WannaCry scenario, 4 findings, 17 graph nodes, 1433.78 ms, 90.47 MB peak RSS).
  Summary: WARN | PASS=13 WARN=1 FAIL=0 SKIP=2
  ```
- **Status:** **PASS**

### Step 4: Full Backend Pytest Suite
- **Command:** `.venv/bin/pytest backend/tests/ -v --tb=short`
- **Expected Result:** 139 passed, 1 skipped (opt-in Ghidra live test).
- **Observed Result:**
  ```text
  ============= 139 passed, 1 skipped, 1 warning in 61.29s (0:01:01) =============
  ```
- **Status:** **PASS**

### Step 5: Frontend TypeScript Strict Check
- **Command:** `cd frontend && npm run typecheck`
- **Expected Result:** `tsc --noEmit` exits with 0 errors.
- **Observed Result:** Clean exit, 0 errors.
- **Status:** **PASS**

### Step 6: Frontend Vitest Suite
- **Command:** `cd frontend && npm test`
- **Expected Result:** 39 passed across 4 test suites.
- **Observed Result:**
  ```text
  ✓ src/__tests__/EnrichmentFlow.test.tsx (4 tests) 1715ms
  ✓ src/__tests__/ReportPage.test.tsx (11 tests) 4153ms
  ✓ src/__tests__/StaticAnalysisPage.test.tsx (14 tests) 4706ms
  ✓ src/__tests__/CorrelationPage.test.tsx (10 tests) 6006ms

  Test Files  4 passed (4)
       Tests  39 passed (39)
    Duration  8.90s
  ```
- **Status:** **PASS**

### Step 7: Frontend Production Bundle Build
- **Command:** `cd frontend && npm run build`
- **Expected Result:** Production bundle built under `dist/` with chunked Cytoscape and page splits.
- **Observed Result:**
  ```text
  ✓ 1529 modules transformed.
  dist/index.html                                0.85 kB │ gzip:   0.49 kB
  dist/assets/StaticAnalysisPage-iLZ-klws.css    0.67 kB │ gzip:   0.34 kB
  dist/assets/CorrelationPage-CDxvPSaZ.css       0.86 kB │ gzip:   0.39 kB
  dist/assets/index-EMQ28tde.css                 5.54 kB │ gzip:   1.82 kB
  dist/assets/BehaviorGraphPage-BKUVeYby.js      7.12 kB │ gzip:   2.42 kB
  dist/assets/CorrelationPage-4IATgWnG.js       50.99 kB │ gzip:  12.64 kB
  dist/assets/StaticAnalysisPage-DDrj6TQF.js    59.90 kB │ gzip:  14.61 kB
  dist/assets/index-BETJAIj7.js                311.68 kB │ gzip:  85.72 kB
  dist/assets/cytoscape.esm-C6b3ySTN.js        443.97 kB │ gzip: 141.80 kB
  ✓ built in 4.09s
  ```
- **Status:** **PASS**

### Step 8: Frontend Security & Dependency Audit
- **Command:** `cd frontend && npm audit`
- **Expected Result:** 0 vulnerabilities found.
- **Observed Result:** `found 0 vulnerabilities` (exit code 0).
- **Status:** **PASS**

---

## 3. Explicit SKIP Justifications

1. **`test_live_ghidra_bwrap_smoke_opt_in` (Backend):**
   - *Reason:* By security design, live Ghidra headless execution is disabled by default to prevent accidental CPU/memory exhaustion or untrusted binary parsing without operator consent.
   - *Operator Activation:* To run this test on Kali, export `MALBOX_RUN_LIVE_GHIDRA_TEST=1` and execute `.venv/bin/pytest backend/tests/test_static_analysis.py -k test_live_ghidra_bwrap_smoke_opt_in`.

2. **CAPE Sandbox Live Execution (System):**
   - *Reason:* Live guest VM hypervisor orchestration is disabled in Replay Mode. CAPE integration logic is verified via unit tests (`test_cape_adapter.py`) using simulated payloads.

---

## 4. Post-Execution Resource & Cleanup Verification

- **Storage Impact:** Zero unmanaged files created outside standard `.pytest_cache/` and `frontend/dist/`.
- **Database Integrity:** Production database `data/malbox.db` remained read-only during tests.
- **Process Cleanup:** Verified with `ps aux | grep -E "(java|ghidra|opencode|uvicorn)"` — 0 residual background processes.
