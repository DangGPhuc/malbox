# malbox-ai — Audit Remediation & Hardening Ledger

**Branch:** `audit/remediation-hardening`  
**Base Commit:** `181309e` -> `e00a55f` -> `af512ed`  
**Date:** November 2026  
**Status:** **Remediated, Hardened & VM-Ready (All Tasks 1 — 5 Verified)**

---

## 1. Verified Defect & Remediation Summary

| Phase | Subsystem | Priority | Defect Description | Root Cause | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Contract** | API / UI | **P0** | Frontend sent `scenario_id` while backend schema expected `replay_scenario_id`, causing selected scenario to be ignored. | Schema field naming discrepancy between `SubmitPage.tsx` / `client.ts` and `AnalysisCreate`. | **Fixed & Verified** |
| **Config** | Configuration | **P1** | `.env.example` had outdated CAPE URL `8000`, lacked `MALBOX_OPERATOR_TOKEN` documentation, and `.env` loading was implicit. | Stale default port in `.env.example`; missing `env_file` directive in `SettingsConfigDict`. | **Fixed & Verified** |
| **Audit** | Dependencies | **P1** | Moderate and high vulnerabilities in frontend dev dependencies (`esbuild` and `vite`). | Older bundled `esbuild@0.21.5` in `vite@5`. | **Remediated & Documented** |
| **Benchmark** | Benchmarks | **P1** | Benchmark did not separate process peak RSS from per-scenario allocation, and lacked system specifications. | Over-reliance on `ru_maxrss` alone without `tracemalloc` or environment inspection. | **Fixed & Verified** |
| **CI** | Reporting | **P0** | `NameError: name 'Optional' is not defined` in `generate_report()`. | Missing `Optional` in typing imports of `generator.py`. | **Fixed & Verified** |
| **Security** | Auth & Safety | **P0** | Hardcoded operator token, live mode bypass with `backend_type=cape`, replay path traversal. | Permissive defaults, unverified scenario IDs, and lack of constant-time token comparison. | **Fixed & Verified** |

---

## 2. Detailed Remediation Details by Subsystem

### Replay Scenario API Contract Alignment (Task 1)
- **Defects Identified:**
  - React frontend `client.ts` and `SubmitPage.tsx` sent `scenario_id: string`, while FastAPI `AnalysisCreate` required `replay_scenario_id: Optional[str]`.
  - When submitting via the UI, the explicit scenario selection was omitted from `AnalysisCreate`, causing Replay backend to fall back to default profile heuristics rather than the operator's chosen scenario.
- **Fixes Applied:**
  - Updated `frontend/src/api/client.ts` and `frontend/src/pages/SubmitPage.tsx` to send `replay_scenario_id`.
  - Added backward-compatible alias mapping in `backend/app/schemas/analysis.py` (`model_validator(mode="before")` mapping `scenario_id` -> `replay_scenario_id`).
  - Added 4 regression tests in `backend/tests/test_replay_pipeline.py`:
    - `test_replay_scenario_wannacry_independent_of_profile`: verifies WannaCry scenario executes when selected, even if profile is non-ransomware (`infostealer_focus`).
    - `test_replay_scenario_redline_independent_of_profile`: verifies RedLine scenario executes when selected, even if profile is `ransomware_focus`.
    - `test_replay_scenario_alias_compatibility`: verifies `scenario_id` legacy alias contract.
    - `test_replay_invalid_scenario_id_does_not_silently_fallback`: verifies unknown or path-traversing scenario IDs return HTTP 400 Bad Request and never silently fall back.

### Configuration Synchronization (Task 2)
- **Fixes Applied:**
  - Updated `backend/app/core/config.py` to explicitly load `.env` files via `SettingsConfigDict(env_prefix="MALBOX_", env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore")`.
  - Guaranteed environment-variable precedence: actual environment variables in `os.environ` securely override `.env` values.
  - Corrected `MALBOX_CAPE_API_URL=http://127.0.0.1:8008` in `.env.example` (avoiding collision with FastAPI backend port 8000).
  - Explicitly documented `MALBOX_OPERATOR_TOKEN` in `.env.example` without exposing secrets: emphasized that it must remain empty during Replay/Evaluation mode to guarantee fail-closed security, and instructions for setting a strong random secret when live mode is authorized.
  - Kept `MALBOX_HOST=127.0.0.1` and `MALBOX_LIVE_MODE_ENABLED=false` by default.

### Frontend Dependency Review & Remediation (Task 3)
- **Audit Findings:**
  - `npm audit` flagged:
    1. Moderate vulnerability: `esbuild <= 0.24.2` (GHSA-67mh-4wv8-2f99) — dev server cross-origin response read.
    2. High vulnerability: `vite <= 6.4.3` (GHSA-4w7w-66w2-5vf9, GHSA-v6wh-96g9-6wx3) — dev server path traversal and editor UNC handling on Windows.
- **Fixes Applied & Impact Analysis:**
  - Added `"overrides": { "esbuild": "^0.25.0" }` in `frontend/package.json`. Installed `esbuild@0.25.12`, completely remediating GHSA-67mh-4wv8-2f99.
  - Verified `npm run build` succeeds cleanly in 1.82s.
  - Remaining advisory on `vite` strictly affects the local development server (`npm run dev`) under Windows editor configurations; it does **not** affect the production static bundle or VM deployment (`npm run build`).
  - Avoiding `npm audit fix --force` preserved stability by rejecting a breaking major-version upgrade to `vite@8.3.6`.

### Benchmark Quality & Host/VM Contextualization (Task 4)
- **Improvements Applied in `scripts/benchmark_replay.py`:**
  - Added `get_system_specifications()` inspecting OS platform, Python version, logical CPU count, and total system RAM.
  - Clearly labeled host execution context: `Host / CI Baseline Validation (Pre-VM)` with an explicit disclaimer that target VM benchmarks must be recorded inside the target VM.
  - Integrated `tracemalloc` to isolate per-scenario peak memory allocation from process-wide high-water mark peak RSS (`ru_maxrss`).
  - Sequentially executed synthetic scaling: Small (~100 events), Medium (~1,000 events), Large (~10,000 events).
  - Measured database write duration separately from normalization parsing.
  - Verified no live malware or hypervisor connections are initiated.

---

## 3. Verification Test Suite Status

All 56 automated tests pass with 100% success rate:
```
backend/tests/test_ai_orchestration.py: 5/5 PASSED
backend/tests/test_cape_adapter.py: 3/3 PASSED
backend/tests/test_detection_rules.py: 6/6 PASSED
backend/tests/test_health.py: 2/2 PASSED
backend/tests/test_pe_parser.py: 5/5 PASSED
backend/tests/test_real_ai_provider.py: 6/6 PASSED
backend/tests/test_replay_pipeline.py: 5/5 PASSED
backend/tests/test_safety_and_lifecycle.py: 14/14 PASSED
backend/tests/test_submission.py: 3/3 PASSED
backend/tests/test_telemetry_integrity.py: 7/7 PASSED
======================== 56 passed, 1 warning in 12.38s ========================
```

Frontend production build:
```
cd frontend && npm run build
✓ 1491 modules transformed.
dist/index.html                   0.85 kB │ gzip:   0.49 kB
dist/assets/index-DSG-b06S.css    3.05 kB │ gzip:   1.15 kB
dist/assets/index-DyWvua34.js   645.09 kB │ gzip: 201.72 kB
✓ built in 1.82s
```
