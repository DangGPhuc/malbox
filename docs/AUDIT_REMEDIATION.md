# malbox-ai — Audit Remediation & Hardening Ledger

**Branch:** `audit/remediation-hardening`  
**Base Commit:** `181309e`  
**Date:** November 2026  
**Status:** In Progress — Remediation & Hardening

---

## 1. Verified Defect & Remediation Summary

| Phase | Subsystem | Priority | Defect Description | Root Cause | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | Packaging | **P0** | `backend/pyproject.toml` missing `backend/README.md` & flat-layout discovery collision with empty `backend/fixtures`. | Missing readme file and missing package find directive in `pyproject.toml`. | **Fixed & Verified** |
| **1** | Safety Gate | **P0** | Inconsistent backend / mode gate allows `backend_type="cape"` with `live_mode=false` to bypass safety check. | API and Worker checked `live_mode` independently of `backend_type`; string backend without strict enum. | *In Progress* |
| **2** | Job Lifecycle | **P0** | BackgroundTasks used as queue; concurrency=1 not enforced; cancellation doesn't halt worker; premature CAPE report fetch. | No durable queue; uncoordinated threading; missing CAPE status polling loop. | *Pending* |
| **3** | AI Orchestrator| **P1** | `RealLLMProvider` delegates to `MockLLMProvider`; blacklist validator; no token/model tracking. | Placeholder delegation in `llm_client.py`; negative key checking instead of positive schema allowlist. | *Pending* |
| **4** | Telemetry | **P1** | Hardcoded OS/confinement in reports; process graph sensitive to event order / PID reuse; potential ungrounded edges. | Lack of instance identity for processes; static strings in report generator. | *Pending* |
| **5** | Detection | **P1** | Overly broad single-event rules (any POST = exfil; any 445 = scanning); "Clean" verdict on zero telemetry. | Lack of contextual behavioral thresholds; binary clean classification instead of inconclusive. | *Pending* |
| **6** | Replay Mode | **P1** | Automatic canned fixture selection based on sample filename; unclear synthetic vs live provenance. | Dynamic selection heuristic conflates real sample with canned threat data. | *Pending* |
| **7** | Security & UI | **P1** | Unescaped HTML in standalone report; frontend lacks live polling; synchronous blocking requests. | Lack of `html.escape()` in HTML generator; no interval polling in React workspace. | *Pending* |
| **8** | QA & Benchmarks| **P1** | Missing CI workflow and automated VM resource benchmark script. | Absence of `.github/workflows/ci.yml` and benchmark script. | *Pending* |

---

## 2. Phase 0 Audit & Fix Details
- **Defects Identified:**
  - `backend/pyproject.toml` declared `readme = "README.md"`, but no `README.md` existed in `backend/`.
  - Empty `backend/fixtures` directory caused setuptools flat-layout error: `Multiple top-level packages discovered in a flat-layout: ['app', 'fixtures']`.
- **Fixes Applied:**
  - Added dedicated `backend/README.md`.
  - Removed obsolete empty `backend/fixtures` directory.
  - Added `[tool.setuptools.packages.find]` with `include = ["app*"]` to `backend/pyproject.toml`.
  - Verified editable install: `pip install -e "backend[dev]"` succeeded without warnings.
