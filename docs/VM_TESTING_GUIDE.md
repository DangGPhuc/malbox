# malbox-ai — Resource-Constrained VM Evaluation & Deployment Guide

This guide provides instructions for deploying, verifying, and benchmarking `malbox-ai` inside a resource-constrained Virtual Machine (e.g., 2 vCPUs, 2 GB to 4 GB RAM) for academic evaluation.

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu 22.04 / 24.04 LTS, Kali Linux, Debian 12, or Rocky Linux 9).
- **Compute Resources:**
  - **vCPU:** 2 cores minimum.
  - **Memory:** 2 GB RAM minimum (tested process-wide peak RSS is ~402 MB; per-scenario allocation < 80 MB even at 10,000 events).
  - **Disk:** 3 GB free disk space.
- **Software Dependencies:**
  - Python 3.10, 3.11, 3.12, or 3.14.
  - Node.js 18+ and npm (tested on Node 20 / 24).
  - Git.

---

## 2. Environment Setup

### A. Clone & Navigate
```bash
git clone https://github.com/DangGPhuc/malbox.git
cd malbox
git checkout audit/remediation-hardening
```

### B. Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e "backend[dev]"
```

### C. Frontend Installation & Production Build
```bash
cd frontend
npm ci
npm run build
cd ..
```

---

## 3. Automated Test Suite Verification

Run the complete regression suite verifying packaging, safety gates, job queues, operator authorization, replay validation, and behavior graph construction:

```bash
source .venv/bin/activate

# 1. Bytecode compilation verification
python -m compileall -q backend/app backend/tests

# 2. Recursive module import verification
python -c "
import importlib, pkgutil, sys
from pathlib import Path
sys.path.insert(0, str(Path('backend').resolve()))
import app
for m in pkgutil.walk_packages(app.__path__, app.__name__ + '.'):
    importlib.import_module(m.name)
print('All app modules imported successfully!')
"

# 3. Full unit and regression test suite
pytest -v backend/tests/
```

**Expected Result:**
```
======================== 56 passed in ~12s ========================
```

---

## 4. Scaled Performance & Resource Benchmark

Execute the automated benchmark suite to evaluate system behavior under standard Replay scenarios and sequential synthetic workloads:

```bash
source .venv/bin/activate
python scripts/benchmark_replay.py
```

### Benchmark Metrics Context:
1. **System Specifications:** Automatically logged at startup (OS, Python version, logical CPU count, available RAM).
2. **Standard Scenarios:**
   - **WannaCry Replay:** ~100 ms latency, ~0.8 MB scenario memory allocation.
   - **RedLine Replay:** ~130 ms latency, ~0.2 MB scenario memory allocation.
3. **Sequential Synthetic Dataset Scaling:**
   - **Small (100 events):** ~49 ms normalization (2,000+ events/sec), ~1.9 ms DB write, ~21 ms graph build.
   - **Medium (1,000 events):** ~158 ms normalization (6,300+ events/sec), ~7.8 ms DB write, ~83 ms graph build.
   - **Large (10,000 events):** ~1,580 ms normalization, ~66 ms DB write, ~915 ms graph build (8,900+ nodes, 9,600+ edges), ~74 MB scenario allocation.
4. **API Latencies:**
   - Status checks, graph retrieval, and report retrieval all respond in under 16 ms.

All metrics are saved to `benchmark_results.json`.

---

## 5. Running the Application Safely

### Safety Policy
- **Live Detonation Disabled by Default:** `MALBOX_LIVE_MODE_ENABLED=False`.
- **Operator Token Boundary:** An explicit `MALBOX_OPERATOR_TOKEN` is required before any live detonation or live cancellation request can be processed. If unconfigured, live requests fail closed with HTTP 403 Forbidden.
- **Replay Mode:** Safe, isolated evaluation using deterministic registered scenarios (`ransomware_wannacry_mock`, `infostealer_redline_mock`). No live execution or hypervisor is touched.
- **Localhost Binding:** Backend binds to `127.0.0.1:8000`.

### A. Start the Backend API Server
```bash
source .venv/bin/activate
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation is available at: `http://127.0.0.1:8000/docs`.

### B. Start the Frontend Development Server (Optional)
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` to access the interactive web interface.

---

## 6. Safe Replay Testing via API (curl)

### 1. Upload a Test Binary Sample
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/samples" \
  -F "file=@backend/README.md;filename=test_sample.exe"
```
Response returns a `sample_id` (e.g., `e1f2...`).

### 2. Submit for Replay Analysis (WannaCry or RedLine)
```bash
# Explicit WannaCry Replay:
curl -X POST "http://127.0.0.1:8000/api/v1/analyses?run_sync=true" \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "<sample_id>",
    "backend_type": "replay",
    "replay_scenario_id": "ransomware_wannacry_mock",
    "live_mode": false,
    "timeout_seconds": 60
  }'

# Explicit RedLine Replay:
curl -X POST "http://127.0.0.1:8000/api/v1/analyses?run_sync=true" \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "<sample_id>",
    "backend_type": "replay",
    "replay_scenario_id": "infostealer_redline_mock",
    "live_mode": false,
    "timeout_seconds": 60
  }'
```

### 3. Retrieve Behavior Graph & Threat Report
```bash
# Get Cytoscape graph nodes and edges:
curl -s "http://127.0.0.1:8000/api/v1/analyses/<analysis_id>/graph" | jq .

# Get structured evidence report:
curl -s "http://127.0.0.1:8000/api/v1/analyses/<analysis_id>/report" | jq .

# Download standalone HTML report:
curl -s "http://127.0.0.1:8000/api/v1/analyses/<analysis_id>/report/html" -o analysis_report.html
```
