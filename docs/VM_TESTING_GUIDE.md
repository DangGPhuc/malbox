# malbox-ai — Resource-Constrained VM Evaluation & Deployment Guide

This guide provides instructions for deploying, verifying, and benchmarking `malbox-ai` inside a resource-constrained Virtual Machine (e.g., 2 vCPUs, 2 GB to 4 GB RAM) for academic evaluation.

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu 22.04 / 24.04 LTS, Kali Linux, Debian 12, or Rocky Linux 9).
- **Compute Resources:**
  - **vCPU:** 2 cores minimum.
  - **Memory:** 2 GB RAM minimum (tested peak RSS is ~402 MB).
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
======================== 52 passed in ~10s ========================
```

---

## 4. Scaled Performance & Resource Benchmark

Execute the automated benchmark suite to evaluate system behavior under increasing synthetic workloads:

```bash
source .venv/bin/activate
python scripts/benchmark_replay.py
```

### Benchmark Output Expectations:
1. **Standard Scenarios:**
   - **WannaCry Replay:** ~75 ms end-to-end pipeline latency.
   - **RedLine Replay:** ~52 ms end-to-end pipeline latency.
   - **Peak Process RSS:** ~402 MB.
2. **Synthetic Dataset Scaling:**
   - **Small (100 events):** ~12 ms normalization, ~6 ms graph build.
   - **Medium (1,000 events):** ~43 ms normalization (23,000+ events/sec), ~20 ms graph build.
   - **Large (10,000 events):** ~530 ms normalization (18,000+ events/sec), ~270 ms graph build (8,900+ nodes, 9,600+ edges).
3. **API Latencies:**
   - Status check, graph retrieval, and report retrieval all respond in under 15 ms.

All metrics are saved to `benchmark_results.json`.

---

## 5. Running the Application Safely

### Safety Policy
- **Live Detonation Disabled by Default:** `MALBOX_LIVE_MODE_ENABLED=False`.
- **Operator Token Boundary:** An explicit `MALBOX_OPERATOR_TOKEN` is required before any live detonation or live cancellation request can be processed. If unconfigured, live requests fail closed with HTTP 403 Forbidden.
- **Replay Mode:** Safe, isolated evaluation using deterministic registered scenarios (`ransomware_wannacry_mock`, `infostealer_redline_mock`). No live execution or hypervisor is touched.

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

### 2. Submit for Replay Analysis
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyses?run_sync=true" \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "<sample_id>",
    "backend_type": "replay",
    "replay_scenario_id": "ransomware_wannacry_mock",
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
