# malbox-ai — Resource-Constrained VM Evaluation Guide

This guide provides instructions for deploying, testing, and evaluating `malbox-ai` within a resource-constrained academic or laboratory Virtual Machine (e.g., 2 vCPUs, 2 GB to 4 GB RAM).

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu 22.04/24.04, Kali Linux, Debian 12) or macOS / WSL2.
- **Hardware Resources:**
  - **vCPU:** Minimum 2 cores (recommended).
  - **RAM:** Minimum 2 GB (tested peak RSS: < 400 MB).
  - **Storage:** 2 GB free disk space.
- **Software Dependencies:**
  - Python 3.10, 3.11, 3.12, or 3.14.
  - Node.js 18+ and npm (tested on Node 20 / 24).
  - Git.

---

## 2. Installation & Environment Setup

### A. Clone & Navigate to Repository
```bash
git clone https://github.com/DangGPhuc/malbox.git
cd malbox
git checkout audit/remediation-hardening
```

### B. Python Virtual Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e "backend[dev]"
```

### C. Frontend Setup & Build
```bash
cd frontend
npm ci
npm run build
cd ..
```

---

## 3. Automated Test Verification

Run the complete regression test suite verifying safety gates, job queue lifecycle, AI fallback, telemetry integrity, and detection rules:

```bash
source .venv/bin/activate
pytest -v backend/tests/
```

**Expected Result:**
```
======================== 44 passed in ~8s ========================
```

---

## 4. Automated Performance & Memory Benchmark

Execute the automated replay benchmark utility to measure latency, CPU time, and memory consumption:

```bash
source .venv/bin/activate
python scripts/benchmark_replay.py
```

**Sample Benchmark Metrics (Resource-Constrained VM):**
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

## 5. Starting the Platform Services

### A. Start Backend Server
```bash
source .venv/bin/activate
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
The FastAPI backend documentation will be accessible at: `http://127.0.0.1:8000/docs`

### B. Start Frontend Dev Server (in a second terminal)
```bash
cd frontend
npm run dev
```
The interactive user interface will open at: `http://localhost:5173`

---

## 6. End-to-End Evaluation Walkthrough (Replay Mode)

### Step 1: Submit a Sample
1. Navigate to `http://localhost:5173/submit`.
2. Click **"WannaCry Ransomware Scenario"** under **Instant Replay Scenarios** (or browse an arbitrary test `.exe`).
3. Note the static PE triage results (SHA-256, sections, entropy calculation).

### Step 2: Configure & Launch
1. Ensure **Execution Backend** is set to `Deterministic Replay Sandbox (Safe / Offline)`.
2. Notice the Replay Scenario Fixture dropdown: select `WannaCry Ransomware Mock`.
3. Click **"Start Dynamic Analysis Workflow"**.

### Step 3: Observe Real-Time Pipeline Progress
1. The analysis enters the queue (`QUEUED`) and transitions through all 10 stages:
   `PREFLIGHT` → `PLANNED` → `RUNNING` → `COLLECTING` → `NORMALIZING` → `CORRELATING` → `SCORING` → `REPORTING` → `COMPLETED`.
2. Observe the prominent **Replay Provenance Badge** identifying synthetic offline telemetry.
3. Inspect normalized forensic events across Process, File, Registry, and Network categories.
4. Review the AI Orchestration Decision audit log capturing AI proposed plans, policy validation status, and token usage metadata.

### Step 4: Explore Cytoscape Behavior Graph
1. Click **"Behavior Graph"** in the top navigation or from the workspace.
2. Pan, zoom, and select nodes (Sample, Process, File, Registry, Domain, BehavioralFinding).
3. Confirm that suspicious nodes are visually highlighted and edges provide verified provenance back to telemetry event IDs.

### Step 5: Export Standalone Forensic HTML Report
1. Click **"Full Intelligence Report"**.
2. Click **"Export Standalone HTML Report"** or navigate to:
   `http://127.0.0.1:8000/api/v1/analyses/{analysis_id}/report/html`
3. Notice:
   - Complete CSP security header protection.
   - Clean HTML-escaped output.
   - Distinct synthetic replay provenance warning banner.
   - MITRE ATT&CK technique mapping table.

---

## 7. Verifying Safety Gates (Security Review)

To test the security boundary enforcing zero unauthorized live malware execution:

```bash
# 1. Attempt to launch CAPE analysis without live mode enabled (Must fail HTTP 422)
curl -s -X POST http://127.0.0.1:8000/api/v1/analyses \
  -H "Content-Type: application/json" \
  -d '{"sample_id": "<SAMPLE_ID>", "backend_type": "cape", "live_mode": false}' | jq .

# 2. Attempt to launch CAPE analysis without user approval (Must fail HTTP 422)
curl -s -X POST http://127.0.0.1:8000/api/v1/analyses \
  -H "Content-Type: application/json" \
  -d '{"sample_id": "<SAMPLE_ID>", "backend_type": "cape", "live_mode": true, "approved_by_user": false}' | jq .

# 3. Attempt to launch CAPE analysis without operator security token (Must fail HTTP 401)
curl -s -X POST http://127.0.0.1:8000/api/v1/analyses \
  -H "Content-Type: application/json" \
  -d '{"sample_id": "<SAMPLE_ID>", "backend_type": "cape", "live_mode": true, "approved_by_user": true}' | jq .
```
All safety violations are logged, blocked, and produce zero outbound network connections to external sandboxes.
