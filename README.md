# malbox-ai — AI-Driven Dynamic Malware Analysis & Behavioral Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-green.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2-blue.svg)](https://www.typescriptlang.org)
[![Cytoscape.js](https://img.shields.io/badge/Cytoscape.js-3.28-orange.svg)](https://js.cytoscape.org)
[![License](https://img.shields.io/badge/License-Academic%20Evaluation-purple.svg)]()

> **malbox-ai** is an academic dynamic malware analysis platform inspired by the workflows of VirusTotal and Hybrid Analysis. It provides evidence-grounded dynamic detonation, AI-orchestrated analysis planning, interactive behavioral relationship graph modeling, deterministic MITRE ATT&CK mapping, and structured forensic reporting.

---

## 1. System Architecture

```mermaid
flowchart TD
    User([Analyst / Web Browser]) <--> UI[React 18 + Vite UI]
    UI <--> API[FastAPI REST API /api/v1]
    
    subgraph CoreEngine ["malbox-ai Core Pipeline"]
        Sub[Submission & PE Triage] -->|Hash, Quarantine, Entropy| Orch[AI Orchestrator]
        Orch -->|Validated Plan| Sandbox[Sandbox Integration Layer]
        Sandbox -->|Raw Telemetry| Norm[Telemetry Normalizer]
        Norm -->|Unified Events| Corr[Process Tree & Correlator]
        Corr --> Graph[Behavior Graph Engine]
        Corr --> Detect[Detection & MITRE ATT&CK Engine]
        Detect --> Rep[Report Generator & Exporter]
    end

    API --> Sub
    Rep --> API
    Graph --> API
```

### Key Differentiators
1. **Interactive AI Orchestration:** AI actively participates in preflight planning (selecting profiles, setting bounded execution durations, focusing telemetry) and post-execution gap evaluation.
2. **Deterministic Policy Final Authority:** A strict rule-based policy engine validates every AI proposal against an allowlist before execution. Host shell commands and arbitrary execution are strictly rejected.
3. **Dual Sandbox Integration:**
   - **ReplaySandboxBackend:** High-fidelity, synthetic offline replay engine for zero-risk testing, rapid development, and evaluation.
   - **CapeSandboxBackend:** Official CAPE Sandbox v2 REST API client ready for live cluster deployment.
4. **Interactive Behavior Graph:** Full Cytoscape.js property graph connecting samples, processes, files, registry keys, network endpoints, and findings with supporting event provenance.
5. **Strict Host Isolation:** Uploaded samples are quarantined with read-only permissions (`0400`) and never executed on the host.

---

## 2. Quickstart Installation Guide

### Prerequisites
- Linux / macOS / WSL
- Python 3.10+ (Tested on Python 3.14.7)
- Node.js v18+ and npm (Tested on Node v24.19.0)

### Step 1: Clone and Set Up Virtual Environment
```bash
git clone <repo-url> malbox-ai
cd malbox-ai

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -e "backend[dev]"
```

### Step 2: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### Step 3: Run the Backend Server
```bash
# In terminal 1 (with virtualenv active)
export PYTHONPATH=backend
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*API Swagger Documentation will be available at:* `http://127.0.0.1:8000/docs`

### Step 4: Run the Frontend Application
```bash
# In terminal 2
cd frontend
npm run dev
```
*Web Dashboard will be accessible at:* `http://localhost:5173`

---

## 3. End-to-End Walkthrough Demo Scenario

To demonstrate the platform during an academic presentation or evaluation:

1. Open `http://localhost:5173` in your browser.
2. Click **Submit Executable** in the top navigation.
3. Under **Instant Replay Scenarios**, click **WannaCry Ransomware Scenario**.
   - *Static Triage:* Notice the automatic extraction of SHA-256, Shannon entropy calculation, section breakdown, and PE characteristics.
4. Click **Start Dynamic Analysis Workflow**.
5. Observe the **10-Step State Machine** in the **Analysis Workspace**:
   - `PREFLIGHT` → `PLANNED` → `QUEUED` → `RUNNING` → `COLLECTING` → `NORMALIZING` → `CORRELATING` → `SCORING` → `REPORTING` → `COMPLETED`.
6. Inspect the **AI Orchestration Card** to view:
   - AI proposed profile and timeout.
   - Policy Validator allowlist check (`ALLOWED` or `MODIFIED`).
7. Click **Behavior Graph** to interactively explore the process lineage (`sample.exe` → `cmd.exe` → `vssadmin.exe delete shadows`), file encryption bursts, and registry persistence keys.
8. Click **Full Intelligence Report** to view:
   - Executive Threat Summary.
   - Explainable Risk Score (`100/100 MALICIOUS`).
   - MITRE ATT&CK Technique Mappings (`T1490`, `T1486`, `T1547.001`, `T1046`).
   - Extracted IOCs (Domains, IPs, Persistence Keys).
   - Click **Standalone HTML** or **Export JSON** to export reports.

---

## 4. API Endpoints Contract

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health, live mode status, and backend readiness |
| `POST` | `/api/v1/samples` | Upload PE executable for quarantine & static triage |
| `GET` | `/api/v1/samples/{id}` | Retrieve sample metadata and PE headers |
| `POST` | `/api/v1/analyses` | Initiate dynamic analysis state machine |
| `GET` | `/api/v1/analyses` | List recent analysis jobs with risk metrics |
| `GET` | `/api/v1/analyses/{id}` | Detailed analysis task lifecycle status |
| `GET` | `/api/v1/analyses/{id}/events` | Filtered and paginated normalized telemetry |
| `GET` | `/api/v1/analyses/{id}/process-tree`| Reconstructed process ancestry hierarchy |
| `GET` | `/api/v1/analyses/{id}/graph` | Cytoscape-compatible interactive behavior graph |
| `GET` | `/api/v1/analyses/{id}/findings` | Behavioral findings and MITRE ATT&CK techniques |
| `GET` | `/api/v1/analyses/{id}/orchestration`| AI orchestration audit trail and policy logs |
| `GET` | `/api/v1/analyses/{id}/report` | Structured JSON forensic intelligence report |
| `GET` | `/api/v1/analyses/{id}/report/html`| Downloadable standalone dark-theme HTML report |
| `GET` | `/api/v1/analyses/{id}/artifacts` | Downloadable forensic artifacts (PCAP, dumps) |

---

## 5. Security Gates & Host Isolation

- **Zero Host Detonation:** Executable binaries are never executed via `subprocess` or shell commands on the host machine.
- **Quarantine Permissions:** Quarantined samples are set to non-executable, read-only (`0400`) in private data storage.
- **Prompt-Injection Defense:** All untrusted strings (command-lines, registry keys, URLs) are sanitized and stripped of prompt injection patterns before inclusion in AI context.
- **Disabled Live Detonation by Default:** Live mode requires an explicit environment flag (`MALBOX_LIVE_MODE_ENABLED=true`) and per-job analyst signoff.

---

## 6. Verification & Test Suite

Run the full automated test suite:
```bash
PYTHONPATH=backend ./.venv/bin/pytest backend/tests -v
```

All 19 tests pass:
- Static PE header & Shannon entropy triage
- Sample deduplication by SHA-256
- End-to-end replay pipeline (submission to report)
- AI orchestration planning & policy allowlist enforcement
- Command injection rejection
- CAPE Sandbox v2 API adapter error recovery & normalization
