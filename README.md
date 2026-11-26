# MalBox — Automated Malware Analysis Sandbox (3-VM Isolated Lab)

MalBox is a lightweight, terminal-driven three-VM malware analysis sandbox built for isolated academic and defensive malware-analysis lab workflows, combining **Static Analysis**, **Dynamic Behavioral Observation**, **Archive/Manifest Integrity Verification**, and local **MalBox MCP** evidence querying.

> **Lab Safety Notice:** Execute samples **only** on Machine 3 (`Windows Sandbox`) inside an isolated VirtualBox Internal Network with no Internet access, no DNS, and no Default Gateway. Always restore the clean Machine 3 snapshot (**`M3-CLEAN`**) after every analysis run.

---

## 1. Isolated Network Topology (Internal Network)

MalBox separates roles across three independent VMs bridged by two isolated VirtualBox **Internal Networks** (`malbox-net1` and `malbox-net2`). IP forwarding on Machine 2 is disabled so Machine 1 can reach Machine 2 over HTTP without direct network routing to Machine 3:

```text
+-----------------------+       malbox-net1       +------------------------+       malbox-net2       +-------------------------+
|  Machine 1 (Client)   |  <------------------->  |  Machine 2 (Gateway)   |  <------------------->  |  Machine 3 (Sandbox)    |
|  Kali Linux           |     10.10.10.10/24      |  REMnux                |     10.10.20.20/24      |  Windows 10 / 11 x64    |
|  CLI: doctor <sample> |  -> 10.10.10.20:8000    |  HTTP Relay (:8000)    |  -> 10.10.20.30:8001    |  Static + Dynamic + MCP |
+-----------------------+                         +------------------------+                         +-------------------------+
```

| VM | Role | Network Adapter | Static IP | Service / Port |
| :--- | :--- | :--- | :--- | :--- |
| **Machine 1 (Kali)** | Client submits samples & inspects reports | `malbox-net1` | `10.10.10.10/24` | CLI `doctor` |
| **Machine 2 (REMnux)** | Application-level HTTP Relay (IP forwarding disabled) | `malbox-net1` / `malbox-net2` | `10.10.10.20/24` / `10.10.20.20/24` | `gateway.py` (`:8000`) |
| **Machine 3 (Windows)** | Malware Analysis Sandbox (REMWin / Win10 x64 / Win11) | `malbox-net2` | `10.10.20.30/24` | `sandbox.py` (`:8001`) |

*(All three VMs omit Default Gateway and DNS configuration to maintain full Internet isolation.)*

---

## 2. Repository Structure & Workflow Summary

```text
malbox/
├── README.md
├── .gitignore
├── machine1-client/         # Machine 1 (Kali): standalone `doctor` CLI, config, readiness checker
├── machine2-gateway/        # Machine 2 (REMnux): standalone HTTP relay, optional INetSim diagnostics, readiness checker
├── machine3-sandbox/        # Machine 3 (Windows): analyzer, static/dynamic collectors, Sysmon/Ghidra/MCP server
└── docs/                    # Architecture, networking, tools setup, snapshots, v2 changelog, and checklist
```

Each `machine*` directory is standalone and shares no Python imports across machines:

1. **Sample Submission:** Machine 1 (`doctor`) hashes the binary cleanly without executing it and streams it over HTTP to Machine 2 (`gateway.py`), which checks Machine 3 (`READY`), streams it to Machine 3, and unlinks its temp file.
2. **Static & Dynamic Analysis (Machine 3 only):** Machine 3 runs static analysis (`hashlib`, `pefile`, `FLOSS`, `capa`, `YARA`, optional `Detect It Easy`) and headless `Ghidra` (`GhidraExport.java`), prompts for local operator approval (`Approve dynamic execution...? [y/N]`, default enabled), launches the sample for a `120s` observation window while capturing `Sysmon`, `Procmon`, `dumpcap`/`tshark`, `psutil`, `ProcDump`, optional `WinPmem`/`Volatility 3`, and Windows Event Logs (`wevtutil`), then builds `summary.json`, `timeline.json`, `attack_mapping.json`, `report.md`, `manifest.json`, and `evidence_<job_id>.zip`.
3. **End-to-End Verification & Return:** Gateway verifies archive checksum, ZIP safety limits, CRC integrity, and bidirectional `manifest.json` hashes before acknowledging Sandbox (`/ack`, moving Sandbox to `RESTORE_REQUIRED`). Client repeats full safety and manifest SHA-256 verification before acknowledging Gateway and saving evidence under `evidence/<job_id>/`.

---

## 3. First-Time VM Setup (Before Disconnecting Internet)

Clone the repository onto each VM while temporary Internet access is attached, run only the setup command for that machine, install external Windows analysis tools ([docs/tools-setup.md](docs/tools-setup.md)), disconnect Internet / attach Internal Networks, and verify offline with `--check-only` / `-CheckOnly`:

- **Machine 1 (Kali):**
  ```bash
  cd ~/malbox/machine1-client
  bash setup.sh
  ```
- **Machine 2 (REMnux):**
  ```bash
  cd ~/malbox/machine2-gateway
  bash setup.sh
  ```
- **Machine 3 (Windows — before taking the clean snapshot `M3-CLEAN`):**
  ```powershell
  cd C:\malbox\machine3-sandbox
  .\setup.ps1 -CloneGitTools
  .\setup.ps1 -CheckOnly
  ```
  See [docs/setup-and-readiness.md](docs/setup-and-readiness.md) and [docs/snapshot-setup.md](docs/snapshot-setup.md) for detailed checks and snapshot preparation.

---

## 4. Operating & Testing Runbook (3-VM Isolated Lab)

Start VMs and services **from inside out** (`Machine 3 -> Machine 2 -> Machine 1`).

> **8 GB RAM Host Tip:** After rebooting the physical Linux host, re-enable swap before powering on all three VMs:
> ```bash
> sudo swapon /swapfile_malbox && free -h
> ```

### Step 1: Machine 3 — Windows Sandbox (`10.10.20.30:8001`)

Ensure Machine 3 is restored to its clean snapshot (**`M3-CLEAN`**). Open an **Administrator Command Prompt** and start `sandbox.py` (or `run_sandbox.bat`):

```cmd
cd C:\malbox\machine3-sandbox
.\.venv\Scripts\python.exe sandbox.py
```

Expected output:
```text
[SANDBOX] Server started on 0.0.0.0:8001.
[SANDBOX] Waiting for sample...
```

### Step 2: Machine 2 — REMnux Gateway (`10.10.10.20:8000`)

Boot Machine 2, verify reachability to Machine 3 and offline readiness, then start the Gateway relay:

```bash
# 1. Verify connectivity to Machine 3 and local readiness
ping -c 2 10.10.20.30
cd ~/malbox/machine2-gateway && bash setup.sh --check-only

# 2. Start Gateway Relay (or run ./run_gateway.sh)
source .venv/bin/activate
python gateway.py
```

Expected output:
- `setup.sh --check-only` reports `sandbox_peer_status` as `PASS` (`APPLICATION_STATE   : READY`).
- `gateway.py` prints:
  ```text
  [GATEWAY] Server started on 0.0.0.0:8000.
  [GATEWAY] Waiting for client...
  ```

### Step 3: Machine 1 — Kali Client (`10.10.10.10`)

Boot Machine 1, confirm network segmentation, and verify end-to-end readiness:

```bash
# 1. Reach Gateway (must succeed: 0% packet loss)
ping -c 2 10.10.10.20

# 2. Confirm Sandbox isolation (must be unreachable directly from Machine 1)
ping -c 2 10.10.20.30

# 3. Verify end-to-end control path
cd ~/malbox/machine1-client && bash setup.sh --check-only
```

Expected readiness summary:
```text
NETWORK_READINESS   : CONTROL_PATH_READY
PEER_CONNECTIVITY   : GATEWAY_AND_SANDBOX_HTTP_REACHABLE
APPLICATION_STATE   : READY (remote Sandbox reported state)
```

---

## 5. Submitting a Sample & Reviewing Evidence (Machine 1)

From Machine 1 (`machine1-client`):

```bash
cd ~/malbox/machine1-client
source .venv/bin/activate

# Submit sample for analysis (use an actual harmless test file path)
doctor --verbose ~/test_sample.exe
```

*(If `doctor` is not in `PATH`, invoke `~/.local/bin/doctor --verbose ...` or `python doctor.py --verbose ...`.)*

### Monitoring the Analysis Flow

1. Wait for static phases (`static_analysis`, `ghidra_analysis`) to complete.
2. When Machine 3 prompts on its Administrator CMD window:
   ```text
   [SANDBOX] Approve dynamic execution for '...' (SHA256: ...)? [y/N]:
   ```
   Type **`y`** and press `Enter` to permit dynamic observation (default window: `120s`).
3. Once Machine 1 prints `[OK] Saved to evidence/<JOB_ID>/`, inspect the verified report and collected evidence:

```bash
cd ~/malbox/machine1-client/evidence/<JOB_ID>

# List all collected evidence files
find . -maxdepth 3 -type f -exec ls -lh {} +

# Read the summary report, manifest inventory, and any collector error logs
cat report.md
cat manifest.json
cat logs/errors.log
```

### Optional Post-Collection AI/LLM Report Generation (Machine 1)

To generate an evidence-grounded DFIR Markdown report from a completed `evidence/<JOB_ID>/` bundle, use the defensive prompt template in [machine1-client/prompts/evidence-analysis-report.md](machine1-client/prompts/evidence-analysis-report.md) against a **read-only copy** of the evidence folder and save the LLM report outside `evidence/<JOB_ID>/` (never overwriting MalBox's original `report.md`). See [machine1-client/README.md](machine1-client/README.md#post-collection-llm-analysis--reporting).

---

## 6. Post-Analysis Cleanup & Snapshot Restore (Mandatory)

> **Mandatory:** Always restore **`M3-CLEAN`** on Machine 3 before submitting another sample. Sandbox enforces a dirty-state gate (`HTTP 409 RESTORE_REQUIRED`) until restored.

1. **Machine 3 (Windows):** Press `Ctrl + C` to stop `sandbox.py`, then shut down cleanly:
   ```cmd
   shutdown /s /t 0
   ```
   Once VM status becomes `Powered Off`, open **VirtualBox → Snapshots → select `M3-CLEAN` → Restore** (leave *"Create a snapshot of the current machine state"* **unchecked**).
2. **Machine 2 (REMnux) & Machine 1 (Kali):** Press `Ctrl + C` to stop running services, then shut down cleanly so `evidence/` and `retained_evidence/` persist intact:
   ```bash
   sudo poweroff
   ```

---

## 7. Integrated Tools & Scope Notes

- **Static:** `hashlib`, file format/extension mismatch detection, `pefile`, Mandiant `FLOSS`, `capa` + `capa-rules`, `YARA`, optional `Detect It Easy` (`diec.exe`), headless `Ghidra` (`GhidraExport.java`).
- **Dynamic:** `Sysmon`, `Procmon`, `dumpcap`/`tshark`, `psutil`, `ProcDump`, Windows Event Logs (`wevtutil`), optional `WinPmem` & `Volatility 3`, optional canary fixtures & Gateway `INetSim` diagnostics.
- **Correlation & MCP:** Evidence-backed MITRE ATT&CK mapper (`attack_mapping.json`), `MalBox MCP` (`mcp` Python SDK over local `stdio`), and optional `GhidraMCP`.
- **Constraints:** Single active job at a time (`READY -> ANALYZING -> RETURNING_EVIDENCE -> RESTORE_REQUIRED`); no authentication/TLS on isolated lab HTTP links; no Docker, databases, cloud APIs, or hypervisor automation APIs.

---

## 8. Documentation Index

- [Architecture](docs/architecture.md)
- [Network Setup](docs/network-setup.md)
- [Setup & Environment Readiness](docs/setup-and-readiness.md)
- [Tools Setup (Windows Sandbox)](docs/tools-setup.md)
- [Snapshot Setup & Workflow](docs/snapshot-setup.md)
- [Analysis Coverage & Capabilities](docs/analysis-coverage.md)
- [Scope & Explicit Limitations](docs/scope-and-limitations.md)
- [v2.0 Changelog](docs/v2-changelog.md)
- [v2.0 Acceptance Checklist](docs/v2-acceptance-checklist.md)
- [Troubleshooting](docs/troubleshooting.md)
