# MalBox — Automated Malware Analysis Sandbox

MalBox is a lightweight, terminal-driven three-VM malware analysis sandbox built for academic lab workflows combining **Static Analysis** and **Dynamic Analysis** in an isolated network environment.

> **Lab Safety Notice:** Only analyze authorized samples inside an isolated virtual lab with Internet connectivity disabled on the sandbox network. Restore the Windows 11 `CLEAN` snapshot after every dynamic analysis run.

---

## Architecture Overview

MalBox separates responsibilities across three independent virtual machines connected over two isolated **Internal Networks** (no NAT, no bridged networking, no IP forwarding between networks):

```text
+-----------------------+       Internal Net 1       +------------------------+       Internal Net 2       +-------------------------+
|  Machine 1 (Client)   |  <---------------------->  |  Machine 2 (Gateway)   |  <---------------------->  |  Machine 3 (Sandbox)    |
|  Kali Linux           |     10.10.10.10 -> .20     |  REMnux / Kali Linux   |     10.10.20.20 -> .30     |  Windows 11 VM          |
|  CLI: doctor <sample> |     HTTP :8000             |  HTTP Relay (:8000)    |     HTTP :8001             |  Static + Dynamic + MCP |
+-----------------------+                            +------------------------+                            +-------------------------+
```

### Data Flow

1. **Sample Submission**
   - `Machine 1` runs `doctor file.exe` (never executes the sample), calculates SHA-256, checks Gateway connectivity, and streams the binary to `Machine 2`.
   - `Machine 2` checks `Machine 3` state (`READY`), streams the binary to `Machine 3`, and immediately removes its temporary copy.
   - `Machine 3` saves the sample into an isolated job workspace and enters `ANALYZING`.

2. **Analysis & Evidence Collection (Machine 3 only)**
   - **Static Analysis:** Hashes, PE structure/imports/exports/entropy (`pefile`), strings & indicators (`FLOSS` / Python fallback), capabilities (`capa`), local `YARA` rules, and headless `Ghidra` disassembly/decompilation.
   - **Dynamic Analysis:** Starts evidence collectors (`Sysmon`, `Procmon`, `dumpcap`/`TShark`, `psutil`, `ProcDump`, optional `WinPmem`/`Volatility 3`), optionally awaits local operator approval on the Sandbox terminal, runs the sample for a configurable observation window (default `120` seconds), cleanly terminates only the job's tracked processes, collects Windows Event Logs, builds `timeline.json`, `summary.json`, `manifest.json`, and `report.md`.

3. **Evidence Return**
   - `Machine 3` packages the evidence folder (excluding the original sample and newly dropped executables) into a ZIP archive and enters `RETURNING_EVIDENCE`.
   - `Machine 2` streams the ZIP archive from `Machine 3`, acknowledges transfer (moving `Machine 3` to `RESTORE_REQUIRED`), and streams the ZIP archive unchanged to `Machine 1`.
   - `Machine 1` saves and safely extracts the evidence into `evidence/<job_id>/`.

---

## Repository Structure

```text
malbox/
├── README.md
├── .gitignore
├── machine1-client/         # Kali Linux CLI client (`doctor`)
├── machine2-gateway/        # REMnux/Kali HTTP application-level relay
├── machine3-sandbox/        # Windows 11 analyzer, collectors, Sysmon/Ghidra configs, and MalBox MCP
└── docs/                    # Setup, networking, tools, snapshot, and troubleshooting guides
```

Each `machine*` directory is completely standalone and does not import code from any other machine directory.

---

## Quick Setup & Startup

Clone the repository onto each VM (before disconnecting Internet for lab isolation), then set up only the folder belonging to that VM:

### Machine 1 — Kali Linux Client
```bash
cd malbox/machine1-client
bash setup.sh
# Offline readiness re-check after network isolation:
bash setup.sh --check-only
doctor /path/to/sample.exe
```

### Machine 2 — REMnux / Kali Gateway
```bash
cd malbox/machine2-gateway
bash setup.sh
# Offline readiness re-check after network isolation:
bash setup.sh --check-only
source .venv/bin/activate
python gateway.py
```

### Machine 3 — Windows 11 Sandbox (before taking CLEAN snapshot)
Run PowerShell in `malbox\machine3-sandbox`:
```powershell
.\setup.ps1 -CloneGitTools
# Follow docs\tools-setup.md to install Sysmon, Wireshark, Ghidra, FLOSS, capa, etc., then verify:
.\setup.ps1 -CheckOnly
.\.venv\Scripts\Activate.ps1
python sandbox.py
```

---

## Integrated Tools

- **Static:** Python `hashlib` + file signature/mismatch checks, `pefile`, Mandiant `FLOSS`, Mandiant `capa` + `capa-rules`, `YARA` (`yara-python` / `yara64`), optional `Detect It Easy` (`diec`), NSA `Ghidra` Headless Analyzer (`GhidraExport.java`).
- **Dynamic:** `Sysmon`, Sysinternals `Procmon`, `psutil`, Wireshark (`dumpcap` / `tshark`), `ProcDump`, optional `WinPmem` & `Volatility 3`, Windows `wevtutil` Event Logs, optional canary fixtures & Gateway `INetSim` diagnostics.
- **Correlation & Querying:** Evidence-backed MITRE ATT&CK mapper (`attack_mapping.json`), `MalBox MCP` (`mcp` official Python SDK over local `stdio`), plus optional `GhidraMCP`.

---

## Limitations & Scope

- Single-job processing at a time (`READY -> ANALYZING -> RETURNING_EVIDENCE -> RESTORE_REQUIRED`).
- No authentication/encryption on Internal Networks (intended strictly for isolated local academic labs).
- Dynamic execution occurs only on Machine 3 and defaults to requiring local operator approval on the Sandbox terminal (`require_local_approval: true` in `machine3-sandbox/config.json`).
- Sandbox does **not** automatically clean Windows or restore VM snapshots; you must manually restore the `CLEAN` snapshot after every analysis.
- No hypervisor APIs, Docker, Redis, Celery, databases, or cloud services are used.

---

## Documentation

- [Setup & Environment Readiness](docs/setup-and-readiness.md)
- [Architecture](docs/architecture.md)
- [Network Setup](docs/network-setup.md)
- [Tools Setup (Windows 11)](docs/tools-setup.md)
- [Snapshot Setup & Workflow](docs/snapshot-setup.md)
- [Analysis Coverage & Capabilities](docs/analysis-coverage.md)
- [Scope & Explicit Limitations](docs/scope-and-limitations.md)
- [v2.0 Changelog](docs/v2-changelog.md)
- [v2.0 Acceptance Checklist](docs/v2-acceptance-checklist.md)
- [Troubleshooting](docs/troubleshooting.md)
