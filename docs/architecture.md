# MalBox Architecture

MalBox splits malware analysis across three isolated virtual machines communicating over plain HTTP on two separate host-only / internal networks.

## 1. Component Roles

| Machine | OS | Role | Executes Samples? |
| --- | --- | --- | --- |
| Machine 1 (`machine1-client`) | Kali Linux | CLI submission (`doctor`), evidence download & storage | **No** |
| Machine 2 (`machine2-gateway`) | REMnux or Kali Linux | Application-level HTTP relay between Net 1 and Net 2 | **No** |
| Machine 3 (`machine3-sandbox`) | Windows 11 | Static analysis, Ghidra headless, dynamic monitoring, packaging, local MCP | **Yes (isolated lab only)** |

## 2. State Machine (Machine 3)

1. `READY`: Clean snapshot awaiting one submission (`workspace/.dirty_state` absent).
2. `ANALYZING`: Static analysis + dynamic collectors + observation window running.
3. `RETURNING_EVIDENCE`: Evidence ZIP created and available for streaming to Gateway.
4. `RESTORE_REQUIRED`: Evidence acknowledged (`workspace/.dirty_state` persisted). Rejects all new jobs until the operator manually restores the `CLEAN` VM snapshot.

## 3. End-to-End Request Flow

1. Operator runs `doctor file.exe` on Machine 1.
2. Client calls `GET http://10.10.10.20:8000/health` to verify Gateway connectivity.
3. Client computes SHA-256 locally and streams binary bytes via `POST /analyze`.
4. Gateway saves incoming bytes temporarily, queries `GET http://10.10.20.30:8001/status` to confirm `READY`, streams the binary to Sandbox `POST /analyze`, and immediately unlinks its temp sample copy.
5. Sandbox performs:
   - File metadata & PE analysis (`pefile`)
   - Strings & indicators (`FLOSS` or Python fallback)
   - Capability detection (`capa` + `capa-rules`)
   - Local `YARA` rule scan
   - Headless `Ghidra` disassembly/decompilation
   - Starts dynamic collectors (`Procmon`, `dumpcap`, `psutil` baseline)
   - Awaits local console approval (`require_local_approval: true`)
   - Launches sample under standard user context for `observation_duration_seconds` (default `120`s)
   - Captures process memory dumps (`ProcDump` on live tracked PIDs), safely terminates tracked sample PIDs, collects optional WinPmem/Volatility 3, exports Windows Event Logs (`wevtutil`), correlates Sysmon/Procmon/TShark data, builds `timeline.json`, `summary.json`, `report.md`, `manifest.json`, and streams files into `evidence_<job_id>.zip` (excluding original sample and dropped executables).
6. Gateway downloads the ZIP archive (`GET /jobs/<id>/evidence`), retains a backup copy under `retained_evidence/` (`retain_evidence_archives: true`), calls `POST /jobs/<id>/ack` on Sandbox (moving Sandbox to `RESTORE_REQUIRED`), and streams the exact ZIP unchanged to Client.
7. Client downloads, verifies SHA-256 and ZIP integrity, safely extracts `evidence/<job_id>/`, and sends `POST /jobs/<id>/ack` to Gateway. If Client transfer or extraction fails, the archive remains recoverable on Gateway (`retained_evidence/` or `GET /jobs/<id>/evidence`).

## 4. MalBox MCP Integration

`machine3-sandbox/mcp/server.py` uses the official Python MCP SDK over `stdio` to query generated evidence directories read-only. Core pipeline execution does not require MCP or any LLM to be running.
