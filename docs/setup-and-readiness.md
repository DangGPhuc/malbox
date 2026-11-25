# Setup & Environment Readiness Guide

Each MalBox machine includes a one-command setup and readiness verification entrypoint (`setup.sh` on Linux, `setup.ps1` on Windows 11) backed by a standalone `readiness.py` checker.

---

## 1. Execution Order

1. **While VMs still have temporary Internet access:**
   - Install **Python 3.10+** on all 3 machines (**64-bit Python 3.10+** required on Machine 3 Windows 11; Python 3.11/3.12 x64 recommended).
   - Clone `https://github.com/DangGPhuc/malbox.git` onto all 3 VMs.
   - Run `bash setup.sh` on **Machine 1** and **Machine 2**.
   - Run `.\setup.ps1 -CloneGitTools` on **Machine 3** and install the required manual Windows binaries/installers (see [tools-setup.md](tools-setup.md)).
   - Re-run `.\setup.ps1` on Machine 3 until `LOCAL_READINESS` reaches `LIMITED` (or `READY` once all optional components and probes are satisfied).
2. **Isolate Internal Networks (manual):**
   - Switch adapters to Internal Network 1 & 2, assign static IPs (`10.10.10.10`, `10.10.10.20`, `10.10.20.20`, `10.10.20.30`), and verify Internet is disconnected on Machine 3 (see [network-setup.md](network-setup.md)).
3. **Offline Check-Only Verification (after isolation):**
   - Start `sandbox.py` on Machine 3 and `gateway.py` on Machine 2.
   - Run `--check-only` / `-CheckOnly` on each VM. Confirm `NETWORK_READINESS` on **Machine 1** (`CONTROL_PATH_READY`) — Machine 1 queries Gateway and Sandbox through the actual relay chain, whereas Machine 3's local check can only confirm `LOCAL_SERVICE_ONLY`.
4. **Save the `CLEAN` snapshot on Machine 3:**
   - Confirm `SNAPSHOT_STATE` is `NO_DIRTY_MARKER` (never `RESTORE_REQUIRED`) **and** visually verify Windows 11 cleanliness and empty `workspace/` / `evidence/` folders before saving the `CLEAN` snapshot.

---

## 2. Commands per Machine

| Machine | Default Setup Command | Offline Check-Only Command | Output Report |
| --- | --- | --- | --- |
| **Machine 1 (Kali)** | `cd malbox/machine1-client && bash setup.sh` | `bash setup.sh --check-only` | `machine1-client/setup_report.json` |
| **Machine 2 (Gateway)** | `cd malbox/machine2-gateway && bash setup.sh` | `bash setup.sh --check-only` | `machine2-gateway/setup_report.json` |
| **Machine 3 (Windows 11)** | `cd malbox\machine3-sandbox; .\setup.ps1` | `.\setup.ps1 -CheckOnly` | `machine3-sandbox/setup_report.json` |

### Behavior of `--check-only` / `-CheckOnly`
- Runs strictly offline without `pip install`, `git clone`, `git pull`, or file downloads.
- Never modifies drivers, network configuration, HKCU Sysinternals EULA registry entries, `.dirty_state`, VM snapshots, or existing evidence.
- Only writes `setup_report.json` and transient `.readiness_probe_*` read/write test files inside existing directories (always removed in `finally:` cleanup).
- Never executes malware samples.

---

## 3. Standardized Exit Codes

All three setup wrappers (`setup.sh`, `setup.ps1`) and readiness checkers (`readiness.py`) share identical exit code semantics across **both** default `setup` mode and `--check-only` / `-CheckOnly` mode:

| Exit Code | Meaning |
| --- | --- |
| **`0`** | Mandatory local checks passed (`LOCAL_READINESS` is `READY` or `LIMITED`). Note: `NETWORK_READINESS` or `APPLICATION_STATE` may still be `PENDING` / `LOCAL_SERVICE_ONLY` before peer VMs are started; inspect terminal output or `setup_report.json` for peer/service details. |
| **`1`** | `LOCAL_READINESS` is `NOT_READY` (at least one mandatory dependency/check failed or is missing, invalid `config.json`, or `RESTORE_REQUIRED` dirty marker on Machine 3), setup installer prerequisite failed, or `setup_report.json` could not be saved. |
| **`2`** | Invalid or unknown command-line arguments. |

---

## 4. Mandatory vs Optional Dependencies & Unavailable Evidence Mapping

### Machine 1 & Machine 2
- **Mandatory:** Linux OS, Python `>= 3.10`, `.venv` (`>= 3.10`), `pip`, `requests` (and `Flask` on Machine 2) passing `pip check`, valid `config.json`, writable `evidence`/`tmp`/`retained_evidence` directories, `doctor --help` (Machine 1), `ip_forward=0` (Machine 2), sufficient disk space.
- **Peer/Network (not counted against `LOCAL_READINESS`):** Reachable peer HTTP `/health` and `/status` endpoints, loopback safety on `listen_host`, and host NIC static IP checks.

### Machine 3 (Windows 11 Sandbox)
- **Mandatory (`LOCAL_READINESS` becomes `NOT_READY` if missing or failing):**
  - **OS & Build:** Windows OS (`windows_os`) and verified **Windows 11 build >= 22000** (`windows_11_version`).
  - **Runtimes:** PowerShell (`5.1` or `7+`), **64-bit Python `>= 3.10`** (`python_runtime` & `.venv`), `pip`, all `requirements.txt` packages (`Flask`, `requests`, `psutil`, `pefile`, `yara-python`, `python-evtx`, `mcp`) passing `pip check`.
  - **Config & State:** Strictly valid `config.json`, writable `workspace`/`evidence` directories, free disk `>= min_free_disk_mb`, no `.dirty_state` marker (`sandbox_snapshot_state`).
  - **Static Tools:** `hashlib`, `pefile`, `floss.exe`, `capa.exe`, `capa-rules`, `yara-python` + compiled `.yar` rules, `Java` (`>= 17` / `21`), `Ghidra Headless` installation (`analyzeHeadless` + `scripts/ghidra_export.py`), and compatible Ghidra/JDK version metadata (`ghidra_version_compat`).
  - **Dynamic & MCP:** `Sysmon64.exe` + running `Sysmon64` Windows service + readable `Microsoft-Windows-Sysmon/Operational`, `System`/`Application` Event Log readability (`wevtutil`), `psutil`, Wireshark `dumpcap.exe` + `tshark.exe` + running `Npcap` driver, and `MalBox MCP` (`mcp/server.py` + `mcp/config.json` + live `stdio` handshake registering all 16 read-only tools).

- **Optional or Setup-Unverified Checks (`LOCAL_READINESS` becomes `LIMITED` when missing, disabled, unprivileged, or unverified offline):**

| Component | Mandatory? | Evidence / Feature Unavailable When Missing, Disabled, or Unverified | Fallback Still Collected |
| --- | --- | --- | --- |
| `yara_cli_optional` (`yara64.exe`) | Optional | External YARA CLI fallback only | `static/yara.json` via `yara-python` |
| `procmon_optional` (`Procmon64.exe`) | Optional | `raw/procmon.pml` raw Sysinternals capture and Procmon-sourced rows in `dynamic/filesystem/changes.json` and `dynamic/registry/changes.json` (also skipped when `sandbox.py` runs unprivileged without kernel driver rights) | Sysmon EID `11`, `12`, `13`, `14`, `23` filesystem and registry events |
| `procdump_optional` (`procdump64.exe`) | Optional | Full user-mode process minidumps (`dynamic/memory/dumps/proc_<pid>.dmp`); processes that exit early or are protected also cannot be dumped | `psutil` system/process RAM usage telemetry (`dynamic/memory/memory_usage.json`) |
| `winpmem_optional` (`winpmem.exe`) | Optional (`false` by default) | Full physical RAM image (`dynamic/memory/dumps/physical_memory.raw`); Windows 11 kernel driver compatibility is never verified by executable presence alone | `psutil` telemetry + optional ProcDump process dumps |
| `volatility3_optional` (`vol.py` + ISF symbols) | Optional | Offline physical memory forensics (`dynamic/memory/volatility/*.json`: `pslist`, `pstree`, `cmdline`, `netscan`, `malfind`). Note: requires `physical_memory.raw`, never parses ProcDump `.dmp` files | None (physical RAM plugin output omitted) |
| `ghidramcp_optional` (`GhidraMCP`) | Optional | Interactive Ghidra GUI MCP bridge only (cloning repo or receiving HTTP `200` on port `8080` does **not** prove working MCP integration) | Automated `ghidra/` headless export + MalBox's 16-tool `stdio` MCP server |
| `ghidra_headless_verification` | Setup-unverified probe | If Ghidra Headless fails during VM execution, `ghidra/functions.json`, `disassembly.txt`, and `decompiled/*.c` will be unavailable or partial | PE/strings/capa/YARA static evidence still runs independently |
| `capture_interfaces` (non-loopback NIC pending) | Pending NIC setup | Off-host packet capture in `dynamic/network/capture.pcapng` is unavailable until Internal Network 2 NIC is attached | Loopback check only; `psutil` + Sysmon EID `3`/`22` still run on live VMs |
| Security / Defender EVTX ACL limits | Standard-user limit | `dynamic/eventlogs/security.evtx` (and restricted ACL channels) marked unexported when `sandbox.py` runs as a non-admin user | `system.evtx`, `application.evtx`, and readable Sysmon/PowerShell logs |

---

## 5. Separated Status Semantics

To prevent false confidence, every `setup_report.json` and terminal summary separates six distinct fields:

1. **`LOCAL_READINESS`** (`READY`, `LIMITED`, `NOT_READY`): Local host packages, directories, configs, static/dynamic/MCP readiness on this VM.
2. **`LOCAL_SERVICE_STATE`**: Whether this VM's own HTTP server is `RUNNING`, `NOT_STARTED`, `PORT_CONFLICT`, `LOOPBACK_ONLY_MISCONFIGURED`, or `NOT_APPLICABLE` (Machine 1).
3. **`NETWORK_READINESS`**:
   - **Machine 1 (Client):** `CONTROL_PATH_READY` (Gateway + Sandbox `/status` reachable **and** Sandbox reports `READY`), `CONTROL_PATH_SANDBOX_NOT_READY`, `PENDING`, or `NOT_READY`. (Full binary upload/download flow is only proven during controlled acceptance testing.)
   - **Machine 2 (Gateway):** `PARTIAL_PEER_VERIFIED` (Gateway local service running, `ip_forward=0`, NIC IPs bound, and Sandbox HTTP `/status` reachable), `PEER_REACHABLE_SANDBOX_NOT_READY`, `PENDING`, or `NOT_READY`. Inbound connectivity from Machine 1 must be checked on Machine 1.
   - **Machine 3 (Sandbox):** `LOCAL_SERVICE_ONLY` (local `127.0.0.1:8001` HTTP service + `10.10.20.30` NIC present), `PENDING`, or `NOT_READY`. Machine 3 never claims end-to-end `READY` from a localhost HTTP probe because inbound Machine 2 reachability and firewall rules cannot be tested from localhost.
4. **`PEER_CONNECTIVITY`**: Exact directional peer path actually tested from this machine (e.g. `UNVERIFIED_PASSIVE_LISTENER` on Machine 3, `SANDBOX_HTTP_REACHABLE_CLIENT_INBOUND_UNVERIFIED` on Machine 2, `GATEWAY_AND_SANDBOX_HTTP_REACHABLE` on Machine 1).
5. **`APPLICATION_STATE`**: MalBox Sandbox controller state (`READY`, `ANALYZING`, `RETURNING_EVIDENCE`, `RESTORE_REQUIRED`, `NOT_RUNNING`, `UNREACHABLE`).
6. **`SNAPSHOT_STATE`**: `NO_DIRTY_MARKER` (`workspace/.dirty_state` absent — operator must still manually verify clean VM state before snapshotting) vs `RESTORE_REQUIRED` (`.dirty_state` present on disk).

---

## 6. Verification Depth Levels

MalBox never equates file existence, version banners, generic CLI output, unsuccessful exit codes (`!= 0`), or raw HTTP `200` responses with verified functionality:

- **`installed_only`**: Files/packages exist on disk (e.g. `analyzeHeadless.bat`, `WinPmem`, `Procmon64`, cloned `GhidraMCP`).
- **`version_detected`**: Version metadata and compatibility checked (e.g. `ghidra_version_compat`: `Ghidra 11.x` + `JDK 21`), without running functional pipelines.
- **`runtime_verified`**: Non-destructive command exited `0` or service/handshake succeeded (`doctor --help`, `java -version`, `sc query Sysmon64`, `dumpcap -D`, MalBox MCP `stdio` `initialize` + `tools/list`). Note: `analyzeHeadless -help` typically exits `1` for CLI usage banners — an unsuccessful exit code is **never** marked `runtime_verified` or `PASS`.
- **`feature_verified`**: Real functional probe succeeded on safe fixture data or local OS facilities (`windows_11_version` build check `>= 22000`, `pefile.PE(data=...)`, `yara.compile(...)` on harmless `MZ` bytes, `wevtutil` read probe, directory read/write test).
- **`not_verified`**: Functionality unverified during offline checks (e.g. full Ghidra `ghidra_export.py` execution, WinPmem Windows 11 driver loading, Procmon kernel driver capture, interactive `GhidraMCP` GUI bridge even if port `8080` answers HTTP `200`).
