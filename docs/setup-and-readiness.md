# Setup & Environment Readiness Guide

Each MalBox machine includes a one-command setup and readiness verification entrypoint (`setup.sh` on Linux, `setup.ps1` on Windows 11) backed by a standalone `readiness.py` checker.

---

## 1. Execution Order

1. **While VMs still have temporary Internet access:**
   - Clone `https://github.com/DangGPhuc/malbox.git` onto all 3 VMs.
   - Run `bash setup.sh` on **Machine 1** and **Machine 2**.
   - Run `.\setup.ps1 -CloneGitTools` on **Machine 3** and install the required manual Windows binaries/installers (see [tools-setup.md](tools-setup.md)).
   - Re-run `.\setup.ps1` on Machine 3 until `LOCAL_READINESS` reaches `READY` (or `LIMITED` if optional tools are intentionally omitted).
2. **Isolate Internal Networks (manual):**
   - Switch adapters to Internal Network 1 & 2, assign static IPs (`10.10.10.10`, `10.10.10.20`, `10.10.20.20`, `10.10.20.30`), and verify Internet is disconnected on Machine 3 (see [network-setup.md](network-setup.md)).
3. **Offline Check-Only Verification (after isolation):**
   - Start `sandbox.py` on Machine 3 and `gateway.py` on Machine 2.
   - Run `--check-only` / `-CheckOnly` on each VM to verify both `LOCAL_READINESS` and `NETWORK_READINESS` before saving the `CLEAN` snapshot or running acceptance tests.
4. **Save the `CLEAN` snapshot on Machine 3:**
   - Confirm `SNAPSHOT_STATE` is `CLEAN_MARKER_NOT_PRESENT` (never `RESTORE_REQUIRED`) before saving the `CLEAN` snapshot.

---

## 2. Commands per Machine

| Machine | Default Setup Command | Offline Check-Only Command | Output Report |
| --- | --- | --- | --- |
| **Machine 1 (Kali)** | `cd malbox/machine1-client && bash setup.sh` | `bash setup.sh --check-only` | `machine1-client/setup_report.json` |
| **Machine 2 (Gateway)** | `cd malbox/machine2-gateway && bash setup.sh` | `bash setup.sh --check-only` | `machine2-gateway/setup_report.json` |
| **Machine 3 (Windows 11)** | `cd malbox\machine3-sandbox; .\setup.ps1` | `.\setup.ps1 -CheckOnly` | `machine3-sandbox/setup_report.json` |

### Behavior of `--check-only` / `-CheckOnly`
- Runs strictly offline without `pip install`, `git clone`, `git pull`, or file downloads.
- Never modifies drivers, network configuration, `.dirty_state`, VM snapshots, or existing evidence.
- Only creates `setup_report.json` and transient `.readiness_probe_*` permission test files (deleted immediately).
- Never executes malware samples.

---

## 3. Mandatory vs Optional Tools

### Machine 1 & Machine 2
- **Mandatory:** Linux OS, Python `>= 3.9`, `.venv`, `pip`, `requests` (and `Flask` on Machine 2), valid `config.json`, writable `evidence`/`tmp`/`retained_evidence` directories, `doctor --help` (Machine 1), `ip_forward=0` (Machine 2), sufficient disk space.
- **Peer/Network (governs `NETWORK_READINESS`):** Reachable peer HTTP `/health` and `/status` endpoints with valid JSON payloads.

### Machine 3 (Windows 11 Sandbox)
- **Mandatory (`LOCAL_READINESS` becomes `NOT_READY` if missing/failing):**
  - Windows OS + PowerShell + 64-bit Python `>= 3.10` + `.venv` + `pip` + all `requirements.txt` packages (`Flask`, `requests`, `psutil`, `pefile`, `yara-python`, `python-evtx`, `mcp`) passing `pip check`.
  - Valid `config.json`, writable `workspace`/`evidence` directories, free disk `>= min_free_disk_mb`, no `.dirty_state` marker.
  - Static: `hashlib`, `pefile`, `floss.exe`, `capa.exe`, `capa-rules`, `yara-python` + rule compilation, compatible `Java` (`>= 17` / `21` depending on Ghidra version) + `Ghidra Headless` + `scripts/ghidra_export.py`.
  - Dynamic: `Sysmon64.exe` + running `Sysmon64` Windows service + readable `Microsoft-Windows-Sysmon/Operational` channel, `System`/`Application` Event Log readability (`wevtutil`), `psutil`, Wireshark `dumpcap.exe` + `tshark.exe` + running `Npcap` driver + capture interface check.
  - MCP: `mcp` SDK + `mcp/server.py` + `mcp/config.json` + live `stdio` handshake registering all 16 read-only tools.
- **Optional (`LOCAL_READINESS` becomes `LIMITED` if missing/unverified):**
  - `YARA CLI` (`yara64.exe`), `Procmon64.exe` (requires Administrator elevation to load kernel driver), `procdump64.exe`, `WinPmem` (optional full RAM dump; driver compatibility on Windows 11 cannot be assumed from binary presence), `Volatility 3` + offline symbol tables, and `GhidraMCP` (optional interactive Ghidra GUI plugin).

---

## 4. Understanding Statuses & Report Fields

### Per-Check Statuses
- **`PASS`**: Check succeeded and met verification requirements.
- **`FAIL`**: Component exists or responded, but failed validation, compatibility, permissions, or returned an unexpected service payload.
- **`MISSING`**: Required binary, folder, virtual environment, or rule set is not installed.
- **`OPTIONAL`**: Optional component is absent; core pipeline remains functional.
- **`PENDING`**: Waiting on user setup step or peer VM service (e.g., Gateway/Sandbox not started yet, network NIC not yet assigned, or Ghidra GUI server not active).
- **`SKIPPED`**: Probe could not run due to a prerequisite check being absent.

### Verification Levels
- **`installed`**: Binary, package, or repository exists on disk.
- **`version_detected`**: Executable or package reported a concrete version string.
- **`runtime_verified`**: Bounded non-destructive command or service query succeeded (e.g., `doctor --help`, `java -version`, `sc query Sysmon64`, `dumpcap -D`, MCP `initialize` + `tools/list`).
- **`feature_verified`**: Real functional probe succeeded on safe fixture data (e.g., `pefile.PE(data=...)`, `yara.compile(...)` matching `MZ` fixture, `wevtutil` channel read, directory write/read test).
- **`not_verified`**: Not yet executed/verified (never assumed solely from file existence).

### Overall Readiness Levels
- **`LOCAL_READINESS`**:
  - `READY`: All mandatory and optional local checks passed.
  - `LIMITED`: All mandatory local checks passed, but one or more optional tools (`Procmon`, `ProcDump`, `WinPmem`, `Volatility 3`, `GhidraMCP`, etc.) are missing or unverified.
  - `NOT_READY`: At least one mandatory local requirement failed or is missing (or `.dirty_state` requires snapshot restore).
- **`NETWORK_READINESS`**:
  - `READY`: Expected peer HTTP endpoints and network interfaces responded with valid MalBox service payloads.
  - `PENDING`: Services have not been started yet or Internal Network IPs are not assigned yet.
  - `NOT_READY`: Port conflict or wrong service responded on a MalBox port.

---

## 5. Readiness Before Snapshot & Acceptance Testing

- **Before taking the `CLEAN` snapshot on Machine 3:**
  - `LOCAL_READINESS` must be `READY` (or accepted `LIMITED`), `SNAPSHOT_STATE` must be `CLEAN_MARKER_NOT_PRESENT`, and `workspace/` + `evidence/` must contain no prior job artifacts.
- **Before running harmless acceptance testing (`doctor <benign.exe>`):**
  - All 3 machines report `LOCAL_READINESS` = `READY` (or `LIMITED`) in `--check-only` / `-CheckOnly` mode.
  - `NETWORK_READINESS` = `READY` on Machine 1 (confirming Gateway + Sandbox reachable), Machine 2, and Machine 3.
  - Machine 3 confirms `SNAPSHOT_STATE` = `CLEAN_MARKER_NOT_PRESENT` and Sandbox state = `READY`.
