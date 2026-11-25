# Machine 3 Tools & MCP Setup Guide (Windows 11)

Install and verify all tools **while Machine 3 has temporary Internet access**, prior to switching to Internal Network 2 and taking the `CLEAN` snapshot.

> Never disable Windows Defender, Tamper Protection, UAC, or driver signature enforcement to force tools to run. MalBox runs samples non-elevated and records exact collector availability and limitations honestly.

---

## 1. Base Python Setup

1. Install **Python 3.11+** (x64) and **Git for Windows**.
2. Clone the repository into `C:\malbox` (or your chosen directory).
3. Run the setup helper in Windows PowerShell 5.1 or PowerShell 7+:
   ```powershell
   cd C:\malbox\machine3-sandbox
   Set-ExecutionPolicy -Scope Process Bypass
   .\install.ps1 -CloneGitTools
   ```
   `-CloneGitTools` clones `capa-rules`, `volatility3`, and `GhidraMCP` into `tools\`, then creates `tools\volatility3\symbols\` afterward so `git clone` never fails on a non-empty folder. `install.ps1` verifies Python/pip/git exit codes and writes JSON configs in UTF-8 without BOM.

---

## 2. Official Release Tools Requiring Manual Download/Install

Download official releases into `machine3-sandbox\tools\` (or default install locations):

### A. FLOSS (Strings & Deobfuscated Strings)
- Source: https://github.com/mandiant/flare-floss/releases
- Extract `floss.exe` to: `machine3-sandbox\tools\floss\floss.exe`
- *(If omitted, MalBox falls back to pure-Python ASCII/UTF-16LE string extraction and records `strings_floss` status as `partial`.)*

### B. capa (Capability Identification)
- Source: https://github.com/mandiant/capa/releases
- Extract `capa.exe` to: `machine3-sandbox\tools\capa\capa.exe`
- Rules cloned at: `machine3-sandbox\tools\capa-rules\`

### C. YARA
- `yara-python` is automatically installed via `requirements.txt` inside `.venv`.
- Optional CLI fallback: extract `yara64.exe` from https://github.com/VirusTotal/yara/releases into `machine3-sandbox\tools\yara\yara64.exe`.
- Add custom `.yar` rules into `machine3-sandbox\scripts\yara_rules\`.

### D. NSA Ghidra Headless Analyzer & Export Limits
- Prerequisite: Install **JDK 17 or JDK 21** (Eclipse Temurin / OpenJDK) and verify `java -version`.
- Source: https://github.com/NationalSecurityAgency/ghidra/releases
- Extract the official release archive to `machine3-sandbox\tools\ghidra\` so `analyzeHeadless.bat` sits at `machine3-sandbox\tools\ghidra\support\analyzeHeadless.bat` (or re-run `.\install.ps1` to auto-update `config.json`).
- **Automated Export Limits (`scripts/ghidra_export.py`):** To keep analysis bounded within `ghidra_timeout_seconds` (default `300s`) and avoid oversized evidence ZIPs, headless export caps output to:
  - Up to `2000` imports, `500` exports, and `3000` defined strings.
  - Disassembly for up to `80` non-external functions (`200` instructions per function).
  - Decompiled C pseudocode for up to `40` non-thunk/non-external functions (`30s` timeout per function).
  - Very large, packed, or obfuscated binaries may hit these caps or time out; check `ghidra/analysis.log` for full headless details.

### E. Sysinternals (`Sysmon`, `Procmon`, `ProcDump`) & Privilege Limits
- Download from Microsoft Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- Extract `Sysmon64.exe`, `Procmon64.exe`, and `procdump64.exe` into `machine3-sandbox\tools\sysinternals\`.
- **Sysmon (one-time Admin setup before snapshot):**
  ```powershell
  cd C:\malbox\machine3-sandbox
  .\tools\sysinternals\Sysmon64.exe -accepteula -i .\configs\sysmon.xml
  Get-Service Sysmon64
  ```
  `Sysmon64` runs as a privileged Windows driver/service while `sandbox.py` runs unprivileged. Note that reading `Microsoft-Windows-Sysmon/Operational` via `wevtutil` may require Administrator or `Event Log Readers` group permissions depending on local Windows ACLs.
- **Procmon (`Procmon64.exe`):** Loading Procmon's kernel driver requires Administrator elevation. When `sandbox.py` runs as a standard unprivileged user, Procmon capture cannot start and `filesystem_monitor` / `registry_monitor` record this limitation while relying on Sysmon events.
- **ProcDump (`procdump64.exe`) Limits:** MalBox runs `procdump64.exe -ma <pid>` **only on tracked sample/child PIDs still alive at the end of the observation window** (capped at `10` PIDs). Processes that terminate early before the dump checkpoint or elevated/protected processes cannot be dumped by an unprivileged ProcDump call.

### F. Wireshark (`dumpcap` & `tshark`)
- Install official Wireshark Windows installer (includes **Npcap**): https://www.wireshark.org/download.html
- During Npcap installation, leave **"Restrict Npcap driver's access to Administrators only"** **unchecked** if `sandbox.py` will run as a standard user.
- Verify `C:\Program Files\Wireshark\dumpcap.exe -D` lists your Internal Network 2 adapter and set `"network_interface"` in `config.json` if auto-detection needs overriding.

### G. Windows Event Logs (`wevtutil.exe`)
- MalBox exports `Sysmon`, `System`, `Application`, `Security`, `PowerShell`, and `Defender` channels scoped from `dynamic_window_utc` without clearing original logs.
- `Security` (and on some builds `Sysmon` / `Defender`) requires elevated or `Event Log Readers` access; denied channels are recorded as unexported in `dynamic/eventlogs/events_summary.json` and `manifest.json`.

### H. Optional Memory Tools (`WinPmem` & `Volatility 3`)
- **WinPmem:** https://github.com/Velocidex/WinPmem/releases -> `tools\winpmem\winpmem.exe`.
- **Volatility 3:** Cloned into `tools\volatility3\`. Pre-cache offline Windows ISF symbol tables into `tools\volatility3\symbols\` while online.
- **Limitations:** `"winpmem_enabled"` is `false` by default in `config.json`. Full physical RAM acquisition requires Administrator privilege, compatible Windows 11 kernel driver support (without disabling Secure Boot/driver signing), and free disk space larger than guest RAM size. Volatility 3 plugins run offline against full physical RAM images (`physical_memory.raw`), **not** against ProcDump user-mode `.dmp` files.

---

## 3. Using MalBox MCP and Optional GhidraMCP Locally

- `install.ps1` generates `machine3-sandbox\mcp\config.json` from `mcp\config.example.json` (UTF-8 without BOM).
- **MalBox MCP** (`machine3-sandbox\mcp\server.py`) runs offline over `stdio` to query completed `evidence/<job_id>/` directories read-only.
- **GhidraMCP** (`https://github.com/LaurieWired/GhidraMCP`) is **optional** and **separate** from headless Ghidra analysis:
  1. Cloning `tools\GhidraMCP\` only provides the repository and bridge script (`bridge_mcp_ghidra.py`).
  2. To actually use `GhidraMCP`, you must manually install/build its Ghidra extension inside Ghidra GUI (`File -> Install Extensions...`), open the binary in Ghidra GUI, and start its local HTTP server (`127.0.0.1:8080`) before launching `bridge_mcp_ghidra.py`.
  3. The automated pipeline (`ghidra_analysis.py`) never starts or runtime-verifies `GhidraMCP`, and reports repo clone / extension / dependency / runtime status separately in `manifest.json`.
