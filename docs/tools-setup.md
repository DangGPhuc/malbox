# Machine 3 Tools & MCP Setup Guide (Windows 11)

Install and verify all tools **while Machine 3 has temporary Internet access**, prior to switching to Internal Network 2 and taking the `CLEAN` snapshot.

> Never disable Windows Defender, Tamper Protection, UAC, or driver signature enforcement to force tools to run. MalBox runs samples non-elevated and records exact collector availability and limitations honestly.

---

## 1. Base Python Setup

1. Install **Python 3.10+ (64-bit)** (recommended: Python 3.11 or 3.12 x64) and **Git for Windows**.
2. Clone the repository into `C:\malbox` (or your chosen directory).
3. Run the setup helper in Windows PowerShell 5.1 or PowerShell 7+:
   ```powershell
   cd C:\malbox\machine3-sandbox
   .\install.ps1 -CloneGitTools
   ```
   *(If local PowerShell execution policy restricts unsigned local scripts on the lab guest, verify policy requirements for local scripts cleanly rather than disabling OS security protections.)*
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
- Prerequisite: Install a compatible **JDK** (`JDK 17` for Ghidra 11.0–11.1, `JDK 21` for Ghidra 11.2–12.1, or `JDK 25+` for Ghidra 12.2+; check `Ghidra/application.properties` -> `application.java.min`) and verify `java -version`.
- Source: https://github.com/NationalSecurityAgency/ghidra/releases
- Extract the official release archive to `machine3-sandbox\tools\ghidra\` so `analyzeHeadless.bat` sits at `machine3-sandbox\tools\ghidra\support\analyzeHeadless.bat` (or re-run `.\install.ps1` to auto-update `config.json`).
- MalBox v2 uses the Java post-script **`scripts/GhidraExport.java`** (avoiding Ghidra 12.x PyGhidra/Jython initialization issues). `scripts/ghidra_export.py` is kept only as a legacy reference.
- **Automated Export Limits (`scripts/GhidraExport.java`):** To keep analysis bounded within `ghidra_timeout_seconds` (default `300s`) and avoid oversized evidence ZIPs, headless export caps output to:
  - Up to `10000` function records in `functions.json` (with `total_function_count` and `functions_truncated` flags), `2000` imports, `500` exports, and `3000` defined strings.
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
- **Limitations:** `"winpmem_enabled"` is `false` by default in `config.json`. Full physical RAM acquisition requires Administrator privilege, compatible Windows 11/10 kernel driver support (without disabling Secure Boot/driver signing), and free disk space larger than guest RAM size. Volatility 3 plugins run offline against full physical RAM images (`physical_memory.raw`), **not** against ProcDump user-mode `.dmp` files.

### I. Optional Detect It Easy (`diec.exe`)
- Download official Detect It Easy Windows release (`die_win64_portable_*.zip`) and extract `diec.exe` + `db/` into `tools\die\`.
- **Verification & Optionality:** Checked by `readiness.py` (`detect_it_easy_optional`) using `diec.exe --version`. During analysis, `static_analysis.py` runs `diec.exe -j <sample>` to write `static/die.json` (compiler/linker/packer indicators). If `diec.exe` is not installed, MalBox records `detect_it_easy` as `unavailable` (`optional_static`) without degrading mandatory job status.

---

## 3. Using MalBox MCP and Optional GhidraMCP Locally

- `install.ps1` generates `machine3-sandbox\mcp\config.json` from `mcp\config.example.json` (UTF-8 without BOM).
- **MalBox MCP** (`machine3-sandbox\mcp\server.py`) runs offline over `stdio` to query completed `evidence/<job_id>/` directories read-only.
- **GhidraMCP** (`https://github.com/LaurieWired/GhidraMCP`) is **optional** and **separate** from headless Ghidra analysis:
  1. Cloning `tools\GhidraMCP\` only provides the repository and bridge script (`bridge_mcp_ghidra.py`).
  2. To actually use `GhidraMCP`, you must manually install/build its Ghidra extension inside Ghidra GUI (`File -> Install Extensions...`), open the binary in Ghidra GUI, and start its local HTTP server (`127.0.0.1:8080`) before launching `bridge_mcp_ghidra.py`.
  3. The automated pipeline (`ghidra_analysis.py`) never starts or runtime-verifies `GhidraMCP`, and reports repo clone / extension / dependency / runtime status separately in `manifest.json`. Likewise, `readiness.py` never treats an HTTP `200` on `127.0.0.1:8080/methods` alone as verified MCP bridge functionality.

---

## 4. Installed vs Version-Detected vs Runtime-Verified vs Feature-Verified

MalBox readiness checks (`setup_report.json`) strictly separate verification depth:

1. **Installed (`installed: true`):** Binary, Python package, or cloned repo exists on disk.
2. **Version detected (`detected_version`):** Executable or package metadata responded with an explicit version or commit ID.
3. **Runtime verified (`runtime_verified: true`):** Bounded non-destructive command, service query, or protocol handshake succeeded (`java -version`, `sc query Sysmon64`, `dumpcap -D`, MCP `stdio` `initialize` + `tools/list`).
4. **Feature verified (`feature_verified: true`):** Tool performed a real functional probe on safe fixture data or local logs (`pefile` parsing synthetic header, `yara.compile` matching harmless `MZ` bytes, `wevtutil` reading `Microsoft-Windows-Sysmon/Operational`).
5. **Not verified:** Present on disk only (e.g., `WinPmem` Windows 11 driver compatibility or `GhidraMCP` when Ghidra GUI is not running).

See [setup-and-readiness.md](setup-and-readiness.md) for the full schema and mandatory vs optional list.
