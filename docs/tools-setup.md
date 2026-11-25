# Machine 3 Tools & MCP Setup Guide (Windows 11)

Install and verify all tools **while Machine 3 has temporary Internet access**, prior to switching to Internal Network 2 and taking the `CLEAN` snapshot.

> Never disable Windows Defender, Tamper Protection, or driver signature enforcement to force tools to run. MalBox records exact tool availability and limitations honestly.

---

## 1. Base Python Setup

1. Install **Python 3.11+** (x64) and **Git for Windows**.
2. Clone the repository into `C:\malbox` (or your chosen directory).
3. Run the setup helper in PowerShell:
   ```powershell
   cd C:\malbox\machine3-sandbox
   Set-ExecutionPolicy -Scope Process Bypass
   .\install.ps1 -CloneGitTools
   ```
   `-CloneGitTools` clones `capa-rules`, `volatility3`, and `GhidraMCP` into `tools\`.

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

### D. NSA Ghidra Headless Analyzer
- Prerequisite: Install **JDK 17 or JDK 21** (Eclipse Temurin / OpenJDK) and ensure `java -version` works.
- Source: https://github.com/NationalSecurityAgency/ghidra/releases
- Extract the official release archive to `machine3-sandbox\tools\ghidra\` so `analyzeHeadless.bat` sits at `machine3-sandbox\tools\ghidra\support\analyzeHeadless.bat` (or re-run `.\install.ps1` to auto-update `config.json`).

### E. Sysinternals (Sysmon, Procmon, ProcDump)
- Download from Microsoft Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- Extract `Sysmon64.exe`, `Procmon64.exe`, and `procdump64.exe` into `machine3-sandbox\tools\sysinternals\`.
- **Install Sysmon service (Administrator PowerShell):**
  ```powershell
  cd C:\malbox\machine3-sandbox
  .\tools\sysinternals\Sysmon64.exe -accepteula -i .\configs\sysmon.xml
  Get-Service Sysmon64
  ```
- Accept EULA once for Procmon and ProcDump if desired (`Procmon64.exe /AcceptEula /Quiet /Terminate`). Note that Procmon requires elevation when launched interactively; if running `sandbox.py` unprivileged, Procmon notes the privilege limitation and MalBox still collects Sysmon Operational logs.

### F. Wireshark (`dumpcap` & `tshark`)
- Install official Wireshark Windows installer (includes **Npcap**): https://www.wireshark.org/download.html
- Verify `C:\Program Files\Wireshark\dumpcap.exe -D` lists your Internal Network 2 Ethernet adapter without requiring Admin UAC (enable "Restrict Npcap driver's access to Administrators only = OFF" during Npcap setup if running Sandbox as standard user).
- Set `"network_interface"` in `config.json` to the interface number/name if auto-detection needs overriding.

### G. Optional Memory Tools (`WinPmem` & `Volatility 3`)
- **WinPmem:** https://github.com/Velocidex/WinPmem/releases -> `tools\winpmem\winpmem.exe`
- **Volatility 3:** Cloned into `tools\volatility3\`. Download/pre-cache offline Windows ISF symbol tables into `tools\volatility3\symbols\` before isolating the VM.
- Set `"winpmem_enabled": true` in `config.json` only if you want full physical RAM dumps (requires compatible Windows driver/privileges and generous free disk space).

---

## 3. Using MalBox MCP and GhidraMCP Locally

- `install.ps1` generates `machine3-sandbox\mcp\config.json` from `mcp\config.example.json`.
- **MalBox MCP** (`machine3-sandbox\mcp\server.py`) works completely offline over `stdio` to query any completed `evidence/<job_id>/` folder (`get_static_analysis`, `get_process_tree`, `get_network_connections`, `get_ghidra_results`, etc.).
- **GhidraMCP** (`https://github.com/LaurieWired/GhidraMCP`) can be installed in `tools\GhidraMCP\` for interactive reverse engineering in Ghidra GUI after analysis. If GhidraMCP is not running, headless Ghidra analysis still executes and exports `functions.json`, `disassembly.txt`, and `decompiled/*.c` normally.
