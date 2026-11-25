# MalBox Troubleshooting Guide

## 1. `[ERROR] Gateway unavailable at http://10.10.10.20:8000`
- Verify `python gateway.py` is running on Machine 2.
- Verify Machine 1 and Machine 2 are both attached to Internal Network 1 (`10.10.10.10/24` and `10.10.10.20/24`).
- Test `ping -c 2 10.10.10.20` and `curl http://10.10.10.20:8000/health` from Machine 1.
- Check host firewall (`ufw status` / `iptables`) on Machine 2 for port `8000/tcp`.

## 2. `[ERROR] Sandbox unavailable`
- Verify `python sandbox.py` is running on Machine 3 (`10.10.20.30:8001`).
- Verify Machine 2 NIC 2 and Machine 3 NIC 1 are both attached to Internal Network 2 (`10.10.20.20/24` and `10.10.20.30/24`).
- Verify Windows Firewall on Machine 3 allows inbound TCP port `8001` from `10.10.20.20`.

## 3. `[ERROR] RESTORE_REQUIRED: Sandbox requires restoring the CLEAN snapshot`
- Machine 3 already ran a sample (or `workspace/.dirty_state` exists on disk).
- Revert Machine 3 to your `CLEAN` VM snapshot in VirtualBox/VMware before running `doctor` again.

## 4. `Sysmon` or `Security` Event Logs Show `unavailable` / Access Denied
- `Sysmon` must be installed beforehand as Administrator (`Sysmon64.exe -accepteula -i configs\sysmon.xml`).
- Standard non-admin Windows users can read `System`, `Application`, and usually `Microsoft-Windows-Sysmon/Operational` (if permissions allow), while `Security` event log requires Administrator/Event Log Readers privilege. MalBox leaves original Windows logs untouched and records exact permissions in `manifest.json` and `logs/errors.log`.

## 5. `dumpcap` Produces Empty or Missing `capture.pcapng`
- Run `dumpcap.exe -D` on Machine 3 to check interface indices.
- Set `"network_interface": "<index_or_device>"` explicitly in `machine3-sandbox/config.json`.
- Ensure Npcap was installed without restricting packet capture solely to Administrators if `sandbox.py` runs as a standard user.

## 6. Ghidra Headless Times Out or Fails
- Verify JDK 17/21 is installed and `java -version` works in PowerShell.
- Verify `"ghidra_headless"` in `machine3-sandbox/config.json` points to `analyzeHeadless.bat`.
- Increase `"ghidra_timeout_seconds"` (default `300`) in `config.json` for large binaries.
- Check `evidence/<job_id>/ghidra/analysis.log` for Ghidra stdout/stderr details.

## 7. `Procmon` Not Producing `raw/procmon.pml`
- Verify `Procmon64.exe` path in `machine3-sandbox/config.json`.
- Note that Procmon requires elevation to load its kernel driver; when running `sandbox.py` under a standard unprivileged user account, Procmon records a limitation and Sysmon + `psutil` provide process/filesystem/registry evidence.

## 8. MalBox MCP Import Conflict (`No module named 'mcp.server.fastmcp'`)
- Always launch `machine3-sandbox/mcp/server.py` using the virtual environment Python (`machine3-sandbox\.venv\Scripts\python.exe`). `server.py` automatically strips the local `mcp/` directory from `sys.path` before importing the official `mcp` Python SDK.

## 9. Client Fails During Evidence Download or ZIP Extraction
- Gateway keeps returned archives under `machine2-gateway/retained_evidence/evidence_<job_id>.zip` (when `retain_evidence_archives` is `true` in `machine2-gateway/config.json`).
- You can re-fetch the archive manually from Machine 1 using:
  `curl -f -o evidence_<job_id>.zip http://10.10.10.20:8000/jobs/<job_id>/evidence`

## 10. `JSONDecodeError: Unexpected UTF-8 BOM` on Windows
- `install.ps1` writes UTF-8 files without BOM on both Windows PowerShell 5.1 and PowerShell 7+.
- `doctor.py`, `gateway.py`, `sandbox.py`, `analyzer.py`, `readiness.py`, and `mcp/tools.py` all read JSON with `utf-8-sig`, so manual edits saved with BOM in Windows editors are tolerated safely.

## 11. `LOCAL_READINESS` Shows `NOT_READY` or `LIMITED`
- Inspect `setup_report.json` in the corresponding `machine*` directory (`missing_required_tools`, `missing_optional_tools`, `evidence_impact_when_optional_missing`, `manual_actions_required`).
- `NOT_READY` (exit code `1` in both `setup` and `--check-only` / `-CheckOnly` modes) means a mandatory dependency failed or is missing (including invalid `config.json`, Python `< 3.10`, non-Windows-11 build `< 22000`, or `.dirty_state` requiring CLEAN snapshot restore).
- `LIMITED` (exit code `0`) means all mandatory local checks passed, while optional or offline-unverified items (`Procmon64`, `ProcDump64`, `WinPmem`, `Volatility 3`, `YARA CLI`, `GhidraMCP`, or offline `ghidra_headless_verification`) are absent, disabled, or pending VM testing. See [setup-and-readiness.md](setup-and-readiness.md).
