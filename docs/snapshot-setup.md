# CLEAN Snapshot Setup & Restore Workflow

Maintaining a clean Windows 11 VM baseline is critical for valid dynamic analysis results. MalBox enforces `RESTORE_REQUIRED` after every completed job via both in-memory state and `workspace/.dirty_state`.

---

## 1. Preparing the `CLEAN` Snapshot

Complete these checks **before** taking your `CLEAN` snapshot on Machine 3:

1. All tools installed and verified via `.\setup.ps1 -CheckOnly` (`LOCAL_READINESS` is `READY` or accepted `LIMITED`, and `SNAPSHOT_STATE` is `CLEAN_MARKER_NOT_PRESENT`).
2. Sysmon service is installed and active (`Get-Service Sysmon64` shows `Running`).
3. Internal Network 2 static IP (`10.10.20.30/24`) is configured; NAT/Bridged adapters and Internet access are disconnected (`NETWORK_READINESS` = `READY` when `sandbox.py` is started).
4. `machine3-sandbox\workspace\` and `machine3-sandbox\evidence\` are empty (no `.dirty_state` marker exists).
5. `machine3-sandbox\config.json` has your preferred settings (`observation_duration_seconds`, `require_local_approval`, `network_interface`, etc.).
6. Optional convenience: Open PowerShell in `C:\malbox\machine3-sandbox`, activate `.venv`, and verify `python sandbox.py` starts in `READY` state (`[SANDBOX] Waiting for sample...`).
7. Take a live VM snapshot named **`CLEAN`** (in VirtualBox: *Machine -> Take Snapshot*; in VMware: *VM -> Snapshot -> Take Snapshot*).

---

## 2. Analysis & Snapshot Restore Loop

1. Ensure Machine 3 is running from the **`CLEAN`** snapshot and `python sandbox.py` is listening.
2. Ensure Machine 2 (`python gateway.py`) is running.
3. On Machine 1, run:
   ```bash
   doctor /path/to/sample.exe
   ```
4. If `require_local_approval` is `true` on Machine 3, approve execution in the Sandbox terminal when prompted:
   ```text
   [SANDBOX] Awaiting local analysis approval...
   [SANDBOX] Approve dynamic execution for 'sample.exe' ...? [y/N]: y
   ```
5. After the 120-second observation completes and evidence is returned to Machine 1, Machine 3 prints:
   ```text
   [ACTION REQUIRED]
   Restore the CLEAN snapshot before the next analysis.
   ```
6. Power off / revert Machine 3 to the **`CLEAN`** snapshot in your hypervisor before submitting the next sample.

---

## 3. Locating Evidence on Machine 1

After `doctor` finishes, evidence for that run is saved without overwriting earlier jobs at:

```text
machine1-client/evidence/<job_id>/
├── report.md        # Human-readable summary report
├── summary.json     # Structured overview + potential IOCs
├── manifest.json    # Job metadata, tool versions, collector statuses, file inventory
├── timeline.json    # Merged chronological timeline
├── static/          # hashes.json, pe_info.json, imports.json, exports.json, strings.txt, floss.json, capa.json, yara.json
├── ghidra/          # functions.json, disassembly.txt, decompiled/*.c, analysis.log
├── dynamic/         # process/, network/, memory/, filesystem/, registry/, eventlogs/
├── raw/             # procmon.pml (if captured)
└── logs/            # analysis.log, collectors.log, tool_status.json, errors.log
```
