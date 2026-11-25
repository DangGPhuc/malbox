# MalBox Machine 3 — Windows 11 Sandbox

Machine 3 runs on an isolated **Windows 11 VM** on Internal Network 2 (`10.10.20.30/24`). It performs static analysis, headless Ghidra analysis, dynamic behavioral observation, evidence collection, ZIP packaging, and exposes local evidence querying via **MalBox MCP**.

## State Machine

- `READY` — Clean snapshot ready to receive one sample.
- `ANALYZING` — Static and/or dynamic analysis running for current job.
- `RETURNING_EVIDENCE` — Evidence ZIP packaged and awaiting Gateway transfer confirmation.
- `RESTORE_REQUIRED` — Analysis finished (persisted via `workspace/.dirty_state`). **Restore the CLEAN VM snapshot before starting another analysis.**

## Installation (before isolating VM & taking CLEAN snapshot)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -CloneGitTools
```

Then complete the manual Windows tool setup (Sysmon driver install, Wireshark/Npcap, Ghidra JDK, FLOSS/capa release binaries) described in [../docs/tools-setup.md](../docs/tools-setup.md).

## Starting the Sandbox Server

```powershell
.\.venv\Scripts\Activate.ps1
python sandbox.py
```

By default, `require_local_approval` is `true` in `config.json`, meaning the local operator confirms dynamic execution on the Sandbox console (`y` + Enter) before the sample runs for `observation_duration_seconds` (default `120` seconds). `manifest.json` and `summary.json` explicitly record both configured and actual observation duration, execution status (`completed`, `skipped`, `launch_failed`, `interrupted`), and distinguish `0` observed events from uncollected (`unavailable` / `failed` / `skipped`) collectors.

## Local MalBox MCP Server

After an analysis produces `evidence/<job_id>/`, you can inspect artifacts locally over `stdio` using the generated `mcp/config.json`:

```powershell
.\.venv\Scripts\python.exe mcp\server.py
```

Note: `GhidraMCP` is an optional interactive GUI extension and is separate from automated headless Ghidra export. See [../docs/tools-setup.md](../docs/tools-setup.md) for extension setup and collector/Windows privilege limitations.
