#!/usr/bin/env python3
"""MalBox Local MCP Server (stdio transport using official Python MCP SDK).

Exposes read-only evidence inspection tools strictly scoped to job evidence
workspaces. Provides no arbitrary shell, sample execution, or hypervisor APIs.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

MCP_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = MCP_DIR.parent

# Prevent local `machine3-sandbox/mcp/` folder from shadowing the official `mcp` SDK.
_original_sys_path = list(sys.path)
sys.path[:] = [
    p for p in sys.path if Path(p or ".").resolve() not in (MCP_DIR, SANDBOX_DIR)
]
from mcp.server.fastmcp import FastMCP  # noqa: E402

sys.path[:] = _original_sys_path

_tools_spec = importlib.util.spec_from_file_location("malbox_mcp_tools", MCP_DIR / "tools.py")
if _tools_spec is None or _tools_spec.loader is None:
    raise RuntimeError("Could not load mcp/tools.py")
_tools_mod = importlib.util.module_from_spec(_tools_spec)
_tools_spec.loader.exec_module(_tools_mod)
EvidenceStore = _tools_mod.EvidenceStore

store = EvidenceStore(sandbox_dir=SANDBOX_DIR)
mcp = FastMCP("malbox-mcp")


@mcp.tool()
def get_analysis_status(job_id: str | None = None) -> dict[str, Any]:
    """Get sandbox disk state and optional job completion/collector status."""
    return store.get_analysis_status(job_id=job_id)


@mcp.tool()
def get_sample_metadata(job_id: str) -> dict[str, Any]:
    """Get manifest, hashes, and PE header metadata for a completed job."""
    return store.get_sample_metadata(job_id=job_id)


@mcp.tool()
def get_static_analysis(job_id: str) -> dict[str, Any]:
    """Get static analysis findings (PE, imports, exports, FLOSS/strings, capa, YARA)."""
    return store.get_static_analysis(job_id=job_id)


@mcp.tool()
def get_process_tree(job_id: str) -> dict[str, Any]:
    """Get parent-child process tree observed during dynamic execution."""
    return store.get_process_tree(job_id=job_id)


@mcp.tool()
def get_process_events(job_id: str, limit: int = 200) -> dict[str, Any]:
    """Get chronological process creation/termination events (Sysmon, Procmon, psutil)."""
    return store.get_process_events(job_id=job_id, limit=limit)


@mcp.tool()
def get_network_connections(job_id: str, limit: int = 200) -> dict[str, Any]:
    """Get observed network connections from PCAPNG/TShark, Sysmon, and psutil."""
    return store.get_network_connections(job_id=job_id, limit=limit)


@mcp.tool()
def get_dns_queries(job_id: str, limit: int = 200) -> dict[str, Any]:
    """Get DNS queries observed passively in PCAPNG or Sysmon EID 22."""
    return store.get_dns_queries(job_id=job_id, limit=limit)


@mcp.tool()
def get_memory_summary(job_id: str) -> dict[str, Any]:
    """Get RAM usage telemetry, process memory dumps, and optional Volatility output list."""
    return store.get_memory_summary(job_id=job_id)


@mcp.tool()
def get_filesystem_changes(job_id: str, limit: int = 200) -> dict[str, Any]:
    """Get filesystem creations/modifications/deletions and dropped artifact metadata."""
    return store.get_filesystem_changes(job_id=job_id, limit=limit)


@mcp.tool()
def get_registry_changes(job_id: str, limit: int = 200) -> dict[str, Any]:
    """Get Windows Registry modifications and persistence key detections."""
    return store.get_registry_changes(job_id=job_id, limit=limit)


@mcp.tool()
def get_windows_events(job_id: str, channel: str = "all", limit: int = 200) -> dict[str, Any]:
    """Get Windows Event Log channel metadata and parsed event previews."""
    return store.get_windows_events(job_id=job_id, channel=channel, limit=limit)


@mcp.tool()
def get_ghidra_results(
    job_id: str,
    function_name: str | None = None,
    include_decompiled: bool = False,
) -> dict[str, Any]:
    """Get Ghidra headless functions, imports, exports, and optional decompiled C snippets."""
    return store.get_ghidra_results(
        job_id=job_id,
        function_name=function_name,
        include_decompiled=include_decompiled,
    )


@mcp.tool()
def get_yara_matches(job_id: str) -> dict[str, Any]:
    """Get local YARA rule matches and compile status for a job."""
    return store.get_yara_matches(job_id=job_id)


@mcp.tool()
def get_analysis_timeline(job_id: str, limit: int = 300) -> dict[str, Any]:
    """Get merged chronological timeline across static and dynamic events."""
    return store.get_analysis_timeline(job_id=job_id, limit=limit)


@mcp.tool()
def list_evidence(job_id: str | None = None) -> dict[str, Any]:
    """List available evidence job IDs or list all files inside a specific job evidence folder."""
    return store.list_evidence(job_id=job_id)


@mcp.tool()
def get_evidence_summary(job_id: str) -> dict[str, Any]:
    """Get summary.json and full report.md for a job."""
    return store.get_evidence_summary(job_id=job_id)


def main() -> None:
    """Start MalBox MCP over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
