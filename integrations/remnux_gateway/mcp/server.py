"""
Malbox REMnux Constrained MCP Interface
Exposes only strictly allowlisted, deterministic sandbox operations.
NO AI / NO LLM INFERENCE / NO UNRESTRICTED TERMINAL OR COMMAND EXECUTION.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..config import settings
from ..contracts.schemas import GatewayJobStatus
from ..controller.job_controller import REMnuxJobController


class ConstrainedSandboxMCPServer:
    """
    Constrained MCP interface over the deterministic Gateway Service.
    All actions delegate directly to REMnuxJobController without shell escape.
    """

    def __init__(self, controller: Optional[REMnuxJobController] = None) -> None:
        self.controller = controller or REMnuxJobController()

    def get_supported_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "sandbox_health",
                "description": "Returns operational readiness of REMnux gateway and connected hypervisor.",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "verify_sample",
                "description": "Verifies binary sample integrity against expected SHA-256 hash.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sample_hex": {"type": "string", "description": "Hex encoded binary"},
                        "expected_sha256": {"type": "string", "description": "Expected SHA-256"},
                    },
                    "required": ["sample_hex", "expected_sha256"],
                },
            },
            {
                "name": "check_guest_readiness",
                "description": "Probes physical Kali Host Controller and REMWin guest agent readiness.",
                "parameters": {"type": "object", "properties": {}},
            },
            {
                "name": "start_authorized_job",
                "description": "Submits and starts an authorized execution job with monotonic deadline.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "analysis_id": {"type": "string"},
                        "sample_hex": {"type": "string"},
                        "filename": {"type": "string"},
                        "expected_sha256": {"type": "string"},
                        "timeout_seconds": {"type": "integer", "default": 300},
                    },
                    "required": ["analysis_id", "sample_hex", "expected_sha256"],
                },
            },
            {
                "name": "get_job_status",
                "description": "Queries current execution state, remaining time budget, and telemetry status.",
                "parameters": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string"}},
                    "required": ["job_id"],
                },
            },
            {
                "name": "cancel_job",
                "description": "Requests emergency cancellation, guest process termination, and VM rollback.",
                "parameters": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string"}},
                    "required": ["job_id"],
                },
            },
            {
                "name": "get_evidence_manifest",
                "description": "Retrieves the immutable evidence manifest and artifact hashes for a completed job.",
                "parameters": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string"}},
                    "required": ["job_id"],
                },
            },
            {
                "name": "get_evidence_status",
                "description": "Checks whether the packaged evidence archive is ready for Kali retrieval.",
                "parameters": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string"}},
                    "required": ["job_id"],
                },
            },
        ]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Strictly dispatches only to approved, hardcoded methods."""
        if tool_name == "sandbox_health":
            return self._tool_sandbox_health()
        elif tool_name == "verify_sample":
            return self._tool_verify_sample(arguments)
        elif tool_name == "check_guest_readiness":
            return self._tool_check_guest_readiness()
        elif tool_name == "start_authorized_job":
            return self._tool_start_authorized_job(arguments)
        elif tool_name == "get_job_status":
            return self._tool_get_job_status(arguments)
        elif tool_name == "cancel_job":
            return self._tool_cancel_job(arguments)
        elif tool_name == "get_evidence_manifest":
            return self._tool_get_evidence_manifest(arguments)
        elif tool_name == "get_evidence_status":
            return self._tool_get_evidence_status(arguments)
        else:
            return {"error": f"Tool '{tool_name}' is not allowlisted in constrained sandbox MCP."}

    def _tool_sandbox_health(self) -> Dict[str, Any]:
        return {
            "status": "ready",
            "service": "malbox-remnux-gateway-mcp",
            "target_vm": settings.TARGET_VM_IDENTIFIER,
            "clean_snapshot": settings.CLEAN_SNAPSHOT_NAME,
            "max_execution_seconds": settings.EXECUTION_MAX_SECONDS,
            "mcp_policy": "NO_AI_NO_TERMINAL_DETERMINISTIC_ONLY",
        }

    def _tool_verify_sample(self, args: Dict[str, Any]) -> Dict[str, Any]:
        import hashlib
        try:
            raw = bytes.fromhex(args.get("sample_hex", ""))
            actual = hashlib.sha256(raw).hexdigest()
            expected = args.get("expected_sha256", "").lower()
            return {
                "valid": (actual == expected),
                "actual_sha256": actual,
                "expected_sha256": expected,
                "size_bytes": len(raw),
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _tool_check_guest_readiness(self) -> Dict[str, Any]:
        hc_ok, hc_code, hc_data = self.controller._http_request(f"{settings.HOST_CONTROLLER_URL}/health", timeout=3.0)
        return {
            "host_controller_reachable": hc_ok,
            "host_controller_status": hc_data if hc_ok else f"HTTP {hc_code}",
            "target_vm": settings.TARGET_VM_IDENTIFIER,
        }

    def _tool_start_authorized_job(self, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            sample_bytes = bytes.fromhex(args["sample_hex"])
            res = self.controller.submit_job(
                analysis_id=args["analysis_id"],
                filename=args.get("filename", "sample.exe"),
                sample_bytes=sample_bytes,
                expected_sha256=args["expected_sha256"],
                timeout_seconds=args.get("timeout_seconds", 300),
                approved_by_operator=True,
            )
            self.controller.start_job_execution(res.job_id)
            return {"success": True, "job": res.model_dump()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _tool_get_job_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        job_id = args.get("job_id", "")
        res = self.controller.get_job(job_id)
        if not res:
            return {"found": False, "error": f"Job {job_id} not found"}
        return {"found": True, "job": res.model_dump()}

    def _tool_cancel_job(self, args: Dict[str, Any]) -> Dict[str, Any]:
        job_id = args.get("job_id", "")
        ok = self.controller.cancel_job(job_id)
        return {"cancelled": ok, "job_id": job_id}

    def _tool_get_evidence_manifest(self, args: Dict[str, Any]) -> Dict[str, Any]:
        job_id = args.get("job_id", "")
        manifest = self.controller.get_evidence_manifest(job_id)
        if not manifest:
            return {"ready": False, "error": f"Evidence manifest not ready for {job_id}"}
        return {"ready": True, "manifest": manifest.model_dump()}

    def _tool_get_evidence_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        job_id = args.get("job_id", "")
        path = self.controller.get_evidence_archive_path(job_id)
        return {
            "ready": bool(path and path.is_file()),
            "job_id": job_id,
            "bundle_size_bytes": path.stat().st_size if (path and path.is_file()) else None,
        }


def handle_jsonrpc_request(server: ConstrainedSandboxMCPServer, req: Dict[str, Any]) -> Dict[str, Any]:
    """Handles an incoming JSON-RPC 2.0 MCP request deterministically."""
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params", {}) or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "malbox-remnux-gateway-mcp", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": server.get_supported_tools()},
        }

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = server.execute_tool(name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": "error" in result,
            },
        }

    # Direct tool invocation
    if any(t["name"] == method for t in server.get_supported_tools()):
        result = server.execute_tool(method, params)
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: '{method}'"},
    }


def run_mcp_stdio_server(server: Optional[ConstrainedSandboxMCPServer] = None) -> None:
    """Runs a standard JSON-RPC 2.0 stdio loop reading from sys.stdin."""
    import sys
    srv = server or ConstrainedSandboxMCPServer()
    for line in sys.stdin:
        clean = line.strip()
        if not clean:
            continue
        try:
            req = json.loads(clean)
            resp = handle_jsonrpc_request(srv, req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_mcp_stdio_server()
