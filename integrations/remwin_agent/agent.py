"""
Malbox REMWin Execution & Telemetry Agent
Minimal, deterministic Windows execution agent designed to run inside
the isolated REMWin analysis guest (10.77.0.10:8000).

NO AI / NO LLM INFERENCE / DETERMINISTIC AUDITABLE TELEMETRY.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

AGENT_HOST = os.getenv("MALBOX_AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("MALBOX_AGENT_PORT", "8000"))
AGENT_SECRET = os.getenv("MALBOX_AGENT_SECRET", "remwin-guest-agent-token")
WORKSPACE_ROOT = Path(os.getenv("MALBOX_AGENT_WORKSPACE", r"C:\malbox\workspace"))

# In-memory job state
CURRENT_JOB: Optional[Dict[str, Any]] = None
SPAWNED_PROCESS: Optional[subprocess.Popen] = None
JOB_START_TIME: Optional[float] = None
EXECUTION_MAX_SECONDS = 300


def get_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class REMWinAgentHandler(BaseHTTPRequestHandler):
    server_version = "MalboxREMWinAgent/1.0"

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _verify_auth(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").replace("Token ", "").strip()
        if not token:
            token = self.headers.get("X-Malbox-Agent-Token", "").strip()
        return (token == AGENT_SECRET)

    def do_GET(self) -> None:
        global CURRENT_JOB, SPAWNED_PROCESS, JOB_START_TIME
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            # Health is accessible without auth for network readiness probe
            self._send_json(200, {
                "status": "ready",
                "os": platform.platform(),
                "python": sys.version.split()[0],
                "current_job_active": bool(SPAWNED_PROCESS and SPAWNED_PROCESS.poll() is None),
                "workspace": str(WORKSPACE_ROOT),
                "max_execution_budget": EXECUTION_MAX_SECONDS,
            })
            return

        if not self._verify_auth():
            self._send_json(401, {"error": "Unauthorized: valid agent token required"})
            return

        if path == "/status":
            if not CURRENT_JOB:
                self._send_json(200, {"status": "IDLE", "job": None})
                return

            elapsed = (time.monotonic() - JOB_START_TIME) if JOB_START_TIME else 0.0
            is_running = bool(SPAWNED_PROCESS and SPAWNED_PROCESS.poll() is None)
            exit_code = SPAWNED_PROCESS.poll() if SPAWNED_PROCESS else None

            # Monotonic watchdog enforcement inside guest
            if is_running and elapsed > EXECUTION_MAX_SECONDS:
                try:
                    SPAWNED_PROCESS.terminate()
                except Exception:
                    pass
                is_running = False

            self._send_json(200, {
                "status": "RUNNING" if is_running else "FINISHED",
                "job_id": CURRENT_JOB.get("job_id"),
                "sample_sha256": CURRENT_JOB.get("sha256"),
                "pid": CURRENT_JOB.get("pid"),
                "elapsed_seconds": round(elapsed, 2),
                "remaining_seconds": max(0.0, round(EXECUTION_MAX_SECONDS - elapsed, 2)),
                "exit_code": exit_code,
                "is_active": is_running,
            })
            return

        if path == "/telemetry":
            self._collect_telemetry_payload()
            return

        self._send_json(404, {"error": f"Unknown endpoint: {path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._verify_auth():
            self._send_json(401, {"error": "Unauthorized: valid agent token required"})
            return

        content_length = int(self.headers.get("Content-Length", 0))

        if path == "/stage":
            self._handle_stage(content_length)
            return

        if path == "/execute":
            self._handle_execute(content_length)
            return

        if path == "/cancel":
            self._handle_cancel()
            return

        self._send_json(404, {"error": f"Unknown endpoint: {path}"})

    def _handle_stage(self, content_length: int) -> None:
        global CURRENT_JOB, SPAWNED_PROCESS
        if SPAWNED_PROCESS and SPAWNED_PROCESS.poll() is None:
            self._send_json(409, {"error": "A job is currently executing on this guest."})
            return

        # Expect multipart form or binary upload
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            raw_body = self.rfile.read(content_length)
            data = json.loads(raw_body.decode("utf-8"))
            job_id = data.get("job_id", f"job_{int(time.time())}")
            expected_sha256 = data.get("expected_sha256", "").lower()
            filename = data.get("filename", "sample.exe")
            # If payload passed as hex or b64
            payload_hex = data.get("payload_hex")
            if not payload_hex:
                self._send_json(400, {"error": "Missing payload_hex in JSON stage request"})
                return
            binary_bytes = bytes.fromhex(payload_hex)
        else:
            # Raw binary upload with headers
            job_id = self.headers.get("X-Malbox-Job-ID", f"job_{int(time.time())}")
            expected_sha256 = self.headers.get("X-Malbox-Expected-SHA256", "").lower()
            filename = self.headers.get("X-Malbox-Filename", "sample.exe")
            binary_bytes = self.rfile.read(content_length)

        # Validate hash
        actual_sha256 = hashlib.sha256(binary_bytes).hexdigest()
        if expected_sha256 and actual_sha256 != expected_sha256:
            self._send_json(400, {
                "error": "Hash mismatch",
                "expected": expected_sha256,
                "actual": actual_sha256,
            })
            return

        job_dir = WORKSPACE_ROOT / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        # Prevent path traversal in filename
        safe_filename = Path(filename).name or "sample.exe"
        target_path = job_dir / safe_filename
        target_path.write_bytes(binary_bytes)

        CURRENT_JOB = {
            "job_id": job_id,
            "filename": safe_filename,
            "staged_path": str(target_path),
            "sha256": actual_sha256,
            "staged_at": time.time(),
            "status": "STAGED",
        }

        self._send_json(200, {
            "status": "STAGED",
            "job_id": job_id,
            "sha256": actual_sha256,
            "staged_path": str(target_path),
            "size_bytes": len(binary_bytes),
        })

    def _handle_execute(self, content_length: int) -> None:
        global CURRENT_JOB, SPAWNED_PROCESS, JOB_START_TIME
        if not CURRENT_JOB or CURRENT_JOB.get("status") not in ("STAGED", "FINISHED"):
            self._send_json(400, {"error": "No staged sample available for execution."})
            return

        staged_path = Path(CURRENT_JOB["staged_path"])
        if not staged_path.is_file():
            self._send_json(404, {"error": f"Staged sample file not found: {staged_path}"})
            return

        # Read optional parameters
        timeout = EXECUTION_MAX_SECONDS
        if content_length > 0:
            try:
                body = self.rfile.read(content_length)
                data = json.loads(body.decode("utf-8"))
                timeout = min(int(data.get("timeout_seconds", EXECUTION_MAX_SECONDS)), EXECUTION_MAX_SECONDS)
            except Exception:
                pass

        try:
            # Deterministic launch
            proc = subprocess.Popen(
                [str(staged_path)],
                cwd=str(staged_path.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            SPAWNED_PROCESS = proc
            JOB_START_TIME = time.monotonic()
            CURRENT_JOB["pid"] = proc.pid
            CURRENT_JOB["status"] = "RUNNING"
            CURRENT_JOB["started_at"] = time.time()
            CURRENT_JOB["timeout_seconds"] = timeout

            self._send_json(200, {
                "status": "RUNNING",
                "job_id": CURRENT_JOB["job_id"],
                "pid": proc.pid,
                "sha256": CURRENT_JOB["sha256"],
                "timeout_seconds": timeout,
                "message": "Sample process initiated in sandbox workspace.",
            })
        except Exception as e:
            self._send_json(500, {"error": f"Failed to execute binary: {str(e)}"})

    def _handle_cancel(self) -> None:
        global SPAWNED_PROCESS, CURRENT_JOB
        if SPAWNED_PROCESS and SPAWNED_PROCESS.poll() is None:
            try:
                # Force kill process tree if on Windows
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/PID", str(SPAWNED_PROCESS.pid), "/T", "/F"], capture_output=True)
                else:
                    SPAWNED_PROCESS.kill()
            except Exception:
                pass
        if CURRENT_JOB:
            CURRENT_JOB["status"] = "CANCELLED"
        self._send_json(200, {"status": "CANCELLED", "message": "Execution terminated."})

    def _collect_telemetry_payload(self) -> None:
        """Gathers available process, network, and event log observations."""
        global CURRENT_JOB, SPAWNED_PROCESS

        processes: List[Dict[str, Any]] = []
        network: List[Dict[str, Any]] = []

        if CURRENT_JOB and "pid" in CURRENT_JOB:
            processes.append({
                "pid": CURRENT_JOB["pid"],
                "name": CURRENT_JOB.get("filename", "sample.exe"),
                "command_line": CURRENT_JOB.get("staged_path"),
                "start_time": CURRENT_JOB.get("started_at"),
                "status": "RUNNING" if (SPAWNED_PROCESS and SPAWNED_PROCESS.poll() is None) else "TERMINATED",
                "exit_code": SPAWNED_PROCESS.poll() if SPAWNED_PROCESS else None,
            })

        # Netstat snapshot
        try:
            net_res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
            if net_res.returncode == 0:
                for line in net_res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                        network.append({
                            "protocol": parts[0],
                            "local_address": parts[1],
                            "remote_address": parts[2],
                            "state": parts[3] if len(parts) > 4 else "UNKNOWN",
                            "pid": parts[-1] if len(parts) >= 5 else None,
                        })
        except Exception:
            pass

        self._send_json(200, {
            "job_id": CURRENT_JOB.get("job_id") if CURRENT_JOB else None,
            "sha256": CURRENT_JOB.get("sha256") if CURRENT_JOB else None,
            "processes": processes,
            "network": network,
            "collected_at": time.time(),
        })


def run_agent() -> None:
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    server_address = (AGENT_HOST, AGENT_PORT)
    httpd = HTTPServer(server_address, REMWinAgentHandler)
    print(f"[*] Malbox REMWin Execution Agent listening on {AGENT_HOST}:{AGENT_PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Agent shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    run_agent()
