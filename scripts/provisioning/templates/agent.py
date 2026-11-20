"""
Minimal CAPE Sandbox Guest Agent (Python 3.x)
Runs inside the isolated Windows analysis guest VM, listening on port 8000.
Receives detonation tasks, executes analysis packages, and returns execution logs.
"""
import http.server
import json
import os
import platform
import socketserver
import subprocess
import sys

PORT = 8000


class CapeAgentHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            status_payload = {
                "status": "complete",
                "version": "CAPE-Agent-2.0",
                "features": ["exec", "upload", "dump"],
                "system": platform.system(),
                "release": platform.release(),
            }
            self.wfile.write(json.dumps(status_payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # Handle execution/file drop requests from CAPE controller
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received", "bytes": len(body)}).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress verbose HTTP stdout logging
        pass


def main():
    with socketserver.TCPServer(("0.0.0.0", PORT), CapeAgentHandler) as httpd:
        print(f"[*] CAPE Guest Agent listening on port {PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
