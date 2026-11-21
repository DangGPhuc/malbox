from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional


class PCAPCollector:
    """Manages packet capture on the isolated internal network interface."""

    def __init__(self, interface: str = "eth1", output_path: Optional[Path] = None):
        self.interface = interface
        self.output_path = output_path
        self.process: Optional[subprocess.Popen] = None

    def start(self, output_path: Path) -> bool:
        self.output_path = output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        tool = shutil.which("dumpcap") or shutil.which("tcpdump")
        if not tool:
            # Tool not found; write empty marker pcap or note
            output_path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
            return False

        cmd = [tool, "-i", self.interface, "-w", str(output_path), "-q"]
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            return (self.process.poll() is None)
        except Exception:
            # Fallback to minimal valid pcap header
            output_path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
            return False

    def stop(self) -> bool:
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        # Ensure file exists
        if self.output_path and not self.output_path.exists():
            self.output_path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
        return True
