"""Network monitoring using dumpcap/TShark, Sysmon (EID 3 & 22), and psutil."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

import psutil

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    CollectorResult,
    resolve_tool_path,
    run_subprocess_safe,
    timestamp_from_epoch,
    utc_now_iso,
    write_json,
)


def _safe_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


class NetworkMonitor:
    """Captures PCAPNG traffic and correlates connections + DNS queries without external probes."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.tools_cfg = config.get("tools", {})
        self.result = CollectorResult(name="network_monitor")

        self.dumpcap_bin = resolve_tool_path(
            self.tools_cfg.get("dumpcap"),
            self.base_dir,
            ["dumpcap.exe", "dumpcap"],
        )
        self.tshark_bin = resolve_tool_path(
            self.tools_cfg.get("tshark"),
            self.base_dir,
            ["tshark.exe", "tshark"],
        )
        self.capture_proc: subprocess.Popen[str] | None = None
        self.pcap_path: Path | None = None
        self.psutil_connections: list[dict[str, Any]] = []
        self.seen_psutil_keys: set[tuple[Any, ...]] = set()

    def _detect_interface(self) -> str | None:
        configured = str(self.config.get("network_interface") or "").strip()
        if configured:
            return configured

        if not self.dumpcap_bin:
            return None

        res = run_subprocess_safe([str(self.dumpcap_bin), "-D"], timeout=10.0)
        if res["returncode"] != 0:
            return None

        lines = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
        preferred: str | None = None
        fallback: str | None = None
        for line in lines:
            # Format: "1. \Device\NPF_{...} (Ethernet)"
            idx = line.split(".", 1)[0].strip()
            lower = line.lower()
            if fallback is None and idx.isdigit():
                fallback = idx
            if "loopback" in lower or "npcap loopback" in lower:
                continue
            if any(token in lower for token in ("ethernet", "eth", "ens", "enp", "intel", "vmware", "virtualbox")):
                preferred = idx
                break
        return preferred or fallback

    def start(self, evidence_dir: Path) -> None:
        """Start passive packet capture before the sample runs."""
        net_dir = evidence_dir / "dynamic" / "network"
        net_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_path = net_dir / "capture.pcapng"

        if not self.dumpcap_bin:
            self.result.limitations.append(
                "Wireshark dumpcap executable not found; PCAPNG capture unavailable."
            )
            return

        iface = self._detect_interface()
        if not iface:
            self.result.limitations.append("Could not detect capture network interface for dumpcap.")
            return

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            self.capture_proc = subprocess.Popen(
                [str(self.dumpcap_bin), "-i", iface, "-q", "-w", str(self.pcap_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                creationflags=creationflags,
            )
            self.result.tool_versions["dumpcap"] = str(self.dumpcap_bin)
        except OSError as exc:
            self.result.errors.append(f"Failed to start dumpcap: {exc}")
            self.capture_proc = None

    def poll_once(self, tracked_pids: set[int]) -> None:
        """Sample Windows native socket connections belonging to tracked sample PIDs."""
        if not tracked_pids:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.Error:
            return

        now_iso = utc_now_iso()
        for conn in conns:
            if conn.pid not in tracked_pids:
                continue
            laddr_ip = conn.laddr.ip if conn.laddr else None
            laddr_port = conn.laddr.port if conn.laddr else None
            raddr_ip = conn.raddr.ip if conn.raddr else None
            raddr_port = conn.raddr.port if conn.raddr else None
            proto = "TCP" if conn.type == 1 else ("UDP" if conn.type == 2 else str(conn.type))
            key = (conn.pid, proto, laddr_ip, laddr_port, raddr_ip, raddr_port, conn.status)
            if key in self.seen_psutil_keys:
                continue
            self.seen_psutil_keys.add(key)

            proc_name = ""
            try:
                proc_name = psutil.Process(conn.pid).name()
            except psutil.Error:
                pass

            self.psutil_connections.append(
                {
                    "timestamp": now_iso,
                    "source": "psutil",
                    "pid": conn.pid,
                    "process_name": proc_name,
                    "protocol": proto,
                    "src_ip": laddr_ip,
                    "src_port": laddr_port,
                    "dst_ip": raddr_ip,
                    "dst_port": raddr_port,
                    "status": conn.status,
                }
            )

    def stop(self) -> None:
        """Stop dumpcap cleanly so the PCAPNG footer and blocks are flushed."""
        if not self.capture_proc:
            return
        try:
            self.capture_proc.terminate()
            self.capture_proc.wait(timeout=8.0)
        except subprocess.TimeoutExpired:
            self.capture_proc.kill()
            self.capture_proc.wait(timeout=3.0)
        except OSError as exc:
            self.result.errors.append(f"Error stopping dumpcap: {exc}")

    def finalize(
        self,
        evidence_dir: Path,
        sysmon_events: list[dict[str, Any]],
        tracked_pids: set[int],
    ) -> CollectorResult:
        """Parse PCAPNG with TShark and correlate with Sysmon EID 3/22 and psutil connections."""
        net_dir = evidence_dir / "dynamic" / "network"
        net_dir.mkdir(parents=True, exist_ok=True)

        connections: list[dict[str, Any]] = list(self.psutil_connections)
        dns_queries: list[dict[str, Any]] = []

        if self.pcap_path and self.pcap_path.is_file() and self.pcap_path.stat().st_size > 0:
            self.result.artifacts.append("dynamic/network/capture.pcapng")
            if self.tshark_bin:
                self.result.tool_versions["tshark"] = str(self.tshark_bin)
                self._parse_pcap_with_tshark(self.pcap_path, connections, dns_queries)
            else:
                self.result.limitations.append(
                    "TShark executable not found; raw PCAPNG saved without offline TShark packet summary."
                )
        else:
            self.result.limitations.append("No PCAPNG capture file was produced.")

        # Merge Sysmon NetworkConnect (EID 3) and DNSQuery (EID 22) for tracked PIDs.
        for ev in sysmon_events:
            eid = ev.get("event_id")
            data = ev.get("data", {})
            pid = _safe_int(data.get("ProcessId"))
            if pid not in tracked_pids:
                continue

            if eid == 3:
                connections.append(
                    {
                        "timestamp": ev.get("time_created") or data.get("UtcTime") or "",
                        "source": "sysmon_eid3",
                        "pid": pid,
                        "process_name": os.path.basename(data.get("Image", "")),
                        "protocol": (data.get("Protocol") or "").upper(),
                        "src_ip": data.get("SourceIp"),
                        "src_port": _safe_int(data.get("SourcePort")),
                        "dst_ip": data.get("DestinationIp"),
                        "dst_port": _safe_int(data.get("DestinationPort")),
                        "dst_hostname": data.get("DestinationHostname"),
                        "initiated": data.get("Initiated"),
                    }
                )
            elif eid == 22:
                dns_queries.append(
                    {
                        "timestamp": ev.get("time_created") or data.get("UtcTime") or "",
                        "source": "sysmon_eid22",
                        "pid": pid,
                        "process_name": os.path.basename(data.get("Image", "")),
                        "query_name": data.get("QueryName"),
                        "query_status": data.get("QueryStatus"),
                        "query_results": data.get("QueryResults"),
                    }
                )

        connections.sort(key=lambda item: str(item.get("timestamp") or ""))
        dns_queries.sort(key=lambda item: str(item.get("timestamp") or ""))

        write_json(
            net_dir / "connections.json",
            {"connection_count": len(connections), "connections": connections[:5000]},
        )
        write_json(
            net_dir / "dns.json",
            {"dns_query_count": len(dns_queries), "queries": dns_queries[:5000]},
        )
        self.result.artifacts.extend(["dynamic/network/connections.json", "dynamic/network/dns.json"])
        self.result.summary = {
            "connection_event_count": len(connections),
            "dns_query_count": len(dns_queries),
            "has_pcapng": bool(self.pcap_path and self.pcap_path.is_file()),
        }

        if not self.dumpcap_bin and not sysmon_events and not self.psutil_connections:
            return self.result.finish(STATUS_UNAVAILABLE)
        if self.result.limitations or self.result.errors:
            return self.result.finish(STATUS_PARTIAL)
        return self.result.finish(STATUS_COMPLETED)

    def _parse_pcap_with_tshark(
        self,
        pcap_path: Path,
        connections: list[dict[str, Any]],
        dns_queries: list[dict[str, Any]],
    ) -> None:
        conn_cmd = [
            str(self.tshark_bin),
            "-r",
            str(pcap_path),
            "-Y",
            "tcp || udp",
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-c",
            "3000",
        ]
        res = run_subprocess_safe(conn_cmd, timeout=60.0)
        if res["returncode"] == 0:
            for line in res["stdout"].splitlines():
                parts = line.split("\t")
                if len(parts) < 8:
                    continue
                epoch_str, src_ip, dst_ip, tcp_sp, tcp_dp, udp_sp, udp_dp, proto = parts[:8]
                if not src_ip and not dst_ip:
                    continue
                ts = ""
                try:
                    ts = timestamp_from_epoch(float(epoch_str))
                except ValueError:
                    ts = epoch_str
                connections.append(
                    {
                        "timestamp": ts,
                        "source": "tshark_pcap",
                        "pid": None,
                        "process_name": None,
                        "protocol": proto or ("TCP" if tcp_sp else "UDP"),
                        "src_ip": src_ip or None,
                        "src_port": _safe_int(tcp_sp or udp_sp),
                        "dst_ip": dst_ip or None,
                        "dst_port": _safe_int(tcp_dp or udp_dp),
                    }
                )
        else:
            self.result.limitations.append(f"TShark packet parsing failed: {res['stderr'].strip()}")

        dns_cmd = [
            str(self.tshark_bin),
            "-r",
            str(pcap_path),
            "-Y",
            "dns",
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.qry.type",
            "-e",
            "dns.a",
            "-c",
            "2000",
        ]
        dns_res = run_subprocess_safe(dns_cmd, timeout=45.0)
        if dns_res["returncode"] == 0:
            for line in dns_res["stdout"].splitlines():
                parts = line.split("\t")
                if len(parts) < 5:
                    continue
                epoch_str, src_ip, qname, qtype, ans_a = parts[:5]
                if not qname:
                    continue
                ts = ""
                try:
                    ts = timestamp_from_epoch(float(epoch_str))
                except ValueError:
                    ts = epoch_str
                dns_queries.append(
                    {
                        "timestamp": ts,
                        "source": "tshark_dns",
                        "src_ip": src_ip,
                        "query_name": qname,
                        "query_type": qtype,
                        "answers": ans_a,
                    }
                )
