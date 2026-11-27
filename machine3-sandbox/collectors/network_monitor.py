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
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    resolve_tool_path,
    run_subprocess_safe,
    timestamp_from_epoch,
    utc_now_iso,
    write_json,
)


BACKGROUND_MULTICAST_ENDPOINTS = {
    ("239.255.255.250", 1900),   # SSDP
    ("239.255.255.250", 3702),   # WS-Discovery
    ("224.0.0.251", 5353),       # mDNS IPv4
    ("ff02::fb", 5353),          # mDNS IPv6
    ("224.0.0.252", 5355),       # LLMNR IPv4
    ("ff02::1:3", 5355),         # LLMNR IPv6
}
BACKGROUND_PORTS = {67, 68, 123, 137, 138, 546, 547, 1900, 3702, 5353, 5355}
CLASS_CATEGORIES = (
    "sample_related_traffic",
    "control_traffic",
    "background_traffic",
    "unattributed_traffic",
)


def _safe_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _is_loopback_ip(ip_val: str | None) -> bool:
    if not ip_val:
        return False
    return ip_val == "::1" or ip_val.startswith("127.")


def classify_connections(
    connections: list[dict[str, Any]],
    tracked_pids: set[int],
    sandbox_pid: int,
    control_port: int,
) -> dict[str, int]:
    """Classify collected connections without deleting evidence or hard-banning peer IPs."""
    sample_tuples: set[tuple[str, str, int | None, str, int | None]] = set()
    for conn in connections:
        pid = _safe_int(conn.get("pid"))
        if pid is not None and pid in tracked_pids:
            proto = str(conn.get("protocol") or "").upper()
            sip = str(conn.get("src_ip") or "")
            sp = _safe_int(conn.get("src_port"))
            dip = str(conn.get("dst_ip") or "")
            dp = _safe_int(conn.get("dst_port"))
            sample_tuples.add((proto, sip, sp, dip, dp))
            sample_tuples.add((proto, dip, dp, sip, sp))

    counts = {cat: 0 for cat in CLASS_CATEGORIES}
    for conn in connections:
        pid = _safe_int(conn.get("pid"))
        proto = str(conn.get("protocol") or "").upper()
        sip = str(conn.get("src_ip") or "")
        sp = _safe_int(conn.get("src_port"))
        dip = str(conn.get("dst_ip") or "")
        dp = _safe_int(conn.get("dst_port"))

        if pid is not None and pid in tracked_pids:
            cat = "sample_related_traffic"
            conf = "high"
            reason = f"Socket attributed directly to tracked PID {pid}."
        elif pid is not None and pid == sandbox_pid:
            cat = "control_traffic"
            conf = "high"
            reason = "Socket owned by MalBox Sandbox service PID."
        elif pid is None and (sp == control_port or dp == control_port):
            cat = "control_traffic"
            conf = "medium"
            reason = f"Packet matches MalBox Sandbox HTTP control port {control_port}."
        elif pid is None and (proto, sip, sp, dip, dp) in sample_tuples:
            cat = "sample_related_traffic"
            conf = "medium"
            reason = "Packet 4-tuple correlates with tracked sample PID socket."
        elif (
            (dip, dp) in BACKGROUND_MULTICAST_ENDPOINTS
            or (sip, sp) in BACKGROUND_MULTICAST_ENDPOINTS
            or (pid is None and ((sp in BACKGROUND_PORTS) or (dp in BACKGROUND_PORTS)))
            or (pid is None and _is_loopback_ip(sip) and _is_loopback_ip(dip))
            or dip.startswith(("224.", "239.", "ff02:", "ff05:"))
            or dip == "255.255.255.255"
        ):
            cat = "background_traffic"
            conf = "medium"
            reason = "Matches Windows discovery/multicast/broadcast/loopback background traffic without tracked PID."
        else:
            cat = "unattributed_traffic"
            conf = "unattributed"
            reason = "Observed connection without tracked sample PID attribution."

        conn["classification"] = cat
        conn["attribution_confidence"] = conf
        conn["attribution_reason"] = reason
        counts[cat] += 1
    return counts


def classify_dns_queries(
    dns_queries: list[dict[str, Any]],
    tracked_pids: set[int],
    sandbox_pid: int,
) -> dict[str, int]:
    """Classify DNS queries conservatively into sample_related, background, or unattributed."""
    tracked_names = {
        str(q.get("query_name") or "").strip().lower().rstrip(".")
        for q in dns_queries
        if _safe_int(q.get("pid")) in tracked_pids and q.get("query_name")
    }
    counts = {cat: 0 for cat in CLASS_CATEGORIES}
    for q in dns_queries:
        pid = _safe_int(q.get("pid"))
        qname = str(q.get("query_name") or "").strip().lower().rstrip(".")
        if pid is not None and pid in tracked_pids:
            cat = "sample_related_traffic"
            conf = "high"
            reason = f"DNS query attributed directly to tracked PID {pid}."
        elif pid is not None and pid == sandbox_pid:
            cat = "control_traffic"
            conf = "high"
            reason = "DNS query originated from Sandbox host process."
        elif pid is None and qname and qname in tracked_names:
            cat = "sample_related_traffic"
            conf = "medium"
            reason = "PCAP DNS query matches domain queried by tracked sample PID."
        elif (
            not qname
            or qname.endswith((".in-addr.arpa", ".ip6.arpa", ".local"))
            or qname in ("wpad", "localhost")
            or qname.startswith("wpad.")
        ):
            cat = "background_traffic"
            conf = "medium"
            reason = "Matches OS background name resolution pattern without tracked PID."
        else:
            cat = "unattributed_traffic"
            conf = "unattributed"
            reason = "PCAP DNS query without Sysmon PID attribution."

        q["classification"] = cat
        q["attribution_confidence"] = conf
        q["attribution_reason"] = reason
        counts[cat] += 1
    return counts


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
            if self.capture_proc.poll() is None:
                self.capture_proc.terminate()
                self.capture_proc.wait(timeout=8.0)
        except subprocess.TimeoutExpired:
            self.capture_proc.kill()
            self.capture_proc.wait(timeout=3.0)
        except OSError as exc:
            self.result.errors.append(f"Error stopping dumpcap: {exc}")
        finally:
            self.capture_proc = None

    def finalize(
        self,
        evidence_dir: Path,
        sysmon_events: list[dict[str, Any]],
        tracked_pids: set[int],
        sysmon_available: bool = False,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> CollectorResult:
        """Parse PCAPNG with TShark and correlate with Sysmon EID 3/22 and psutil connections."""
        net_dir = evidence_dir / "dynamic" / "network"
        net_dir.mkdir(parents=True, exist_ok=True)

        if skipped:
            reason = skip_reason or "Dynamic sample execution did not run."
            write_json(net_dir / "connections.json", {"collected": False, "connection_count": 0, "connections": [], "not_collected_reason": reason})
            write_json(net_dir / "dns.json", {"collected": False, "dns_query_count": 0, "queries": [], "not_collected_reason": reason})
            self.result.artifacts.extend(["dynamic/network/connections.json", "dynamic/network/dns.json"])
            self.result.limitations.append(reason)
            self.result.summary = {"collected": False, "has_pcapng": False}
            return self.result.finish(STATUS_SKIPPED)

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

        sandbox_pid = os.getpid()
        control_port = int(self.config.get("listen_port", 8001))
        conn_counts = classify_connections(
            connections=connections,
            tracked_pids=tracked_pids,
            sandbox_pid=sandbox_pid,
            control_port=control_port,
        )
        dns_counts = classify_dns_queries(
            dns_queries=dns_queries,
            tracked_pids=tracked_pids,
            sandbox_pid=sandbox_pid,
        )

        # Keep sample_related and unattributed entries prioritized if total exceeds cap
        def _cap_prioritized(items: list[dict[str, Any]], cap: int = 5000) -> list[dict[str, Any]]:
            if len(items) <= cap:
                return items
            prio = [x for x in items if x.get("classification") in ("sample_related_traffic", "unattributed_traffic")]
            rest = [x for x in items if x.get("classification") not in ("sample_related_traffic", "unattributed_traffic")]
            if len(prio) >= cap:
                return prio[:cap]
            kept = prio + rest[: cap - len(prio)]
            kept.sort(key=lambda item: str(item.get("timestamp") or ""))
            return kept

        stored_conns = _cap_prioritized(connections, 5000)
        stored_dns = _cap_prioritized(dns_queries, 5000)

        write_json(
            net_dir / "connections.json",
            {
                "collected": True,
                "connection_count": len(connections),
                "stored_connection_count": len(stored_conns),
                "classification_summary": conn_counts,
                "connections": stored_conns,
            },
        )
        write_json(
            net_dir / "dns.json",
            {
                "collected": True,
                "dns_query_count": len(dns_queries),
                "stored_dns_query_count": len(stored_dns),
                "classification_summary": dns_counts,
                "queries": stored_dns,
            },
        )
        self.result.artifacts.extend(["dynamic/network/connections.json", "dynamic/network/dns.json"])
        has_pcapng = bool(self.pcap_path and self.pcap_path.is_file() and self.pcap_path.stat().st_size > 0)
        self.result.summary = {
            "collected": True,
            "connection_event_count": len(connections),
            "sample_related_connection_count": conn_counts["sample_related_traffic"],
            "control_traffic_connection_count": conn_counts["control_traffic"],
            "background_traffic_connection_count": conn_counts["background_traffic"],
            "unattributed_connection_count": conn_counts["unattributed_traffic"],
            "dns_query_count": len(dns_queries),
            "sample_related_dns_count": dns_counts["sample_related_traffic"],
            "has_pcapng": has_pcapng,
            "sysmon_available": sysmon_available,
        }

        if not has_pcapng and not sysmon_available and not self.psutil_connections:
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
