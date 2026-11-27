#!/usr/bin/env python3
"""Read-only, conservative INetSim diagnostic inspector & session log parser for Machine 2.

Safety & isolation rules:
- Never starts, restarts, configures, or exposes INetSim services.
- Never modifies system firewall, Netplan, or network routing settings.
- Strips query parameter values, Authorization headers, cookies, and POST bodies.
- Separates Machine 2 diagnostic artifacts cleanly without mutating Machine 3's evidence ZIP.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# INetSim standard line timestamp prefix: [YYYY-MM-DD HH:MM:SS]
INETSIM_TS_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s*(.*)$")
SRC_IP_RE = re.compile(r"(?:\bfrom\s+|\[)(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::\d+|\])?", re.IGNORECASE)
DNS_TYPE_RE = re.compile(r"(?:Query\s+Type\s+|\bType\s*[:=]\s*|\b)(?P<type>AAAA|CNAME|PTR|SOA|TXT|MX|NS|ANY|A)\b", re.IGNORECASE)
DNS_NAME_RE = re.compile(r"(?:\bName\s*[:=]?\s*|\b(?:AAAA|CNAME|PTR|SOA|TXT|MX|NS|ANY|A)\s+)(?P<qname>[A-Za-z0-9_.-]+\.[A-Za-z0-9_-]{1,63}|localhost)\b", re.IGNORECASE)
HTTP_REQ_RE = re.compile(
    r"\b(?P<method>GET|HEAD|POST|PUT|OPTIONS|DELETE)\s+(?P<target>\S+)",
    re.IGNORECASE,
)
STATUS_CODE_RE = re.compile(r"\b(?:status|code|resp(?:onse)?)\s*[:=]?\s*(\d{3})\b", re.IGNORECASE)


def _run_readonly(cmd: list[str], timeout: float = 5.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "error": None,
        }
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"returncode": -1, "stdout": "", "stderr": "", "error": str(exc)}


def _parse_ts_utc(raw_ts: str) -> datetime | None:
    text = raw_ts.strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _sanitize_http_path(raw_target: str) -> str:
    """Preserve path while stripping query values/credentials/fragments completely."""
    cleaned = raw_target.strip()
    if "://" in cleaned:
        _, rest = cleaned.split("://", 1)
        if "@" in rest.split("/", 1)[0]:
            rest = rest.split("@", 1)[1]
        cleaned = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    if "?" in cleaned:
        cleaned = cleaned.split("?", 1)[0] + "?<query_stripped>"
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0]
    return cleaned[:240]


def inspect_inetsim_environment(config: dict[str, Any]) -> dict[str, Any]:
    """Perform read-only inspection of INetSim binary, version, service state, config, and logs."""
    cfg_bin = str(config.get("inetsim_binary") or "/usr/bin/inetsim").strip()
    cfg_conf = Path(str(config.get("inetsim_conf_path") or "/etc/inetsim/inetsim.conf"))
    cfg_log_dir = Path(str(config.get("inetsim_log_dir") or "/var/log/inetsim"))

    bin_path: Path | None = None
    for cand in (Path(cfg_bin), Path("/usr/bin/inetsim"), Path("/usr/local/bin/inetsim")):
        if cand.is_file():
            bin_path = cand
            break
    if bin_path is None:
        which_bin = shutil.which("inetsim")
        if which_bin:
            bin_path = Path(which_bin)

    version: str | None = None
    if bin_path and os.access(bin_path, os.X_OK):
        vres = _run_readonly([str(bin_path), "--version"], timeout=5.0)
        out = (vres["stdout"] or vres["stderr"] or "").splitlines()
        if vres["returncode"] == 0 and out:
            version = out[0][:120]

    # Service status check (strictly non-modifying)
    service_state = "not_checked"
    systemctl = shutil.which("systemctl")
    if systemctl:
        sres = _run_readonly([systemctl, "is-active", "inetsim"], timeout=5.0)
        state_txt = (sres["stdout"] or sres["stderr"]).strip().lower()
        if sres["returncode"] == 0 and state_txt == "active":
            service_state = "active"
        elif state_txt in ("inactive", "dead", "failed", "activating", "deactivating"):
            service_state = state_txt
        else:
            service_state = state_txt or "unknown"
    else:
        service_state = "systemctl_unavailable"

    # Config visibility (non-sensitive selected keys only)
    conf_info: dict[str, Any] = {
        "path": str(cfg_conf),
        "exists": cfg_conf.is_file(),
        "readable": False,
        "selected_settings": {},
    }
    interesting_keys = {
        "service_bind_address",
        "dns_bind_port",
        "dns_default_ip",
        "http_bind_port",
        "https_bind_port",
        "start_service",
    }
    if cfg_conf.is_file():
        try:
            text = cfg_conf.read_text(encoding="utf-8", errors="replace")
            conf_info["readable"] = True
            enabled_services: list[str] = []
            for raw_line in text.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                k, v = parts[0].strip(), parts[1].strip()
                if k == "start_service":
                    enabled_services.append(v)
                elif k in interesting_keys:
                    conf_info["selected_settings"][k] = v
            if enabled_services:
                conf_info["selected_settings"]["start_services"] = enabled_services
        except OSError as exc:
            conf_info["read_error"] = str(exc)

    # Log directory visibility
    log_info: dict[str, Any] = {
        "path": str(cfg_log_dir),
        "exists": cfg_log_dir.is_dir(),
        "readable": False,
        "files": [],
    }
    if cfg_log_dir.is_dir():
        try:
            files = []
            for entry in sorted(cfg_log_dir.iterdir()):
                if entry.is_file() and entry.name in ("service.log", "debug.log") or entry.name.startswith("report"):
                    readable = os.access(entry, os.R_OK)
                    files.append(
                        {
                            "name": entry.name,
                            "readable": readable,
                            "size_bytes": entry.stat().st_size if readable else None,
                        }
                    )
            log_info["readable"] = True
            log_info["files"] = files[:20]
        except OSError as exc:
            log_info["read_error"] = str(exc)

    return {
        "installed": bin_path is not None,
        "binary_path": str(bin_path) if bin_path else None,
        "version": version,
        "service_state": service_state,
        "config": conf_info,
        "logs": log_info,
        "limitations": [
            "Operator-managed local simulator diagnostics only; presence of INetSim never configures networking or implies full Internet fidelity."
        ],
    }


def _read_bounded_tail(path: Path, max_bytes: int) -> tuple[list[str], bool]:
    """Read up to max_bytes from the end of a text log safely."""
    size = path.stat().st_size
    truncated = size > max_bytes
    with path.open("rb") as fh:
        if truncated:
            fh.seek(size - max_bytes)
        raw = fh.read(max_bytes)
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if truncated and lines:
        # Drop partial first line after seek
        lines = lines[1:]
    return lines, truncated


def _safe_bounded_int(
    config: dict[str, Any],
    key: str,
    default: int,
    min_val: int,
    max_val: int,
) -> int:
    raw = config.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int):
        return default
    return max(min_val, min(raw, max_val))


def collect_session_inetsim_evidence(
    job_id: str,
    session_start_utc: datetime,
    session_end_utc: datetime,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Import strictly session-scoped, sanitized INetSim diagnostic events on Machine 2."""
    raw_log_dir = config.get("inetsim_log_dir")
    log_dir = Path(str(raw_log_dir)) if isinstance(raw_log_dir, str) and raw_log_dir.strip() else Path("/var/log/inetsim")
    service_log = log_dir / "service.log"
    max_mb = _safe_bounded_int(config, "max_inetsim_log_mb", 5, min_val=1, max_val=64)
    max_bytes = max_mb * 1024 * 1024
    max_events = _safe_bounded_int(config, "max_inetsim_events", 1000, min_val=10, max_val=10000)

    try:
        env_meta = inspect_inetsim_environment(config)
    except Exception as exc:
        env_meta = {"installed": False, "error": str(exc)}
    dns_events: list[dict[str, Any]] = []
    http_events: list[dict[str, Any]] = []
    other_lines_in_window = 0
    truncated = False
    log_status = "collected"
    note = ""

    if not log_dir.is_dir():
        log_status = "unavailable"
        note = f"INetSim log directory missing: {log_dir}"
    elif not service_log.is_file():
        log_status = "unavailable"
        note = f"INetSim service.log not found at {service_log}"
    elif not os.access(service_log, os.R_OK):
        log_status = "permission_denied"
        note = f"Current user lacks read permission for {service_log}"
    else:
        try:
            lines, truncated = _read_bounded_tail(service_log, max_bytes=max_bytes)
            for line in lines:
                m_ts = INETSIM_TS_RE.match(line)
                if not m_ts:
                    continue
                orig_ts_str, rest = m_ts.group(1), m_ts.group(2)
                parsed_dt = _parse_ts_utc(orig_ts_str)
                if parsed_dt is None:
                    continue
                if parsed_dt < session_start_utc or parsed_dt > session_end_utc:
                    continue

                src_match = SRC_IP_RE.search(rest)
                src_ip = src_match.group("src") if src_match else None
                rest_lower = rest.lower()
                is_dns_line = "dns" in rest_lower and ("query" in rest_lower or "recv:" in rest_lower)
                is_http_line = "http" in rest_lower and ("recv:" in rest_lower or "request" in rest_lower or HTTP_REQ_RE.search(rest) is not None)

                if is_dns_line and (m_qname := DNS_NAME_RE.search(rest)) is not None:
                    if len(dns_events) < max_events:
                        m_type = DNS_TYPE_RE.search(rest)
                        dns_events.append(
                            {
                                "original_timestamp": orig_ts_str,
                                "timestamp_utc": parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "source_machine": "machine2-gateway",
                                "source_component": "inetsim_service_log",
                                "protocol": "DNS",
                                "src_ip": src_ip,
                                "query_type": (m_type.group("type") if m_type else "UNKNOWN").upper(),
                                "query_name": m_qname.group("qname"),
                            }
                        )
                elif is_http_line and (m_http := HTTP_REQ_RE.search(rest)) is not None:
                    if len(http_events) < max_events:
                        m_st = STATUS_CODE_RE.search(rest)
                        http_events.append(
                            {
                                "original_timestamp": orig_ts_str,
                                "timestamp_utc": parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "source_machine": "machine2-gateway",
                                "source_component": "inetsim_service_log",
                                "protocol": "HTTP",
                                "src_ip": src_ip,
                                "method": m_http.group("method").upper(),
                                "sanitized_target": _sanitize_http_path(m_http.group("target")),
                                "status_code": int(m_st.group(1)) if m_st else None,
                            }
                        )
                else:
                    other_lines_in_window += 1
        except (OSError, ValueError, RuntimeError) as exc:
            log_status = "read_error"
            note = f"Failed reading {service_log}: {exc}"

    return {
        "schema_version": "1.0",
        "job_id": job_id,
        "source_machine": "machine2-gateway",
        "source_component": "inetsim_diagnostics",
        "separate_from_sandbox_zip": True,
        "sandbox_archive_integrity_preserved": True,
        "session_window_utc": {
            "start": session_start_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": session_end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "sanitization_policy": {
            "credentials_collected": False,
            "request_bodies_collected": False,
            "query_parameters_stripped": True,
            "log_tail_truncated": truncated,
            "max_events_per_protocol": max_events,
        },
        "inetsim_status": env_meta,
        "log_import_status": log_status,
        "log_import_note": note or None,
        "dns_event_count": len(dns_events),
        "http_event_count": len(http_events),
        "other_inetsim_log_lines_in_window": other_lines_in_window,
        "dns_events": dns_events,
        "http_events": http_events,
        "limitations": [
            "Diagnostic artifact generated strictly on Machine 2 for operator-managed isolated tests.",
            "INetSim simulated DNS/HTTP logs do not reproduce full real-world external network behavior.",
            "Kept outside Machine 3 evidence_<job_id>.zip so original X-Archive-SHA256 checksums remain intact.",
        ],
    }
