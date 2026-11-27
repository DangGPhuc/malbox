"""Windows Event Log collector (Sysmon, System, Application, Security, PowerShell, Defender)."""

from __future__ import annotations

import hashlib
import logging
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    run_subprocess_safe,
    write_json,
)

EVENT_CHANNELS = [
    ("sysmon", "Microsoft-Windows-Sysmon/Operational", "sysmon.evtx"),
    ("system", "System", "system.evtx"),
    ("application", "Application", "application.evtx"),
    ("security", "Security", "security.evtx"),
    ("powershell", "Microsoft-Windows-PowerShell/Operational", "powershell.evtx"),
    ("defender", "Microsoft-Windows-Windows Defender/Operational", "defender.evtx"),
]

_EVTX_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$"
)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def normalize_event_timestamp(raw_ts: str | None) -> str | None:
    """Normalize EVTX timestamps to canonical UTC ISO-8601 while preserving valid inputs."""
    if not raw_ts:
        return None
    text = str(raw_ts).strip()
    m = _EVTX_TS_RE.match(text)
    if not m:
        return text
    date_part, time_part, frac_part, tz_part = m.groups()
    frac_norm = (frac_part or "")[:6].ljust(6, "0")
    tz_norm = "+00:00"
    if tz_part and tz_part != "Z":
        tz_clean = tz_part if ":" in tz_part else f"{tz_part[:3]}:{tz_part[3:]}"
        tz_norm = tz_clean
    try:
        dt = datetime.fromisoformat(f"{date_part}T{time_part}.{frac_norm}{tz_norm}")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return text


def inspect_sysmon_config_provenance(base_dir: Path) -> dict[str, Any]:
    """Read local Sysmon XML configuration provenance metadata without modifying host config."""
    cfg_path = base_dir / "configs" / "sysmon.xml"
    if not cfg_path.is_file():
        return {"config_file": "configs/sysmon.xml", "present": False}
    try:
        raw_bytes = cfg_path.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        root = ET.fromstring(raw_bytes.decode("utf-8-sig", errors="replace"))
        schema_ver = root.attrib.get("schemaversion")
        hash_algos = None
        for child in root:
            if _strip_ns(child.tag) == "HashAlgorithms" and child.text:
                hash_algos = child.text.strip()
                break
        return {
            "config_file": "configs/sysmon.xml",
            "present": True,
            "sha256": sha256,
            "schemaversion": schema_ver,
            "hash_algorithms": hash_algos,
            "note": "Provenance of sandbox Sysmon configuration template; live host driver schema depends on installed Sysmon service.",
        }
    except (OSError, ET.ParseError) as exc:
        return {"config_file": "configs/sysmon.xml", "present": True, "parse_error": str(exc)}


def _classify_wevtutil_failure(err_msg: str) -> str:
    low = err_msg.lower()
    if "access is denied" in low or "privilege" in low or "unauthorized" in low:
        return "access_denied"
    if "could not be found" in low or "specified channel could not be found" in low or "15007" in low:
        return "channel_not_found"
    return "export_error"


def parse_evtx_xml_detailed(evtx_path: Path, max_records: int = 10000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse and deduplicate an exported .evtx file with explicit truncation and count metadata."""
    meta: dict[str, Any] = {
        "raw_record_count": 0,
        "deduplicated_record_count": 0,
        "duplicate_records_skipped": 0,
        "parse_errors_skipped": 0,
        "truncated": False,
        "max_records_limit": max_records,
        "error": None,
    }
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except ImportError as exc:
        meta["error"] = f"python-evtx not installed: {exc}"
        return [], meta

    records: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()
    try:
        with evtx.Evtx(str(evtx_path)) as log:
            for record in log.records():
                meta["raw_record_count"] += 1
                try:
                    root = ET.fromstring(record.xml())
                except ET.ParseError:
                    meta["parse_errors_skipped"] += 1
                    continue

                system_el = None
                event_data_el = None
                for child in root:
                    name = _strip_ns(child.tag)
                    if name == "System":
                        system_el = child
                    elif name == "EventData":
                        event_data_el = child

                event_id = None
                event_record_id = None
                time_created_raw = None
                provider_name = None
                channel_name = None
                if system_el is not None:
                    for sub in system_el:
                        sname = _strip_ns(sub.tag)
                        if sname == "EventID" and sub.text:
                            try:
                                event_id = int(sub.text)
                            except ValueError:
                                event_id = sub.text
                        elif sname == "EventRecordID" and sub.text:
                            try:
                                event_record_id = int(sub.text)
                            except ValueError:
                                event_record_id = sub.text
                        elif sname == "TimeCreated":
                            time_created_raw = sub.attrib.get("SystemTime")
                        elif sname == "Provider":
                            provider_name = sub.attrib.get("Name")
                        elif sname == "Channel":
                            channel_name = sub.text

                data_map: dict[str, str] = {}
                if event_data_el is not None:
                    for item in event_data_el:
                        key = item.attrib.get("Name")
                        if key:
                            data_map[key] = item.text or ""

                dedupe_key: tuple[Any, ...]
                if event_record_id is not None:
                    dedupe_key = ("rec", channel_name or "", event_record_id)
                else:
                    dedupe_key = (
                        "hash",
                        channel_name or "",
                        event_id,
                        time_created_raw or "",
                        tuple(sorted(data_map.items())),
                    )
                if dedupe_key in seen_keys:
                    meta["duplicate_records_skipped"] += 1
                    continue
                seen_keys.add(dedupe_key)

                if len(records) >= max_records:
                    meta["truncated"] = True
                    break

                records.append(
                    {
                        "event_id": event_id,
                        "event_record_id": event_record_id,
                        "time_created": normalize_event_timestamp(time_created_raw),
                        "time_created_raw": time_created_raw,
                        "provider": provider_name,
                        "channel": channel_name,
                        "data": data_map,
                    }
                )
    except Exception as exc:
        meta["deduplicated_record_count"] = len(records)
        meta["error"] = f"Failed parsing {evtx_path.name}: {exc}"
        return records, meta

    meta["deduplicated_record_count"] = len(records)
    return records, meta


def parse_evtx_xml_records(evtx_path: Path, max_records: int = 10000) -> tuple[list[dict[str, Any]], str | None]:
    """Parse an exported .evtx file into structured dicts using python-evtx."""
    records, meta = parse_evtx_xml_detailed(evtx_path=evtx_path, max_records=max_records)
    return records, meta.get("error")


class EventLogMonitor:
    """Exports and parses Windows Event Logs scoped to the analysis window."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger

    def collect(
        self,
        evidence_dir: Path,
        start_time_utc: str,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> tuple[CollectorResult, dict[str, list[dict[str, Any]]], bool]:
        """Export EVTX channels without clearing original Windows logs."""
        res = CollectorResult(name="eventlog_monitor")
        eventlogs_dir = evidence_dir / "dynamic" / "eventlogs"
        eventlogs_dir.mkdir(parents=True, exist_ok=True)
        parsed_by_channel: dict[str, list[dict[str, Any]]] = {}
        sysmon_provenance = inspect_sysmon_config_provenance(self.base_dir)
        max_records = max(100, int(self.config.get("max_eventlog_records", 10000)))

        if skipped:
            write_json(
                eventlogs_dir / "events_summary.json",
                {
                    "window_start_utc": start_time_utc,
                    "collected": False,
                    "not_collected_reason": skip_reason or "Dynamic sample execution did not run.",
                    "sysmon_config_provenance": sysmon_provenance,
                    "missing_channels": [k for k, _, _ in EVENT_CHANNELS],
                    "channels": {},
                },
            )
            res.artifacts.append("dynamic/eventlogs/events_summary.json")
            res.limitations.append(skip_reason or "Dynamic sample execution did not run.")
            return res.finish(STATUS_SKIPPED), parsed_by_channel, False

        if not sys.platform.startswith("win"):
            res.limitations.append("Windows Event Log collection requires Windows host (wevtutil.exe).")
            return res.finish(STATUS_UNAVAILABLE), parsed_by_channel, False

        exported_count = 0
        channel_statuses: dict[str, Any] = {}
        query = f"*[System[TimeCreated[@SystemTime>='{start_time_utc}']]]"

        for key, channel_name, filename in EVENT_CHANNELS:
            out_path = eventlogs_dir / filename
            cmd = ["wevtutil.exe", "epl", channel_name, str(out_path), f"/q:{query}", "/ow:true"]
            cmd_res = run_subprocess_safe(cmd, timeout=60.0)

            if cmd_res["returncode"] != 0:
                err_msg = (cmd_res["stderr"] or cmd_res["error"] or f"exit {cmd_res['returncode']}").strip()
                reason = _classify_wevtutil_failure(err_msg)
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": False,
                    "channel_status_reason": reason,
                    "error": err_msg,
                }
                res.limitations.append(f"Channel '{channel_name}' unavailable ({reason}): {err_msg}")
                continue

            if out_path.is_file() and out_path.stat().st_size > 0:
                exported_count += 1
                res.artifacts.append(f"dynamic/eventlogs/{filename}")
                records, parse_meta = parse_evtx_xml_detailed(out_path, max_records=max_records)
                parse_err = parse_meta.get("error")
                parsed_by_channel[key] = records
                if parse_meta.get("truncated"):
                    res.limitations.append(
                        f"Channel '{channel_name}' parsed records capped at {max_records} events."
                    )
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": True,
                    "channel_status_reason": "empty_or_no_events" if len(records) == 0 and not parse_err else "exported_ok",
                    "size_bytes": out_path.stat().st_size,
                    "parsed_event_count": len(records),
                    "raw_record_count": parse_meta.get("raw_record_count", len(records)),
                    "deduplicated_record_count": parse_meta.get("deduplicated_record_count", len(records)),
                    "duplicate_records_skipped": parse_meta.get("duplicate_records_skipped", 0),
                    "parse_errors_skipped": parse_meta.get("parse_errors_skipped", 0),
                    "truncated": bool(parse_meta.get("truncated", False)),
                    "max_records_limit": max_records,
                    "parse_note": parse_err,
                }
                if parse_err:
                    res.limitations.append(parse_err)
            else:
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": False,
                    "channel_status_reason": "empty_or_missing_evtx",
                    "error": "Empty or missing exported EVTX.",
                }

        missing_channels = [k for k, meta in channel_statuses.items() if not meta.get("exported")]
        sysmon_meta = channel_statuses.get("sysmon", {})
        sysmon_available = bool(sysmon_meta.get("exported")) and sysmon_meta.get("parse_note") is None

        summary_doc = {
            "window_start_utc": start_time_utc,
            "collected": exported_count > 0,
            "sysmon_available": sysmon_available,
            "sysmon_config_provenance": sysmon_provenance,
            "missing_channels": missing_channels,
            "channels": channel_statuses,
            "sysmon_events_preview": parsed_by_channel.get("sysmon", [])[:300],
            "powershell_events_preview": parsed_by_channel.get("powershell", [])[:150],
            "defender_events_preview": parsed_by_channel.get("defender", [])[:150],
            "system_events_preview": parsed_by_channel.get("system", [])[:150],
            "application_events_preview": parsed_by_channel.get("application", [])[:150],
        }
        write_json(eventlogs_dir / "events_summary.json", summary_doc)
        res.artifacts.append("dynamic/eventlogs/events_summary.json")
        res.summary = {
            "exported_channels": exported_count,
            "missing_channels": missing_channels,
            "sysmon_available": sysmon_available,
            "sysmon_event_count": len(parsed_by_channel.get("sysmon", [])),
        }

        if exported_count == 0:
            return res.finish(STATUS_FAILED), parsed_by_channel, sysmon_available
        if exported_count < len(EVENT_CHANNELS):
            return res.finish(STATUS_PARTIAL), parsed_by_channel, sysmon_available
        return res.finish(STATUS_COMPLETED), parsed_by_channel, sysmon_available
