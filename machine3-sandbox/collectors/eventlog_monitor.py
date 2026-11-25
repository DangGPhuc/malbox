"""Windows Event Log collector (Sysmon, System, Application, Security, PowerShell, Defender)."""

from __future__ import annotations

import logging
import sys
import xml.etree.ElementTree as ET
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


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_evtx_xml_records(evtx_path: Path, max_records: int = 10000) -> tuple[list[dict[str, Any]], str | None]:
    """Parse an exported .evtx file into structured dicts using python-evtx."""
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except ImportError as exc:
        return [], f"python-evtx not installed: {exc}"

    records: list[dict[str, Any]] = []
    try:
        with evtx.Evtx(str(evtx_path)) as log:
            for idx, record in enumerate(log.records()):
                if idx >= max_records:
                    break
                try:
                    root = ET.fromstring(record.xml())
                except ET.ParseError:
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
                time_created = None
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
                        elif sname == "TimeCreated":
                            time_created = sub.attrib.get("SystemTime")
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

                records.append(
                    {
                        "event_id": event_id,
                        "time_created": time_created,
                        "provider": provider_name,
                        "channel": channel_name,
                        "data": data_map,
                    }
                )
    except Exception as exc:
        return records, f"Failed parsing {evtx_path.name}: {exc}"

    return records, None


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

        if skipped:
            write_json(
                eventlogs_dir / "events_summary.json",
                {
                    "window_start_utc": start_time_utc,
                    "collected": False,
                    "not_collected_reason": skip_reason or "Dynamic sample execution did not run.",
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
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": False,
                    "error": err_msg,
                }
                res.limitations.append(f"Channel '{channel_name}' unavailable or denied: {err_msg}")
                continue

            if out_path.is_file() and out_path.stat().st_size > 0:
                exported_count += 1
                res.artifacts.append(f"dynamic/eventlogs/{filename}")
                records, parse_err = parse_evtx_xml_records(out_path)
                parsed_by_channel[key] = records
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": True,
                    "size_bytes": out_path.stat().st_size,
                    "parsed_event_count": len(records),
                    "parse_note": parse_err,
                }
                if parse_err:
                    res.limitations.append(parse_err)
            else:
                channel_statuses[key] = {
                    "channel": channel_name,
                    "exported": False,
                    "error": "Empty or missing exported EVTX.",
                }

        sysmon_meta = channel_statuses.get("sysmon", {})
        sysmon_available = bool(sysmon_meta.get("exported")) and sysmon_meta.get("parse_note") is None

        summary_doc = {
            "window_start_utc": start_time_utc,
            "collected": exported_count > 0,
            "sysmon_available": sysmon_available,
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
            "sysmon_available": sysmon_available,
            "sysmon_event_count": len(parsed_by_channel.get("sysmon", [])),
        }

        if exported_count == 0:
            return res.finish(STATUS_FAILED), parsed_by_channel, sysmon_available
        if exported_count < len(EVENT_CHANNELS):
            return res.finish(STATUS_PARTIAL), parsed_by_channel, sysmon_available
        return res.finish(STATUS_COMPLETED), parsed_by_channel, sysmon_available
