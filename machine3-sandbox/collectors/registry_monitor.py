"""Registry change monitor correlating Sysmon (EID 12, 13, 14) and Procmon."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    write_json,
)

PERSISTENCE_KEY_PATTERNS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\policies\\explorer\\run",
    "\\currentcontrolset\\services",
    "\\winlogon",
    "\\image file execution options",
    "\\appinit_dlls",
    "\\schedule\\taskcache",
    "\\shell\\open\\command",
)


def _safe_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _is_persistence_key(target_object: str) -> bool:
    lower = (target_object or "").lower()
    return any(pattern in lower for pattern in PERSISTENCE_KEY_PATTERNS)


class RegistryMonitor:
    """Extracts registry creation, modification, deletion, and persistence indicators."""

    REG_PROCMON_OPS = {
        "RegCreateKey",
        "RegSetValue",
        "RegDeleteKey",
        "RegDeleteValue",
        "RegRenameKey",
    }

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.result = CollectorResult(name="registry_monitor")

    def finalize(
        self,
        evidence_dir: Path,
        sysmon_events: list[dict[str, Any]],
        procmon_rows: list[dict[str, str]],
        tracked_pids: set[int],
        sysmon_available: bool = False,
        procmon_available: bool = False,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> CollectorResult:
        """Correlate registry operations for tracked PIDs into dynamic/registry/changes.json."""
        reg_dir = evidence_dir / "dynamic" / "registry"
        reg_dir.mkdir(parents=True, exist_ok=True)

        if skipped:
            reason = skip_reason or "Dynamic sample execution did not run."
            write_json(
                reg_dir / "changes.json",
                {
                    "collected": False,
                    "not_collected_reason": reason,
                    "change_count": 0,
                    "persistence_indicator_count": 0,
                    "persistence_indicators": [],
                    "changes": [],
                },
            )
            self.result.artifacts.append("dynamic/registry/changes.json")
            self.result.limitations.append(reason)
            self.result.summary = {"collected": False}
            return self.result.finish(STATUS_SKIPPED)

        changes: list[dict[str, Any]] = []
        persistence_hits: list[dict[str, Any]] = []

        for ev in sysmon_events:
            eid = ev.get("event_id")
            if eid not in (12, 13, 14):
                continue
            data = ev.get("data", {})
            pid = _safe_int(data.get("ProcessId"))
            if pid not in tracked_pids:
                continue

            target = data.get("TargetObject", "")
            entry = {
                "timestamp": ev.get("time_created") or data.get("UtcTime") or "",
                "source": f"sysmon_eid{eid}",
                "operation": data.get("EventType") or f"registry_eid{eid}",
                "target_object": target,
                "details": data.get("Details") or data.get("NewName") or "",
                "pid": pid,
                "process": os.path.basename(data.get("Image", "")),
                "is_persistence_related": _is_persistence_key(target),
            }
            changes.append(entry)
            if entry["is_persistence_related"]:
                persistence_hits.append(entry)

        for row in procmon_rows:
            op = row.get("Operation", "")
            if op not in self.REG_PROCMON_OPS:
                continue
            target = row.get("Path", "")
            entry = {
                "timestamp": row.get("Time of Day", ""),
                "source": "procmon",
                "operation": op,
                "target_object": target,
                "details": row.get("Detail", ""),
                "pid": _safe_int(row.get("PID")),
                "process": row.get("Process Name", ""),
                "result": row.get("Result", ""),
                "is_persistence_related": _is_persistence_key(target),
            }
            changes.append(entry)
            if entry["is_persistence_related"]:
                persistence_hits.append(entry)

        changes.sort(key=lambda item: str(item.get("timestamp") or ""))
        write_json(
            reg_dir / "changes.json",
            {
                "collected": sysmon_available or procmon_available,
                "change_count": len(changes),
                "persistence_indicator_count": len(persistence_hits),
                "persistence_indicators": persistence_hits[:500],
                "changes": changes[:5000],
            },
        )
        self.result.artifacts.append("dynamic/registry/changes.json")
        self.result.summary = {
            "collected": sysmon_available or procmon_available,
            "registry_event_count": len(changes),
            "persistence_indicator_count": len(persistence_hits),
            "sysmon_available": sysmon_available,
            "procmon_available": procmon_available,
        }

        if not sysmon_available and not procmon_available:
            self.result.limitations.append(
                "Neither Sysmon nor Procmon registry telemetry was available."
            )
            return self.result.finish(STATUS_UNAVAILABLE)
        if not sysmon_available or not procmon_available:
            if not sysmon_available:
                self.result.limitations.append("Sysmon registry events unavailable.")
            if not procmon_available:
                self.result.limitations.append("Procmon registry export unavailable.")
            return self.result.finish(STATUS_PARTIAL)
        return self.result.finish(STATUS_COMPLETED)
