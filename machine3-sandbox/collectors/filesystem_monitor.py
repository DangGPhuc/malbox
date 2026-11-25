"""Filesystem monitor and shared Procmon session manager."""

from __future__ import annotations

import csv
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from collectors.common import (
    EXECUTABLE_EXTENSIONS,
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    compute_file_hashes,
    resolve_tool_path,
    run_subprocess_safe,
    write_json,
)


def _safe_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


class ProcmonSession:
    """Manages one Procmon64 capture session producing raw/procmon.pml and CSV export."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.tools_cfg = config.get("tools", {})
        self.procmon_bin = resolve_tool_path(
            self.tools_cfg.get("procmon"),
            self.base_dir,
            ["Procmon64.exe", "Procmon.exe"],
        )
        self.pml_path: Path | None = None
        self.csv_path: Path | None = None
        self.started = False
        self.exported_ok = False
        self.notes: list[str] = []

    def start(self, evidence_dir: Path) -> None:
        """Start Procmon backing file capture prior to sample execution."""
        raw_dir = evidence_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        self.pml_path = raw_dir / "procmon.pml"

        if not sys.platform.startswith("win"):
            self.notes.append("Procmon capture requires Windows.")
            return

        if not self.procmon_bin:
            self.notes.append("Procmon executable not found.")
            return

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.Popen(
                [
                    str(self.procmon_bin),
                    "/AcceptEula",
                    "/Quiet",
                    "/Minimized",
                    "/BackingFile",
                    str(self.pml_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creationflags,
            )
            self.started = True
        except OSError as exc:
            self.notes.append(f"Failed launching Procmon (check UAC/privileges): {exc}")

    def filter_exported_csv(self, tracked_pids: set[int]) -> list[dict[str, str]]:
        """Read an already-exported Procmon CSV filtered to the current tracked_pids set."""
        if not self.csv_path or not self.csv_path.is_file():
            return []
        filtered_rows: list[dict[str, str]] = []
        try:
            with self.csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    pid = _safe_int(row.get("PID"))
                    if pid in tracked_pids:
                        filtered_rows.append(dict(row))
                        if len(filtered_rows) >= 15000:
                            break
        except OSError as exc:
            self.notes.append(f"Failed reading Procmon CSV export: {exc}")
        return filtered_rows

    def terminate_only(self) -> None:
        """Stop an active Procmon session safely without exporting (used during error cleanup)."""
        if not self.started or not self.procmon_bin:
            return
        run_subprocess_safe([str(self.procmon_bin), "/Terminate"], timeout=20.0)
        self.started = False

    def stop_and_export(self, workspace_dir: Path, tracked_pids: set[int]) -> list[dict[str, str]]:
        """Terminate Procmon capture, convert .pml to .csv, and filter rows for tracked PIDs."""
        if not self.started or not self.procmon_bin:
            return []

        term_res = run_subprocess_safe([str(self.procmon_bin), "/Terminate"], timeout=30.0)
        self.started = False
        if term_res["returncode"] != 0:
            self.notes.append(f"Procmon /Terminate note: {term_res['stderr'].strip() or term_res['error']}")

        if not self.pml_path or not self.pml_path.is_file():
            self.notes.append("Procmon backing file raw/procmon.pml was not created.")
            return []

        self.csv_path = workspace_dir / "procmon_export.csv"
        conv_res = run_subprocess_safe(
            [str(self.procmon_bin), "/OpenLog", str(self.pml_path), "/SaveAs", str(self.csv_path)],
            timeout=90.0,
        )
        if conv_res["returncode"] != 0 or not self.csv_path.is_file():
            self.notes.append(
                f"Procmon CSV export failed: {conv_res['stderr'].strip() or conv_res['error']}"
            )
            return []

        self.exported_ok = True
        return self.filter_exported_csv(tracked_pids)


class FilesystemMonitor:
    """Extracts filesystem modifications from Sysmon, Procmon, and sandbox run dir metadata."""

    FS_PROCMON_OPS = {
        "CreateFile",
        "WriteFile",
        "SetDispositionInformationFile",
        "SetRenameInformationFile",
        "DeleteFile",
    }

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.result = CollectorResult(name="filesystem_monitor")

    def finalize(
        self,
        evidence_dir: Path,
        sample_run_dir: Path,
        sample_filename: str,
        sysmon_events: list[dict[str, Any]],
        procmon_rows: list[dict[str, str]],
        procmon_session: ProcmonSession,
        tracked_pids: set[int],
        sysmon_available: bool = False,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> CollectorResult:
        """Correlate file creations, edits, deletions, and renames without copying dropped EXEs."""
        fs_dir = evidence_dir / "dynamic" / "filesystem"
        fs_dir.mkdir(parents=True, exist_ok=True)

        if skipped:
            reason = skip_reason or "Dynamic sample execution did not run."
            write_json(
                fs_dir / "changes.json",
                {
                    "collected": False,
                    "not_collected_reason": reason,
                    "change_count": 0,
                    "dropped_artifact_metadata_count": 0,
                    "dropped_artifact_metadata": [],
                    "changes": [],
                },
            )
            self.result.artifacts.append("dynamic/filesystem/changes.json")
            self.result.limitations.append(reason)
            self.result.summary = {"collected": False}
            return self.result.finish(STATUS_SKIPPED)

        changes: list[dict[str, Any]] = []
        created_paths: set[str] = set()

        for ev in sysmon_events:
            eid = ev.get("event_id")
            if eid not in (11, 15, 23, 26):
                continue
            data = ev.get("data", {})
            pid = _safe_int(data.get("ProcessId"))
            if pid not in tracked_pids:
                continue

            target = data.get("TargetFilename", "")
            op_map = {
                11: "file_create",
                15: "file_create_stream_hash",
                23: "file_delete_archived",
                26: "file_delete_detected",
            }
            if eid == 11 and target:
                created_paths.add(target)

            changes.append(
                {
                    "timestamp": ev.get("time_created") or data.get("UtcTime") or "",
                    "source": f"sysmon_eid{eid}",
                    "operation": op_map.get(eid, f"eid_{eid}"),
                    "path": target,
                    "pid": pid,
                    "process": os.path.basename(data.get("Image", "")),
                    "hashes": data.get("Hashes", ""),
                }
            )

        for row in procmon_rows:
            op = row.get("Operation", "")
            if op not in self.FS_PROCMON_OPS:
                continue
            path_val = row.get("Path", "")
            detail = row.get("Detail", "")
            normalized_op = op
            if op == "SetDispositionInformationFile" and "Delete: True" in detail:
                normalized_op = "file_delete"
            elif op == "SetRenameInformationFile":
                normalized_op = "file_rename"
            elif op == "CreateFile":
                normalized_op = "file_create_or_open"
            changes.append(
                {
                    "timestamp": row.get("Time of Day", ""),
                    "source": "procmon",
                    "operation": normalized_op,
                    "path": path_val,
                    "pid": _safe_int(row.get("PID")),
                    "process": row.get("Process Name", ""),
                    "result": row.get("Result", ""),
                    "detail": detail,
                }
            )

        # Collect hash & metadata only (never copy dropped binaries into evidence ZIP).
        dropped_artifacts: list[dict[str, Any]] = []
        candidate_paths = set(created_paths)
        if sample_run_dir.is_dir():
            for item in sample_run_dir.rglob("*"):
                if item.is_file() and item.name != sample_filename:
                    candidate_paths.add(str(item))

        for path_str in sorted(candidate_paths)[:200]:
            p = Path(path_str)
            if not p.is_file():
                continue
            try:
                meta = compute_file_hashes(p)
                meta["path"] = str(p)
                meta["is_executable_extension"] = p.suffix.lower() in EXECUTABLE_EXTENSIONS
                meta["archived_in_evidence"] = False
                dropped_artifacts.append(meta)
            except OSError:
                continue

        changes.sort(key=lambda item: str(item.get("timestamp") or ""))
        write_json(
            fs_dir / "changes.json",
            {
                "collected": sysmon_available or procmon_session.exported_ok or bool(dropped_artifacts),
                "change_count": len(changes),
                "dropped_artifact_metadata_count": len(dropped_artifacts),
                "dropped_artifact_metadata": dropped_artifacts,
                "changes": changes[:5000],
            },
        )
        self.result.artifacts.append("dynamic/filesystem/changes.json")
        if procmon_session.pml_path and procmon_session.pml_path.is_file():
            self.result.artifacts.append("raw/procmon.pml")
            self.result.tool_versions["procmon"] = str(procmon_session.procmon_bin)

        self.result.limitations.extend(procmon_session.notes)
        self.result.summary = {
            "collected": sysmon_available or procmon_session.exported_ok,
            "filesystem_event_count": len(changes),
            "dropped_artifact_count": len(dropped_artifacts),
            "sysmon_available": sysmon_available,
            "procmon_available": procmon_session.exported_ok,
        }

        if not sysmon_available and not procmon_session.exported_ok:
            return self.result.finish(STATUS_UNAVAILABLE if not dropped_artifacts else STATUS_PARTIAL)
        if not sysmon_available or not procmon_session.exported_ok or procmon_session.notes:
            return self.result.finish(STATUS_PARTIAL)
        return self.result.finish(STATUS_COMPLETED)
