"""Process monitoring, safe sample launch, process tree correlation, and scoped termination."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    CollectorResult,
    timestamp_from_epoch,
    utc_now_iso,
    write_json,
)


def _safe_int(val: Any) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


class ProcessMonitor:
    """Monitors sample execution, child processes, resource usage, and safe teardown."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.result = CollectorResult(name="process_monitor")
        self.result.tool_versions["psutil"] = getattr(psutil, "__version__", "installed")

        self.baseline_pids: set[int] = set()
        self.sample_pid: int | None = None
        self.sample_proc: subprocess.Popen[bytes] | None = None
        self.tracked_pids: set[int] = set()
        self.process_records: dict[int, dict[str, Any]] = {}
        self.psutil_events: list[dict[str, Any]] = []
        self.launch_timestamp: str = ""
        self.termination_report: dict[str, Any] = {}
        self.protected_pids: set[int] = self._collect_protected_pids()

    @staticmethod
    def _collect_protected_pids() -> set[int]:
        protected = {0, 4, os.getpid()}
        try:
            current = psutil.Process(os.getpid())
            for parent in current.parents():
                protected.add(parent.pid)
        except psutil.Error:
            pass
        return protected

    def start_baseline(self) -> None:
        """Capture baseline running PIDs prior to launching the sample."""
        self.baseline_pids = set(psutil.pids())

    def launch_sample(self, sample_path: Path, run_dir: Path) -> bool:
        """Launch the sample strictly under the current non-elevated user context."""
        run_dir.mkdir(parents=True, exist_ok=True)
        self.launch_timestamp = utc_now_iso()

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
                subprocess, "CREATE_NEW_CONSOLE", 0
            )

        try:
            self.sample_proc = subprocess.Popen(
                [str(sample_path)],
                cwd=str(run_dir),
                shell=False,
                creationflags=creationflags,
            )
            self.sample_pid = self.sample_proc.pid
            self.tracked_pids.add(self.sample_pid)
            self.psutil_events.append(
                {
                    "timestamp": self.launch_timestamp,
                    "source": "launcher",
                    "event_type": "process_launched",
                    "pid": self.sample_pid,
                    "ppid": os.getpid(),
                    "name": sample_path.name,
                    "executable": str(sample_path),
                    "command_line": str(sample_path),
                }
            )
            self.poll_once()
            return True
        except OSError as exc:
            self.result.errors.append(f"Failed to start sample process: {exc}")
            return False

    def poll_once(self) -> None:
        """Sample live tracked processes and newly spawned descendants."""
        now_iso = utc_now_iso()
        discovered: set[int] = set(self.tracked_pids)

        for pid in list(self.tracked_pids):
            try:
                proc = psutil.Process(pid)
                for child in proc.children(recursive=True):
                    if child.pid not in self.protected_pids:
                        discovered.add(child.pid)
            except psutil.Error:
                continue

        self.tracked_pids.update(discovered)

        for pid in list(self.tracked_pids):
            if pid in self.protected_pids:
                continue
            try:
                proc = psutil.Process(pid)
                with proc.oneshot():
                    name = proc.name()
                    ppid = proc.ppid()
                    try:
                        exe = proc.exe()
                    except psutil.Error:
                        exe = ""
                    try:
                        cmdline = " ".join(proc.cmdline())
                    except psutil.Error:
                        cmdline = ""
                    try:
                        ctime = timestamp_from_epoch(proc.create_time())
                    except psutil.Error:
                        ctime = now_iso
                    cpu_pct = proc.cpu_percent(interval=None)
                    mem_info = proc.memory_info()
                    rss_bytes = mem_info.rss
                    vms_bytes = mem_info.vms

                modules: list[str] = []
                try:
                    for mmap in proc.memory_maps()[:100]:
                        if mmap.path and mmap.path not in modules:
                            modules.append(mmap.path)
                except (psutil.Error, NotImplementedError, AttributeError):
                    pass

                if pid not in self.process_records:
                    self.process_records[pid] = {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "executable": exe,
                        "command_line": cmdline,
                        "creation_time": ctime,
                        "termination_time": None,
                        "max_cpu_percent": cpu_pct,
                        "max_rss_bytes": rss_bytes,
                        "max_vms_bytes": vms_bytes,
                        "loaded_modules": modules,
                        "source": "psutil",
                    }
                    if pid != self.sample_pid:
                        self.psutil_events.append(
                            {
                                "timestamp": ctime,
                                "source": "psutil",
                                "event_type": "child_process_observed",
                                "pid": pid,
                                "ppid": ppid,
                                "name": name,
                                "executable": exe,
                                "command_line": cmdline,
                            }
                        )
                else:
                    rec = self.process_records[pid]
                    rec["max_cpu_percent"] = max(float(rec.get("max_cpu_percent", 0.0)), float(cpu_pct))
                    rec["max_rss_bytes"] = max(int(rec.get("max_rss_bytes", 0)), int(rss_bytes))
                    rec["max_vms_bytes"] = max(int(rec.get("max_vms_bytes", 0)), int(vms_bytes))
                    if modules and not rec.get("loaded_modules"):
                        rec["loaded_modules"] = modules
            except psutil.NoSuchProcess:
                rec = self.process_records.get(pid)
                if rec and rec.get("termination_time") is None:
                    rec["termination_time"] = now_iso
                    self.psutil_events.append(
                        {
                            "timestamp": now_iso,
                            "source": "psutil",
                            "event_type": "process_exited",
                            "pid": pid,
                            "ppid": rec.get("ppid"),
                            "name": rec.get("name"),
                            "executable": rec.get("executable"),
                        }
                    )
            except psutil.Error:
                continue

    def get_live_tracked_pids(self) -> list[int]:
        """Return currently alive PIDs within the tracked job scope."""
        alive: list[int] = []
        for pid in sorted(self.tracked_pids):
            if pid in self.protected_pids:
                continue
            if psutil.pid_exists(pid):
                try:
                    proc = psutil.Process(pid)
                    if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                        alive.append(pid)
                except psutil.Error:
                    pass
        return alive

    def terminate_tracked_processes(self) -> dict[str, Any]:
        """Terminate only the sample and its descendant processes; never touch OS system processes."""
        self.poll_once()
        targets = [pid for pid in sorted(self.tracked_pids) if pid not in self.protected_pids]
        terminated: list[int] = []
        already_exited: list[int] = []
        surviving: list[dict[str, Any]] = []

        for pid in reversed(targets):
            if not psutil.pid_exists(pid):
                already_exited.append(pid)
                continue
            try:
                proc = psutil.Process(pid)
                proc.terminate()
            except psutil.NoSuchProcess:
                already_exited.append(pid)
            except psutil.Error as exc:
                self.result.errors.append(f"Terminate failed for PID {pid}: {exc}")

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            still_up = [pid for pid in targets if psutil.pid_exists(pid)]
            if not still_up:
                break
            time.sleep(0.25)

        for pid in reversed(targets):
            if not psutil.pid_exists(pid):
                if pid not in already_exited:
                    terminated.append(pid)
                continue
            try:
                proc = psutil.Process(pid)
                proc.kill()
                proc.wait(timeout=3.0)
                terminated.append(pid)
            except psutil.NoSuchProcess:
                terminated.append(pid)
            except psutil.Error as exc:
                surviving.append({"pid": pid, "reason": str(exc)})

        now_iso = utc_now_iso()
        for pid in terminated:
            if pid in self.process_records and not self.process_records[pid].get("termination_time"):
                self.process_records[pid]["termination_time"] = now_iso

        if surviving:
            self.result.limitations.append(
                f"{len(surviving)} tracked process(es) survived termination; snapshot restore required."
            )

        self.termination_report = {
            "timestamp": now_iso,
            "tracked_pids": targets,
            "already_exited": sorted(already_exited),
            "terminated_by_sandbox": sorted(set(terminated)),
            "surviving_processes": surviving,
        }
        return self.termination_report

    def finalize(
        self,
        evidence_dir: Path,
        sysmon_events: list[dict[str, Any]],
        procmon_rows: list[dict[str, str]],
        sysmon_available: bool = False,
        skipped: bool = False,
        launch_failed: bool = False,
        skip_reason: str = "",
    ) -> CollectorResult:
        """Correlate psutil, Sysmon (EID 1 & 5), and Procmon process data into evidence/dynamic/process/."""
        out_dir = evidence_dir / "dynamic" / "process"
        out_dir.mkdir(parents=True, exist_ok=True)

        if skipped:
            reason = skip_reason or "Dynamic execution skipped by local operator."
            write_json(out_dir / "processes.json", {"collected": False, "processes": [], "not_collected_reason": reason})
            write_json(out_dir / "process_tree.json", {"collected": False, "roots": [], "not_collected_reason": reason})
            write_json(out_dir / "process_events.json", {"collected": False, "events": [], "not_collected_reason": reason})
            self.result.artifacts.extend(
                [
                    "dynamic/process/processes.json",
                    "dynamic/process/process_tree.json",
                    "dynamic/process/process_events.json",
                ]
            )
            self.result.limitations.append(reason)
            return self.result.finish(STATUS_SKIPPED)

        if launch_failed:
            reason = "; ".join(self.result.errors) or "Sample process failed to launch."
            write_json(out_dir / "processes.json", {"collected": False, "launch_failed": True, "processes": [], "error": reason})
            write_json(out_dir / "process_tree.json", {"collected": False, "launch_failed": True, "roots": [], "error": reason})
            write_json(out_dir / "process_events.json", {"collected": False, "launch_failed": True, "events": [], "error": reason})
            self.result.artifacts.extend(
                [
                    "dynamic/process/processes.json",
                    "dynamic/process/process_tree.json",
                    "dynamic/process/process_events.json",
                ]
            )
            return self.result.finish(STATUS_FAILED)

        correlated_events = list(self.psutil_events)
        scoped_pids = set(self.tracked_pids)

        # Expand tracked PID scope using Sysmon Event ID 1 parent->child lineage to catch short-lived children.
        sysmon_creates = [ev for ev in sysmon_events if ev.get("event_id") == 1]
        changed = True
        while changed:
            changed = False
            for ev in sysmon_creates:
                data = ev.get("data", {})
                pid = _safe_int(data.get("ProcessId"))
                ppid = _safe_int(data.get("ParentProcessId"))
                if pid is not None and ppid in scoped_pids and pid not in scoped_pids and pid not in self.protected_pids:
                    scoped_pids.add(pid)
                    changed = True

        self.tracked_pids.update(scoped_pids)

        for ev in sysmon_events:
            eid = ev.get("event_id")
            data = ev.get("data", {})
            pid = _safe_int(data.get("ProcessId"))
            if pid not in scoped_pids:
                continue

            if eid == 1:
                ppid = _safe_int(data.get("ParentProcessId"))
                image = data.get("Image", "")
                name = os.path.basename(image) if image else ""
                cmdline = data.get("CommandLine", "")
                ctime = ev.get("time_created") or data.get("UtcTime") or ""
                correlated_events.append(
                    {
                        "timestamp": ctime,
                        "source": "sysmon_eid1",
                        "event_type": "process_create",
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "executable": image,
                        "command_line": cmdline,
                        "hashes": data.get("Hashes", ""),
                        "user": data.get("User", ""),
                    }
                )
                if pid not in self.process_records:
                    self.process_records[pid] = {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "executable": image,
                        "command_line": cmdline,
                        "creation_time": ctime,
                        "termination_time": None,
                        "max_cpu_percent": None,
                        "max_rss_bytes": None,
                        "max_vms_bytes": None,
                        "loaded_modules": [],
                        "source": "sysmon",
                    }
                else:
                    if not self.process_records[pid].get("command_line"):
                        self.process_records[pid]["command_line"] = cmdline
                    self.process_records[pid]["sysmon_confirmed"] = True
            elif eid == 5:
                ttime = ev.get("time_created") or data.get("UtcTime") or ""
                correlated_events.append(
                    {
                        "timestamp": ttime,
                        "source": "sysmon_eid5",
                        "event_type": "process_terminate",
                        "pid": pid,
                        "executable": data.get("Image", ""),
                    }
                )
                if pid in self.process_records and not self.process_records[pid].get("termination_time"):
                    self.process_records[pid]["termination_time"] = ttime

        for row in procmon_rows:
            op = row.get("Operation", "")
            if op not in ("Process Start", "Process Exit", "Process Create"):
                continue
            pid = _safe_int(row.get("PID"))
            if pid not in scoped_pids:
                continue
            correlated_events.append(
                {
                    "timestamp": row.get("Time of Day", ""),
                    "source": "procmon",
                    "event_type": op.lower().replace(" ", "_"),
                    "pid": pid,
                    "name": row.get("Process Name", ""),
                    "executable": row.get("Path", ""),
                    "detail": row.get("Detail", ""),
                }
            )

        correlated_events.sort(key=lambda item: str(item.get("timestamp") or ""))
        processes_list = sorted(self.process_records.values(), key=lambda item: int(item.get("pid") or 0))
        tree = self._build_process_tree(processes_list)

        write_json(
            out_dir / "processes.json",
            {
                "collected": True,
                "root_sample_pid": self.sample_pid,
                "tracked_pid_count": len(processes_list),
                "processes": processes_list,
                "termination_report": self.termination_report,
            },
        )
        write_json(out_dir / "process_tree.json", {"collected": True, "roots": tree})
        write_json(
            out_dir / "process_events.json",
            {"collected": True, "event_count": len(correlated_events), "events": correlated_events},
        )

        self.result.artifacts.extend(
            [
                "dynamic/process/processes.json",
                "dynamic/process/process_tree.json",
                "dynamic/process/process_events.json",
            ]
        )
        self.result.summary = {
            "root_sample_pid": self.sample_pid,
            "observed_process_count": len(processes_list),
            "process_event_count": len(correlated_events),
            "sysmon_available": sysmon_available,
        }

        if not sysmon_available:
            self.result.limitations.append(
                "Sysmon process events unavailable; short-lived child processes rely on psutil/Procmon."
            )
            return self.result.finish(STATUS_PARTIAL if processes_list else STATUS_FAILED)
        return self.result.finish(STATUS_COMPLETED)

    def _build_process_tree(self, processes_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        nodes: dict[int, dict[str, Any]] = {}
        for proc in processes_list:
            pid = int(proc["pid"])
            nodes[pid] = {
                "pid": pid,
                "ppid": proc.get("ppid"),
                "name": proc.get("name"),
                "executable": proc.get("executable"),
                "command_line": proc.get("command_line"),
                "creation_time": proc.get("creation_time"),
                "termination_time": proc.get("termination_time"),
                "children": [],
            }

        roots: list[dict[str, Any]] = []
        for pid, node in nodes.items():
            ppid = _safe_int(node.get("ppid"))
            if ppid is not None and ppid in nodes and ppid != pid:
                nodes[ppid]["children"].append(node)
            else:
                roots.append(node)
        return roots
