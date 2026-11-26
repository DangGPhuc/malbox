"""Memory monitoring: RAM telemetry, ProcDump process dumps, and optional WinPmem/Volatility 3."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import psutil

from collectors.common import (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    CollectorResult,
    resolve_path,
    resolve_tool_path,
    run_subprocess_safe,
    utc_now_iso,
    write_json,
)


class MemoryMonitor:
    """Separately tracks RAM usage telemetry, process memory dumps, and optional full memory dumps."""

    def __init__(self, config: dict[str, Any], base_dir: Path, logger: logging.Logger) -> None:
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        self.tools_cfg = config.get("tools", {})
        self.result = CollectorResult(name="memory_monitor")
        self.result.tool_versions["psutil"] = getattr(psutil, "__version__", "installed")

        self.procdump_bin = resolve_tool_path(
            self.tools_cfg.get("procdump"),
            self.base_dir,
            ["procdump64.exe", "procdump.exe"],
        )
        self.winpmem_bin = resolve_tool_path(
            self.tools_cfg.get("winpmem"),
            self.base_dir,
            ["winpmem.exe", "winpmem_mini_x64_rc2.exe"],
        )
        self.volatility_script = resolve_path(self.tools_cfg.get("volatility3"), self.base_dir)
        self.volatility_symbols = resolve_path(self.tools_cfg.get("volatility_symbols_dir"), self.base_dir)

        self.ram_samples: list[dict[str, Any]] = []
        self.process_dumps: list[dict[str, Any]] = []
        self.procdump_note: str | None = None
        self.full_memory_info: dict[str, Any] = {
            "status": "skipped",
            "reason": "Full physical RAM acquisition not executed yet.",
        }
        self.volatility_outputs: list[str] = []

    def poll_once(self, tracked_pids: set[int]) -> None:
        """Sample host RAM usage and RSS/VMS of tracked sample processes."""
        vm = psutil.virtual_memory()
        proc_stats: list[dict[str, Any]] = []

        for pid in sorted(tracked_pids):
            try:
                proc = psutil.Process(pid)
                mem = proc.memory_info()
                proc_stats.append(
                    {
                        "pid": pid,
                        "name": proc.name(),
                        "rss_bytes": mem.rss,
                        "vms_bytes": mem.vms,
                    }
                )
            except psutil.Error:
                continue

        self.ram_samples.append(
            {
                "timestamp": utc_now_iso(),
                "system_total_bytes": vm.total,
                "system_available_bytes": vm.available,
                "system_used_percent": vm.percent,
                "tracked_processes": proc_stats,
            }
        )

    def capture_process_dumps(self, evidence_dir: Path, live_pids: list[int]) -> None:
        """Dump live sample/child process memory with ProcDump before terminating them."""
        dumps_dir = evidence_dir / "dynamic" / "memory" / "dumps"
        dumps_dir.mkdir(parents=True, exist_ok=True)

        if not bool(self.config.get("procdump_enabled", True)):
            self.result.summary["procdump_disabled_by_config"] = True
            return

        if not live_pids:
            self.procdump_note = "No live tracked processes remained at dump checkpoint; RAM telemetry still recorded."
            return

        if not self.procdump_bin:
            self.result.limitations.append(
                "ProcDump executable not found; process memory dumps unavailable."
            )
            return

        self.result.tool_versions["procdump"] = str(self.procdump_bin)
        for pid in live_pids[:10]:
            dmp_path = dumps_dir / f"proc_{pid}.dmp"
            cmd = [str(self.procdump_bin), "-accepteula", "-ma", str(pid), str(dmp_path)]
            res = run_subprocess_safe(cmd, timeout=60.0)
            if res["returncode"] == 0 and dmp_path.is_file():
                rel = f"dynamic/memory/dumps/{dmp_path.name}"
                self.result.artifacts.append(rel)
                self.process_dumps.append(
                    {
                        "pid": pid,
                        "dump_type": "process_memory_dump",
                        "path": rel,
                        "size_bytes": dmp_path.stat().st_size,
                        "status": "completed",
                    }
                )
            else:
                err_msg = (res["stderr"] or res["stdout"] or res["error"] or f"exit {res['returncode']}").strip()
                self.process_dumps.append(
                    {
                        "pid": pid,
                        "dump_type": "process_memory_dump",
                        "status": "failed",
                        "error": err_msg,
                    }
                )
                self.result.limitations.append(f"ProcDump failed for PID {pid}: {err_msg}")

    def capture_full_memory_and_volatility(self, evidence_dir: Path) -> None:
        """Optionally capture full physical RAM via WinPmem and run offline Volatility 3."""
        mem_dir = evidence_dir / "dynamic" / "memory"
        dumps_dir = mem_dir / "dumps"
        vol_dir = mem_dir / "volatility"
        dumps_dir.mkdir(parents=True, exist_ok=True)
        vol_dir.mkdir(parents=True, exist_ok=True)

        if not bool(self.config.get("winpmem_enabled", False)):
            self.full_memory_info = {
                "dump_type": "full_physical_memory_dump",
                "status": "disabled_by_config",
                "reason": "Optional winpmem_enabled is false in config.json; relying on RAM telemetry and process dumps.",
            }
            return

        if not sys.platform.startswith("win") or not self.winpmem_bin:
            self.full_memory_info = {
                "dump_type": "full_physical_memory_dump",
                "status": "unavailable",
                "reason": "WinPmem executable not found or host is not Windows.",
            }
            self.result.limitations.append(self.full_memory_info["reason"])
            return

        self.result.tool_versions["winpmem"] = str(self.winpmem_bin)
        raw_dump = dumps_dir / "physical_memory.raw"
        res = run_subprocess_safe([str(self.winpmem_bin), str(raw_dump)], timeout=300.0)
        if res["returncode"] != 0 or not raw_dump.is_file():
            err_msg = (res["stderr"] or res["stdout"] or res["error"] or f"exit {res['returncode']}").strip()
            self.full_memory_info = {
                "dump_type": "full_physical_memory_dump",
                "status": "failed",
                "reason": f"WinPmem acquisition failed (driver/privilege or Windows compatibility): {err_msg}",
            }
            self.result.limitations.append(self.full_memory_info["reason"])
            return

        self.result.artifacts.append("dynamic/memory/dumps/physical_memory.raw")
        self.full_memory_info = {
            "dump_type": "full_physical_memory_dump",
            "status": "completed",
            "path": "dynamic/memory/dumps/physical_memory.raw",
            "size_bytes": raw_dump.stat().st_size,
        }

        # Run Volatility 3 offline against the physical memory image if configured.
        if not self.volatility_script or not self.volatility_script.is_file():
            self.result.limitations.append("Volatility 3 vol.py not found; physical dump saved unparsed.")
            return

        self.result.tool_versions["volatility3"] = str(self.volatility_script)
        timeout = float(self.config.get("volatility_timeout_seconds", 180))
        plugins = [
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
            "windows.malfind",
        ]
        for plugin in plugins:
            cmd = [sys.executable, str(self.volatility_script), "--offline"]
            if self.volatility_symbols and self.volatility_symbols.is_dir():
                cmd.extend(["-s", str(self.volatility_symbols)])
            cmd.extend(["-f", str(raw_dump), "-r", "json", plugin])
            v_res = run_subprocess_safe(cmd, timeout=timeout)
            out_file = vol_dir / f"{plugin}.json"
            if v_res["returncode"] == 0 and v_res["stdout"].strip():
                out_file.write_text(v_res["stdout"], encoding="utf-8", errors="replace")
                rel = f"dynamic/memory/volatility/{out_file.name}"
                self.result.artifacts.append(rel)
                self.volatility_outputs.append(rel)
            else:
                self.result.limitations.append(
                    f"Volatility plugin {plugin} failed or lacked offline symbols: {v_res['stderr'].strip()}"
                )

    def finalize(self, evidence_dir: Path, skipped: bool = False, skip_reason: str = "") -> CollectorResult:
        """Write dynamic/memory/memory_usage.json cleanly distinguishing telemetry vs dumps."""
        mem_dir = evidence_dir / "dynamic" / "memory"
        mem_dir.mkdir(parents=True, exist_ok=True)

        if skipped:
            reason = skip_reason or "Dynamic sample execution did not run."
            doc = {
                "collected": False,
                "not_collected_reason": reason,
                "telemetry_type": "ram_usage_sampling",
                "sample_count": 0,
                "process_memory_dumps": [],
                "full_physical_memory_dump": {"status": "skipped", "reason": reason},
                "volatility_outputs": [],
            }
            write_json(mem_dir / "memory_usage.json", doc)
            self.result.artifacts.append("dynamic/memory/memory_usage.json")
            self.result.limitations.append(reason)
            self.result.summary = {"collected": False, "process_dump_count": 0, "full_memory_status": "skipped"}
            return self.result.finish(STATUS_SKIPPED)

        peak_system_pct = max((s["system_used_percent"] for s in self.ram_samples), default=0.0)
        peak_proc_rss: dict[int, int] = {}
        for sample in self.ram_samples:
            for proc in sample.get("tracked_processes", []):
                pid = int(proc["pid"])
                peak_proc_rss[pid] = max(peak_proc_rss.get(pid, 0), int(proc["rss_bytes"]))

        doc = {
            "collected": True,
            "telemetry_type": "ram_usage_sampling",
            "note": "RAM usage telemetry is distinct from process memory dumps and full physical RAM dumps.",
            "sample_count": len(self.ram_samples),
            "peak_system_memory_used_percent": peak_system_pct,
            "peak_tracked_process_rss_bytes": {str(k): v for k, v in peak_proc_rss.items()},
            "ram_usage_samples": self.ram_samples[:1000],
            "process_memory_dumps": self.process_dumps,
            "procdump_note": self.procdump_note,
            "full_physical_memory_dump": self.full_memory_info,
            "volatility_outputs": self.volatility_outputs,
        }
        write_json(mem_dir / "memory_usage.json", doc)
        self.result.artifacts.append("dynamic/memory/memory_usage.json")
        self.result.summary = {
            "collected": True,
            "ram_sample_count": len(self.ram_samples),
            "process_dump_count": sum(1 for d in self.process_dumps if d.get("status") == "completed"),
            "procdump_note": self.procdump_note,
            "full_memory_status": self.full_memory_info.get("status"),
            "volatility_output_count": len(self.volatility_outputs),
            "procdump_enabled": bool(self.config.get("procdump_enabled", True)),
            "winpmem_enabled": bool(self.config.get("winpmem_enabled", False)),
        }

        has_dump_failure = any(d.get("status") == "failed" for d in self.process_dumps)
        if not self.ram_samples:
            self.result.limitations.append("No RAM telemetry samples were captured.")
            return self.result.finish(STATUS_PARTIAL)
        if self.full_memory_info.get("status") in ("failed", "unavailable"):
            has_dump_failure = True
        if self.result.errors or has_dump_failure or self.result.limitations:
            return self.result.finish(STATUS_PARTIAL)
        return self.result.finish(STATUS_COMPLETED)
