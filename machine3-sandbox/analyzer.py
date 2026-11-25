"""MalBox Machine 3 Analysis Pipeline Orchestrator."""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import time
import zipfile
from pathlib import Path
from typing import Any, Callable

from collectors.common import (
    EXECUTABLE_EXTENSIONS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    CollectorResult,
    compute_file_hashes,
    utc_now_iso,
    write_json,
)
from collectors.eventlog_monitor import EventLogMonitor
from collectors.filesystem_monitor import FilesystemMonitor, ProcmonSession
from collectors.ghidra_analysis import GhidraAnalyzer
from collectors.memory_monitor import MemoryMonitor
from collectors.network_monitor import NetworkMonitor
from collectors.process_monitor import ProcessMonitor
from collectors.registry_monitor import RegistryMonitor
from collectors.static_analysis import StaticAnalyzer


def _read_json_safe(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return {}


def _build_job_loggers(logs_dir: Path, job_id: str) -> tuple[logging.Logger, logging.Logger, logging.Logger, list[logging.Handler]]:
    logs_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handlers: list[logging.Handler] = []

    def make_logger(name: str, filename: str, level: int = logging.INFO) -> logging.Logger:
        lg = logging.getLogger(f"malbox.job.{job_id}.{name}")
        lg.setLevel(level)
        lg.propagate = False
        fh = logging.FileHandler(logs_dir / filename, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(formatter)
        lg.addHandler(fh)
        handlers.append(fh)
        return lg

    analysis_log = make_logger("analysis", "analysis.log")
    collectors_log = make_logger("collectors", "collectors.log")
    errors_log = make_logger("errors", "errors.log", level=logging.WARNING)
    return analysis_log, collectors_log, errors_log, handlers


def _build_timeline(evidence_dir: Path, milestones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = list(milestones)

    proc_events = _read_json_safe(evidence_dir / "dynamic" / "process" / "process_events.json").get("events", [])
    for ev in proc_events[:1000]:
        timeline.append(
            {
                "timestamp": ev.get("timestamp", ""),
                "category": "process",
                "event": ev.get("event_type", "process_event"),
                "detail": f"PID={ev.get('pid')} {ev.get('name') or ev.get('executable', '')}",
                "source": ev.get("source", ""),
            }
        )

    conns = _read_json_safe(evidence_dir / "dynamic" / "network" / "connections.json").get("connections", [])
    for conn in conns[:1000]:
        timeline.append(
            {
                "timestamp": conn.get("timestamp", ""),
                "category": "network",
                "event": f"{conn.get('protocol', 'NET')}_connection",
                "detail": f"{conn.get('src_ip')}:{conn.get('src_port')} -> {conn.get('dst_ip')}:{conn.get('dst_port')} (PID={conn.get('pid')})",
                "source": conn.get("source", ""),
            }
        )

    dns_items = _read_json_safe(evidence_dir / "dynamic" / "network" / "dns.json").get("queries", [])
    for q in dns_items[:1000]:
        timeline.append(
            {
                "timestamp": q.get("timestamp", ""),
                "category": "dns",
                "event": "dns_query",
                "detail": f"{q.get('query_name')} -> {q.get('answers') or q.get('query_results', '')}",
                "source": q.get("source", ""),
            }
        )

    fs_changes = _read_json_safe(evidence_dir / "dynamic" / "filesystem" / "changes.json").get("changes", [])
    for ch in fs_changes[:1000]:
        timeline.append(
            {
                "timestamp": ch.get("timestamp", ""),
                "category": "filesystem",
                "event": ch.get("operation", "file_op"),
                "detail": f"{ch.get('path')} (PID={ch.get('pid')})",
                "source": ch.get("source", ""),
            }
        )

    reg_changes = _read_json_safe(evidence_dir / "dynamic" / "registry" / "changes.json").get("changes", [])
    for ch in reg_changes[:1000]:
        timeline.append(
            {
                "timestamp": ch.get("timestamp", ""),
                "category": "registry",
                "event": ch.get("operation", "reg_op"),
                "detail": f"{ch.get('target_object')} (PID={ch.get('pid')})",
                "source": ch.get("source", ""),
            }
        )

    timeline.sort(key=lambda item: str(item.get("timestamp") or ""))
    return timeline


def _build_report_markdown(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    sample = summary.get("sample", {})
    static = summary.get("static", {})
    dynamic = summary.get("dynamic", {})
    iocs = summary.get("potential_iocs", {})
    limitations = manifest.get("analysis_limitations", [])

    lines = [
        f"# MalBox Analysis Report — `{manifest.get('job_id')}`",
        "",
        "> **Note:** Observations below reflect artifacts collected in an isolated sandbox window. "
        "Do not treat any single collector output in isolation as a definitive malware or benign verdict.",
        "",
        "## 1. Sample Information",
        f"- **Filename:** `{sample.get('filename')}`",
        f"- **Size (bytes):** {sample.get('size_bytes')}",
        f"- **File Type:** {sample.get('file_type')}",
        f"- **MD5:** `{sample.get('md5')}`",
        f"- **SHA-1:** `{sample.get('sha1')}`",
        f"- **SHA-256:** `{sample.get('sha256')}`",
        f"- **Analysis Window (UTC):** `{manifest.get('analysis_start_time')}` -> `{manifest.get('analysis_end_time')}`",
        f"- **Observation Duration:** {manifest.get('dynamic_observation_duration_seconds')}s",
        f"- **Final Job Status:** `{manifest.get('final_status')}`",
        "",
        "## 2. Static Findings",
        f"- **PE Architecture:** {static.get('architecture', 'N/A')}",
        f"- **PE Sections:** {static.get('section_count', 0)}",
        f"- **Imported DLLs:** {static.get('imported_dll_count', 0)}",
        f"- **Exported Functions:** {static.get('exported_function_count', 0)}",
        f"- **Extracted Strings:** {static.get('string_count', 0)} (source: `{static.get('strings_source', 'N/A')}`)",
        f"- **CAPA Capabilities:** {static.get('capa_capability_count', 0)}",
        f"- **YARA Matches:** {static.get('yara_match_count', 0)}",
        f"- **Ghidra Functions:** {static.get('ghidra_function_count', 0)}",
        "",
        "## 3. Observed Process Activity",
        f"- **Root Sample PID:** {dynamic.get('root_sample_pid')}",
        f"- **Observed Processes:** {dynamic.get('observed_process_count', 0)}",
        f"- **Process Events:** {dynamic.get('process_event_count', 0)}",
        "",
        "## 4. Network Activity",
        f"- **Network Connection Events:** {dynamic.get('connection_event_count', 0)}",
        f"- **DNS Queries Observed:** {dynamic.get('dns_query_count', 0)}",
        f"- **PCAPNG Captured:** {dynamic.get('has_pcapng', False)}",
        "",
        "## 5. Filesystem Activity",
        f"- **Filesystem Events:** {dynamic.get('filesystem_event_count', 0)}",
        f"- **Dropped/Modified Artifact Metadata Entries:** {dynamic.get('dropped_artifact_count', 0)}",
        "",
        "## 6. Registry Activity",
        f"- **Registry Events:** {dynamic.get('registry_event_count', 0)}",
        f"- **Persistence-Related Registry Hits:** {dynamic.get('persistence_indicator_count', 0)}",
        "",
        "## 7. Memory Evidence",
        f"- **RAM Telemetry Samples:** {dynamic.get('ram_sample_count', 0)}",
        f"- **Peak System Memory Used (%):** {dynamic.get('peak_system_memory_used_percent', 0)}",
        f"- **Process Memory Dumps:** {dynamic.get('process_dump_count', 0)}",
        f"- **Full Physical Memory Status:** `{dynamic.get('full_memory_status', 'skipped')}`",
        "",
        "## 8. Potential Indicators of Compromise",
        f"- **Static URLs:** {', '.join(iocs.get('static_urls', [])[:20]) or 'None observed'}",
        f"- **Static Domains:** {', '.join(iocs.get('static_domains', [])[:20]) or 'None observed'}",
        f"- **Static IP Addresses:** {', '.join(iocs.get('static_ips', [])[:20]) or 'None observed'}",
        f"- **Dynamic Remote Destinations:** {', '.join(iocs.get('dynamic_destinations', [])[:20]) or 'None observed'}",
        f"- **Dynamic DNS Queries:** {', '.join(iocs.get('dynamic_dns_queries', [])[:20]) or 'None observed'}",
        f"- **YARA Matched Rules:** {', '.join(iocs.get('yara_rules', [])[:20]) or 'None matched'}",
        "",
        "## 9. Analysis Limitations & Collector Status",
    ]

    for name, c_data in manifest.get("collector_status", {}).items():
        lines.append(f"- `{name}`: **{c_data.get('status')}**")

    lines.append("")
    if limitations:
        lines.append("### Limitations Recorded")
        for item in limitations:
            lines.append(f"- {item}")
    else:
        lines.append("- No collector limitations reported.")

    lines.append("")
    return "\n".join(lines)


def _package_evidence_zip(evidence_dir: Path, zip_path: Path, sample_filename: str) -> str:
    """Stream evidence files into a ZIP archive while excluding sample and dropped executables."""
    digest = hashlib.sha256()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for file_path in sorted(evidence_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(evidence_dir).as_posix()
            # Never bundle the original sample or raw dropped executable binaries inside evidence ZIP.
            if file_path.name == sample_filename and not rel_path.startswith("ghidra/"):
                continue
            if rel_path.startswith("dynamic/filesystem/dropped_files/"):
                continue
            if not rel_path.startswith(("logs/", "static/", "ghidra/")) and file_path.suffix.lower() in EXECUTABLE_EXTENSIONS:
                continue
            zf.write(file_path, arcname=rel_path)

    with zip_path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_analysis(
    job_id: str,
    sample_path: Path,
    sample_sha256: str,
    config: dict[str, Any],
    base_dir: Path,
    workspace_dir: Path,
    evidence_dir: Path,
    approval_prompt_fn: Callable[[str, str], bool],
    stage_callback: Callable[[str], None],
    terminal_logger: logging.Logger,
) -> dict[str, Any]:
    """Execute the full static + dynamic analysis pipeline for one sample."""
    start_time_utc = utc_now_iso()
    milestones: list[dict[str, Any]] = [
        {"timestamp": start_time_utc, "category": "pipeline", "event": "job_started", "detail": job_id}
    ]

    for sub in (
        "static",
        "ghidra/decompiled",
        "dynamic/process",
        "dynamic/network",
        "dynamic/memory/dumps",
        "dynamic/memory/volatility",
        "dynamic/filesystem",
        "dynamic/registry",
        "dynamic/eventlogs",
        "raw",
        "logs",
    ):
        (evidence_dir / sub).mkdir(parents=True, exist_ok=True)

    analysis_log, collectors_log, errors_log, log_handlers = _build_job_loggers(
        evidence_dir / "logs", job_id
    )

    terminal_logger.info("[SANDBOX] Preparing analysis workspace...")
    stage_callback("preparing_workspace")
    analysis_log.info("Starting job %s for sample %s (SHA-256: %s)", job_id, sample_path.name, sample_sha256)

    collector_results: dict[str, CollectorResult] = {}
    all_limitations: list[str] = []

    try:
        # 1. Static analysis + Ghidra Headless
        terminal_logger.info("[SANDBOX] Running static analysis...")
        stage_callback("static_analysis")
        static_analyzer = StaticAnalyzer(config=config, base_dir=base_dir, logger=collectors_log)
        static_results = static_analyzer.run(sample_path=sample_path, evidence_dir=evidence_dir)
        collector_results.update(static_results)

        stage_callback("ghidra_analysis")
        ghidra_analyzer = GhidraAnalyzer(config=config, base_dir=base_dir, logger=collectors_log)
        collector_results["ghidra"] = ghidra_analyzer.run(
            sample_path=sample_path, workspace_dir=workspace_dir, evidence_dir=evidence_dir
        )
        milestones.append(
            {"timestamp": utc_now_iso(), "category": "pipeline", "event": "static_completed", "detail": job_id}
        )

        # 2. Start dynamic collectors BEFORE sample execution
        terminal_logger.info("[SANDBOX] Starting evidence collectors...")
        stage_callback("starting_collectors")
        dynamic_start_utc = utc_now_iso()

        process_mon = ProcessMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        network_mon = NetworkMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        memory_mon = MemoryMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        procmon_session = ProcmonSession(config=config, base_dir=base_dir, logger=collectors_log)
        filesystem_mon = FilesystemMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        registry_mon = RegistryMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        eventlog_mon = EventLogMonitor(config=config, base_dir=base_dir, logger=collectors_log)

        process_mon.start_baseline()
        procmon_session.start(evidence_dir=evidence_dir)
        network_mon.start(evidence_dir=evidence_dir)
        memory_mon.poll_once(set())

        # 3. Local analysis approval gate (controlled on isolated Sandbox terminal)
        require_approval = bool(config.get("require_local_approval", True))
        if require_approval:
            terminal_logger.info("[SANDBOX] Awaiting local analysis approval...")
            stage_callback("awaiting_local_approval")
            approved = approval_prompt_fn(sample_path.name, sample_sha256)
        else:
            terminal_logger.info("[SANDBOX] Executing sample for dynamic observation now...")
            approved = True

        duration = int(config.get("observation_duration_seconds", 120))
        poll_step = float(config.get("poll_sample_interval_seconds", 0.5))
        run_dir = workspace_dir / "run"
        execution_skipped = False

        if approved:
            stage_callback("dynamic_observation")
            launched = process_mon.launch_sample(sample_path=sample_path, run_dir=run_dir)
            if launched:
                terminal_logger.info("[SANDBOX] Dynamic observation started.")
                terminal_logger.info("[SANDBOX] Observation duration: %d seconds.", duration)
                milestones.append(
                    {
                        "timestamp": utc_now_iso(),
                        "category": "pipeline",
                        "event": "dynamic_started",
                        "detail": f"PID={process_mon.sample_pid}",
                    }
                )
                end_deadline = time.monotonic() + duration
                while time.monotonic() < end_deadline:
                    process_mon.poll_once()
                    network_mon.poll_once(process_mon.tracked_pids)
                    memory_mon.poll_once(process_mon.tracked_pids)
                    remaining = end_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(poll_step, remaining))

                terminal_logger.info("[SANDBOX] Observation completed.")
                milestones.append(
                    {
                        "timestamp": utc_now_iso(),
                        "category": "pipeline",
                        "event": "dynamic_completed",
                        "detail": f"{duration}s",
                    }
                )

                # Capture process memory dumps while target processes are still alive.
                live_pids = process_mon.get_live_tracked_pids()
                memory_mon.capture_process_dumps(evidence_dir=evidence_dir, live_pids=live_pids)

                # Cleanly terminate only tracked sample processes.
                process_mon.terminate_tracked_processes()
                memory_mon.capture_full_memory_and_volatility(evidence_dir=evidence_dir)
            else:
                execution_skipped = False
                errors_log.error("Sample launch failed: %s", "; ".join(process_mon.result.errors))
        else:
            execution_skipped = True
            analysis_log.info("Dynamic execution declined by local operator; finalizing static evidence.")
            all_limitations.append("Dynamic sample execution skipped by local sandbox operator.")

        # 4. Stop collectors and export/correlate logs
        stage_callback("finalizing_evidence")
        terminal_logger.info("[SANDBOX] Finalizing evidence...")

        network_mon.stop()
        procmon_rows = procmon_session.stop_and_export(
            workspace_dir=workspace_dir, tracked_pids=process_mon.tracked_pids
        )

        eventlog_res, parsed_channels = eventlog_mon.collect(
            evidence_dir=evidence_dir, start_time_utc=dynamic_start_utc
        )
        collector_results["eventlog_monitor"] = eventlog_res
        sysmon_events = parsed_channels.get("sysmon", [])

        # Process monitor runs first so Sysmon EID 1 expands tracked_pids before network/FS/registry filtering.
        collector_results["process_monitor"] = process_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            skipped=execution_skipped,
        )
        # Re-filter exported Procmon CSV if Sysmon EID 1 added short-lived descendant PIDs.
        if procmon_session.csv_path and procmon_session.csv_path.is_file():
            procmon_rows = procmon_session.filter_exported_csv(process_mon.tracked_pids)

        collector_results["network_monitor"] = network_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            tracked_pids=process_mon.tracked_pids,
        )
        collector_results["memory_monitor"] = memory_mon.finalize(evidence_dir=evidence_dir)
        collector_results["filesystem_monitor"] = filesystem_mon.finalize(
            evidence_dir=evidence_dir,
            sample_run_dir=run_dir,
            sample_filename=sample_path.name,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            procmon_session=procmon_session,
            tracked_pids=process_mon.tracked_pids,
        )
        collector_results["registry_monitor"] = registry_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            tracked_pids=process_mon.tracked_pids,
        )

        # Log any collector errors/limitations into collectors.log and errors.log.
        tool_versions: dict[str, str] = {}
        collector_status_map: dict[str, Any] = {}
        for name, res in collector_results.items():
            collector_status_map[name] = res.to_dict()
            tool_versions.update(res.tool_versions)
            all_limitations.extend(res.limitations)
            collectors_log.info("Collector %s finished with status=%s", name, res.status)
            for err in res.errors:
                errors_log.error("[%s] %s", name, err)
            for lim in res.limitations:
                collectors_log.warning("[%s] limitation: %s", name, lim)

        end_time_utc = utc_now_iso()
        statuses = [res.status for res in collector_results.values()]
        if all(s == STATUS_FAILED for s in statuses):
            final_status = STATUS_FAILED
        elif any(s in (STATUS_FAILED, STATUS_PARTIAL, STATUS_UNAVAILABLE, STATUS_SKIPPED) for s in statuses):
            final_status = STATUS_PARTIAL
        else:
            final_status = STATUS_COMPLETED

        timeline = _build_timeline(evidence_dir=evidence_dir, milestones=milestones)
        write_json(evidence_dir / "timeline.json", {"event_count": len(timeline), "events": timeline})

        hashes_doc = _read_json_safe(evidence_dir / "static" / "hashes.json")
        pe_doc = _read_json_safe(evidence_dir / "static" / "pe_info.json")
        floss_doc = _read_json_safe(evidence_dir / "static" / "floss.json")
        capa_doc = _read_json_safe(evidence_dir / "static" / "capa.json")
        yara_doc = _read_json_safe(evidence_dir / "static" / "yara.json")
        ghidra_doc = _read_json_safe(evidence_dir / "ghidra" / "functions.json")
        proc_doc = _read_json_safe(evidence_dir / "dynamic" / "process" / "processes.json")
        net_doc = _read_json_safe(evidence_dir / "dynamic" / "network" / "connections.json")
        dns_doc = _read_json_safe(evidence_dir / "dynamic" / "network" / "dns.json")
        mem_doc = _read_json_safe(evidence_dir / "dynamic" / "memory" / "memory_usage.json")
        fs_doc = _read_json_safe(evidence_dir / "dynamic" / "filesystem" / "changes.json")
        reg_doc = _read_json_safe(evidence_dir / "dynamic" / "registry" / "changes.json")

        indicators = floss_doc.get("indicators", {})
        dynamic_dests = sorted(
            {
                f"{c.get('dst_ip')}:{c.get('dst_port')}"
                for c in net_doc.get("connections", [])
                if c.get("dst_ip")
            }
        )
        dynamic_dns = sorted(
            {q.get("query_name") for q in dns_doc.get("queries", []) if q.get("query_name")}
        )
        yara_rules = [m.get("rule") for m in yara_doc.get("matches", []) if m.get("rule")]

        summary_doc = {
            "job_id": job_id,
            "final_status": final_status,
            "sample": {
                "filename": sample_path.name,
                "size_bytes": hashes_doc.get("size_bytes", sample_path.stat().st_size),
                "md5": hashes_doc.get("md5"),
                "sha1": hashes_doc.get("sha1"),
                "sha256": sample_sha256,
                "file_type": hashes_doc.get("file_type"),
            },
            "static": {
                "architecture": pe_doc.get("architecture"),
                "section_count": pe_doc.get("number_of_sections", 0),
                "imported_dll_count": collector_results["file_metadata"].summary.get("imported_dll_count", 0),
                "exported_function_count": collector_results["file_metadata"].summary.get("exported_function_count", 0),
                "strings_source": floss_doc.get("source"),
                "string_count": floss_doc.get("total_extracted_strings", 0),
                "capa_capability_count": capa_doc.get("capability_count", 0),
                "yara_match_count": yara_doc.get("match_count", 0),
                "ghidra_function_count": len(ghidra_doc.get("functions", [])),
            },
            "dynamic": {
                "execution_skipped": execution_skipped,
                "root_sample_pid": proc_doc.get("root_sample_pid"),
                "observed_process_count": proc_doc.get("tracked_pid_count", 0),
                "process_event_count": collector_results["process_monitor"].summary.get("process_event_count", 0),
                "connection_event_count": net_doc.get("connection_count", 0),
                "dns_query_count": dns_doc.get("dns_query_count", 0),
                "has_pcapng": collector_results["network_monitor"].summary.get("has_pcapng", False),
                "filesystem_event_count": fs_doc.get("change_count", 0),
                "dropped_artifact_count": fs_doc.get("dropped_artifact_metadata_count", 0),
                "registry_event_count": reg_doc.get("change_count", 0),
                "persistence_indicator_count": reg_doc.get("persistence_indicator_count", 0),
                "ram_sample_count": mem_doc.get("sample_count", 0),
                "peak_system_memory_used_percent": mem_doc.get("peak_system_memory_used_percent", 0),
                "process_dump_count": collector_results["memory_monitor"].summary.get("process_dump_count", 0),
                "full_memory_status": collector_results["memory_monitor"].summary.get("full_memory_status"),
            },
            "potential_iocs": {
                "static_urls": indicators.get("urls", []),
                "static_domains": indicators.get("domains", []),
                "static_ips": indicators.get("ip_addresses", []),
                "dynamic_destinations": dynamic_dests,
                "dynamic_dns_queries": dynamic_dns,
                "yara_rules": yara_rules,
            },
        }
        write_json(evidence_dir / "summary.json", summary_doc)
        write_json(evidence_dir / "logs" / "tool_status.json", collector_status_map)

        manifest_skeleton = {
            "job_id": job_id,
            "sample_filename": sample_path.name,
            "sample_sha256": sample_sha256,
            "analysis_start_time": start_time_utc,
            "analysis_end_time": end_time_utc,
            "dynamic_observation_duration_seconds": 0 if execution_skipped else duration,
            "windows_version": platform.platform(),
            "tool_versions": tool_versions,
            "collector_status": {
                k: {"status": v["status"], "errors": v["errors"], "limitations": v["limitations"]}
                for k, v in collector_status_map.items()
            },
            "analysis_limitations": sorted(set(all_limitations)),
            "final_status": final_status,
            "evidence_file_inventory": [],
        }

        report_md = _build_report_markdown(summary=summary_doc, manifest=manifest_skeleton)
        (evidence_dir / "report.md").write_text(report_md, encoding="utf-8")

        analysis_log.info("Analysis finalized with status=%s", final_status)
        for h in log_handlers:
            h.flush()
            h.close()
            for lg_name in ("analysis", "collectors", "errors"):
                logging.getLogger(f"malbox.job.{job_id}.{lg_name}").removeHandler(h)

        inventory: list[dict[str, Any]] = []
        for item in sorted(evidence_dir.rglob("*")):
            if item.is_file():
                rel = item.relative_to(evidence_dir).as_posix()
                try:
                    info = compute_file_hashes(item)
                    inventory.append(
                        {"path": rel, "size_bytes": info["size_bytes"], "sha256": info["sha256"]}
                    )
                except OSError:
                    inventory.append({"path": rel, "size_bytes": item.stat().st_size, "sha256": ""})
        manifest_skeleton["evidence_file_inventory"] = inventory
        write_json(evidence_dir / "manifest.json", manifest_skeleton)

        terminal_logger.info("[SANDBOX] Packaging evidence...")
        stage_callback("packaging_evidence")
        zip_path = workspace_dir / f"evidence_{job_id}.zip"
        archive_sha256 = _package_evidence_zip(
            evidence_dir=evidence_dir, zip_path=zip_path, sample_filename=sample_path.name
        )

        return {
            "job_status": final_status,
            "zip_path": zip_path,
            "archive_sha256": archive_sha256,
            "error": None,
        }
    except Exception as exc:
        errors_log.exception("Fatal pipeline error: %s", exc)
        for h in log_handlers:
            try:
                h.flush()
                h.close()
            except Exception:
                pass
        # Package whatever partial evidence exists so Gateway/Client still receive diagnostic logs.
        zip_path = workspace_dir / f"evidence_{job_id}.zip"
        try:
            archive_sha256 = _package_evidence_zip(
                evidence_dir=evidence_dir, zip_path=zip_path, sample_filename=sample_path.name
            )
            return {
                "job_status": STATUS_FAILED,
                "zip_path": zip_path,
                "archive_sha256": archive_sha256,
                "error": str(exc),
            }
        except Exception as pkg_exc:
            return {
                "job_status": STATUS_FAILED,
                "zip_path": None,
                "archive_sha256": "",
                "error": f"{exc} (packaging failed: {pkg_exc})",
            }
