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
from collectors.attack_mapping import build_attack_mapping
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
        return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except ValueError:
        return {}


def _build_job_loggers(
    logs_dir: Path, job_id: str
) -> tuple[logging.Logger, logging.Logger, logging.Logger, list[logging.Handler]]:
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


def _close_job_loggers(job_id: str, log_handlers: list[logging.Handler]) -> None:
    for h in log_handlers:
        try:
            h.flush()
            h.close()
        except Exception:
            pass
        for lg_name in ("analysis", "collectors", "errors"):
            logging.getLogger(f"malbox.job.{job_id}.{lg_name}").removeHandler(h)


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


def _fmt_metric(value: Any, collector_status: str | None) -> str:
    if value is None:
        return f"Not collected (status: {collector_status or 'unavailable'})"
    return str(value)


def _build_report_markdown(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    sample = summary.get("sample", {})
    file_ident = sample.get("file_identification", {}) or {}
    static = summary.get("static", {})
    dynamic = summary.get("dynamic", {})
    statuses = summary.get("collector_statuses", {})
    iocs = summary.get("potential_iocs", {})
    attack_summary = summary.get("attack_mapping", {}) or {}
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
        f"- **File Type (magic/header):** {sample.get('file_type')}",
        f"- **Declared Extension / Format Family:** `{file_ident.get('declared_extension') or 'none'}` / `{file_ident.get('format_family') or 'unknown'}`",
        f"- **Format Extension Mismatch:** `{bool(file_ident.get('format_mismatch', False))}`"
        + (f" ({file_ident.get('format_mismatch_reason')})" if file_ident.get("format_mismatch_reason") else ""),
        f"- **MD5:** `{sample.get('md5')}`",
        f"- **SHA-1:** `{sample.get('sha1')}`",
        f"- **SHA-256:** `{sample.get('sha256')}`",
        f"- **Job Start / End (UTC):** `{manifest.get('analysis_start_time')}` -> `{manifest.get('analysis_end_time')}`",
        f"- **Dynamic Execution Status:** `{manifest.get('dynamic_execution_status')}`",
        f"- **Dynamic Observation Window (UTC):** `{manifest.get('dynamic_started_at') or 'N/A'}` -> `{manifest.get('dynamic_completed_at') or 'N/A'}`",
        f"- **Configured Observation Duration:** {manifest.get('configured_observation_duration_seconds')}s",
        f"- **Actual Observation Duration:** {manifest.get('actual_observation_duration_seconds')}s",
        f"- **Process Session Ended (UTC):** `{manifest.get('process_session_ended_at') or 'N/A'}`",
        f"- **Actual Process Session Duration:** {manifest.get('actual_process_session_duration_seconds')}s",
        f"- **Evidence Finalized (UTC):** `{manifest.get('evidence_finalized_at') or 'N/A'}`",
        f"- **Final Job Status:** `{manifest.get('final_status')}`",
        "",
        "## 2. Static Findings",
        f"- **PE Architecture:** {static.get('architecture') or 'N/A'}",
        f"- **PE Sections:** {_fmt_metric(static.get('section_count'), statuses.get('file_metadata'))}",
        f"- **Imported DLLs:** {_fmt_metric(static.get('imported_dll_count'), statuses.get('file_metadata'))}",
        f"- **Exported Functions:** {_fmt_metric(static.get('exported_function_count'), statuses.get('file_metadata'))}",
        f"- **Extracted Strings:** {_fmt_metric(static.get('string_count'), statuses.get('strings_floss'))} (source: `{static.get('strings_source') or 'N/A'}`)",
        f"- **CAPA Capabilities:** {_fmt_metric(static.get('capa_capability_count'), statuses.get('capa'))}",
        f"- **YARA Matches:** {_fmt_metric(static.get('yara_match_count'), statuses.get('yara'))}",
        f"- **Detect It Easy (optional):** {_fmt_metric(static.get('die_detections'), statuses.get('detect_it_easy'))}",
        f"- **Ghidra Functions:** {_fmt_metric(static.get('ghidra_function_count'), statuses.get('ghidra'))}",
        "",
        "## 3. Observed Process Activity",
        f"- **Root Sample PID:** {dynamic.get('root_sample_pid') if dynamic.get('root_sample_pid') is not None else 'N/A'}",
        f"- **Observed Processes:** {_fmt_metric(dynamic.get('observed_process_count'), statuses.get('process_monitor'))}",
        f"- **Process Events:** {_fmt_metric(dynamic.get('process_event_count'), statuses.get('process_monitor'))}",
        "",
        "## 4. Network Activity",
        f"- **Network Connection Events (total recorded):** {_fmt_metric(dynamic.get('connection_event_count'), statuses.get('network_monitor'))}",
        f"- **Sample-Attributed Connection Events:** {_fmt_metric(dynamic.get('sample_related_connection_count'), statuses.get('network_monitor'))}",
        f"- **Traffic Classification Counts:** {dynamic.get('network_classification') or 'N/A'}",
        f"- **DNS Queries Observed (total):** {_fmt_metric(dynamic.get('dns_query_count'), statuses.get('network_monitor'))}",
        f"- **PCAPNG Captured:** {dynamic.get('has_pcapng', False)}",
        "",
        "## 5. Filesystem Activity",
        f"- **Filesystem Events:** {_fmt_metric(dynamic.get('filesystem_event_count'), statuses.get('filesystem_monitor'))}",
        f"- **Dropped/Modified Artifact Metadata Entries:** {_fmt_metric(dynamic.get('dropped_artifact_count'), statuses.get('filesystem_monitor'))}",
        "",
        "## 6. Registry Activity",
        f"- **Registry Events:** {_fmt_metric(dynamic.get('registry_event_count'), statuses.get('registry_monitor'))}",
        f"- **Persistence-Related Registry Hits:** {_fmt_metric(dynamic.get('persistence_indicator_count'), statuses.get('registry_monitor'))}",
        "",
        "## 7. Memory Evidence",
        f"- **RAM Telemetry Samples:** {_fmt_metric(dynamic.get('ram_sample_count'), statuses.get('memory_monitor'))}",
        f"- **Peak System Memory Used (%):** {_fmt_metric(dynamic.get('peak_system_memory_used_percent'), statuses.get('memory_monitor'))}",
        f"- **Process Memory Dumps:** {_fmt_metric(dynamic.get('process_dump_count'), statuses.get('memory_monitor'))}",
        f"- **Full Physical Memory Status:** `{dynamic.get('full_memory_status', 'skipped')}`",
        "",
        "## 8. Potential Indicators of Compromise",
        f"- **Static URLs (string candidates):** {', '.join(iocs.get('static_urls', [])[:20]) or 'None observed'}",
        f"- **Static Domains (string candidates):** {', '.join(iocs.get('static_domains', [])[:20]) or 'None observed'}",
        f"- **Static IP Addresses (string candidates):** {', '.join(iocs.get('static_ips', [])[:20]) or 'None observed'}",
        f"- **Dynamic Sample-Attributed Destinations:** {', '.join(iocs.get('dynamic_destinations', [])[:20]) or 'None attributed to tracked sample'}",
        f"- **Dynamic Unattributed Destinations (review context):** {', '.join(iocs.get('dynamic_unattributed_destinations', [])[:20]) or 'None observed'}",
        f"- **Dynamic Sample-Attributed DNS Queries:** {', '.join(iocs.get('dynamic_dns_queries', [])[:20]) or 'None attributed to tracked sample'}",
        f"- **YARA Matched Rules:** {', '.join(iocs.get('yara_rules', [])[:20]) or 'None matched'}",
        "",
        "## 9. Analysis Limitations & Collector Status",
    ]

    for name, c_data in manifest.get("collector_status", {}).items():
        lines.append(f"- `{name}`: **{c_data.get('status')}**")

    if manifest.get("fatal_error"):
        lines.extend(["", "### Fatal Error", f"- {manifest.get('fatal_error')}"])

    lines.append("")
    if limitations:
        lines.append("### Limitations Recorded")
        for item in limitations:
            lines.append(f"- {item}")
    else:
        lines.append("- No collector limitations reported.")

    lines.extend(["", "## 10. Evidence-Backed MITRE ATT&CK Mapping"])
    if not attack_summary.get("enabled", True):
        lines.append("- ATT&CK mapping disabled by configuration (`enable_attack_mapping=false`).")
    else:
        top_techs = attack_summary.get("top_techniques") or []
        lines.append(
            f"- **Mapped Techniques:** {attack_summary.get('technique_count', 0)} "
            f"(counts: {attack_summary.get('counts_by_observation_type') or {}})"
        )
        if top_techs:
            for m in top_techs[:15]:
                srcs = ", ".join(m.get("evidence_sources") or [])
                lines.append(
                    f"- `{m.get('technique_id')}` {m.get('technique_name')} "
                    f"[{m.get('observation_type')}, confidence={m.get('confidence')}, sources={srcs}]"
                )
        else:
            lines.append("- No ATT&CK technique indicators or correlated behaviors mapped.")

    lines.append("")
    return "\n".join(lines)


COLLECTOR_CLASSIFICATION: dict[str, str] = {
    "file_metadata": "mandatory_static",
    "strings_floss": "mandatory_static_with_fallback",
    "capa": "mandatory_static",
    "yara": "mandatory_static",
    "detect_it_easy": "optional_static",
    "ghidra": "conditional_static",
    "process_monitor": "mandatory_dynamic",
    "network_monitor": "mandatory_dynamic",
    "filesystem_monitor": "mandatory_dynamic",
    "registry_monitor": "mandatory_dynamic",
    "eventlog_monitor": "mandatory_dynamic",
    "memory_monitor": "mandatory_dynamic_telemetry_optional_dumps",
}


def _should_archive_file(
    rel_path: str,
    file_path: Path,
    sample_filename: str,
    include_raw_pml: bool,
    max_raw_pml_bytes: int,
) -> tuple[bool, str | None]:
    """Single source of truth deciding what goes into both manifest inventory and ZIP archive."""
    if file_path.name == sample_filename and not rel_path.startswith("ghidra/"):
        return False, "original_sample_excluded"
    if rel_path.startswith("dynamic/filesystem/dropped_files/"):
        return False, "dropped_binary_excluded"
    if not rel_path.startswith(("logs/", "static/", "ghidra/")) and file_path.suffix.lower() in EXECUTABLE_EXTENSIONS:
        return False, "executable_artifact_excluded"
    if rel_path == "raw/procmon.pml":
        if not include_raw_pml:
            return False, "omitted_by_config_include_raw_pml_false"
        try:
            if file_path.stat().st_size > max_raw_pml_bytes:
                return False, "omitted_exceeded_max_raw_pml_mb"
        except OSError:
            return False, "omitted_stat_failed"
    return True, None


def _build_inventory(
    evidence_dir: Path,
    sample_filename: str = "",
    include_raw_pml: bool = True,
    max_raw_pml_bytes: int = 200 * 1024 * 1024,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build exact archive-aligned file inventory and explicit omitted/excluded list."""
    inventory: list[dict[str, Any]] = []
    omitted: list[dict[str, Any]] = []
    for item in sorted(evidence_dir.rglob("*")):
        if not item.is_file():
            continue
        rel = item.relative_to(evidence_dir).as_posix()
        # Self-reference exception: manifest.json is packaged in the ZIP archive,
        # but cannot contain its own final SHA-256 digest without invalidating itself.
        if rel == "manifest.json":
            continue
        allowed, reason = _should_archive_file(
            rel_path=rel,
            file_path=item,
            sample_filename=sample_filename,
            include_raw_pml=include_raw_pml,
            max_raw_pml_bytes=max_raw_pml_bytes,
        )
        try:
            size_b = item.stat().st_size
        except OSError:
            size_b = 0
        if not allowed:
            omitted.append({"path": rel, "size_bytes": size_b, "reason": reason})
            continue
        try:
            info = compute_file_hashes(item)
            inventory.append({"path": rel, "size_bytes": info["size_bytes"], "sha256": info["sha256"]})
        except OSError:
            omitted.append({"path": rel, "size_bytes": size_b, "reason": "unreadable_for_digest"})
    return inventory, omitted


def _reconcile_collector_artifacts(
    collector_status: dict[str, Any],
    archived_paths: set[str],
    omitted_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Ensure collector artifact lists distinguish packaged files from omitted files cleanly."""
    omitted_lookup = {entry["path"]: entry.get("reason", "omitted") for entry in omitted_entries}
    reconciled: dict[str, Any] = {}
    for cname, cdata in collector_status.items():
        orig_arts = list(cdata.get("artifacts", []))
        packaged = [p for p in orig_arts if p in archived_paths or p == "manifest.json"]
        omitted = [
            {"path": p, "reason": omitted_lookup.get(p, "not_packaged_in_zip")}
            for p in orig_arts
            if p not in archived_paths and p != "manifest.json"
        ]
        updated = dict(cdata)
        updated["artifacts"] = packaged
        if omitted:
            updated["omitted_artifacts"] = omitted
        reconciled[cname] = updated
    return reconciled


def _package_evidence_zip(
    evidence_dir: Path,
    zip_path: Path,
    sample_filename: str,
    include_raw_pml: bool = False,
    max_raw_pml_bytes: int = 200 * 1024 * 1024,
) -> str:
    """Stream eligible evidence files into a ZIP archive strictly matching _should_archive_file."""
    digest = hashlib.sha256()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for file_path in sorted(evidence_dir.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(evidence_dir).as_posix()
            allowed, _ = _should_archive_file(
                rel_path=rel_path,
                file_path=file_path,
                sample_filename=sample_filename,
                include_raw_pml=include_raw_pml,
                max_raw_pml_bytes=max_raw_pml_bytes,
            )
            if not allowed:
                continue
            zf.write(file_path, arcname=rel_path)

    with zip_path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _metric_if_collected(
    collector_results: dict[str, CollectorResult],
    collector_name: str,
    value: Any,
    collected_flag: bool | None = None,
) -> Any:
    """Return value only when the collector ran; otherwise None to distinguish 0 from uncollected."""
    res = collector_results.get(collector_name)
    if res is None:
        return None
    if res.status in (STATUS_UNAVAILABLE, STATUS_FAILED, STATUS_SKIPPED):
        return None
    if collected_flag is False:
        return None
    return value


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

    configured_duration = int(config.get("observation_duration_seconds", 120))
    actual_duration_seconds = 0.0
    obs_start_mono: float | None = None
    dynamic_execution_status = "not_started"
    dynamic_started_at = ""
    dynamic_completed_at = ""
    evidence_finalized_at = ""
    process_session_ended_at = ""
    actual_process_session_duration_seconds = 0.0

    collector_results: dict[str, CollectorResult] = {}
    all_limitations: list[str] = []

    analysis_log: logging.Logger | None = None
    collectors_log: logging.Logger | None = None
    errors_log: logging.Logger | None = None
    log_handlers: list[logging.Handler] = []

    process_mon: ProcessMonitor | None = None
    network_mon: NetworkMonitor | None = None
    memory_mon: MemoryMonitor | None = None
    procmon_session: ProcmonSession | None = None
    dynamic_terminated = False
    network_stopped = False

    try:
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
        analysis_log.info(
            "Starting job %s for sample %s (SHA-256: %s)", job_id, sample_path.name, sample_sha256
        )
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
            {
                "timestamp": utc_now_iso(),
                "category": "pipeline",
                "event": "static_completed",
                "detail": job_id,
            }
        )

        # 2. Start dynamic collectors BEFORE sample execution
        terminal_logger.info("[SANDBOX] Starting evidence collectors...")
        stage_callback("starting_collectors")
        dynamic_window_utc = utc_now_iso()

        process_mon = ProcessMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        network_mon = NetworkMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        memory_mon = MemoryMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        procmon_session = ProcmonSession(config=config, base_dir=base_dir, logger=collectors_log)
        filesystem_mon = FilesystemMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        registry_mon = RegistryMonitor(config=config, base_dir=base_dir, logger=collectors_log)
        eventlog_mon = EventLogMonitor(config=config, base_dir=base_dir, logger=collectors_log)

        process_mon.start_baseline()
        filesystem_mon.deploy_canary_fixtures(workspace_dir / "run")
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

        poll_step = float(config.get("poll_sample_interval_seconds", 0.5))
        run_dir = workspace_dir / "run"
        execution_skipped = False
        launch_failed = False

        if approved:
            stage_callback("dynamic_observation")
            launched = process_mon.launch_sample(sample_path=sample_path, run_dir=run_dir)
            if launched:
                dynamic_execution_status = "running"
                dynamic_started_at = utc_now_iso()
                obs_start_mono = time.monotonic()
                terminal_logger.info("[SANDBOX] Dynamic observation started.")
                terminal_logger.info(
                    "[SANDBOX] Observation duration: %d seconds.", configured_duration
                )
                milestones.append(
                    {
                        "timestamp": dynamic_started_at,
                        "category": "pipeline",
                        "event": "dynamic_started",
                        "detail": f"PID={process_mon.sample_pid}",
                    }
                )
                end_deadline = obs_start_mono + configured_duration
                while time.monotonic() < end_deadline:
                    process_mon.poll_once()
                    network_mon.poll_once(process_mon.tracked_pids)
                    memory_mon.poll_once(process_mon.tracked_pids)
                    remaining = end_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(poll_step, remaining))

                actual_duration_seconds = round(time.monotonic() - obs_start_mono, 2)
                dynamic_completed_at = utc_now_iso()
                dynamic_execution_status = "completed"
                terminal_logger.info("[SANDBOX] Observation completed.")
                milestones.append(
                    {
                        "timestamp": dynamic_completed_at,
                        "category": "pipeline",
                        "event": "dynamic_completed",
                        "detail": f"actual={actual_duration_seconds}s (configured={configured_duration}s)",
                    }
                )

                # Capture process memory dumps while target processes are still alive.
                live_pids = process_mon.get_live_tracked_pids()
                memory_mon.capture_process_dumps(evidence_dir=evidence_dir, live_pids=live_pids)

                # Cleanly terminate only tracked sample processes.
                process_mon.terminate_tracked_processes()
                dynamic_terminated = True
                memory_mon.capture_full_memory_and_volatility(evidence_dir=evidence_dir)
            else:
                launch_failed = True
                dynamic_execution_status = "launch_failed"
                actual_duration_seconds = 0.0
                err_detail = "; ".join(process_mon.result.errors) or "Sample failed to start."
                errors_log.error("Sample launch failed: %s", err_detail)
                all_limitations.append(f"Dynamic observation did not start: {err_detail}")
        else:
            execution_skipped = True
            dynamic_execution_status = "skipped"
            actual_duration_seconds = 0.0
            analysis_log.info("Dynamic execution declined by local operator; finalizing static evidence.")
            all_limitations.append("Dynamic sample execution skipped by local sandbox operator.")

        # 4. Stop collectors and export/correlate logs
        stage_callback("finalizing_evidence")
        terminal_logger.info("[SANDBOX] Finalizing evidence...")

        network_mon.stop()
        network_stopped = True

        non_executed = execution_skipped or launch_failed
        skip_reason = (
            "Dynamic execution declined by local operator."
            if execution_skipped
            else ("Dynamic observation did not run because sample launch failed." if launch_failed else "")
        )

        if non_executed:
            procmon_session.terminate_only()
            procmon_rows: list[dict[str, str]] = []
        else:
            procmon_rows = procmon_session.stop_and_export(
                workspace_dir=workspace_dir, tracked_pids=process_mon.tracked_pids
            )

        eventlog_res, parsed_channels, sysmon_available = eventlog_mon.collect(
            evidence_dir=evidence_dir,
            start_time_utc=dynamic_window_utc,
            skipped=non_executed,
            skip_reason=skip_reason,
        )
        collector_results["eventlog_monitor"] = eventlog_res
        sysmon_events = parsed_channels.get("sysmon", [])

        # Process monitor runs first so Sysmon EID 1 expands tracked_pids before network/FS/registry filtering.
        collector_results["process_monitor"] = process_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            sysmon_available=sysmon_available,
            skipped=execution_skipped,
            launch_failed=launch_failed,
            skip_reason=skip_reason,
        )
        # Re-filter exported Procmon CSV if Sysmon EID 1 added short-lived descendant PIDs.
        if (
            not non_executed
            and procmon_session.csv_path
            and procmon_session.csv_path.is_file()
        ):
            procmon_rows = procmon_session.filter_exported_csv(process_mon.tracked_pids)

        collector_results["network_monitor"] = network_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            tracked_pids=process_mon.tracked_pids,
            sysmon_available=sysmon_available,
            skipped=non_executed,
            skip_reason=skip_reason,
        )
        collector_results["memory_monitor"] = memory_mon.finalize(
            evidence_dir=evidence_dir,
            skipped=non_executed,
            skip_reason=skip_reason,
        )
        collector_results["filesystem_monitor"] = filesystem_mon.finalize(
            evidence_dir=evidence_dir,
            sample_run_dir=run_dir,
            sample_filename=sample_path.name,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            procmon_session=procmon_session,
            tracked_pids=process_mon.tracked_pids,
            sysmon_available=sysmon_available,
            skipped=non_executed,
            skip_reason=skip_reason,
        )
        collector_results["registry_monitor"] = registry_mon.finalize(
            evidence_dir=evidence_dir,
            sysmon_events=sysmon_events,
            procmon_rows=procmon_rows,
            tracked_pids=process_mon.tracked_pids,
            sysmon_available=sysmon_available,
            procmon_available=procmon_session.exported_ok,
            skipped=non_executed,
            skip_reason=skip_reason,
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

        include_raw_pml = bool(config.get("include_raw_pml", False))
        max_raw_pml_bytes = max(1, int(config.get("max_raw_pml_mb", 200))) * 1024 * 1024

        status_buckets: dict[str, list[str]] = {
            STATUS_COMPLETED: [],
            STATUS_PARTIAL: [],
            STATUS_FAILED: [],
            STATUS_SKIPPED: [],
            STATUS_UNAVAILABLE: [],
        }
        for cname, c_res in collector_results.items():
            status_buckets.setdefault(c_res.status, []).append(cname)

        disabled_optional_features: list[str] = []
        if not include_raw_pml:
            disabled_optional_features.append("include_raw_pml=false")
        if not bool(config.get("winpmem_enabled", False)):
            disabled_optional_features.append("winpmem_enabled=false")
        if not bool(config.get("procdump_enabled", True)):
            disabled_optional_features.append("procdump_enabled=false")

        optional_collectors_unavailable = [
            cname
            for cname, c_res in collector_results.items()
            if COLLECTOR_CLASSIFICATION.get(cname) == "optional_static" and c_res.status == STATUS_UNAVAILABLE
        ]
        if optional_collectors_unavailable:
            disabled_optional_features.extend(
                f"{cname}=unavailable" for cname in optional_collectors_unavailable
            )
        enable_attack_mapping = bool(config.get("enable_attack_mapping", True))
        if not enable_attack_mapping:
            disabled_optional_features.append("enable_attack_mapping=false")

        required_statuses = [
            res.status
            for cname, res in collector_results.items()
            if not (COLLECTOR_CLASSIFICATION.get(cname) == "optional_static" and res.status == STATUS_UNAVAILABLE)
        ]
        statuses = required_statuses or [res.status for res in collector_results.values()]
        if all(s in (STATUS_FAILED, STATUS_UNAVAILABLE) for s in statuses) or (
            launch_failed and process_mon.result.status == STATUS_FAILED and not status_buckets[STATUS_COMPLETED]
        ):
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
        die_doc = _read_json_safe(evidence_dir / "static" / "die.json")
        ghidra_doc = _read_json_safe(evidence_dir / "ghidra" / "functions.json")
        proc_doc = _read_json_safe(evidence_dir / "dynamic" / "process" / "processes.json")
        proc_events_doc = _read_json_safe(evidence_dir / "dynamic" / "process" / "process_events.json")
        net_doc = _read_json_safe(evidence_dir / "dynamic" / "network" / "connections.json")
        dns_doc = _read_json_safe(evidence_dir / "dynamic" / "network" / "dns.json")
        mem_doc = _read_json_safe(evidence_dir / "dynamic" / "memory" / "memory_usage.json")
        fs_doc = _read_json_safe(evidence_dir / "dynamic" / "filesystem" / "changes.json")
        reg_doc = _read_json_safe(evidence_dir / "dynamic" / "registry" / "changes.json")

        if enable_attack_mapping:
            attack_doc = build_attack_mapping(
                pe_doc=pe_doc,
                floss_doc=floss_doc,
                capa_doc=capa_doc,
                yara_doc=yara_doc,
                die_doc=die_doc,
                proc_doc=proc_doc,
                proc_events_doc=proc_events_doc,
                net_doc=net_doc,
                dns_doc=dns_doc,
                fs_doc=fs_doc,
                reg_doc=reg_doc,
                sysmon_events=sysmon_events,
            )
            write_json(evidence_dir / "attack_mapping.json", attack_doc)
        else:
            attack_doc = {
                "schema_version": "1.0",
                "disabled_by_config": True,
                "technique_count": 0,
                "counts_by_observation_type": {},
                "mappings": [],
                "limitations": ["ATT&CK mapping disabled by config (enable_attack_mapping=false)."],
            }

        indicators = floss_doc.get("indicators", {})
        net_conns = net_doc.get("connections", [])
        dynamic_dests = sorted(
            {
                f"{c.get('dst_ip')}:{c.get('dst_port')}"
                for c in net_conns
                if c.get("dst_ip") and c.get("classification", "sample_related_traffic") == "sample_related_traffic"
            }
        )
        dynamic_unattr_dests = sorted(
            {
                f"{c.get('dst_ip')}:{c.get('dst_port')}"
                for c in net_conns
                if c.get("dst_ip") and c.get("classification") == "unattributed_traffic"
            }
        )
        dynamic_dns = sorted(
            {
                q.get("query_name")
                for q in dns_doc.get("queries", [])
                if q.get("query_name") and q.get("classification", "sample_related_traffic") == "sample_related_traffic"
            }
        )
        yara_rules = [m.get("rule") for m in yara_doc.get("matches", []) if m.get("rule")]

        collector_statuses_short = {k: v["status"] for k, v in collector_status_map.items()}
        process_session_ended_at = str(
            proc_doc.get("termination_report", {}).get("process_session_ended_at")
            or process_mon.process_session_ended_at
            or ""
        )
        actual_process_session_duration_seconds = float(
            proc_doc.get("termination_report", {}).get("process_session_duration_seconds")
            or process_mon.process_session_duration_seconds
            or 0.0
        )
        evidence_finalized_at = utc_now_iso()

        summary_doc = {
            "job_id": job_id,
            "final_status": final_status,
            "collector_statuses": collector_statuses_short,
            "collector_status_buckets": status_buckets,
            "disabled_optional_features": disabled_optional_features,
            "timing": {
                "analysis_start_time": start_time_utc,
                "dynamic_started_at": dynamic_started_at or None,
                "dynamic_completed_at": dynamic_completed_at or None,
                "process_session_ended_at": process_session_ended_at or None,
                "evidence_finalized_at": evidence_finalized_at,
                "configured_observation_duration_seconds": configured_duration,
                "actual_observation_duration_seconds": actual_duration_seconds,
                "actual_process_session_duration_seconds": actual_process_session_duration_seconds,
                "dynamic_execution_status": dynamic_execution_status,
            },
            "sample": {
                "filename": sample_path.name,
                "size_bytes": hashes_doc.get("size_bytes", sample_path.stat().st_size),
                "md5": hashes_doc.get("md5"),
                "sha1": hashes_doc.get("sha1"),
                "sha256": sample_sha256,
                "file_type": hashes_doc.get("file_type"),
                "file_identification": hashes_doc.get("file_identification", {}),
            },
            "static": {
                "architecture": pe_doc.get("architecture"),
                "section_count": _metric_if_collected(
                    collector_results, "file_metadata", pe_doc.get("number_of_sections")
                ),
                "imported_dll_count": _metric_if_collected(
                    collector_results,
                    "file_metadata",
                    collector_results["file_metadata"].summary.get("imported_dll_count"),
                ),
                "exported_function_count": _metric_if_collected(
                    collector_results,
                    "file_metadata",
                    collector_results["file_metadata"].summary.get("exported_function_count"),
                ),
                "strings_source": floss_doc.get("source"),
                "string_count": _metric_if_collected(
                    collector_results, "strings_floss", floss_doc.get("total_extracted_strings")
                ),
                "capa_capability_count": _metric_if_collected(
                    collector_results, "capa", capa_doc.get("capability_count")
                ),
                "yara_match_count": _metric_if_collected(
                    collector_results, "yara", yara_doc.get("match_count")
                ),
                "die_detections": _metric_if_collected(
                    collector_results, "detect_it_easy", die_doc.get("detection_count")
                ),
                "optional_collectors_unavailable": optional_collectors_unavailable,
                "ghidra_function_count": _metric_if_collected(
                    collector_results,
                    "ghidra",
                    ghidra_doc.get("total_function_count", len(ghidra_doc.get("functions", []))) if ghidra_doc else None,
                ),
                "ghidra_mcp": collector_results["ghidra"].summary.get("ghidra_mcp"),
            },
            "dynamic": {
                "execution_skipped": execution_skipped,
                "launch_failed": launch_failed,
                "dynamic_execution_status": dynamic_execution_status,
                "root_sample_pid": proc_doc.get("root_sample_pid"),
                "observed_process_count": _metric_if_collected(
                    collector_results,
                    "process_monitor",
                    proc_doc.get("tracked_pid_count"),
                    proc_doc.get("collected"),
                ),
                "process_event_count": _metric_if_collected(
                    collector_results,
                    "process_monitor",
                    collector_results["process_monitor"].summary.get("process_event_count"),
                    proc_doc.get("collected"),
                ),
                "connection_event_count": _metric_if_collected(
                    collector_results,
                    "network_monitor",
                    net_doc.get("connection_count"),
                    net_doc.get("collected"),
                ),
                "sample_related_connection_count": _metric_if_collected(
                    collector_results,
                    "network_monitor",
                    net_doc.get("classification_summary", {}).get("sample_related_traffic"),
                    net_doc.get("collected"),
                ),
                "network_classification": net_doc.get("classification_summary"),
                "dns_query_count": _metric_if_collected(
                    collector_results,
                    "network_monitor",
                    dns_doc.get("dns_query_count"),
                    dns_doc.get("collected"),
                ),
                "has_pcapng": collector_results["network_monitor"].summary.get("has_pcapng", False),
                "filesystem_event_count": _metric_if_collected(
                    collector_results,
                    "filesystem_monitor",
                    fs_doc.get("change_count"),
                    fs_doc.get("collected"),
                ),
                "dropped_artifact_count": _metric_if_collected(
                    collector_results,
                    "filesystem_monitor",
                    fs_doc.get("dropped_artifact_metadata_count"),
                    fs_doc.get("collected"),
                ),
                "registry_event_count": _metric_if_collected(
                    collector_results,
                    "registry_monitor",
                    reg_doc.get("change_count"),
                    reg_doc.get("collected"),
                ),
                "persistence_indicator_count": _metric_if_collected(
                    collector_results,
                    "registry_monitor",
                    reg_doc.get("persistence_indicator_count"),
                    reg_doc.get("collected"),
                ),
                "ram_sample_count": _metric_if_collected(
                    collector_results,
                    "memory_monitor",
                    mem_doc.get("sample_count"),
                    mem_doc.get("collected"),
                ),
                "peak_system_memory_used_percent": _metric_if_collected(
                    collector_results,
                    "memory_monitor",
                    mem_doc.get("peak_system_memory_used_percent"),
                    mem_doc.get("collected"),
                ),
                "process_dump_count": _metric_if_collected(
                    collector_results,
                    "memory_monitor",
                    collector_results["memory_monitor"].summary.get("process_dump_count"),
                    mem_doc.get("collected"),
                ),
                "full_memory_status": collector_results["memory_monitor"].summary.get(
                    "full_memory_status", "skipped"
                ),
            },
            "potential_iocs": {
                "note": "Static string indicators are unverified offline candidates; dynamic_destinations excludes control_traffic and OS background_traffic.",
                "static_urls": indicators.get("urls", []),
                "static_domains": indicators.get("domains", []),
                "static_ips": indicators.get("ip_addresses", []),
                "dynamic_destinations": dynamic_dests,
                "dynamic_unattributed_destinations": dynamic_unattr_dests,
                "dynamic_dns_queries": dynamic_dns,
                "yara_rules": yara_rules,
            },
            "attack_mapping": {
                "enabled": enable_attack_mapping,
                "technique_count": attack_doc.get("technique_count", 0),
                "counts_by_observation_type": attack_doc.get("counts_by_observation_type", {}),
                "artifact": "attack_mapping.json" if enable_attack_mapping else None,
                "top_techniques": [
                    {
                        "technique_id": m.get("technique_id"),
                        "technique_name": m.get("technique_name"),
                        "tactic": m.get("tactic"),
                        "observation_type": m.get("observation_type"),
                        "confidence": m.get("confidence"),
                        "evidence_sources": m.get("evidence_sources", []),
                    }
                    for m in (attack_doc.get("mappings") or [])[:15]
                ],
            },
        }
        write_json(evidence_dir / "summary.json", summary_doc)
        write_json(evidence_dir / "logs" / "tool_status.json", collector_status_map)

        end_time_utc = utc_now_iso()
        manifest_skeleton = {
            "job_id": job_id,
            "sample_filename": sample_path.name,
            "sample_sha256": sample_sha256,
            "analysis_start_time": start_time_utc,
            "analysis_end_time": end_time_utc,
            "dynamic_started_at": dynamic_started_at or None,
            "dynamic_completed_at": dynamic_completed_at or None,
            "process_session_ended_at": process_session_ended_at or None,
            "evidence_finalized_at": evidence_finalized_at,
            "configured_observation_duration_seconds": configured_duration,
            "actual_observation_duration_seconds": actual_duration_seconds,
            "actual_process_session_duration_seconds": actual_process_session_duration_seconds,
            "dynamic_observation_duration_seconds": actual_duration_seconds,
            "dynamic_execution_status": dynamic_execution_status,
            "restore_required": True,
            "windows_version": platform.platform(),
            "tool_versions": tool_versions,
            "archive_policy": {
                "include_raw_pml": include_raw_pml,
                "max_raw_pml_mb": int(config.get("max_raw_pml_mb", 200)),
            },
            "collector_classification": COLLECTOR_CLASSIFICATION,
            "collector_status_buckets": status_buckets,
            "disabled_optional_features": disabled_optional_features,
            "collector_status": {
                k: {
                    "status": v["status"],
                    "classification": COLLECTOR_CLASSIFICATION.get(k, "conditional"),
                    "errors": v["errors"],
                    "limitations": v["limitations"],
                    "artifacts": v["artifacts"],
                }
                for k, v in collector_status_map.items()
            },
            "analysis_limitations": sorted(set(all_limitations)),
            "final_status": final_status,
            "evidence_file_inventory_note": (
                "Inventory strictly lists artifacts packaged into the returned ZIP archive, excluding "
                "manifest.json itself (self-reference exception: manifest.json is included in the ZIP "
                "archive but cannot contain its own final SHA-256 digest)."
            ),
            "manifest_self_reference": {
                "path": "manifest.json",
                "packaged_in_zip": True,
                "included_in_hash_inventory": False,
                "reason": "Self-reference exception: writing manifest.json alters its own byte size and SHA-256 digest.",
            },
            "evidence_file_inventory": [],
            "excluded_or_omitted_files": [],
        }

        report_md = _build_report_markdown(summary=summary_doc, manifest=manifest_skeleton)
        (evidence_dir / "report.md").write_text(report_md, encoding="utf-8")

        analysis_log.info("Analysis finalized with status=%s", final_status)
        _close_job_loggers(job_id, log_handlers)

        inv, omitted = _build_inventory(
            evidence_dir=evidence_dir,
            sample_filename=sample_path.name,
            include_raw_pml=include_raw_pml,
            max_raw_pml_bytes=max_raw_pml_bytes,
        )
        archived_paths = {entry["path"] for entry in inv}
        manifest_skeleton["collector_status"] = _reconcile_collector_artifacts(
            manifest_skeleton["collector_status"],
            archived_paths=archived_paths,
            omitted_entries=omitted,
        )
        manifest_skeleton["evidence_file_inventory"] = inv
        manifest_skeleton["excluded_or_omitted_files"] = omitted
        write_json(evidence_dir / "manifest.json", manifest_skeleton)

        terminal_logger.info("[SANDBOX] Packaging evidence...")
        stage_callback("packaging_evidence")
        zip_path = workspace_dir / f"evidence_{job_id}.zip"
        archive_sha256 = _package_evidence_zip(
            evidence_dir=evidence_dir,
            zip_path=zip_path,
            sample_filename=sample_path.name,
            include_raw_pml=include_raw_pml,
            max_raw_pml_bytes=max_raw_pml_bytes,
        )

        return {
            "job_status": final_status,
            "zip_path": zip_path,
            "archive_sha256": archive_sha256,
            "error": None,
        }
    except Exception as exc:
        if obs_start_mono is not None and actual_duration_seconds == 0.0:
            actual_duration_seconds = round(time.monotonic() - obs_start_mono, 2)
        if dynamic_execution_status == "running":
            dynamic_execution_status = "interrupted"

        if errors_log is not None:
            errors_log.exception("Fatal pipeline error: %s", exc)
        else:
            terminal_logger.error("[ERROR] Fatal pipeline error before logger initialization: %s", exc)

        # Clean up any active child processes, dumpcap, and Procmon locks before packaging partial evidence.
        if process_mon is not None and not dynamic_terminated:
            try:
                process_mon.terminate_tracked_processes()
                process_session_ended_at = process_mon.process_session_ended_at or utc_now_iso()
                actual_process_session_duration_seconds = process_mon.process_session_duration_seconds
            except Exception as cleanup_exc:
                if errors_log is not None:
                    errors_log.error("Process cleanup failed: %s", cleanup_exc)
        if network_mon is not None and not network_stopped:
            try:
                network_mon.stop()
            except Exception as cleanup_exc:
                if errors_log is not None:
                    errors_log.error("Network capture cleanup failed: %s", cleanup_exc)
        if procmon_session is not None:
            try:
                procmon_session.terminate_only()
            except Exception as cleanup_exc:
                if errors_log is not None:
                    errors_log.error("Procmon cleanup failed: %s", cleanup_exc)

        end_time_utc = utc_now_iso()
        collector_status_map = {k: v.to_dict() for k, v in collector_results.items()}

        _close_job_loggers(job_id, log_handlers)

        try:
            include_raw_pml = bool(config.get("include_raw_pml", False))
            max_raw_pml_bytes = max(1, int(config.get("max_raw_pml_mb", 200))) * 1024 * 1024
            (evidence_dir / "logs").mkdir(parents=True, exist_ok=True)
            write_json(evidence_dir / "logs" / "tool_status.json", collector_status_map)

            existing_summary = _read_json_safe(evidence_dir / "summary.json")
            failure_summary = existing_summary if isinstance(existing_summary, dict) else {}
            failure_summary.update(
                {
                    "job_id": job_id,
                    "final_status": STATUS_FAILED,
                    "fatal_error": str(exc),
                    "collector_statuses": {k: v["status"] for k, v in collector_status_map.items()},
                }
            )
            failure_timing = dict(failure_summary.get("timing") or {})
            failure_timing.update(
                {
                    "analysis_start_time": start_time_utc,
                    "dynamic_started_at": dynamic_started_at or None,
                    "dynamic_completed_at": dynamic_completed_at or None,
                    "process_session_ended_at": process_session_ended_at or None,
                    "evidence_finalized_at": end_time_utc,
                    "configured_observation_duration_seconds": configured_duration,
                    "actual_observation_duration_seconds": actual_duration_seconds,
                    "actual_process_session_duration_seconds": actual_process_session_duration_seconds,
                    "dynamic_execution_status": dynamic_execution_status,
                }
            )
            failure_summary["timing"] = failure_timing
            if "sample" not in failure_summary or not isinstance(failure_summary.get("sample"), dict):
                try:
                    sample_size = sample_path.stat().st_size
                except OSError:
                    sample_size = None
                failure_summary["sample"] = {
                    "filename": sample_path.name,
                    "size_bytes": sample_size,
                    "sha256": sample_sha256,
                }
            write_json(evidence_dir / "summary.json", failure_summary)

            failure_manifest: dict[str, Any] = {
                "job_id": job_id,
                "sample_filename": sample_path.name,
                "sample_sha256": sample_sha256,
                "analysis_start_time": start_time_utc,
                "analysis_end_time": end_time_utc,
                "dynamic_started_at": dynamic_started_at or None,
                "dynamic_completed_at": dynamic_completed_at or None,
                "process_session_ended_at": process_session_ended_at or None,
                "evidence_finalized_at": end_time_utc,
                "configured_observation_duration_seconds": configured_duration,
                "actual_observation_duration_seconds": actual_duration_seconds,
                "actual_process_session_duration_seconds": actual_process_session_duration_seconds,
                "dynamic_observation_duration_seconds": actual_duration_seconds,
                "dynamic_execution_status": dynamic_execution_status,
                "restore_required": True,
                "windows_version": platform.platform(),
                "archive_policy": {
                    "include_raw_pml": include_raw_pml,
                    "max_raw_pml_mb": max(1, int(config.get("max_raw_pml_mb", 200))),
                },
                "collector_classification": COLLECTOR_CLASSIFICATION,
                "collector_status": {
                    k: {
                        "status": v["status"],
                        "classification": COLLECTOR_CLASSIFICATION.get(k, "conditional"),
                        "errors": v["errors"],
                        "limitations": v["limitations"],
                        "artifacts": v["artifacts"],
                    }
                    for k, v in collector_status_map.items()
                },
                "analysis_limitations": sorted(set(all_limitations + [f"Fatal error: {exc}"])),
                "fatal_error": str(exc),
                "final_status": STATUS_FAILED,
                "evidence_file_inventory_note": (
                    "Inventory strictly lists artifacts packaged into the returned ZIP archive, excluding "
                    "manifest.json itself (self-reference exception: manifest.json is included in the ZIP "
                    "archive but cannot contain its own final SHA-256 digest)."
                ),
                "manifest_self_reference": {
                    "path": "manifest.json",
                    "packaged_in_zip": True,
                    "included_in_hash_inventory": False,
                    "reason": "Self-reference exception: writing manifest.json alters its own byte size and SHA-256 digest.",
                },
                "evidence_file_inventory": [],
                "excluded_or_omitted_files": [],
            }
            failure_report_md = _build_report_markdown(summary=failure_summary, manifest=failure_manifest)
            (evidence_dir / "report.md").write_text(failure_report_md, encoding="utf-8")

            inv_fail, omitted_fail = _build_inventory(
                evidence_dir=evidence_dir,
                sample_filename=sample_path.name,
                include_raw_pml=include_raw_pml,
                max_raw_pml_bytes=max_raw_pml_bytes,
            )
            archived_fail_paths = {entry["path"] for entry in inv_fail}
            failure_manifest["collector_status"] = _reconcile_collector_artifacts(
                failure_manifest["collector_status"],
                archived_paths=archived_fail_paths,
                omitted_entries=omitted_fail,
            )
            failure_manifest["evidence_file_inventory"] = inv_fail
            failure_manifest["excluded_or_omitted_files"] = omitted_fail
            write_json(evidence_dir / "manifest.json", failure_manifest)
        except OSError as io_exc:
            terminal_logger.error("[ERROR] Could not write failure artifacts to %s: %s", evidence_dir, io_exc)

        zip_path = workspace_dir / f"evidence_{job_id}.zip"
        try:
            if not evidence_dir.exists():
                raise FileNotFoundError(f"Evidence directory unavailable: {evidence_dir}")
            archive_sha256 = _package_evidence_zip(
                evidence_dir=evidence_dir,
                zip_path=zip_path,
                sample_filename=sample_path.name,
                include_raw_pml=bool(config.get("include_raw_pml", False)),
                max_raw_pml_bytes=max(1, int(config.get("max_raw_pml_mb", 200))) * 1024 * 1024,
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
