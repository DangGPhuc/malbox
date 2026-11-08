#!/usr/bin/env python3
"""
malbox-ai VM Evaluation Benchmark Script
Measures execution latency, peak memory (RSS), CPU time, database writes,
and telemetry throughput for resource-constrained VM deployments.
"""

import sys
import time
import resource
import io
import json
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.services.submission.service import SubmissionService
from app.workers.pipeline_worker import PipelineWorker
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.services.graph.builder import build_behavior_graph


def run_benchmark(scenario_id: str, label: str):
    print(f"\n========================================================")
    print(f"[*] Running Benchmark: {label} ({scenario_id})")
    print(f"========================================================")

    init_db()
    db = SessionLocal()

    # Synthetic sample binary
    sample_content = b"MZ" + b"\x90" * 300 + f"Benchmark_{scenario_id}".encode()
    submission_svc = SubmissionService(db)

    # 1. Measure Submission / Preflight Triage Time
    t0 = time.perf_counter()
    sample = submission_svc.submit_sample(
        file_bytes=sample_content,
        original_filename=f"{scenario_id}_sample.exe"
    )
    t_submission = (time.perf_counter() - t0) * 1000

    # 2. Create Analysis
    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        profile="ransomware_focus" if "wannacry" in scenario_id else "infostealer_focus",
        status=AnalysisStatus.QUEUED.value,
        live_mode=False,
        replay_scenario_id=scenario_id,
        timeout_seconds=60,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # 3. Execute Complete 10-Step Pipeline
    rusage_start = resource.getrusage(resource.RUSAGE_SELF)
    cpu_start = time.process_time()
    t_start = time.perf_counter()

    worker = PipelineWorker(db)
    completed_analysis = worker.execute_pipeline(analysis.id)

    t_pipeline = (time.perf_counter() - t_start) * 1000
    cpu_time = (time.process_time() - cpu_start) * 1000
    rusage_end = resource.getrusage(resource.RUSAGE_SELF)

    # Peak RSS (on Linux ru_maxrss is in KiB)
    peak_rss_mb = rusage_end.ru_maxrss / 1024.0

    # 4. Measure Behavior Graph Generation
    t_g0 = time.perf_counter()
    graph = build_behavior_graph(completed_analysis.id, db)
    t_graph = (time.perf_counter() - t_g0) * 1000

    # Collect Forensic Counts
    events_count = len(completed_analysis.events)
    findings_count = len(completed_analysis.findings)
    report = completed_analysis.report
    risk_score = report.risk_score if report else 0
    risk_level = report.risk_level if report else "N/A"

    print(f" Status:             {completed_analysis.status}")
    if completed_analysis.error_message:
        print(f" Error:              {completed_analysis.error_message}")
    print(f" Sample ID:          {sample.id}")
    print(f" Submission Time:    {t_submission:.2f} ms")
    print(f" Total Pipeline:     {t_pipeline:.2f} ms")
    print(f" CPU User/Sys Time:  {cpu_time:.2f} ms")
    print(f" Peak Process RSS:   {peak_rss_mb:.2f} MB")
    print(f" Graph Build Time:   {t_graph:.2f} ms")
    print(f" Ingested Events:    {events_count}")
    print(f" Triggered Findings: {findings_count}")
    print(f" Risk Assessment:    {risk_level} ({risk_score}/100)")
    print(f" Graph Nodes/Edges:  {graph.total_nodes} nodes / {graph.total_edges} edges")

    db.close()

    return {
        "scenario": scenario_id,
        "label": label,
        "submission_ms": round(t_submission, 2),
        "pipeline_ms": round(t_pipeline, 2),
        "cpu_time_ms": round(cpu_time, 2),
        "peak_rss_mb": round(peak_rss_mb, 2),
        "graph_ms": round(t_graph, 2),
        "events_count": events_count,
        "findings_count": findings_count,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "graph_nodes": graph.total_nodes,
        "graph_edges": graph.total_edges,
    }


def main():
    print("================================================================")
    print("      MALBOX-AI VM RESOURCE & EXECUTION BENCHMARK SUITE        ")
    print("================================================================")

    results = []
    results.append(run_benchmark("ransomware_wannacry_mock", "WannaCry Ransomware Scenario"))
    results.append(run_benchmark("infostealer_redline_mock", "RedLine Infostealer Scenario"))

    print("\n\n========================================================")
    print("                 BENCHMARK SUMMARY TABLE                ")
    print("========================================================")
    print(f"| {'Scenario':<28} | {'Pipeline':<10} | {'CPU Time':<10} | {'Peak RSS':<10} | {'Events':<7} |")
    print(f"|{'-'*30}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*9}|")
    for r in results:
        print(f"| {r['label']:<28} | {r['pipeline_ms']:>7} ms | {r['cpu_time_ms']:>7} ms | {r['peak_rss_mb']:>7} MB | {r['events_count']:>7} |")
    print("========================================================\n")


if __name__ == "__main__":
    main()
