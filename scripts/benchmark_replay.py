#!/usr/bin/env python3
"""
malbox-ai VM Evaluation Benchmark Suite
Measures:
- End-to-end pipeline latency and CPU time
- Peak process RSS memory
- Synthetic dataset scaling: Small (~100 events), Medium (~1,000 events), Large (~10,000 events)
- Telemetry normalization throughput (events/sec)
- Database write duration
- Behavior graph construction duration, node count, and edge count
- Report generation duration
- API endpoint response latencies
"""

import sys
import time
import resource
import io
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.database import SessionLocal, init_db, engine
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.services.submission.service import SubmissionService
from app.services.telemetry.normalizer import TelemetryNormalizer
from app.services.detection.engine import DetectionEngine
from app.services.graph.builder import build_behavior_graph
from app.services.reporting.generator import ReportGenerator
from app.workers.pipeline_worker import PipelineWorker
from starlette.testclient import TestClient
from app.main import app


def generate_synthetic_telemetry(target_events: int) -> Dict[str, Any]:
    """Generates deterministic synthetic execution telemetry of arbitrary size."""
    num_procs = max(2, min(500, target_events // 20))
    num_net = max(2, int(target_events * 0.20))
    num_reg = max(2, int(target_events * 0.30))
    num_fs = max(2, target_events - num_procs - num_net - num_reg)

    processes = []
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(num_procs):
        pid = 1000 + i
        ppid = 1000 + (i - 1) if i > 0 else 400
        processes.append({
            "pid": pid,
            "ppid": ppid,
            "name": f"synthetic_proc_{i % 10}.exe",
            "command_line": f"synthetic_proc_{i % 10}.exe --id {i}",
            "start_time": (base_time + timedelta(seconds=i)).isoformat(),
            "end_time": (base_time + timedelta(seconds=i + 30)).isoformat(),
        })

    filesystem = []
    for i in range(num_fs):
        pid = 1000 + (i % num_procs)
        is_enc = (i % 25 == 0)
        ext = ".wnry" if is_enc else ".dat"
        filesystem.append({
            "pid": pid,
            "path": f"C:\\Users\\Analyst\\Documents\\file_{i}{ext}",
            "action": "write" if i % 2 == 0 else "read",
            "is_encrypted_target": is_enc,
            "timestamp": (base_time + timedelta(milliseconds=i * 10)).isoformat(),
        })

    registry = []
    for i in range(num_reg):
        pid = 1000 + (i % num_procs)
        is_run = (i == 0)
        path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Payload" if is_run else f"HKLM\\Software\\Vendor\\Key_{i}"
        registry.append({
            "pid": pid,
            "key": path,
            "value_name": f"Val_{i}",
            "persistence": is_run,
            "timestamp": (base_time + timedelta(milliseconds=i * 12)).isoformat(),
        })

    connections = []
    http_list = []
    dns_list = []
    for i in range(num_net):
        pid = 1000 + (i % num_procs)
        if i % 3 == 0:
            dns_list.append({
                "pid": pid,
                "query": f"synthetic-c2-{i % 50}.local",
                "response": f"198.51.100.{i % 250 + 1}",
                "timestamp": (base_time + timedelta(milliseconds=i * 15)).isoformat(),
            })
        elif i % 3 == 1:
            connections.append({
                "pid": pid,
                "protocol": "TCP",
                "dest_ip": f"198.51.100.{i % 250 + 1}",
                "dest_port": 443 if i % 2 == 0 else 8080,
                "timestamp": (base_time + timedelta(milliseconds=i * 15)).isoformat(),
            })
        else:
            http_list.append({
                "pid": pid,
                "method": "POST" if i % 2 == 0 else "GET",
                "url": f"http://198.51.100.{i % 250 + 1}/beacon.php?worker={i}",
                "status_code": 200,
                "timestamp": (base_time + timedelta(milliseconds=i * 15)).isoformat(),
            })

    return {
        "metadata": {
            "scenario_id": f"synthetic_{target_events}",
            "fixture_version": "2.0-synthetic",
            "environment": {"guest_os": "Windows 10 x64 (Synthetic Benchmark Suite)"},
        },
        "processes": processes,
        "filesystem": filesystem,
        "registry": registry,
        "network": {
            "dns": dns_list,
            "connections": connections,
            "http": http_list,
        },
        "artifacts": [
            {"name": "synthetic_traffic.pcap", "type": "pcap", "description": "Synthetic benchmark pcap"}
        ],
    }


def run_standard_replay_benchmark(scenario_id: str, label: str) -> Dict[str, Any]:
    print(f"\n[*] Running Standard Benchmark: {label} ({scenario_id})")

    init_db()
    db = SessionLocal()

    sample_content = b"MZ" + b"\x90" * 300 + f"Benchmark_{scenario_id}".encode()
    submission_svc = SubmissionService(db)

    t0 = time.perf_counter()
    sample = submission_svc.submit_sample(
        file_bytes=sample_content,
        original_filename=f"{scenario_id}_sample.exe"
    )
    t_submission = (time.perf_counter() - t0) * 1000

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

    cpu_start = time.process_time()
    t_start = time.perf_counter()

    worker = PipelineWorker(db)
    completed_analysis = worker.execute_pipeline(analysis.id)

    t_pipeline = (time.perf_counter() - t_start) * 1000
    cpu_time = (time.process_time() - cpu_start) * 1000
    peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    t_g0 = time.perf_counter()
    graph = build_behavior_graph(completed_analysis.id, db)
    t_graph = (time.perf_counter() - t_g0) * 1000

    events_count = len(completed_analysis.events)
    findings_count = len(completed_analysis.findings)
    report = completed_analysis.report
    risk_score = report.risk_score if report else 0
    risk_level = report.risk_level if report else "N/A"

    print(f"  -> Pipeline Time:    {t_pipeline:.2f} ms")
    print(f"  -> CPU Time:         {cpu_time:.2f} ms")
    print(f"  -> Peak RSS:         {peak_rss_mb:.2f} MB")
    print(f"  -> Graph Build:      {t_graph:.2f} ms ({graph.total_nodes} nodes, {graph.total_edges} edges)")
    print(f"  -> Events / Findings:{events_count} events / {findings_count} findings ({risk_level} {risk_score}/100)")

    db.close()
    return {
        "benchmark_type": "standard_replay",
        "scenario": scenario_id,
        "label": label,
        "events_count": events_count,
        "submission_ms": round(t_submission, 2),
        "pipeline_ms": round(t_pipeline, 2),
        "cpu_time_ms": round(cpu_time, 2),
        "peak_rss_mb": round(peak_rss_mb, 2),
        "graph_ms": round(t_graph, 2),
        "graph_nodes": graph.total_nodes,
        "graph_edges": graph.total_edges,
        "findings_count": findings_count,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def run_synthetic_scale_benchmark(target_events: int, scale_label: str) -> Dict[str, Any]:
    print(f"\n[*] Running Synthetic Scale Benchmark: {scale_label} (~{target_events:,} events)")

    init_db()
    db = SessionLocal()

    # 1. Create dummy sample
    sample = Sample(
        sha256=f"synth_{target_events}_{int(time.time())}".ljust(64, "0"),
        md5="s" * 32,
        sha1="s" * 40,
        file_name=f"synthetic_{scale_label.lower()}.exe",
        file_size=target_events * 50,
        quarantine_path=f"/tmp/synthetic_{scale_label.lower()}.exe",
        is_pe=True,
    )
    db.add(sample)
    db.commit()

    analysis = Analysis(
        sample_id=sample.id,
        backend_type=SandboxBackendType.REPLAY.value,
        profile="standard",
        status=AnalysisStatus.QUEUED.value,
        live_mode=False,
        timeout_seconds=60,
    )
    db.add(analysis)
    db.commit()

    # 2. Generate synthetic raw data
    raw_telemetry = generate_synthetic_telemetry(target_events)

    # 3. Benchmark Telemetry Normalization & DB Ingestion
    normalizer = TelemetryNormalizer(db)
    t_norm_start = time.perf_counter()
    cpu_norm_start = time.process_time()

    normalized_events = normalizer.normalize_sandbox_output(analysis.id, raw_telemetry)

    t_norm_end = time.perf_counter()
    cpu_norm_ms = (time.process_time() - cpu_norm_start) * 1000
    norm_duration_s = max(0.0001, t_norm_end - t_norm_start)
    norm_duration_ms = norm_duration_s * 1000
    actual_event_count = len(normalized_events)
    norm_throughput = actual_event_count / norm_duration_s

    # 4. Benchmark Detection Engine Evaluation
    detector = DetectionEngine(db)
    t_det_start = time.perf_counter()
    findings, assessment = detector.evaluate_behavior(analysis.id)
    t_det_ms = (time.perf_counter() - t_det_start) * 1000

    # 5. Benchmark Behavior Graph Construction
    t_graph_start = time.perf_counter()
    cpu_graph_start = time.process_time()
    graph = build_behavior_graph(analysis.id, db)
    t_graph_ms = (time.perf_counter() - t_graph_start) * 1000
    cpu_graph_ms = (time.process_time() - cpu_graph_start) * 1000

    # 6. Benchmark Report Generation
    reporter = ReportGenerator(db)
    t_rep_start = time.perf_counter()
    report = reporter.generate_report(
        analysis_id=analysis.id,
        risk_assessment=assessment,
        ai_summary="Synthetic benchmark executive summary.",
        ai_follow_up={"needs_second_pass": False, "recommended_profile": None},
        env_metadata=raw_telemetry.get("metadata", {}).get("environment", {}),
    )
    t_rep_ms = (time.perf_counter() - t_rep_start) * 1000

    peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    print(f"  -> Ingested Events:  {actual_event_count:,}")
    print(f"  -> Norm Duration:    {norm_duration_ms:.2f} ms ({norm_throughput:,.1f} events/sec)")
    print(f"  -> Detection Time:   {t_det_ms:.2f} ms ({len(findings)} findings)")
    print(f"  -> Graph Build:      {t_graph_ms:.2f} ms ({graph.total_nodes:,} nodes, {graph.total_edges:,} edges)")
    print(f"  -> Report Duration:  {t_rep_ms:.2f} ms")
    print(f"  -> Peak RSS:         {peak_rss_mb:.2f} MB")

    db.close()
    return {
        "benchmark_type": "synthetic_scaling",
        "scale": scale_label,
        "events_count": actual_event_count,
        "norm_duration_ms": round(norm_duration_ms, 2),
        "norm_throughput_eps": round(norm_throughput, 1),
        "cpu_norm_ms": round(cpu_norm_ms, 2),
        "detection_ms": round(t_det_ms, 2),
        "graph_ms": round(t_graph_ms, 2),
        "cpu_graph_ms": round(cpu_graph_ms, 2),
        "graph_nodes": graph.total_nodes,
        "graph_edges": graph.total_edges,
        "report_duration_ms": round(t_rep_ms, 2),
        "findings_count": len(findings),
        "risk_score": assessment.score,
        "peak_rss_mb": round(peak_rss_mb, 2),
    }


def measure_api_latencies() -> Dict[str, float]:
    print("\n[*] Measuring API Response Latencies via TestClient...")
    client = TestClient(app)

    # 1. Health check
    t0 = time.perf_counter()
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    t_health = (time.perf_counter() - t0) * 1000

    # 2. Sample upload
    sample_file = io.BytesIO(b"MZ" + b"\x00" * 200 + b"BenchmarkAPI")
    t0 = time.perf_counter()
    r_sample = client.post("/api/v1/samples", files={"file": ("api_bench.exe", sample_file)})
    assert r_sample.status_code == 201
    t_sample_upload = (time.perf_counter() - t0) * 1000
    sample_id = r_sample.json()["id"]

    # 3. Synchronous Replay analysis creation & execution
    payload = {
        "sample_id": sample_id,
        "backend_type": "replay",
        "live_mode": False,
        "replay_scenario_id": "ransomware_wannacry_mock",
        "timeout_seconds": 60,
    }
    t0 = time.perf_counter()
    r_analysis = client.post("/api/v1/analyses?run_sync=true", json=payload)
    assert r_analysis.status_code == 201
    t_sync_execution = (time.perf_counter() - t0) * 1000
    analysis_id = r_analysis.json()["id"]

    # 4. GET Analysis Status
    t0 = time.perf_counter()
    r_get = client.get(f"/api/v1/analyses/{analysis_id}")
    assert r_get.status_code == 200
    t_get_status = (time.perf_counter() - t0) * 1000

    # 5. GET Behavior Graph
    t0 = time.perf_counter()
    r_graph = client.get(f"/api/v1/analyses/{analysis_id}/graph")
    assert r_graph.status_code == 200
    t_get_graph = (time.perf_counter() - t0) * 1000

    # 6. GET Full Report
    t0 = time.perf_counter()
    r_report = client.get(f"/api/v1/analyses/{analysis_id}/report")
    assert r_report.status_code == 200
    t_get_report = (time.perf_counter() - t0) * 1000

    latencies = {
        "GET /health": round(t_health, 2),
        "POST /samples (Upload)": round(t_sample_upload, 2),
        "POST /analyses (Sync Replay)": round(t_sync_execution, 2),
        "GET /analyses/{id}": round(t_get_status, 2),
        "GET /analyses/{id}/graph": round(t_get_graph, 2),
        "GET /analyses/{id}/report": round(t_get_report, 2),
    }

    for ep, lat in latencies.items():
        print(f"  -> {ep:<30}: {lat:>7.2f} ms")

    return latencies


def main():
    print("========================================================================")
    print("      MALBOX-AI COMPREHENSIVE PERFORMANCE & SCALABILITY BENCHMARK      ")
    print("========================================================================")

    # 1. Standard Replay Benchmarks
    replay_results = []
    replay_results.append(run_standard_replay_benchmark("ransomware_wannacry_mock", "WannaCry Ransomware"))
    replay_results.append(run_standard_replay_benchmark("infostealer_redline_mock", "RedLine Infostealer"))

    # 2. Synthetic Dataset Scaling Benchmarks (Small: ~100, Medium: ~1,000, Large: ~10,000)
    synthetic_results = []
    synthetic_results.append(run_synthetic_scale_benchmark(100, "Small"))
    synthetic_results.append(run_synthetic_scale_benchmark(1000, "Medium"))
    synthetic_results.append(run_synthetic_scale_benchmark(10000, "Large"))

    # 3. API Response Latency Measurements
    api_latencies = measure_api_latencies()

    # 4. Summaries
    print("\n\n========================================================================")
    print("                 STANDARD REPLAY BENCHMARK SUMMARY TABLE                 ")
    print("========================================================================")
    print(f"| {'Scenario':<24} | {'Pipeline':<10} | {'CPU Time':<10} | {'Peak RSS':<10} | {'Events':<7} | {'Graph':<8} |")
    print(f"|{'-'*26}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*9}|{'-'*10}|")
    for r in replay_results:
        print(f"| {r['label']:<24} | {r['pipeline_ms']:>7} ms | {r['cpu_time_ms']:>7} ms | {r['peak_rss_mb']:>7} MB | {r['events_count']:>7} | {r['graph_ms']:>6} ms |")

    print("\n========================================================================")
    print("                 SYNTHETIC SCALING SUMMARY TABLE                         ")
    print("========================================================================")
    print(f"| {'Scale':<8} | {'Events':<8} | {'Norm (ms)':<10} | {'Throughput':<14} | {'Graph (ms)':<11} | {'Report (ms)':<12} |")
    print(f"|{'-'*10}|{'-'*10}|{'-'*12}|{'-'*16}|{'-'*13}|{'-'*14}|")
    for s in synthetic_results:
        print(f"| {s['scale']:<8} | {s['events_count']:>8,} | {s['norm_duration_ms']:>8.2f} ms | {s['norm_throughput_eps']:>9.1f} ev/s | {s['graph_ms']:>8.2f} ms | {s['report_duration_ms']:>9.2f} ms |")

    print("\n========================================================================")
    print("                 API RESPONSE LATENCY SUMMARY TABLE                      ")
    print("========================================================================")
    for ep, lat in api_latencies.items():
        print(f"| {ep:<36} | {lat:>8.2f} ms |")
    print("========================================================================\n")

    # Persist benchmark results to file for docs reference
    results_out = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "standard_replay": replay_results,
        "synthetic_scaling": synthetic_results,
        "api_latencies": api_latencies,
    }
    bench_file = Path(__file__).resolve().parent.parent / "benchmark_results.json"
    with open(bench_file, "w", encoding="utf-8") as f:
        json.dump(results_out, f, indent=2)
    print(f"[*] Benchmark results successfully saved to {bench_file}\n")


if __name__ == "__main__":
    main()
