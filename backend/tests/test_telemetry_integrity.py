from datetime import datetime, timezone, timedelta
import uuid
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType
from app.models.sample import Sample
from app.models.event import AnalysisEvent
from app.services.correlation.process_tree import build_process_tree
from app.services.graph.builder import build_behavior_graph
from app.services.reporting.generator import ReportGenerator
from app.schemas.report import RiskAssessment


def test_process_tree_pid_reuse(db_session):
    """Processes reusing the same PID at different times must be indexed as distinct process instances."""
    sample = Sample(
        sha256="p" * 64, md5="p" * 32, sha1="p" * 40,
        file_name="pid_reuse.exe", file_size=100, quarantine_path="/tmp/p.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.CORRELATING.value
    )
    db_session.add(analysis)
    db_session.commit()

    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # First instance of PID 1000 (t=0 to t=20)
    ev_proc1 = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time, process_id=1000, process_name="host_proc1.exe",
        parent_process_id=100,
        attributes={"command_line": "host_proc1.exe", "end_time": (base_time + timedelta(seconds=20)).isoformat()}
    )
    # Child of first instance (spawned at t=10 with PPID 1000)
    ev_child1 = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time + timedelta(seconds=10), process_id=1500, process_name="child1.exe",
        parent_process_id=1000,
        attributes={"command_line": "child1.exe"}
    )
    # Second instance of PID 1000 (PID reused at t=30 to t=50)
    ev_proc2 = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time + timedelta(seconds=30), process_id=1000, process_name="reused_proc2.exe",
        parent_process_id=100,
        attributes={"command_line": "reused_proc2.exe", "end_time": (base_time + timedelta(seconds=50)).isoformat()}
    )
    # Child of second instance (spawned at t=35 with PPID 1000)
    ev_child2 = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time + timedelta(seconds=35), process_id=2000, process_name="child2.exe",
        parent_process_id=1000,
        attributes={"command_line": "child2.exe"}
    )

    db_session.add_all([ev_proc1, ev_child1, ev_proc2, ev_child2])
    db_session.commit()

    tree = build_process_tree(analysis.id, db_session)
    assert tree.total_processes == 4

    # Locate the two instances of PID 1000 in root nodes (since parent 100 does not exist in events)
    inst1 = next((n for n in tree.root_nodes if n.pid == 1000 and n.name == "host_proc1.exe"), None)
    inst2 = next((n for n in tree.root_nodes if n.pid == 1000 and n.name == "reused_proc2.exe"), None)

    assert inst1 is not None
    assert inst2 is not None

    # Verify each child was parented to the temporally corresponding instance
    assert any(c.pid == 1500 for c in inst1.children)
    assert any(c.pid == 2000 for c in inst2.children)


def test_process_tree_out_of_order_events(db_session):
    """Child processes arriving out-of-order must be safely parented to their parent."""
    sample = Sample(
        sha256="o" * 64, md5="o" * 32, sha1="o" * 40,
        file_name="ooo.exe", file_size=100, quarantine_path="/tmp/o.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.CORRELATING.value
    )
    db_session.add(analysis)
    db_session.commit()

    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest Child first
    ev_child = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time + timedelta(seconds=5), process_id=200, process_name="child.exe",
        parent_process_id=100, attributes={"command_line": "child.exe"}
    )
    db_session.add(ev_child)
    db_session.commit()

    # Ingest Parent second
    ev_parent = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time, process_id=100, process_name="parent.exe",
        parent_process_id=None, attributes={"command_line": "parent.exe"}
    )
    db_session.add(ev_parent)
    db_session.commit()

    tree = build_process_tree(analysis.id, db_session)
    assert tree.total_processes == 2
    assert len(tree.root_nodes) == 1
    assert tree.root_nodes[0].pid == 100
    assert len(tree.root_nodes[0].children) == 1
    assert tree.root_nodes[0].children[0].pid == 200


def test_process_tree_cycle_resilience(db_session):
    """Telemetry with corrupt cyclic parent relationships (A->B->A) must not cause an infinite loop."""
    sample = Sample(
        sha256="c" * 64, md5="c" * 32, sha1="c" * 40,
        file_name="cycle.exe", file_size=100, quarantine_path="/tmp/c.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.CORRELATING.value
    )
    db_session.add(analysis)
    db_session.commit()

    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    ev_a = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time, process_id=10, process_name="proc_a.exe",
        parent_process_id=20, attributes={"command_line": "proc_a.exe"}
    )
    ev_b = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=base_time + timedelta(seconds=1), process_id=20, process_name="proc_b.exe",
        parent_process_id=10, attributes={"command_line": "proc_b.exe"}
    )
    db_session.add_all([ev_a, ev_b])
    db_session.commit()

    tree = build_process_tree(analysis.id, db_session)
    assert tree.total_processes == 2


def test_behavior_graph_strict_edge_integrity(db_session):
    """Every edge in the behavioral graph must link valid nodes."""
    sample = Sample(
        sha256="g" * 64, md5="g" * 32, sha1="g" * 40,
        file_name="graph_test.exe", file_size=100, quarantine_path="/tmp/g.exe"
    )
    db_session.add(sample)
    db_session.commit()

    analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.REPLAY.value,
        profile="standard", status=AnalysisStatus.CORRELATING.value
    )
    db_session.add(analysis)
    db_session.commit()

    ev_proc = AnalysisEvent(
        analysis_id=analysis.id, category="process", action="spawn",
        timestamp=datetime.now(timezone.utc), process_id=1234, process_name="proc.exe",
        attributes={"command_line": "proc.exe"}
    )
    ev_file = AnalysisEvent(
        analysis_id=analysis.id, category="file", action="write",
        timestamp=datetime.now(timezone.utc), process_id=1234, target_path="C:\\test\\drop.dll",
        attributes={"is_dropped_binary": True}
    )
    db_session.add_all([ev_proc, ev_file])
    db_session.commit()

    graph = build_behavior_graph(analysis.id, db_session)
    node_ids = {n.data.id for n in graph.nodes}

    for edge in graph.edges:
        assert edge.data.source in node_ids, f"Edge source {edge.data.source} missing from nodes!"
        assert edge.data.target in node_ids, f"Edge target {edge.data.target} missing from nodes!"


def test_reporting_no_fabricated_guest_os(db_session):
    """ReportGenerator must not fabricate guest OS and must reflect verified sandbox telemetry."""
    sample = Sample(
        sha256="e" * 64, md5="e" * 32, sha1="e" * 40,
        file_name="env_test.exe", file_size=100, quarantine_path="/tmp/e.exe"
    )
    db_session.add(sample)
    db_session.commit()

    # CAPE analysis with empty environment metadata
    cape_analysis = Analysis(
        sample_id=sample.id, backend_type=SandboxBackendType.CAPE.value,
        profile="standard", status=AnalysisStatus.REPORTING.value, live_mode=True
    )
    db_session.add(cape_analysis)
    db_session.commit()

    generator = ReportGenerator(db_session)
    risk = RiskAssessment(score=10, level="clean", rationale="No anomalies")
    report = generator.generate_report(
        cape_analysis.id, risk, env_metadata={}
    )

    # Must NOT fabricate "Windows 10 Enterprise x64"
    assert report.full_report_json["analysis_environment"]["guest_os"] == "Not reported by sandbox backend"
