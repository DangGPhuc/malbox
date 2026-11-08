from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.schemas.finding import ProcessTreeResponse, ProcessTreeNode

def build_process_tree(analysis_id: str, db: Session) -> ProcessTreeResponse:
    """
    Reconstructs the process execution hierarchy from normalized process telemetry events.
    """
    process_events = (
        db.query(AnalysisEvent)
        .filter(AnalysisEvent.analysis_id == analysis_id, AnalysisEvent.category == "process")
        .order_by(AnalysisEvent.timestamp.asc().nulls_last())
        .all()
    )

    if not process_events:
        return ProcessTreeResponse(analysis_id=analysis_id, root_nodes=[], total_processes=0)

    # All events for the analysis to count events per PID
    all_events = db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
    events_by_pid: Dict[int, List[str]] = {}
    for ev in all_events:
        if ev.process_id:
            events_by_pid.setdefault(ev.process_id, []).append(ev.id)

    # Node map: pid -> ProcessTreeNode
    nodes: Dict[int, ProcessTreeNode] = {}
    suspicious_patterns = [
        "vssadmin", "delete shadows", "-executionpolicy bypass", "-enc",
        "rundll32", "regsvr32", "powershell", "certutil", "bitsadmin"
    ]

    for ev in process_events:
        pid = ev.process_id
        if not pid or pid in nodes:
            continue

        cmd = ev.attributes.get("command_line", "")
        suspicious = any(pat in cmd.lower() for pat in suspicious_patterns)

        node = ProcessTreeNode(
            pid=pid,
            name=ev.process_name or "unknown.exe",
            ppid=ev.parent_process_id,
            command_line=cmd,
            spawn_time=ev.timestamp.isoformat() if ev.timestamp else None,
            terminate_time=ev.attributes.get("end_time"),
            suspicious=suspicious,
            children=[],
            events_count=len(events_by_pid.get(pid, [])),
            event_ids=events_by_pid.get(pid, []),
        )
        nodes[pid] = node

    # Assemble hierarchy
    root_nodes: List[ProcessTreeNode] = []
    for pid, node in nodes.items():
        ppid = node.ppid
        if ppid and ppid in nodes:
            nodes[ppid].children.append(node)
        else:
            root_nodes.append(node)

    return ProcessTreeResponse(
        analysis_id=analysis_id,
        root_nodes=root_nodes,
        total_processes=len(nodes)
    )
