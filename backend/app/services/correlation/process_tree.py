from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.schemas.finding import ProcessTreeResponse, ProcessTreeNode
from app.services.telemetry.normalizer import parse_iso_datetime


def _to_comparable_dt(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalizes any datetime to timezone-naive UTC for robust comparison."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def build_process_tree(analysis_id: str, db: Session) -> ProcessTreeResponse:
    """
    Reconstructs the process execution hierarchy from normalized process telemetry events.
    Robustly handles PID reuse, out-of-order event ingestion, and cycle detection.
    """
    process_events = (
        db.query(AnalysisEvent)
        .filter(AnalysisEvent.analysis_id == analysis_id, AnalysisEvent.category == "process")
        .order_by(AnalysisEvent.timestamp.asc().nulls_last())
        .all()
    )

    if not process_events:
        return ProcessTreeResponse(analysis_id=analysis_id, root_nodes=[], total_processes=0)

    # Collect all other telemetry events to map event IDs to process instances
    all_events = db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()

    suspicious_patterns = [
        "vssadmin", "delete shadows", "-executionpolicy bypass", "-enc",
        "rundll32", "regsvr32", "powershell", "certutil", "bitsadmin", "wscript", "cscript"
    ]

    # Process instances indexed by unique event ID (to differentiate reused PIDs)
    instances: Dict[str, Dict[str, Any]] = {}
    # Helper to look up instances by PID: pid -> list of instance dicts
    pid_to_instances: Dict[int, List[Dict[str, Any]]] = {}

    for ev in process_events:
        pid = ev.process_id
        if not pid:
            continue

        cmd = (ev.attributes or {}).get("command_line", "") or ""
        suspicious = any(pat in cmd.lower() for pat in suspicious_patterns)
        spawn_time = ev.timestamp
        end_time_raw = (ev.attributes or {}).get("end_time")
        end_time = parse_iso_datetime(end_time_raw) if end_time_raw else None

        node = ProcessTreeNode(
            pid=pid,
            name=ev.process_name or "unknown.exe",
            ppid=ev.parent_process_id,
            command_line=cmd,
            spawn_time=spawn_time.isoformat() if spawn_time else None,
            terminate_time=end_time.isoformat() if end_time else None,
            suspicious=suspicious,
            children=[],
            events_count=0,
            event_ids=[],
        )

        inst_data = {
            "id": ev.id,
            "pid": pid,
            "ppid": ev.parent_process_id,
            "spawn_time": spawn_time,
            "comp_spawn_time": _to_comparable_dt(spawn_time),
            "end_time": end_time,
            "comp_end_time": _to_comparable_dt(end_time),
            "node": node,
        }
        instances[ev.id] = inst_data
        pid_to_instances.setdefault(pid, []).append(inst_data)

    # Correlate all events to specific process instance considering temporal lifecycle (PID reuse)
    for ev in all_events:
        pid = ev.process_id
        if not pid or pid not in pid_to_instances:
            continue

        candidates = pid_to_instances[pid]
        target_inst = None

        if len(candidates) == 1:
            target_inst = candidates[0]
        else:
            # PID reuse resolution: match temporal interval
            ev_time = _to_comparable_dt(ev.timestamp)
            if ev_time:
                for cand in candidates:
                    st = cand["comp_spawn_time"]
                    et = cand["comp_end_time"]
                    if st and st <= ev_time and (et is None or ev_time <= et):
                        target_inst = cand
                        break
            if not target_inst:
                target_inst = candidates[-1]

        target_inst["node"].event_ids.append(ev.id)
        target_inst["node"].events_count += 1

    # Assemble hierarchy with cycle prevention and out-of-order handling
    root_nodes: List[ProcessTreeNode] = []
    # Parent-child mapping by instance ID
    parent_map: Dict[str, str] = {}  # child_inst_id -> parent_inst_id

    for inst_id, inst in instances.items():
        ppid = inst["ppid"]
        if not ppid or ppid not in pid_to_instances:
            continue

        parent_candidates = pid_to_instances[ppid]
        chosen_parent = None

        # If child has a spawn_time, find the parent candidate active at or before that time
        child_st = inst["comp_spawn_time"]
        if child_st:
            prior_parents = [p for p in parent_candidates if p["comp_spawn_time"] and p["comp_spawn_time"] <= child_st]
            if prior_parents:
                chosen_parent = prior_parents[-1]

        if not chosen_parent and parent_candidates:
            chosen_parent = parent_candidates[0]

        if chosen_parent and chosen_parent["id"] != inst_id:
            # Prevent immediate cycle or transitive cycle
            curr = chosen_parent["id"]
            cycle_detected = False
            visited = {inst_id}
            while curr in parent_map:
                if curr in visited:
                    cycle_detected = True
                    break
                visited.add(curr)
                curr = parent_map[curr]

            if not cycle_detected:
                parent_map[inst_id] = chosen_parent["id"]
                chosen_parent["node"].children.append(inst["node"])
                continue

        # If no parent could be assigned safely, treat as root node
        root_nodes.append(inst["node"])

    for inst_id, inst in instances.items():
        if inst_id not in parent_map and inst["node"] not in root_nodes:
            root_nodes.append(inst["node"])

    return ProcessTreeResponse(
        analysis_id=analysis_id,
        root_nodes=root_nodes,
        total_processes=len(instances)
    )
