import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional
from sqlalchemy.orm import Session
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.schemas.graph import BehaviorGraphResponse, GraphNode, GraphEdge, GraphNodeData, GraphEdgeData
from app.services.telemetry.normalizer import parse_iso_datetime

def _hash_id(prefix: str, value: str) -> str:
    h = hashlib.md5(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{h}"

def _to_comparable_dt(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalizes any datetime to timezone-naive UTC for robust comparison."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

def build_behavior_graph(analysis_id: str, db: Session) -> BehaviorGraphResponse:
    """
    Builds an evidence-linked behavioral relationship graph.
    - Uses unique process-instance identity (proc_{event_id}) instead of raw PIDs to handle PID reuse.
    - Handles out-of-order parent-child process events temporally.
    - Strictly avoids assigning unknown-origin network events to arbitrary processes.
    - Ensures every relationship edge is backed by verified event IDs.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        return BehaviorGraphResponse(analysis_id=analysis_id, nodes=[], edges=[], total_nodes=0, total_edges=0)

    events = db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
    findings = db.query(BehavioralFinding).filter(BehavioralFinding.analysis_id == analysis_id).all()

    all_event_ids: Set[str] = {e.id for e in events}
    nodes: Dict[str, GraphNode] = {}
    edges: Dict[str, GraphEdge] = {}

    # 1. Sample Root Node
    sample_name = analysis.sample.file_name if analysis.sample else "Sample"
    sample_sha = analysis.sample.sha256 if analysis.sample else ""
    sample_node_id = "node_sample_root"
    nodes[sample_node_id] = GraphNode(
        data=GraphNodeData(
            id=sample_node_id,
            label=sample_name,
            type="Sample",
            details={"sha256": sample_sha, "file_size": analysis.sample.file_size if analysis.sample else 0},
            suspicious=False,
        )
    )

    # 2. Process Instance Nodes & Temporal Lifecycle Index
    proc_events = [e for e in events if e.category == "process"]
    # Sort process events by timestamp to ensure deterministic ordering
    proc_events.sort(key=lambda e: (_to_comparable_dt(e.timestamp) or datetime.min))

    pid_to_instances: Dict[int, List[Dict[str, Any]]] = {}

    for ev in proc_events:
        pid = ev.process_id
        proc_node_id = f"proc_{ev.id}"
        cmd = (ev.attributes or {}).get("command_line", "") or ""
        is_suspicious = any(
            pat in cmd.lower()
            for pat in ["vssadmin", "delete shadows", "-enc", "-executionpolicy bypass", "rundll32", "powershell"]
        )

        spawn_time = ev.timestamp
        end_time_raw = (ev.attributes or {}).get("end_time")
        end_time = parse_iso_datetime(end_time_raw) if end_time_raw else None

        inst_data = {
            "event_id": ev.id,
            "node_id": proc_node_id,
            "pid": pid,
            "ppid": ev.parent_process_id,
            "spawn_time": spawn_time,
            "comp_spawn_time": _to_comparable_dt(spawn_time),
            "end_time": end_time,
            "comp_end_time": _to_comparable_dt(end_time),
        }
        if pid:
            pid_to_instances.setdefault(pid, []).append(inst_data)

        nodes[proc_node_id] = GraphNode(
            data=GraphNodeData(
                id=proc_node_id,
                label=f"{ev.process_name or 'Process'} [{pid or '?'}]",
                type="Process",
                details={
                    "pid": pid,
                    "ppid": ev.parent_process_id,
                    "command_line": cmd,
                    "spawn_time": spawn_time.isoformat() if spawn_time else None,
                    "event_id": ev.id,
                },
                suspicious=is_suspicious,
                pid=pid,
            )
        )

    def find_active_instance(pid: Optional[int], ev_time: Optional[datetime]) -> Optional[str]:
        """Resolves process node ID handling temporal PID reuse."""
        if not pid or pid not in pid_to_instances:
            return None
        candidates = pid_to_instances[pid]
        if len(candidates) == 1:
            return candidates[0]["node_id"]

        comp_time = _to_comparable_dt(ev_time)
        if comp_time:
            # First pass: check interval [spawn_time, end_time]
            for cand in candidates:
                st = cand["comp_spawn_time"]
                et = cand["comp_end_time"]
                if st and st <= comp_time:
                    if et is None or comp_time <= et:
                        return cand["node_id"]

            # Second pass: pick candidate with closest spawn time prior to event
            prior = [c for c in candidates if c["comp_spawn_time"] and c["comp_spawn_time"] <= comp_time]
            if prior:
                return prior[-1]["node_id"]

        return candidates[-1]["node_id"]

    # Process Spawning Edges (Temporal & Cycle-Resilient)
    for ev in proc_events:
        child_node_id = f"proc_{ev.id}"
        parent_node_id = None
        if ev.parent_process_id:
            parent_node_id = find_active_instance(ev.parent_process_id, ev.timestamp)

        if parent_node_id and parent_node_id != child_node_id and parent_node_id in nodes:
            edge_id = f"edge_spawn_{parent_node_id}_{child_node_id}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=parent_node_id,
                    target=child_node_id,
                    label="SPAWNED",
                    event_ids=[ev.id],
                )
            )
        else:
            # Connect to sample root if no parent captured or is root process
            edge_id = f"edge_exec_{sample_node_id}_{child_node_id}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=sample_node_id,
                    target=child_node_id,
                    label="EXECUTED_AS",
                    event_ids=[ev.id],
                )
            )

    # 3. File Nodes and File Operation Edges
    file_events = [e for e in events if e.category == "file"]
    for ev in file_events:
        fpath = ev.target_path or "unknown_file"
        f_id = _hash_id("file", fpath)
        is_dropped = (ev.attributes or {}).get("is_dropped_binary", False)
        is_encrypted = (ev.attributes or {}).get("is_encrypted_target", False)
        is_ransom = (ev.attributes or {}).get("is_ransom_note", False)

        if f_id not in nodes:
            label = fpath.split("\\")[-1] or fpath
            nodes[f_id] = GraphNode(
                data=GraphNodeData(
                    id=f_id,
                    label=label,
                    type="File",
                    details={
                        "full_path": fpath,
                        "is_dropped_binary": is_dropped,
                        "is_encrypted_target": is_encrypted,
                        "is_ransom_note": is_ransom,
                    },
                    suspicious=is_dropped or is_encrypted or is_ransom,
                )
            )

        src_id = find_active_instance(ev.process_id, ev.timestamp) or sample_node_id
        edge_label = "DROPPED" if is_dropped else ("CREATED" if ev.action == "write" else "MODIFIED")
        edge_id = f"edge_{src_id}_{f_id}_{ev.action}"
        if edge_id in edges:
            if ev.id not in edges[edge_id].data.event_ids:
                edges[edge_id].data.event_ids.append(ev.id)
        else:
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=src_id,
                    target=f_id,
                    label=edge_label,
                    event_ids=[ev.id],
                )
            )

    # 4. Registry Nodes and Edges
    reg_events = [e for e in events if e.category == "registry"]
    for ev in reg_events:
        rpath = ev.target_path or "unknown_reg"
        r_id = _hash_id("reg", rpath)
        is_pers = (ev.attributes or {}).get("persistence", False)

        if r_id not in nodes:
            label = rpath.split("\\")[-1] or rpath
            nodes[r_id] = GraphNode(
                data=GraphNodeData(
                    id=r_id,
                    label=label,
                    type="RegistryKey",
                    details={"key": rpath, "value_name": (ev.attributes or {}).get("value_name"), "persistence": is_pers},
                    suspicious=is_pers,
                )
            )

        src_id = find_active_instance(ev.process_id, ev.timestamp) or sample_node_id
        edge_id = f"edge_{src_id}_{r_id}"
        if edge_id in edges:
            if ev.id not in edges[edge_id].data.event_ids:
                edges[edge_id].data.event_ids.append(ev.id)
        else:
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=src_id,
                    target=r_id,
                    label="MODIFIED" if ev.action == "reg_write" else "ACCESSED",
                    event_ids=[ev.id],
                )
            )

    # 5. Network (DNS, IP & HTTP) Nodes and Edges
    # Strictly do NOT assign unknown-origin network events to arbitrary processes
    unassigned_net_id = "node_unattributed_network"

    for ev in events:
        if ev.category == "dns" and ev.target_path:
            d_id = _hash_id("dns", ev.target_path)
            if d_id not in nodes:
                nodes[d_id] = GraphNode(
                    data=GraphNodeData(
                        id=d_id,
                        label=ev.target_path,
                        type="Domain",
                        details={"query": ev.target_path, "response": (ev.attributes or {}).get("response")},
                        suspicious=True,
                    )
                )

            # Attribute only if valid process instance is identified
            src_id = find_active_instance(ev.process_id, ev.timestamp)
            if not src_id:
                if unassigned_net_id not in nodes:
                    nodes[unassigned_net_id] = GraphNode(
                        data=GraphNodeData(
                            id=unassigned_net_id,
                            label="Unattributed Network Traffic",
                            type="NetworkTraffic",
                            details={"description": "Observed network activity without verified process attribution."},
                            suspicious=False,
                        )
                    )
                src_id = unassigned_net_id

            edge_id = f"edge_{src_id}_{d_id}"
            if edge_id in edges:
                if ev.id not in edges[edge_id].data.event_ids:
                    edges[edge_id].data.event_ids.append(ev.id)
            else:
                edges[edge_id] = GraphEdge(
                    data=GraphEdgeData(
                        id=edge_id,
                        source=src_id,
                        target=d_id,
                        label="RESOLVED_TO",
                        event_ids=[ev.id],
                    )
                )

        elif ev.category in ["network", "http"] and ev.target_path:
            target_str = ev.target_path
            net_id = _hash_id("net", target_str)
            if net_id not in nodes:
                nodes[net_id] = GraphNode(
                    data=GraphNodeData(
                        id=net_id,
                        label=target_str,
                        type="IPAddress" if not target_str.startswith("http") else "Domain",
                        details={
                            "endpoint": target_str,
                            "protocol": (ev.attributes or {}).get("protocol", "TCP"),
                            "method": (ev.attributes or {}).get("method"),
                        },
                        suspicious=True,
                    )
                )

            # Attribute only if valid process instance is identified
            src_id = find_active_instance(ev.process_id, ev.timestamp)
            if not src_id:
                if unassigned_net_id not in nodes:
                    nodes[unassigned_net_id] = GraphNode(
                        data=GraphNodeData(
                            id=unassigned_net_id,
                            label="Unattributed Network Traffic",
                            type="NetworkTraffic",
                            details={"description": "Observed network activity without verified process attribution."},
                            suspicious=False,
                        )
                    )
                src_id = unassigned_net_id

            edge_id = f"edge_{src_id}_{net_id}"
            if edge_id in edges:
                if ev.id not in edges[edge_id].data.event_ids:
                    edges[edge_id].data.event_ids.append(ev.id)
            else:
                edges[edge_id] = GraphEdge(
                    data=GraphEdgeData(
                        id=edge_id,
                        source=src_id,
                        target=net_id,
                        label="CONNECTED_TO" if ev.category == "network" else "REQUESTED",
                        event_ids=[ev.id],
                    )
                )

    # 6. Behavioral Finding Nodes & Supporting Edges
    for f in findings:
        f_id = f"finding_{f.rule_id}"
        nodes[f_id] = GraphNode(
            data=GraphNodeData(
                id=f_id,
                label=f.title,
                type="BehavioralFinding",
                details={
                    "severity": f.severity,
                    "mitre_attack_id": f.mitre_attack_id,
                    "description": f.description,
                },
                suspicious=True,
                severity=f.severity,
            )
        )

        # Verify supporting event IDs exist in the actual event store
        valid_supporting_eids = [eid for eid in (f.supporting_event_ids or []) if eid in all_event_ids]

        edges[f"edge_finding_{f_id}"] = GraphEdge(
            data=GraphEdgeData(
                id=f"edge_finding_{f_id}",
                source=sample_node_id,
                target=f_id,
                label="SUPPORTS_FINDING",
                event_ids=valid_supporting_eids,
            )
        )

    # Strictly validate edge integrity: ensure source and target exist in nodes
    valid_edges = [
        edge for edge in edges.values()
        if edge.data.source in nodes and edge.data.target in nodes
    ]

    return BehaviorGraphResponse(
        analysis_id=analysis_id,
        nodes=list(nodes.values()),
        edges=valid_edges,
        total_nodes=len(nodes),
        total_edges=len(valid_edges),
    )
