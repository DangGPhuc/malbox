import hashlib
from typing import Dict, List, Set, Any
from sqlalchemy.orm import Session
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.schemas.graph import BehaviorGraphResponse, GraphNode, GraphEdge, GraphNodeData, GraphEdgeData

def _hash_id(prefix: str, value: str) -> str:
    h = hashlib.md5(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{h}"

def build_behavior_graph(analysis_id: str, db: Session) -> BehaviorGraphResponse:
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        return BehaviorGraphResponse(analysis_id=analysis_id, nodes=[], edges=[], total_nodes=0, total_edges=0)

    events = db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
    findings = db.query(BehavioralFinding).filter(BehavioralFinding.analysis_id == analysis_id).all()

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

    # 2. Process Nodes & Spawning Edges
    proc_events = [e for e in events if e.category == "process"]
    for ev in proc_events:
        pid = ev.process_id
        if not pid:
            continue
        proc_node_id = f"proc_{pid}"
        is_suspicious = any(
            pat in (ev.attributes.get("command_line", "")).lower()
            for pat in ["vssadmin", "delete shadows", "-enc", "-executionpolicy bypass", "rundll32"]
        )

        if proc_node_id not in nodes:
            nodes[proc_node_id] = GraphNode(
                data=GraphNodeData(
                    id=proc_node_id,
                    label=f"{ev.process_name} [{pid}]",
                    type="Process",
                    details={
                        "pid": pid,
                        "ppid": ev.parent_process_id,
                        "command_line": ev.attributes.get("command_line"),
                    },
                    suspicious=is_suspicious,
                    pid=pid,
                )
            )

        # Edge from parent or from sample
        if ev.parent_process_id and f"proc_{ev.parent_process_id}" in nodes:
            edge_id = f"edge_spawn_{ev.parent_process_id}_{pid}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=f"proc_{ev.parent_process_id}",
                    target=proc_node_id,
                    label="SPAWNED",
                    event_ids=[ev.id],
                )
            )
        else:
            # Connect initial process to Sample root
            edge_id = f"edge_exec_{sample_node_id}_{proc_node_id}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=sample_node_id,
                    target=proc_node_id,
                    label="EXECUTED_AS",
                    event_ids=[ev.id],
                )
            )

    # 3. File Nodes and File Operation Edges
    file_events = [e for e in events if e.category == "file"]
    for ev in file_events:
        fpath = ev.target_path or "unknown_file"
        f_id = _hash_id("file", fpath)
        is_dropped = ev.attributes.get("is_dropped_binary", False)
        is_encrypted = ev.attributes.get("is_encrypted_target", False)
        is_ransom = ev.attributes.get("is_ransom_note", False)

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

        src_id = f"proc_{ev.process_id}" if (ev.process_id and f"proc_{ev.process_id}" in nodes) else sample_node_id
        edge_label = "DROPPED" if is_dropped else ("CREATED" if ev.action == "write" else "MODIFIED")
        edge_id = f"edge_{src_id}_{f_id}_{ev.action}"
        if edge_id in edges:
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
        is_pers = ev.attributes.get("persistence", False)

        if r_id not in nodes:
            label = rpath.split("\\")[-1] or rpath
            nodes[r_id] = GraphNode(
                data=GraphNodeData(
                    id=r_id,
                    label=label,
                    type="RegistryKey",
                    details={"key": rpath, "value_name": ev.attributes.get("value_name"), "persistence": is_pers},
                    suspicious=is_pers,
                )
            )

        src_id = f"proc_{ev.process_id}" if (ev.process_id and f"proc_{ev.process_id}" in nodes) else sample_node_id
        edge_id = f"edge_{src_id}_{r_id}"
        if edge_id in edges:
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

    # 5. Network (DNS & IP) Nodes and Edges
    for ev in events:
        if ev.category == "dns" and ev.target_path:
            d_id = _hash_id("dns", ev.target_path)
            if d_id not in nodes:
                nodes[d_id] = GraphNode(
                    data=GraphNodeData(
                        id=d_id,
                        label=ev.target_path,
                        type="Domain",
                        details={"query": ev.target_path, "response": ev.attributes.get("response")},
                        suspicious=True,
                    )
                )
            src_id = f"proc_{ev.process_id}" if (ev.process_id and f"proc_{ev.process_id}" in nodes) else sample_node_id
            edge_id = f"edge_{src_id}_{d_id}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=src_id,
                    target=d_id,
                    label="RESOLVED_TO",
                    event_ids=[ev.id],
                )
            )

        elif ev.category == "network" and ev.target_path:
            ip_id = _hash_id("net", ev.target_path)
            if ip_id not in nodes:
                nodes[ip_id] = GraphNode(
                    data=GraphNodeData(
                        id=ip_id,
                        label=ev.target_path,
                        type="IPAddress",
                        details={"endpoint": ev.target_path, "protocol": ev.attributes.get("protocol")},
                        suspicious=True,
                    )
                )
            src_id = f"proc_{ev.process_id}" if (ev.process_id and f"proc_{ev.process_id}" in nodes) else sample_node_id
            edge_id = f"edge_{src_id}_{ip_id}"
            edges[edge_id] = GraphEdge(
                data=GraphEdgeData(
                    id=edge_id,
                    source=src_id,
                    target=ip_id,
                    label="CONNECTED_TO",
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

        # Connect finding to sample root or to affected processes
        edges[f"edge_finding_{f_id}"] = GraphEdge(
            data=GraphEdgeData(
                id=f"edge_finding_{f_id}",
                source=sample_node_id,
                target=f_id,
                label="SUPPORTS_FINDING",
                event_ids=f.supporting_event_ids or [],
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
