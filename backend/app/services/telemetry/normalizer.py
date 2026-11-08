from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent

def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        # Handles ISO strings with Z or timezone
        clean_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str)
    except Exception:
        return None

class TelemetryNormalizer:
    """
    Normalizes disparate execution outputs from replay or CAPE sandboxes
    into a strictly typed, uniform internal telemetry event stream.
    """

    def __init__(self, db: Session):
        self.db = db

    def normalize_sandbox_output(self, analysis_id: str, raw_data: Dict[str, Any]) -> List[AnalysisEvent]:
        events: List[AnalysisEvent] = []

        # 1. Process Activity
        for p in raw_data.get("processes", []):
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="process",
                action="spawn",
                timestamp=parse_iso_datetime(p.get("start_time")),
                process_id=p.get("pid"),
                process_name=p.get("name"),
                parent_process_id=p.get("ppid"),
                target_path=p.get("name"),
                attributes={
                    "command_line": p.get("command_line"),
                    "start_time": p.get("start_time"),
                    "end_time": p.get("end_time"),
                },
                source_tool="sandbox-monitor",
                confidence=1.0,
            )
            events.append(event)

        # 2. Filesystem Activity
        for f in raw_data.get("filesystem", []):
            action_map = {
                "write": "write",
                "create": "write",
                "modify": "modify",
                "delete": "delete",
                "read": "read",
            }
            action = action_map.get(f.get("action", "").lower(), "access")
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="file",
                action=action,
                timestamp=parse_iso_datetime(f.get("timestamp")),
                process_id=f.get("pid"),
                process_name=f.get("process_name"),
                parent_process_id=None,
                target_path=f.get("path"),
                attributes={
                    "size_bytes": f.get("size_bytes"),
                    "sha256": f.get("sha256"),
                    "is_dropped_binary": f.get("is_dropped_binary", False),
                    "is_encrypted_target": f.get("is_encrypted_target", False),
                    "is_ransom_note": f.get("is_ransom_note", False),
                    "is_credential_target": f.get("is_credential_target", False),
                },
                source_tool="sandbox-fsmon",
                confidence=1.0,
            )
            events.append(event)

        # 3. Registry Activity
        for r in raw_data.get("registry", []):
            action = r.get("action", "reg_write")
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="registry",
                action=action,
                timestamp=parse_iso_datetime(r.get("timestamp")),
                process_id=r.get("pid"),
                process_name=r.get("process_name"),
                parent_process_id=None,
                target_path=r.get("key"),
                attributes={
                    "value_name": r.get("value_name"),
                    "data": r.get("data"),
                    "persistence": r.get("persistence", False),
                },
                source_tool="sandbox-regmon",
                confidence=1.0,
            )
            events.append(event)

        # 4. Network Activity
        net = raw_data.get("network", {})
        
        # DNS
        for d in net.get("dns", []):
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="dns",
                action="resolve",
                timestamp=parse_iso_datetime(d.get("timestamp")),
                process_id=d.get("pid"),
                process_name=d.get("process_name"),
                target_path=d.get("query"),
                attributes={
                    "query": d.get("query"),
                    "record_type": d.get("record_type", "A"),
                    "response": d.get("response"),
                },
                source_tool="sandbox-netmon",
                confidence=1.0,
            )
            events.append(event)

        # Connections (IP/Port)
        for c in net.get("connections", []):
            dest_ip = c.get("dest_ip")
            dest_port = c.get("dest_port")
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="network",
                action="connect",
                timestamp=parse_iso_datetime(c.get("timestamp")),
                process_id=c.get("pid"),
                process_name=c.get("process_name"),
                target_path=f"{dest_ip}:{dest_port}",
                attributes={
                    "protocol": c.get("protocol", "TCP"),
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                },
                source_tool="sandbox-netmon",
                confidence=1.0,
            )
            events.append(event)

        # HTTP
        for h in net.get("http", []):
            url = h.get("url", "")
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="http",
                action="request",
                timestamp=parse_iso_datetime(h.get("timestamp")),
                process_id=h.get("pid"),
                process_name=h.get("process_name"),
                target_path=url,
                attributes={
                    "method": h.get("method", "GET"),
                    "url": url,
                    "status_code": h.get("status_code"),
                    "user_agent": h.get("user_agent"),
                    "payload_size": h.get("payload_size"),
                },
                source_tool="sandbox-httpmon",
                confidence=1.0,
            )
            events.append(event)

        # 5. Artifacts
        for art in raw_data.get("artifacts", []):
            event = AnalysisEvent(
                analysis_id=analysis_id,
                category="artifact",
                action="collect",
                timestamp=None,
                process_id=None,
                target_path=art.get("name"),
                attributes={
                    "name": art.get("name"),
                    "type": art.get("type"),
                    "description": art.get("description"),
                },
                source_tool="sandbox-collector",
                confidence=1.0,
            )
            events.append(event)

        # Commit normalized events to DB
        self.db.add_all(events)
        self.db.commit()
        return events

