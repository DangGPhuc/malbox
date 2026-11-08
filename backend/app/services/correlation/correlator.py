from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.schemas.report import ExtractedIOCs

class CorrelationEngine:
    """
    Correlates entity relationships, reconstructs temporal event sequences,
    and extracts high-confidence Indicators of Compromise (IOCs) with provenance.
    """

    def __init__(self, db: Session):
        self.db = db

    def extract_iocs(self, analysis_id: str) -> ExtractedIOCs:
        events = db_events = self.db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()

        domains = set()
        ips = set()
        urls = set()
        dropped_files = []
        registry_keys = set()

        for ev in events:
            if ev.category == "dns" and ev.target_path:
                domains.add(ev.target_path)
            elif ev.category == "network":
                dest_ip = ev.attributes.get("dest_ip")
                if dest_ip and dest_ip not in ["127.0.0.1", "0.0.0.0"]:
                    ips.add(dest_ip)
            elif ev.category == "http" and ev.target_path:
                urls.add(ev.target_path)
            elif ev.category == "file" and ev.attributes.get("is_dropped_binary"):
                dropped_files.append({
                    "path": ev.target_path,
                    "sha256": ev.attributes.get("sha256", "N/A"),
                    "size_bytes": ev.attributes.get("size_bytes", 0),
                    "event_id": ev.id,
                })
            elif ev.category == "registry" and ev.attributes.get("persistence"):
                if ev.target_path:
                    registry_keys.add(ev.target_path)

        return ExtractedIOCs(
            domains=sorted(list(domains)),
            ips=sorted(list(ips)),
            urls=sorted(list(urls)),
            dropped_files=dropped_files,
            registry_keys=sorted(list(registry_keys)),
        )

    def generate_timeline(self, analysis_id: str) -> List[Dict[str, Any]]:
        """Generates ordered chronological timeline of significant security milestones."""
        events = (
            self.db.query(AnalysisEvent)
            .filter(AnalysisEvent.analysis_id == analysis_id)
            .order_by(AnalysisEvent.timestamp.asc().nulls_last())
            .all()
        )

        timeline = []
        for ev in events:
            # Highlight key actions in the timeline
            if ev.category == "process" and ev.action == "spawn":
                summary = f"Spawned process: {ev.process_name} (PID: {ev.process_id})"
            elif ev.category == "file" and ev.attributes.get("is_dropped_binary"):
                summary = f"Dropped binary payload: {ev.target_path}"
            elif ev.category == "file" and ev.attributes.get("is_encrypted_target"):
                summary = f"Encrypted user file: {ev.target_path}"
            elif ev.category == "registry" and ev.attributes.get("persistence"):
                summary = f"Installed registry persistence key: {ev.target_path}"
            elif ev.category == "dns":
                summary = f"Resolved domain: {ev.target_path} -> {ev.attributes.get('response')}"
            elif ev.category == "network":
                summary = f"Outbound network connection to {ev.target_path} ({ev.attributes.get('protocol')})"
            elif ev.category == "http":
                summary = f"HTTP {ev.attributes.get('method')} request to {ev.target_path}"
            else:
                continue

            timeline.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else "N/A",
                "category": ev.category,
                "action": ev.action,
                "process": ev.process_name,
                "pid": ev.process_id,
                "summary": summary,
                "event_id": ev.id,
            })

        return timeline

