import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import sanitize_untrusted_input_for_ai
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.models.sample import Sample
from app.schemas.finding import ProcessTreeNode
from app.schemas.intelligence import (
    ArtifactEvidence,
    BundleProvenance,
    DeterministicFindingEvidence,
    IOCReferenceEvidence,
    MitreMappingEvidence,
    NetworkRelationshipEvidence,
    NormalizedEventEvidence,
    ProcessRelationshipEvidence,
    SampleIdentityEvidence,
    StaticAnalysisPlaceholder,
    TimelineEntryEvidence,
    TruncationMetadata,
    VerifiedEvidenceBundle,
)
from app.schemas.report import RiskAssessment
from app.services.correlation.correlator import CorrelationEngine
from app.services.correlation.process_tree import build_process_tree


DEFAULT_MAX_EVENTS = 120
DEFAULT_MAX_TIMELINE = 120
DEFAULT_MAX_FIELD_CHARS = 512
DEFAULT_MAX_BUNDLE_BYTES = 65536
DEFAULT_MAX_ATTR_KEYS = 20
DEFAULT_MAX_LIST_ITEMS = 25

_HIGH_SIGNAL_ACTIONS = {
    "delete_shadow_copies",
    "encrypt",
    "mass_write",
    "reg_write",
    "run_key_set",
    "cred_read",
    "credential_access",
    "lateral_move",
    "service_create",
    "scheduled_task",
    "inject",
}


def _to_sort_dt(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return datetime.max.replace(tzinfo=None)
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class _SanitizerTracker:
    def __init__(self, max_chars: int) -> None:
        self.max_chars = max(32, max_chars)
        self.truncated_count = 0

    def clean_str(self, value: Any, max_chars: Optional[int] = None) -> str:
        limit = max_chars or self.max_chars
        text = str(value) if value is not None else ""
        if len(text) > limit:
            self.truncated_count += 1
        cleaned = sanitize_untrusted_input_for_ai(text, max_chars=limit)
        if len(cleaned) > limit:
            cleaned = cleaned[:limit] + "...[truncated]"
            self.truncated_count += 1
        return cleaned

    def clean_value(self, value: Any, depth: int = 0) -> Any:
        if depth > 3:
            return "[nested_truncated]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (bytes, bytearray)):
            self.truncated_count += 1
            return f"[binary_omitted:{len(value)}_bytes]"
        if isinstance(value, str):
            return self.clean_str(value)
        if isinstance(value, list):
            if len(value) > DEFAULT_MAX_LIST_ITEMS:
                self.truncated_count += 1
            return [self.clean_value(v, depth + 1) for v in value[:DEFAULT_MAX_LIST_ITEMS]]
        if isinstance(value, dict):
            result: Dict[str, Any] = {}
            items = list(value.items())
            if len(items) > DEFAULT_MAX_ATTR_KEYS:
                self.truncated_count += 1
            for k, v in items[:DEFAULT_MAX_ATTR_KEYS]:
                key_str = self.clean_str(k, max_chars=80)
                if "raw_bytes" in key_str.lower() or "raw_hex" in key_str.lower():
                    result[key_str] = "[binary_omitted]"
                    self.truncated_count += 1
                else:
                    result[key_str] = self.clean_value(v, depth + 1)
            return result
        return self.clean_str(str(value))


class EvidenceBundleBuilder:
    """
    Constructs a strictly bounded, sanitized, provenance-aware VerifiedEvidenceBundle
    from persisted normalized telemetry, deterministic findings, correlation outputs,
    and sample metadata. Never reads or embeds raw executable bytes.
    """

    def __init__(
        self,
        db: Session,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_timeline: int = DEFAULT_MAX_TIMELINE,
        max_field_chars: int = DEFAULT_MAX_FIELD_CHARS,
        max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
    ) -> None:
        self.db = db
        self.max_events = max(1, max_events)
        self.max_timeline = max(1, max_timeline)
        self.max_field_chars = max(64, max_field_chars)
        self.max_bundle_bytes = max(2048, max_bundle_bytes)

    def build(
        self,
        analysis_id: str,
        risk_assessment: Optional[RiskAssessment] = None,
        env_metadata: Optional[Dict[str, Any]] = None,
        static_analysis: Optional[StaticAnalysisPlaceholder] = None,
    ) -> VerifiedEvidenceBundle:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis '{analysis_id}' not found.")

        sample = self.db.query(Sample).filter(Sample.id == analysis.sample_id).first()
        tracker = _SanitizerTracker(self.max_field_chars)

        is_replay = analysis.backend_type == "replay"
        raw_env = dict(env_metadata or {})
        fixture_version = raw_env.pop("fixture_version", None)
        scenario_id = analysis.replay_scenario_id or raw_env.pop("scenario_id", None)

        if is_replay:
            provenance_stmt = (
                f"SYNTHETIC REPLAY PROVENANCE: Telemetry originates from deterministic replay "
                f"scenario '{scenario_id or 'default'}'. The uploaded sample was triaged statically "
                "and was NOT executed."
            )
        else:
            provenance_stmt = (
                f"DYNAMIC SANDBOX PROVENANCE: Telemetry collected via '{analysis.backend_type}' "
                "sandbox execution within configured timeout and observation bounds."
            )

        provenance = BundleProvenance(
            analysis_id=analysis.id,
            backend_type=analysis.backend_type,
            is_replay=is_replay,
            replay_scenario_id=scenario_id,
            fixture_version=tracker.clean_str(fixture_version, 64) if fixture_version else None,
            provenance_statement=provenance_stmt,
            environment=tracker.clean_value(raw_env) if raw_env else {},
        )

        sample_sha256 = sample.sha256 if sample else "unknown"
        sample_evidence_id = f"sample:{sample_sha256}"
        pe_summary = self._summarize_pe_metadata(sample.pe_metadata if sample else None, tracker)
        sample_identity = SampleIdentityEvidence(
            evidence_id=sample_evidence_id,
            sample_id=sample.id if sample else "unknown",
            file_name=tracker.clean_str(sample.file_name if sample else "unknown", 255),
            file_size=int(sample.file_size) if sample else 0,
            sha256=sample_sha256,
            sha1=sample.sha1 if sample else None,
            md5=sample.md5 if sample else None,
            mime_type=tracker.clean_str(sample.mime_type, 100) if (sample and sample.mime_type) else None,
            is_pe=bool(sample.is_pe) if sample else False,
            pe_metadata_summary=pe_summary,
        )

        findings_db: List[BehavioralFinding] = (
            self.db.query(BehavioralFinding)
            .filter(BehavioralFinding.analysis_id == analysis.id)
            .order_by(BehavioralFinding.created_at.asc(), BehavioralFinding.id.asc())
            .all()
        )
        findings_ev: List[DeterministicFindingEvidence] = []
        finding_event_ids: Set[str] = set()
        mitre_by_id: Dict[str, MitreMappingEvidence] = {}

        for f in findings_db:
            sup_ids = [str(eid) for eid in (f.supporting_event_ids or [])]
            finding_event_ids.update(sup_ids)
            findings_ev.append(
                DeterministicFindingEvidence(
                    finding_id=f.id,
                    rule_id=f.rule_id,
                    title=tracker.clean_str(f.title, 255),
                    description=tracker.clean_str(f.description),
                    severity=f.severity,
                    confidence=float(f.confidence),
                    mitre_attack_id=f.mitre_attack_id,
                    mitre_tactic=f.mitre_tactic,
                    supporting_event_ids=sup_ids,
                )
            )
            if f.mitre_attack_id:
                existing = mitre_by_id.get(f.mitre_attack_id)
                if existing is None:
                    mitre_by_id[f.mitre_attack_id] = MitreMappingEvidence(
                        technique_id=f.mitre_attack_id,
                        tactic=f.mitre_tactic or "Unknown",
                        technique_name=tracker.clean_str(f.title, 255),
                        supporting_event_ids=list(sup_ids),
                        confidence=float(f.confidence),
                    )
                else:
                    merged = set(existing.supporting_event_ids) | set(sup_ids)
                    existing.supporting_event_ids = sorted(merged)

        if risk_assessment is not None:
            det_score = int(risk_assessment.score)
            det_level = str(risk_assessment.level)
        else:
            det_score = 0
            det_level = "Clean" if not findings_ev else "Suspicious"

        all_events_db: List[AnalysisEvent] = (
            self.db.query(AnalysisEvent)
            .filter(AnalysisEvent.analysis_id == analysis.id)
            .all()
        )
        selected_events, omitted_count = self._prioritize_and_select_events(
            all_events_db, finding_event_ids, tracker
        )

        correlator = CorrelationEngine(self.db)
        raw_iocs = correlator.extract_iocs(analysis.id)
        iocs_ev = IOCReferenceEvidence(
            domains=[tracker.clean_str(d, 255) for d in raw_iocs.domains[:DEFAULT_MAX_LIST_ITEMS]],
            ips=[tracker.clean_str(ip, 64) for ip in raw_iocs.ips[:DEFAULT_MAX_LIST_ITEMS]],
            urls=[tracker.clean_str(u) for u in raw_iocs.urls[:DEFAULT_MAX_LIST_ITEMS]],
            dropped_files=[
                tracker.clean_value(df) for df in raw_iocs.dropped_files[:DEFAULT_MAX_LIST_ITEMS]
            ],
            registry_keys=[tracker.clean_str(rk) for rk in raw_iocs.registry_keys[:DEFAULT_MAX_LIST_ITEMS]],
        )

        raw_timeline = correlator.generate_timeline(analysis.id)
        timeline_truncated = len(raw_timeline) > self.max_timeline
        timeline_ev = [
            TimelineEntryEvidence(
                event_id=str(item.get("event_id") or ""),
                timestamp=str(item.get("timestamp")) if item.get("timestamp") else None,
                category=str(item.get("category") or "unknown"),
                action=str(item.get("action") or "unknown"),
                process=tracker.clean_str(item.get("process"), 128) if item.get("process") else None,
                pid=item.get("pid"),
                summary=tracker.clean_str(item.get("summary") or ""),
            )
            for item in raw_timeline[: self.max_timeline]
        ]

        process_tree = build_process_tree(analysis.id, self.db)
        proc_rels = self._flatten_process_tree(process_tree.root_nodes, tracker)
        net_rels, has_unattributed_network = self._extract_network_relationships(all_events_db, tracker)
        artifacts_ev = self._build_artifacts(analysis.id, all_events_db, is_replay, tracker)

        static_info = static_analysis or StaticAnalysisPlaceholder()
        known_limitations = self._build_known_limitations(
            is_replay=is_replay,
            scenario_id=scenario_id,
            total_events=len(all_events_db),
            omitted_events=omitted_count,
            findings_count=len(findings_ev),
            has_unattributed_network=has_unattributed_network,
            static_available=(static_info.status == "available"),
            artifacts=artifacts_ev,
        )

        valid_ids = self._collect_valid_ids(
            sample_evidence_id=sample_evidence_id,
            findings=findings_ev,
            events=selected_events,
            timeline=timeline_ev,
            artifacts=artifacts_ev,
            all_event_ids={e.id for e in all_events_db},
        )

        truncation = TruncationMetadata(
            truncated=(omitted_count > 0 or timeline_truncated or tracker.truncated_count > 0),
            total_events_available=len(all_events_db),
            events_included=len(selected_events),
            events_omitted=omitted_count,
            timeline_truncated=timeline_truncated,
            fields_truncated_count=tracker.truncated_count,
            max_events_limit=self.max_events,
            max_field_chars=self.max_field_chars,
            max_bundle_bytes=self.max_bundle_bytes,
            estimated_bundle_bytes=0,
        )

        bundle = VerifiedEvidenceBundle(
            analysis_id=analysis.id,
            sample_identity=sample_identity,
            provenance=provenance,
            deterministic_risk_score=det_score,
            deterministic_risk_level=det_level,
            events=selected_events,
            timeline=timeline_ev,
            process_relationships=proc_rels,
            network_relationships=net_rels,
            findings=findings_ev,
            mitre_mappings=sorted(mitre_by_id.values(), key=lambda m: m.technique_id),
            iocs=iocs_ev,
            artifacts=artifacts_ev,
            known_limitations=known_limitations,
            static_analysis=static_info,
            valid_evidence_ids=sorted(valid_ids),
            truncation=truncation,
        )

        return self._enforce_byte_budget(bundle, finding_event_ids)

    def _prioritize_and_select_events(
        self,
        events: List[AnalysisEvent],
        finding_event_ids: Set[str],
        tracker: _SanitizerTracker,
    ) -> Tuple[List[NormalizedEventEvidence], int]:
        ranked: List[Tuple[int, datetime, str, AnalysisEvent, str]] = []
        for ev in events:
            tier_rank, tier_name = self._classify_event_tier(ev, finding_event_ids)
            ranked.append((tier_rank, _to_sort_dt(ev.timestamp), ev.id, ev, tier_name))

        ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        chosen = ranked[: self.max_events]
        omitted = max(0, len(ranked) - len(chosen))

        # Re-order chosen subset chronologically for coherent analyst narrative
        chosen.sort(key=lambda item: (item[1], item[2]))

        result: List[NormalizedEventEvidence] = []
        for _, _, _, ev, tier_name in chosen:
            result.append(
                NormalizedEventEvidence(
                    event_id=ev.id,
                    category=ev.category,
                    action=ev.action,
                    timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
                    process_id=ev.process_id,
                    parent_process_id=ev.parent_process_id,
                    process_name=tracker.clean_str(ev.process_name, 128) if ev.process_name else None,
                    target_path=tracker.clean_str(ev.target_path) if ev.target_path else None,
                    attributes=tracker.clean_value(ev.attributes or {}),
                    source_tool=tracker.clean_str(ev.source_tool, 64),
                    confidence=float(ev.confidence),
                    priority_tier=tier_name,
                )
            )
        return result, omitted

    @staticmethod
    def _classify_event_tier(
        ev: AnalysisEvent, finding_event_ids: Set[str]
    ) -> Tuple[int, str]:
        if ev.id in finding_event_ids:
            return 0, "finding_linked"
        if ev.category in {"process", "persistence", "artifact"} or ev.action in _HIGH_SIGNAL_ACTIONS:
            return 1, "security_critical"
        attrs = ev.attributes or {}
        if attrs.get("suspicious") or attrs.get("is_sensitive"):
            return 1, "security_critical"
        if ev.category in {"dns", "http", "network"}:
            return 2, "network_http_dns"
        return 3, "routine"

    def _flatten_process_tree(
        self, nodes: List[ProcessTreeNode], tracker: _SanitizerTracker
    ) -> List[ProcessRelationshipEvidence]:
        flat: List[ProcessRelationshipEvidence] = []

        def _walk(items: Iterable[ProcessTreeNode]) -> None:
            for node in items:
                if len(flat) >= DEFAULT_MAX_LIST_ITEMS:
                    return
                flat.append(
                    ProcessRelationshipEvidence(
                        pid=node.pid,
                        ppid=node.ppid,
                        name=tracker.clean_str(node.name, 128),
                        command_line=tracker.clean_str(node.command_line) if node.command_line else None,
                        spawn_time=node.spawn_time,
                        suspicious=bool(node.suspicious),
                        event_count=int(node.events_count),
                        event_ids=list(node.event_ids[:20]),
                    )
                )
                _walk(node.children)

        _walk(nodes)
        return flat

    def _extract_network_relationships(
        self, events: List[AnalysisEvent], tracker: _SanitizerTracker
    ) -> Tuple[List[NetworkRelationshipEvidence], bool]:
        rels: List[NetworkRelationshipEvidence] = []
        has_unattributed = False
        for ev in sorted(events, key=lambda e: (_to_sort_dt(e.timestamp), e.id)):
            if ev.category not in {"network", "dns", "http"}:
                continue
            if ev.process_id is None and not ev.process_name:
                has_unattributed = True
            attrs = ev.attributes or {}
            dest = (
                attrs.get("destination_ip")
                or attrs.get("domain")
                or attrs.get("host")
                or attrs.get("url")
                or ev.target_path
                or "unknown"
            )
            port_raw = attrs.get("destination_port") or attrs.get("port")
            port_val = int(port_raw) if isinstance(port_raw, (int, str)) and str(port_raw).isdigit() else None
            method_or_query = attrs.get("method") or attrs.get("query_type") or attrs.get("protocol")
            if len(rels) < DEFAULT_MAX_LIST_ITEMS:
                rels.append(
                    NetworkRelationshipEvidence(
                        event_id=ev.id,
                        protocol=ev.category,
                        process_name=tracker.clean_str(ev.process_name, 128) if ev.process_name else None,
                        process_id=ev.process_id,
                        destination=tracker.clean_str(dest, 255),
                        port=port_val,
                        method_or_query=tracker.clean_str(method_or_query, 64) if method_or_query else None,
                    )
                )
        return rels, has_unattributed

    def _build_artifacts(
        self,
        analysis_id: str,
        events: List[AnalysisEvent],
        is_replay: bool,
        tracker: _SanitizerTracker,
    ) -> List[ArtifactEvidence]:
        artifacts_dir = Path(settings.ARTIFACTS_DIR) / analysis_id
        artifacts: List[ArtifactEvidence] = []
        seen_names: Set[str] = set()

        for ev in sorted(events, key=lambda e: (_to_sort_dt(e.timestamp), e.id)):
            if ev.category != "artifact":
                continue
            attrs = ev.attributes or {}
            name = tracker.clean_str(ev.target_path or attrs.get("name") or ev.id, 255)
            seen_names.add(name)
            art_type = tracker.clean_str(attrs.get("type", "unknown"), 64)
            desc = tracker.clean_str(attrs.get("description", ""))
            disk_size = self._safe_artifact_size(artifacts_dir, name)
            synthetic = is_replay or bool(attrs.get("is_synthetic", False))
            if synthetic:
                prov_note = (
                    f"SYNTHETIC MOCK ARTIFACT: Generated by Replay backend for pipeline verification "
                    f"(size={disk_size if disk_size is not None else 'stub'} bytes); does not contain "
                    "live VM capture data."
                )
            else:
                prov_note = "Artifact recorded during dynamic sandbox execution."

            artifacts.append(
                ArtifactEvidence(
                    evidence_id=f"artifact:{name}",
                    name=name,
                    artifact_type=art_type,
                    description=desc,
                    is_synthetic=synthetic,
                    provenance_note=prov_note,
                    size_bytes=disk_size,
                    source_event_id=ev.id,
                )
            )

        if artifacts_dir.is_dir():
            for entry in sorted(artifacts_dir.iterdir(), key=lambda p: p.name):
                if not entry.is_file() or entry.name in seen_names:
                    continue
                size = entry.stat().st_size
                synthetic = is_replay
                prov_note = (
                    f"SYNTHETIC MOCK ARTIFACT: Replay placeholder file on disk ({size} bytes)."
                    if synthetic
                    else "File present in analysis artifacts directory."
                )
                artifacts.append(
                    ArtifactEvidence(
                        evidence_id=f"artifact:{entry.name}",
                        name=tracker.clean_str(entry.name, 255),
                        artifact_type=entry.suffix.lstrip(".") or "file",
                        description="Artifact present in analysis output directory.",
                        is_synthetic=synthetic,
                        provenance_note=prov_note,
                        size_bytes=size,
                        source_event_id=None,
                    )
                )

        return artifacts

    @staticmethod
    def _safe_artifact_size(artifacts_dir: Path, name: str) -> Optional[int]:
        if not name or "/" in name or "\\" in name or ".." in name:
            return None
        candidate = (artifacts_dir / name).resolve()
        try:
            candidate.relative_to(artifacts_dir.resolve())
        except ValueError:
            return None
        if candidate.is_file():
            return candidate.stat().st_size
        return None

    @staticmethod
    def _summarize_pe_metadata(
        pe_metadata: Optional[Dict[str, Any]], tracker: _SanitizerTracker
    ) -> Dict[str, Any]:
        if not isinstance(pe_metadata, dict) or not pe_metadata:
            return {}
        summary: Dict[str, Any] = {}
        safe_scalar_keys = [
            "machine",
            "compile_timestamp",
            "entry_point",
            "subsystem",
            "imphash",
            "is_dll",
            "is_64bit",
            "architecture",
        ]
        for key in safe_scalar_keys:
            if key in pe_metadata and pe_metadata[key] is not None:
                summary[key] = tracker.clean_value(pe_metadata[key])
        if isinstance(pe_metadata.get("sections"), list):
            sec_list = []
            for s in pe_metadata["sections"][:12]:
                if isinstance(s, dict):
                    sec_list.append({
                        "name": tracker.clean_str(s.get("name", ""), 32),
                        "entropy": s.get("entropy"),
                        "virtual_size": s.get("virtual_size"),
                    })
            summary["sections_count"] = len(pe_metadata["sections"])
            summary["sections_preview"] = sec_list
        if isinstance(pe_metadata.get("imports"), list):
            summary["imports_dll_count"] = len(pe_metadata["imports"])
            summary["imports_preview"] = tracker.clean_value(pe_metadata["imports"][:10])
        elif isinstance(pe_metadata.get("imports"), dict):
            summary["imports_dll_count"] = len(pe_metadata["imports"])
            summary["imports_preview"] = [
                tracker.clean_str(k, 64) for k in list(pe_metadata["imports"].keys())[:10]
            ]
        return summary

    @staticmethod
    def _build_known_limitations(
        is_replay: bool,
        scenario_id: Optional[str],
        total_events: int,
        omitted_events: int,
        findings_count: int,
        has_unattributed_network: bool,
        static_available: bool,
        artifacts: List[ArtifactEvidence],
    ) -> List[str]:
        limits: List[str] = []
        if is_replay:
            limits.append(
                f"Replay Mode active (scenario='{scenario_id or 'default'}'): telemetry is synthetic; "
                "the uploaded binary was not dynamically executed."
            )
        if not static_available:
            limits.append(
                "Static decompilation/disassembly (Phase 2B Ghidra) was not executed; binary code internals are unavailable."
            )
        if omitted_events > 0:
            limits.append(
                f"Evidence bundle truncated: included {total_events - omitted_events} prioritized events "
                f"out of {total_events} total events ({omitted_events} lower-priority events omitted)."
            )
        if findings_count == 0:
            limits.append(
                "No deterministic behavioral rule thresholds triggered; dormant or time-delayed capabilities cannot be excluded."
            )
        if has_unattributed_network:
            limits.append(
                "One or more network/DNS/HTTP events lack an associated PID or process name and remain process-unattributed."
            )
        if any(a.is_synthetic for a in artifacts):
            limits.append(
                "Artifacts associated with this analysis are synthetic replay placeholders (e.g., stub PCAP/PNG/text files), "
                "not genuine captured runtime artifacts."
            )
        return limits

    @staticmethod
    def _collect_valid_ids(
        sample_evidence_id: str,
        findings: List[DeterministicFindingEvidence],
        events: List[NormalizedEventEvidence],
        timeline: List[TimelineEntryEvidence],
        artifacts: List[ArtifactEvidence],
        all_event_ids: Set[str],
    ) -> Set[str]:
        valid: Set[str] = {sample_evidence_id}
        for ev in events:
            valid.add(ev.event_id)
        for item in timeline:
            if item.event_id:
                valid.add(item.event_id)
        for art in artifacts:
            valid.add(art.evidence_id)
            if art.source_event_id:
                valid.add(art.source_event_id)
        for f in findings:
            valid.add(f.finding_id)
            valid.add(f"finding:{f.finding_id}")
            valid.add(f.rule_id)
            valid.add(f"rule:{f.rule_id}")
            for eid in f.supporting_event_ids:
                if not all_event_ids or eid in all_event_ids:
                    valid.add(eid)
        return valid

    def _enforce_byte_budget(
        self, bundle: VerifiedEvidenceBundle, finding_event_ids: Set[str]
    ) -> VerifiedEvidenceBundle:
        serialized = bundle.model_dump_json().encode("utf-8")
        if len(serialized) <= self.max_bundle_bytes:
            bundle.truncation.estimated_bundle_bytes = len(serialized)
            return bundle

        # Iteratively trim routine events first, then tail events, then timeline
        events = list(bundle.events)
        timeline = list(bundle.timeline)

        while len(serialized) > self.max_bundle_bytes and len(events) > 0:
            drop_idx = self._pick_droppable_event_index(events, finding_event_ids)
            events.pop(drop_idx)
            bundle.truncation.truncated = True
            bundle.truncation.events_included = len(events)
            bundle.truncation.events_omitted = max(
                0, bundle.truncation.total_events_available - len(events)
            )
            bundle.events = events
            serialized = bundle.model_dump_json().encode("utf-8")

        while len(serialized) > self.max_bundle_bytes and len(timeline) > 0:
            timeline.pop()
            bundle.truncation.truncated = True
            bundle.truncation.timeline_truncated = True
            bundle.timeline = timeline
            serialized = bundle.model_dump_json().encode("utf-8")

        while len(serialized) > self.max_bundle_bytes and len(bundle.network_relationships) > 0:
            bundle.network_relationships.pop()
            bundle.truncation.truncated = True
            serialized = bundle.model_dump_json().encode("utf-8")

        while len(serialized) > self.max_bundle_bytes and len(bundle.process_relationships) > 0:
            bundle.process_relationships.pop()
            bundle.truncation.truncated = True
            serialized = bundle.model_dump_json().encode("utf-8")

        # Refresh valid_evidence_ids to reflect included events/timeline/findings/artifacts
        sample_id = bundle.sample_identity.evidence_id
        all_evt_ids = {e.event_id for e in bundle.events} | {t.event_id for t in bundle.timeline if t.event_id}
        bundle.valid_evidence_ids = sorted(
            self._collect_valid_ids(
                sample_evidence_id=sample_id,
                findings=bundle.findings,
                events=bundle.events,
                timeline=bundle.timeline,
                artifacts=bundle.artifacts,
                all_event_ids=all_evt_ids,
            )
        )

        # Ensure known_limitations mentions truncation if budget forced trimming
        trunc_note = (
            f"Evidence bundle truncated to fit {self.max_bundle_bytes}-byte budget: "
            f"{bundle.truncation.events_included}/{bundle.truncation.total_events_available} events included."
        )
        if bundle.truncation.truncated and not any("truncated" in item.lower() for item in bundle.known_limitations):
            bundle.known_limitations.append(trunc_note)

        final_bytes = len(bundle.model_dump_json().encode("utf-8"))
        bundle.truncation.estimated_bundle_bytes = final_bytes
        return bundle

    @staticmethod
    def _pick_droppable_event_index(
        events: List[NormalizedEventEvidence], finding_event_ids: Set[str]
    ) -> int:
        tier_order = {"routine": 0, "network_http_dns": 1, "security_critical": 2, "finding_linked": 3}
        best_idx = len(events) - 1
        best_score = 99
        # Scan from the end so chronologically latest lower-tier events drop first
        for idx in range(len(events) - 1, -1, -1):
            ev = events[idx]
            if ev.event_id in finding_event_ids:
                score = 3
            else:
                score = tier_order.get(ev.priority_tier, 0)
            if score < best_score:
                best_score = score
                best_idx = idx
                if score == 0:
                    break
        return best_idx
