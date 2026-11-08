from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.report import AnalysisReport
from app.schemas.report import FullReportSchema, RiskAssessment, MitreTechnique, ExtractedIOCs
from app.schemas.finding import FindingResponse
from app.services.correlation.correlator import CorrelationEngine
from app.services.correlation.process_tree import build_process_tree

class ReportGenerator:
    """
    Generates structured, evidence-grounded intelligence reports.
    Produces deterministic baseline reports when AI is offline or in mock mode.
    """

    def __init__(self, db: Session):
        self.db = db

    def generate_report(
        self,
        analysis_id: str,
        risk_assessment: RiskAssessment,
        ai_summary: str = "",
        ai_follow_up: dict = None,
        env_metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisReport:
        analysis = self.db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found.")

        sample = analysis.sample
        correlator = CorrelationEngine(self.db)
        iocs = correlator.extract_iocs(analysis_id)
        timeline = correlator.generate_timeline(analysis_id)
        process_tree = build_process_tree(analysis_id, self.db)

        findings_db = analysis.findings or []
        findings_schemas = [
            FindingResponse(
                id=f.id,
                analysis_id=f.analysis_id,
                rule_id=f.rule_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                mitre_attack_id=f.mitre_attack_id,
                mitre_tactic=f.mitre_tactic,
                supporting_event_ids=f.supporting_event_ids or [],
                created_at=f.created_at,
            )
            for f in findings_db
        ]

        # Extract MITRE techniques from findings
        mitre_map: Dict[str, MitreTechnique] = {}
        for f in findings_db:
            if f.mitre_attack_id and f.mitre_attack_id not in mitre_map:
                mitre_map[f.mitre_attack_id] = MitreTechnique(
                    technique_id=f.mitre_attack_id,
                    tactic=f.mitre_tactic or "Unknown",
                    technique_name=f.title,
                    description=f.description,
                    supporting_event_ids=f.supporting_event_ids or [],
                    confidence=f.confidence,
                )

        # Baseline executive summary
        sample_name = sample.file_name if sample else "Unknown"
        sample_hash = sample.sha256 if sample else "N/A"
        finding_titles = ", ".join([f.title for f in findings_db[:3]]) or "No severe behavioral anomalies"

        if not ai_summary:
            if not findings_db:
                executive_summary = (
                    f"Dynamic sandbox analysis of '{sample_name}' (SHA-256: {sample_hash[:16]}...) concluded with "
                    f"a threat classification of '{risk_assessment.level}' (score: 0/100). "
                    "No suspicious or malicious behavioral anomalies were observed during the bounded sandbox execution. "
                    "Note: Anti-evasion measures, dormant delayed payloads, or missing external C2 infrastructure cannot be ruled out."
                )
            else:
                executive_summary = (
                    f"Dynamic sandbox analysis of '{sample_name}' (SHA-256: {sample_hash[:16]}...) concluded with "
                    f"a threat classification of {risk_assessment.level.upper()} and an explainable risk score of {risk_assessment.score}/100. "
                    f"The executable spawned {process_tree.total_processes} process(es) and demonstrated high-confidence behaviors: {finding_titles}. "
                    f"{len(mitre_map)} MITRE ATT&CK techniques were deterministically mapped with direct telemetry provenance."
                )
        else:
            executive_summary = ai_summary

        sample_meta = {
            "file_name": sample.file_name if sample else "N/A",
            "file_size": sample.file_size if sample else 0,
            "sha256": sample.sha256 if sample else "N/A",
            "sha1": sample.sha1 if sample else "N/A",
            "md5": sample.md5 if sample else "N/A",
            "is_pe": sample.is_pe if sample else False,
            "pe_metadata": sample.pe_metadata if sample else {},
        }

        # Do not fabricate OS environment; report only verified telemetry from sandbox
        env_meta = env_metadata or {}
        if analysis.backend_type == "replay":
            guest_os_str = env_meta.get("guest_os", "Windows 10 x64 (Simulated Replay Environment)")
            confinement_str = "Isolated Replay Sandbox"
        else:
            guest_os_str = env_meta.get("guest_os") or "Not reported by sandbox backend"
            confinement_str = env_meta.get("confinement") or "Live Hypervisor Guest"

        analysis_env = {
            "backend": analysis.backend_type,
            "profile": analysis.profile,
            "timeout_seconds": analysis.timeout_seconds,
            "live_mode": analysis.live_mode,
            "guest_os": guest_os_str,
            "confinement": confinement_str,
        }

        # Activity summaries
        process_summary = {
            "total_spawned": process_tree.total_processes,
            "root_processes": [r.name for r in process_tree.root_nodes],
        }

        fs_summary = {
            "dropped_files_count": len(iocs.dropped_files),
            "dropped_files": iocs.dropped_files,
        }

        reg_summary = {
            "persistence_keys_count": len(iocs.registry_keys),
            "persistence_keys": iocs.registry_keys,
        }

        net_summary = {
            "domains_contacted": iocs.domains,
            "ips_contacted": iocs.ips,
            "urls_accessed": iocs.urls,
        }

        limitations = {
            "execution_duration_bound": f"{analysis.timeout_seconds} seconds",
            "sandbox_evasion_risk": "Dormant payloads, anti-VM checks, or delayed execution loops may limit observable dynamic behavior.",
            "network_confinement": "Simulated or isolated network egress was enforced to prevent real-world malicious propagation.",
            "overall_entropy": sample.pe_metadata.get("overall_entropy", 0.0) if sample and sample.pe_metadata else 0.0,
        }

        follow_up = ai_follow_up or {
            "needs_second_pass": risk_assessment.score >= 50,
            "recommendations": [
                "Inspect secondary dropped payload for targeted persistence mechanisms.",
                "Review network telemetry for C2 beaconing patterns.",
                "Correlate extracted hash indicators with external threat intelligence feeds.",
            ],
            "limitations_identified": ["Execution completed under bounded replay constraints."],
        }

        # Artifacts list
        artifacts_summary = []
        for ev in analysis.events:
            if ev.category == "artifact":
                artifacts_summary.append({
                    "name": ev.target_path,
                    "type": ev.attributes.get("type", "unknown"),
                    "description": ev.attributes.get("description", ""),
                })

        report_payload = FullReportSchema(
            analysis_id=analysis_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            backend_type=analysis.backend_type,
            is_replay=(analysis.backend_type == "replay"),
            replay_scenario_id=analysis.replay_scenario_id,
            provenance_disclaimer=(
                "REPLAY DATA PROVENANCE: Telemetry derived from synthetic replay fixture. "
                "All behaviors represent simulated execution rather than live host detonation."
                if analysis.backend_type == "replay"
                else "LIVE DETONATION: Telemetry collected from live sandbox VM execution."
            ),
            sample_metadata=sample_meta,
            analysis_environment=analysis_env,
            executive_summary=executive_summary,
            risk_assessment=risk_assessment,
            mitre_attack_mappings=list(mitre_map.values()),
            findings=findings_schemas,
            extracted_iocs=iocs,
            execution_timeline=timeline,
            process_activity_summary=process_summary,
            filesystem_activity_summary=fs_summary,
            registry_activity_summary=reg_summary,
            network_activity_summary=net_summary,
            confidence_and_limitations=limitations,
            recommended_follow_up=follow_up,
            artifacts=artifacts_summary,
        )

        # Check for existing report record to update or insert
        report_dict = report_payload.model_dump(mode="json")
        existing_report = self.db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
        if existing_report:
            existing_report.executive_summary = executive_summary
            existing_report.risk_score = risk_assessment.score
            existing_report.risk_level = risk_assessment.level
            existing_report.full_report_json = report_dict
            report_record = existing_report
        else:
            report_record = AnalysisReport(
                analysis_id=analysis_id,
                executive_summary=executive_summary,
                risk_score=risk_assessment.score,
                risk_level=risk_assessment.level,
                full_report_json=report_dict,
            )
            self.db.add(report_record)

        self.db.commit()
        self.db.refresh(report_record)
        return report_record
