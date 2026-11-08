from typing import List, Tuple
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.services.detection.rules import BEHAVIORAL_RULES, BehavioralRule
from app.schemas.report import RiskAssessment

class DetectionEngine:
    """
    Deterministic behavioral rule engine that identifies malicious TTPs,
    maps MITRE ATT&CK techniques, and derives explainable risk scores.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_behavior(self, analysis_id: str) -> Tuple[List[BehavioralFinding], RiskAssessment]:
        events = self.db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
        findings: List[BehavioralFinding] = []
        rule_score_contribs: List[dict] = []
        total_score = 0

        # Pre-group events by category for efficient evaluation
        proc_cmds = [(e.id, (e.attributes.get("command_line") or "").lower()) for e in events if e.category == "process"]
        file_writes = [(e.id, (e.target_path or "").lower(), e.attributes) for e in events if e.category == "file"]
        reg_writes = [(e.id, (e.target_path or "").lower(), e.attributes) for e in events if e.category == "registry"]
        net_conns = [(e.id, e.attributes) for e in events if e.category == "network"]
        http_reqs = [(e.id, (e.target_path or "").lower(), e.attributes) for e in events if e.category == "http"]

        for rule in BEHAVIORAL_RULES:
            matched_event_ids = []

            if rule.rule_id == "RULE_SHADOW_COPY_DELETION":
                for ev_id, cmd in proc_cmds:
                    if "vssadmin" in cmd and "delete" in cmd:
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_MASS_FILE_ENCRYPTION":
                for ev_id, path, attrs in file_writes:
                    if attrs.get("is_encrypted_target") or attrs.get("is_ransom_note") or ".wnry" in path:
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_REGISTRY_RUN_PERSISTENCE":
                for ev_id, path, attrs in reg_writes:
                    if "currentversion\\run" in path or attrs.get("persistence"):
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_POWERSHELL_OBFUSCATED":
                for ev_id, cmd in proc_cmds:
                    if "powershell" in cmd and ("-enc" in cmd or "bypass" in cmd):
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_CREDENTIAL_VAULT_ACCESS":
                for ev_id, path, attrs in file_writes:
                    if attrs.get("is_credential_target") or "login data" in path or "key4.db" in path:
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_C2_HTTP_EXFILTRATION":
                for ev_id, url, attrs in http_reqs:
                    if "gate.php" in url or attrs.get("method") == "POST":
                        matched_event_ids.append(ev_id)

            elif rule.rule_id == "RULE_LATERAL_SMB_PROBE":
                for ev_id, attrs in net_conns:
                    if attrs.get("dest_port") == 445:
                        matched_event_ids.append(ev_id)

            if matched_event_ids:
                finding = BehavioralFinding(
                    analysis_id=analysis_id,
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    mitre_attack_id=rule.mitre_attack_id,
                    mitre_tactic=rule.mitre_tactic,
                    supporting_event_ids=matched_event_ids,
                )
                findings.append(finding)
                total_score += rule.score_weight
                rule_score_contribs.append({
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "weight": rule.score_weight,
                    "matched_events": len(matched_event_ids),
                })

        # Bounded score 0-100
        clamped_score = min(100, total_score)
        if clamped_score >= 80:
            level = "Malicious"
        elif clamped_score >= 50:
            level = "Suspicious"
        elif clamped_score >= 20:
            level = "Low"
        else:
            level = "Clean"

        # Persist findings to database
        self.db.add_all(findings)
        self.db.commit()

        assessment = RiskAssessment(
            score=clamped_score,
            level=level,
            rule_breakdown=rule_score_contribs,
            confidence=0.95,
        )

        return findings, assessment

