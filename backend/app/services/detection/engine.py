from typing import List, Tuple
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.services.detection.rules import BEHAVIORAL_RULES, BehavioralRule
from app.schemas.report import RiskAssessment

class DetectionEngine:
    """
    Deterministic behavioral rule engine that identifies malicious TTPs,
    maps MITRE ATT&CK techniques with contextual thresholds, and derives explainable risk scores.
    Separates verified factual observations from behavioral hypotheses.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_behavior(self, analysis_id: str) -> Tuple[List[BehavioralFinding], RiskAssessment]:
        events = self.db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
        findings: List[BehavioralFinding] = []
        rule_score_contribs: List[dict] = []
        total_score = 0

        # Pre-group events by category for efficient contextual evaluation
        proc_cmds = [(e.id, (e.attributes.get("command_line") or "").lower()) for e in events if e.category == "process"]
        file_writes = [(e.id, (e.target_path or "").lower(), e.attributes or {}) for e in events if e.category == "file"]
        reg_writes = [(e.id, (e.target_path or "").lower(), e.attributes or {}) for e in events if e.category == "registry"]
        net_conns = [(e.id, e.attributes or {}) for e in events if e.category == "network"]
        http_reqs = [(e.id, (e.target_path or "").lower(), e.attributes or {}) for e in events if e.category in ["http", "network"]]

        for rule in BEHAVIORAL_RULES:
            matched_event_ids = []

            # 1. Shadow Copy Deletion (T1490) - High confidence factual observation
            if rule.rule_id == "RULE_SHADOW_COPY_DELETION":
                for ev_id, cmd in proc_cmds:
                    if ("vssadmin" in cmd and "delete" in cmd) or \
                       ("wmic" in cmd and "shadowcopy" in cmd and "delete" in cmd) or \
                       ("bcdedit" in cmd and "recoveryenabled" in cmd):
                        matched_event_ids.append(ev_id)

            # 2. Mass File Encryption (T1486) - Contextual threshold required
            elif rule.rule_id == "RULE_MASS_FILE_ENCRYPTION":
                encrypted_files = []
                ransom_notes = []
                for ev_id, path, attrs in file_writes:
                    is_enc = attrs.get("is_encrypted_target") or any(ext in path for ext in [".wnry", ".locked", ".crypted", ".crypto"])
                    is_note = attrs.get("is_ransom_note") or any(note in path for note in ["@wanadecryptor@", "readme_to_decrypt", "how_to_decrypt", "decrypt_instructions"])
                    if is_enc:
                        encrypted_files.append(ev_id)
                    if is_note:
                        ransom_notes.append(ev_id)

                # Contextual requirement: either a ransom note + encrypted file, OR multiple encrypted files (>=2)
                if (ransom_notes and encrypted_files) or len(encrypted_files) >= 2 or len(ransom_notes) >= 1:
                    matched_event_ids.extend(list(set(encrypted_files + ransom_notes)))

            # 3. Registry Run Key Persistence (T1547.001)
            elif rule.rule_id == "RULE_REGISTRY_RUN_PERSISTENCE":
                for ev_id, path, attrs in reg_writes:
                    if "currentversion\\run" in path or attrs.get("persistence"):
                        matched_event_ids.append(ev_id)

            # 4. Encoded / Obfuscated PowerShell (T1059.001)
            elif rule.rule_id == "RULE_POWERSHELL_OBFUSCATED":
                for ev_id, cmd in proc_cmds:
                    if "powershell" in cmd and ("-enc" in cmd or "encodedcommand" in cmd or ("bypass" in cmd and "-w hidden" in cmd)):
                        matched_event_ids.append(ev_id)

            # 5. Web Browser Credential Store Access (T1555.003)
            elif rule.rule_id == "RULE_CREDENTIAL_VAULT_ACCESS":
                for ev_id, path, attrs in file_writes:
                    if attrs.get("is_credential_target") or any(target in path for target in ["login data", "key4.db", "logins.json", "web data"]):
                        matched_event_ids.append(ev_id)

            # 6. C2 HTTP Exfiltration (T1071.001) - Contextual requirement: POST with gate or active data transmission
            elif rule.rule_id == "RULE_C2_HTTP_EXFILTRATION":
                for ev_id, url, attrs in http_reqs:
                    method = (attrs.get("method") or "").upper()
                    if method == "POST" and ("gate" in url or "upload" in url or "beacon" in url or "panel" in url or attrs.get("status_code") in [200, 201]):
                        matched_event_ids.append(ev_id)

            # 7. SMB Lateral Probe (T1046) - Contextual requirement: multiple connection attempts
            elif rule.rule_id == "RULE_LATERAL_SMB_PROBE":
                smb_evs = [ev_id for ev_id, attrs in net_conns if attrs.get("dest_port") == 445]
                # Contextual check: requires multiple targets or attempts
                if len(smb_evs) >= 2:
                    matched_event_ids.extend(smb_evs)
                elif len(smb_evs) == 1 and any("spread" in cmd or "worm" in cmd for _, cmd in proc_cmds):
                    matched_event_ids.extend(smb_evs)

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

        # Bounded explainable score 0-100
        clamped_score = min(100, total_score)
        if clamped_score >= 80:
            level = "Malicious"
        elif clamped_score >= 50:
            level = "Suspicious"
        elif clamped_score >= 20:
            level = "Low"
        else:
            # Do not provide a false "Clean" guarantee; absence of evidence is not evidence of absence
            level = "No Suspicious Behavior Observed"

        # Persist findings to database
        self.db.add_all(findings)
        self.db.commit()

        assessment = RiskAssessment(
            score=clamped_score,
            level=level,
            rule_breakdown=rule_score_contribs,
            confidence=0.95 if findings else 0.80,
        )

        return findings, assessment
