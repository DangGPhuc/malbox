from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session

from app.schemas.classification import (
    MalwareClassificationResult,
    CategoryAssessment,
    MALWARE_CATEGORIES,
    UNSUPPORTED_PE_CATEGORIES,
)
from app.models.analysis import Analysis
from app.models.finding import BehavioralFinding
from app.models.event import AnalysisEvent


class MalwareClassificationEngine:
    """
    Deterministic evidence-grounded malware taxonomy classifier.
    Evaluates verified telemetry and behavioral findings against structured category rules.
    Does not hallucinate family names or extrapolate without direct evidence.
    """

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def classify(
        self,
        analysis_id: str,
        sample_sha256: str,
        findings: Optional[List[Any]] = None,
        events: Optional[List[Any]] = None,
        pe_metadata: Optional[Dict[str, Any]] = None,
        is_pe: bool = True,
        telemetry_completeness: str = "COMPLETE",
        is_replay: bool = False,
    ) -> MalwareClassificationResult:
        """
        Classifies an analysis into standard malware taxonomy categories
        based on grounded dynamic events, behavioral findings, and static facts.
        """
        all_findings = findings or []
        all_events = events or []
        pe_meta = pe_metadata or {}

        # 1. Index findings by rule_id and MITRE attack ID
        rule_ids: Set[str] = set()
        mitre_ids: Set[str] = set()
        finding_map: Dict[str, Any] = {}

        for f in all_findings:
            rid = getattr(f, "rule_id", None) or (f.get("rule_id") if isinstance(f, dict) else None)
            mid = getattr(f, "mitre_attack_id", None) or (f.get("mitre_attack_id") if isinstance(f, dict) else None)
            fid = getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else None)
            if rid:
                rule_ids.add(rid)
                finding_map[rid] = f
            if mid:
                mitre_ids.add(mid)

        # 2. Index events by category and attributes
        proc_events = [e for e in all_events if getattr(e, "category", "") == "process" or (isinstance(e, dict) and e.get("category") == "process")]
        file_events = [e for e in all_events if getattr(e, "category", "") == "file" or (isinstance(e, dict) and e.get("category") == "file")]
        reg_events = [e for e in all_events if getattr(e, "category", "") == "registry" or (isinstance(e, dict) and e.get("category") == "registry")]
        net_events = [e for e in all_events if getattr(e, "category", "") in ("network", "http", "dns") or (isinstance(e, dict) and e.get("category") in ("network", "http", "dns"))]

        assessments: List[CategoryAssessment] = []
        limitations: List[str] = []

        if is_replay:
            limitations.append("Classification evaluated against historical/synthetic replay telemetry; not live host detonation.")

        if telemetry_completeness in ("PARTIAL", "TRUNCATED", "UNVERIFIED"):
            limitations.append(f"Telemetry completeness is {telemetry_completeness}; unobserved behaviors may have occurred outside capture window.")

        # =========================================================================
        # Category Rule Evaluations
        # =========================================================================

        # 1. Ransomware
        ransom_rules = {"RULE_RANSOMWARE_ENCRYPTION", "RULE_SHADOW_COPY_DELETION", "RULE_RECOVERY_INHIBITION", "RULE_RANSOM_NOTE_CREATION"}
        matched_ransom_rules = list(rule_ids.intersection(ransom_rules))
        has_file_encryption = any(
            bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_encrypted_target"))
            for e in file_events
        )
        has_ransom_note = any(
            bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_ransom_note"))
            for e in file_events
        )

        if len(matched_ransom_rules) >= 2 or (len(matched_ransom_rules) >= 1 and (has_file_encryption or has_ransom_note)):
            conf = 0.95 if (has_file_encryption and has_ransom_note) else 0.85
            assessments.append(CategoryAssessment(
                category_id="ransomware",
                category_name="Ransomware",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=conf,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_ransom_rules],
                explanation=f"Correlated ransomware indicators observed: {len(matched_ransom_rules)} behavioral detection rules matched (including shadow copy deletion and mass file encryption).",
            ))
        elif len(matched_ransom_rules) == 1 or has_file_encryption:
            conf = 0.70
            assessments.append(CategoryAssessment(
                category_id="ransomware",
                category_name="Ransomware",
                category_type="behavior",
                classification_status="SUSPECTED",
                confidence=conf,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_ransom_rules],
                explanation="Isolated ransomware-associated behavior detected (single indicator without correlated multi-stage encryption).",
            ))

        # 2. Stealer
        stealer_rules = {"RULE_BROWSER_CREDENTIAL_ACCESS", "RULE_CREDENTIAL_ACCESS", "RULE_DATA_EXFILTRATION", "RULE_INFOSTEALER_TARGETED_READ"}
        matched_stealer_rules = list(rule_ids.intersection(stealer_rules))
        has_cred_target = any(
            any(t in str((getattr(e, "target_path", "") or (e.get("target_path", "") if isinstance(e, dict) else "")).lower()) for t in ["login data", "web data", "cookies", "wallet", "vault"])
            for e in file_events
        )

        if len(matched_stealer_rules) >= 2 or (len(matched_stealer_rules) >= 1 and len(net_events) > 0):
            assessments.append(CategoryAssessment(
                category_id="stealer",
                category_name="Stealer",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.88,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_stealer_rules],
                explanation="Observed targeted credential access across browser/system databases with outbound network telemetry.",
            ))
        elif matched_stealer_rules or has_cred_target:
            assessments.append(CategoryAssessment(
                category_id="stealer",
                category_name="Stealer",
                category_type="behavior",
                classification_status="SUSPECTED",
                confidence=0.65,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_stealer_rules],
                explanation="Access to sensitive browser/credential file paths observed without confirmed exfiltration channel.",
            ))

        # 3. Injector
        injector_rules = {"RULE_PROCESS_INJECTION_TECHNIQUE", "RULE_PROCESS_HOLLOWING", "RULE_REMOTE_THREAD_CREATION"}
        matched_injector_rules = list(rule_ids.intersection(injector_rules))

        if matched_injector_rules:
            assessments.append(CategoryAssessment(
                category_id="injector",
                category_name="Injector",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_injector_rules],
                explanation="Verified remote process memory manipulation with contextual execution evidence (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread).",
            ))

        # 4. Dropper
        dropper_rules = {"RULE_DROPPED_EXECUTABLE_PAYLOAD"}
        matched_dropper_rules = list(rule_ids.intersection(dropper_rules))
        has_dropped_exe = any(
            bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_dropped_binary"))
            for e in file_events
        )

        if matched_dropper_rules and has_dropped_exe:
            assessments.append(CategoryAssessment(
                category_id="dropper",
                category_name="Dropper",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.85,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_dropper_rules],
                explanation="Observed verified write of executable binary payload to secondary location on filesystem.",
            ))

        # 5. Downloader
        downloader_rules = {"RULE_DOWNLOAD_PAYLOAD", "RULE_NETWORK_BEACONING"}
        matched_downloader_rules = list(rule_ids.intersection(downloader_rules))
        has_net_payload = has_dropped_exe and len(net_events) > 0

        if matched_downloader_rules or has_net_payload:
            assessments.append(CategoryAssessment(
                category_id="downloader",
                category_name="Downloader",
                category_type="behavior",
                classification_status="CONFIRMED" if has_net_payload else "SUSPECTED",
                confidence=0.80 if has_net_payload else 0.60,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_downloader_rules],
                explanation="Observed network transfer correlated with downloaded content or secondary payload acquisition.",
            ))

        # 6. Loader
        loader_rules = {"RULE_MODULE_LOAD_PAYLOAD", "RULE_DYNAMIC_API_RESOLUTION"}
        matched_loader_rules = list(rule_ids.intersection(loader_rules))

        if matched_loader_rules:
            assessments.append(CategoryAssessment(
                category_id="loader",
                category_name="Loader",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.75,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_loader_rules],
                explanation="Observed dynamic module loading and in-memory function resolution for secondary execution stages.",
            ))

        # 7. Launcher
        has_suspicious_spawn = any(
            any(pat in str((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("command_line", "")).lower()
                for pat in ["powershell", "cmd.exe /c", "-enc", "-executionpolicy bypass", "rundll32", "mshta", "wscript", "cscript"])
            for e in proc_events
        )
        if has_suspicious_spawn:
            assessments.append(CategoryAssessment(
                category_id="launcher",
                category_name="Launcher",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.75,
                evidence_ids=[],
                explanation="Observed parent process spawning child interpreters/proxies with scripted command-line arguments.",
            ))

        # 8. Backdoor
        backdoor_rules = {"RULE_PERSISTENCE_REGISTRY", "RULE_COMMAND_AND_CONTROL"}
        matched_backdoor_rules = list(rule_ids.intersection(backdoor_rules))

        if len(matched_backdoor_rules) >= 2 or ("RULE_PERSISTENCE_REGISTRY" in matched_backdoor_rules and len(net_events) > 0):
            assessments.append(CategoryAssessment(
                category_id="backdoor",
                category_name="Backdoor",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.82,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_backdoor_rules],
                explanation="Demonstrated persistent system autorun modification combined with active external control channel.",
            ))

        # 9. RAT (Remote Access Trojan)
        rat_rules = {"RULE_REMOTE_ACCESS_TROJAN", "RULE_KEYLOGGER_ACTIVE", "RULE_SCREEN_CAPTURE"}
        matched_rat_rules = list(rule_ids.intersection(rat_rules))

        if matched_rat_rules:
            assessments.append(CategoryAssessment(
                category_id="rat",
                category_name="RAT",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.85,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_rat_rules],
                explanation="Observed interactive surveillance, remote management, or keystroke/screen logging capabilities.",
            ))

        # 10. Botnet
        botnet_rules = {"RULE_BOTNET_C2", "RULE_IRC_COMMUNICATION"}
        matched_botnet_rules = list(rule_ids.intersection(botnet_rules))

        if matched_botnet_rules:
            assessments.append(CategoryAssessment(
                category_id="botnet",
                category_name="Botnet",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.78,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_botnet_rules],
                explanation="Demonstrated periodic group C2 beaconing or coordinated command-reception loops.",
            ))

        # 11. Rootkit
        rootkit_rules = {"RULE_ROOTKIT_DRIVER", "RULE_KERNEL_MANIPULATION"}
        matched_rootkit_rules = list(rule_ids.intersection(rootkit_rules))

        if matched_rootkit_rules:
            assessments.append(CategoryAssessment(
                category_id="rootkit",
                category_name="Rootkit",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_rootkit_rules],
                explanation="Observed kernel driver manipulation or concealment of system objects.",
            ))

        # 12. Wiper
        wiper_rules = {"RULE_WIPER_MASS_DELETE", "RULE_RAW_DISK_WRITE"}
        matched_wiper_rules = list(rule_ids.intersection(wiper_rules))

        if matched_wiper_rules:
            assessments.append(CategoryAssessment(
                category_id="wiper",
                category_name="Wiper",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_wiper_rules],
                explanation="Deliberate destructive disk sector or file wiping behavior detected without ransom note.",
            ))

        # 13. Spyware
        spyware_rules = {"RULE_KEYLOGGER_ACTIVE", "RULE_CLIPBOARD_MONITOR"}
        matched_spyware_rules = list(rule_ids.intersection(spyware_rules))

        if matched_spyware_rules:
            assessments.append(CategoryAssessment(
                category_id="spyware",
                category_name="Spyware",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.80,
                evidence_ids=[str(getattr(finding_map[r], "id", r)) for r in matched_spyware_rules],
                explanation="Observed background user surveillance, clipboard harvesting, or input interception.",
            ))

        # 14. Kernel Driver (Component type, not standalone malicious verdict)
        is_driver = pe_meta.get("subsystem") == 1 or pe_meta.get("is_driver", False)
        if is_driver:
            assessments.append(CategoryAssessment(
                category_id="kernel_driver",
                category_name="Kernel Driver",
                category_type="component",
                classification_status="CONFIRMED",
                confidence=1.0,
                evidence_ids=[],
                explanation="File structure indicates a Windows kernel-mode driver (.sys). Note: drivers may be benign system components.",
            ))

        # 15. Obfuscation (Characteristic type)
        is_packed = pe_meta.get("is_packed", False)
        high_entropy = pe_meta.get("overall_entropy", 0.0) >= 7.2
        if is_packed or high_entropy:
            assessments.append(CategoryAssessment(
                category_id="obfuscation",
                category_name="Obfuscation",
                category_type="characteristic",
                classification_status="CONFIRMED",
                confidence=0.85 if is_packed else 0.70,
                evidence_ids=[],
                explanation=f"Code packing/compression heuristics detected (entropy: {pe_meta.get('overall_entropy', 0.0):.2f}, packed: {is_packed}). Characteristic only; not a standalone malware verdict.",
            ))

        # 16 & 17. Unsupported categories on Windows PE
        for unsupp in UNSUPPORTED_PE_CATEGORIES:
            cat_info = MALWARE_CATEGORIES[unsupp]
            assessments.append(CategoryAssessment(
                category_id=unsupp,
                category_name=cat_info["name"],
                category_type=cat_info["type"],
                classification_status="UNSUPPORTED",
                confidence=0.0,
                evidence_ids=[],
                explanation=f"Analysis of {cat_info['name']} is unsupported for Windows PE binaries.",
                limitations=[f"Platform analyzer for {cat_info['name']} is not configured or unsupported for PE."],
            ))

        # =========================================================================
        # Primary & Secondary Selection
        # =========================================================================
        behavior_candidates = [
            a for a in assessments
            if a.category_type == "behavior" and a.classification_status in ("CONFIRMED", "SUSPECTED")
        ]
        # Sort by confidence desc, status CONFIRMED > SUSPECTED
        behavior_candidates.sort(
            key=lambda x: (1 if x.classification_status == "CONFIRMED" else 0, x.confidence),
            reverse=True,
        )

        primary_cat: Optional[str] = None
        secondary_cats: List[str] = []

        if behavior_candidates:
            primary_cat = behavior_candidates[0].category_name
            secondary_cats = [c.category_name for c in behavior_candidates[1:]]

        # Component / characteristic additions to secondary
        for a in assessments:
            if a.category_type in ("component", "characteristic") and a.classification_status == "CONFIRMED":
                if a.category_name not in secondary_cats and a.category_name != primary_cat:
                    secondary_cats.append(a.category_name)

        # Classification Status
        if primary_cat:
            overall_status = "CLASSIFIED"
        elif len(all_events) == 0 and len(all_findings) == 0:
            overall_status = "INSUFFICIENT_EVIDENCE"
            limitations.append("Zero events and zero behavioral findings collected; insufficient evidence to classify.")
        else:
            overall_status = "UNKNOWN"

        return MalwareClassificationResult(
            analysis_id=analysis_id,
            sample_sha256=sample_sha256,
            taxonomy_version="1.0",
            classifier_version="1.0.0",
            primary_category=primary_cat,
            secondary_categories=secondary_cats,
            suspected_family=None,  # Never hallucinate family names without explicit signature
            family_confidence=None,
            overall_evidence_quality=telemetry_completeness,
            classification_status=overall_status,
            classification_findings=assessments,
            limitations=limitations,
            unsupported_categories=list(UNSUPPORTED_PE_CATEGORIES),
        )
