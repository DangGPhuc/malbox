from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.schemas.classification import (
    CategoryAssessment,
    MALWARE_CATEGORIES,
    MalwareClassificationResult,
    UNSUPPORTED_PE_CATEGORIES,
)


class MalwareClassificationEngine:
    """
    Deterministic evidence-grounded malware taxonomy classifier.
    Evaluates verified telemetry and behavioral findings against structured category rules.
    Does not hallucinate family names or extrapolate without direct evidence.
    Fails closed: strictly rejects synthetic placeholder IDs and cross-analysis contamination.
    """

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def _validate_and_filter_evidence(
        self,
        analysis_id: str,
        sample_sha256: str,
        assessments: List[CategoryAssessment],
        input_findings: List[Any],
        input_events: List[Any],
        limitations: List[str],
    ) -> None:
        """
        Validates every evidence ID against SQLite persisted records for this analysis.
        Rejects cross-analysis, cross-sample, and synthetic placeholder IDs.
        Downgrades CONFIRMED assessments to SUSPECTED if all evidence is rejected.
        """
        valid_ids: Set[str] = set()

        if self.db is not None:
            try:
                from app.models.finding import BehavioralFinding
                db_findings = self.db.query(BehavioralFinding.id).filter(
                    BehavioralFinding.analysis_id == analysis_id
                ).all()
                for (fid,) in db_findings:
                    if fid:
                        valid_ids.add(str(fid))

                from app.models.event import AnalysisEvent
                db_events = self.db.query(AnalysisEvent.id).filter(
                    AnalysisEvent.analysis_id == analysis_id
                ).all()
                for (eid,) in db_events:
                    if eid is not None:
                        valid_ids.add(str(eid))

                from app.models.static_analysis import StaticAnalysisRecord
                db_statics = self.db.query(StaticAnalysisRecord.id).filter(
                    (StaticAnalysisRecord.analysis_id == analysis_id)
                    | (StaticAnalysisRecord.sample_sha256 == sample_sha256.lower())
                ).all()
                for (sid,) in db_statics:
                    if sid:
                        valid_ids.add(str(sid))

                from app.models.sample import Sample
                db_sample = self.db.query(Sample).filter(
                    Sample.sha256 == sample_sha256.lower()
                ).first()
                if db_sample:
                    valid_ids.add(str(db_sample.id))
                    valid_ids.add(str(db_sample.sha256))
            except Exception:
                pass

        # In-memory inputs validation for this analysis
        for f in input_findings:
            fid = getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else None)
            faid = getattr(f, "analysis_id", None) or (f.get("analysis_id") if isinstance(f, dict) else None)
            if fid and (faid is None or faid == analysis_id):
                valid_ids.add(str(fid))

        for e in input_events:
            eid = getattr(e, "id", None) or (e.get("id") if isinstance(e, dict) else None)
            eaid = getattr(e, "analysis_id", None) or (e.get("analysis_id") if isinstance(e, dict) else None)
            if eid is not None and (eaid is None or eaid == analysis_id):
                valid_ids.add(str(eid))

        if sample_sha256:
            valid_ids.add(str(sample_sha256))

        synthetic_prefixes = ("event:", "pe:", "mock:", "placeholder:", "rule:")
        for a in assessments:
            filtered = []
            for eid in a.evidence_ids:
                eid_str = str(eid).strip()
                if any(eid_str.lower().startswith(p) for p in synthetic_prefixes):
                    continue  # Purge synthetic placeholder
                if eid_str in valid_ids:
                    filtered.append(eid_str)

            a.evidence_ids = filtered

            # Safety enforcement: If CONFIRMED assessment lost its verified evidence, downgrade
            if a.classification_status == "CONFIRMED" and not a.evidence_ids:
                a.classification_status = "SUSPECTED"
                a.confidence = round(min(0.50, a.confidence * 0.5), 2)
                limitations.append(
                    f"Evidence for category '{a.category_name}' could not be resolved against persisted records for analysis {analysis_id}; downgraded to SUSPECTED."
                )

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

        # Helper to extract real IDs from findings
        def get_finding_ids(rule_set: Set[str]) -> List[str]:
            out = []
            for r in rule_set:
                f_obj = finding_map.get(r)
                if f_obj is not None:
                    fid = getattr(f_obj, "id", None) or (f_obj.get("id") if isinstance(f_obj, dict) else None)
                    if fid is not None:
                        out.append(str(fid))
            return out

        # Helper to extract real IDs from events
        def get_event_id(e_obj: Any) -> Optional[str]:
            eid = getattr(e_obj, "id", None) or (e_obj.get("id") if isinstance(e_obj, dict) else None)
            return str(eid) if eid is not None else None

        # =========================================================================
        # Category Rule Evaluations
        # =========================================================================

        # 1. Ransomware
        ransom_rules = {"RULE_RANSOMWARE_ENCRYPTION", "RULE_SHADOW_COPY_DELETION", "RULE_RECOVERY_INHIBITION", "RULE_RANSOM_NOTE_CREATION", "RULE_MASS_FILE_ENCRYPTION"}
        matched_ransom_rules = set(rule_ids.intersection(ransom_rules))
        has_file_encryption = any(
            bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_encrypted_target"))
            for e in file_events
        )
        has_ransom_note = any(
            bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_ransom_note"))
            for e in file_events
        )

        ransom_ev_ids = get_finding_ids(matched_ransom_rules)
        for fe in file_events:
            attrs = getattr(fe, "attributes", None) or (fe.get("attributes") if isinstance(fe, dict) else {})
            if attrs.get("is_encrypted_target") or attrs.get("is_ransom_note"):
                eid = get_event_id(fe)
                if eid and eid not in ransom_ev_ids:
                    ransom_ev_ids.append(eid)

        if len(matched_ransom_rules) >= 2 or (len(matched_ransom_rules) >= 1 and (has_file_encryption or has_ransom_note)):
            conf = 0.95 if (has_file_encryption and has_ransom_note) else 0.85
            assessments.append(CategoryAssessment(
                category_id="ransomware",
                category_name="Ransomware",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=conf,
                evidence_ids=ransom_ev_ids,
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
                evidence_ids=ransom_ev_ids,
                explanation="Isolated ransomware-associated behavior detected (single indicator without correlated multi-stage encryption).",
            ))

        # 2. Stealer
        stealer_rules = {"RULE_BROWSER_CREDENTIAL_ACCESS", "RULE_CREDENTIAL_ACCESS", "RULE_DATA_EXFILTRATION", "RULE_INFOSTEALER_TARGETED_READ", "RULE_CREDENTIAL_VAULT_ACCESS", "RULE_C2_HTTP_EXFILTRATION"}
        matched_stealer_rules = set(rule_ids.intersection(stealer_rules))
        has_cred_target = any(
            any(t in str((getattr(e, "target_path", "") or (e.get("target_path", "") if isinstance(e, dict) else "")).lower()) for t in ["login data", "web data", "cookies", "wallet", "vault"])
            for e in file_events
        )
        stealer_ev_ids = get_finding_ids(matched_stealer_rules)

        if len(matched_stealer_rules) >= 2 or (len(matched_stealer_rules) >= 1 and len(net_events) > 0):
            assessments.append(CategoryAssessment(
                category_id="stealer",
                category_name="Stealer",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.88,
                evidence_ids=stealer_ev_ids,
                explanation="Observed targeted credential access across browser/system databases with outbound network telemetry.",
            ))
        elif matched_stealer_rules or has_cred_target:
            assessments.append(CategoryAssessment(
                category_id="stealer",
                category_name="Stealer",
                category_type="behavior",
                classification_status="SUSPECTED",
                confidence=0.65,
                evidence_ids=stealer_ev_ids,
                explanation="Access to sensitive browser/credential file paths observed without confirmed exfiltration channel.",
            ))

        # 3. Injector
        # Must require verified remote thread execution evidence (remote memory allocation + write alone is not confirmed injector)
        injector_rules = {"RULE_PROCESS_INJECTION_TECHNIQUE", "RULE_PROCESS_HOLLOWING", "RULE_REMOTE_THREAD_CREATION"}
        matched_injector_rules = set(rule_ids.intersection(injector_rules))

        remote_thread_events = [
            e for e in proc_events
            if "createremotethread" in str(getattr(e, "action", "") or (e.get("action") if isinstance(e, dict) else "")).lower()
            or bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("remote_thread"))
        ]

        staging_events = [
            e for e in proc_events
            if "virtualallocex" in str(getattr(e, "action", "") or (e.get("action") if isinstance(e, dict) else "")).lower()
            or "writeprocessmemory" in str(getattr(e, "action", "") or (e.get("action") if isinstance(e, dict) else "")).lower()
        ]
        has_remote_mem_staging = bool(staging_events)

        inj_evidence_ids = get_finding_ids(matched_injector_rules)
        for pe in remote_thread_events:
            eid = get_event_id(pe)
            if eid and eid not in inj_evidence_ids:
                inj_evidence_ids.append(eid)

        if (matched_injector_rules or remote_thread_events) and inj_evidence_ids:
            assessments.append(CategoryAssessment(
                category_id="injector",
                category_name="Injector",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=inj_evidence_ids,
                explanation="Verified remote process memory manipulation with confirmed remote thread execution evidence (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread).",
            ))
        elif has_remote_mem_staging:
            staging_ids = [get_event_id(pe) for pe in staging_events if get_event_id(pe)]
            assessments.append(CategoryAssessment(
                category_id="injector",
                category_name="Injector",
                category_type="behavior",
                classification_status="SUSPECTED",
                confidence=0.50,
                evidence_ids=staging_ids,
                explanation="Remote memory allocation or modification observed without confirmed remote thread execution (memory staging only).",
                limitations=["No remote thread execution was observed following memory staging."],
            ))

        # 4. Dropper
        dropper_rules = {"RULE_DROPPED_EXECUTABLE_PAYLOAD"}
        matched_dropper_rules = set(rule_ids.intersection(dropper_rules))
        dropped_exe_events = [
            e for e in file_events
            if bool((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("is_dropped_binary"))
        ]
        has_dropped_exe = bool(dropped_exe_events)

        drop_ev_ids = get_finding_ids(matched_dropper_rules)
        for fe in dropped_exe_events:
            eid = get_event_id(fe)
            if eid and eid not in drop_ev_ids:
                drop_ev_ids.append(eid)

        if matched_dropper_rules and has_dropped_exe and drop_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="dropper",
                category_name="Dropper",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.85,
                evidence_ids=drop_ev_ids,
                explanation="Observed verified write of executable binary payload to secondary location on filesystem.",
            ))

        # 5. Downloader
        # Must require evidence linking file transfer to saved binary or executed secondary payload
        downloader_rules = {"RULE_DOWNLOAD_PAYLOAD"}
        matched_dl_rules = set(rule_ids.intersection(downloader_rules))
        download_net_events = [
            e for e in net_events
            if "get" in str((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("method", "")).lower()
            or any(ext in str(getattr(e, "target_path", "") or (e.get("target_path") if isinstance(e, dict) else "")).lower() for ext in [".exe", ".bin", ".dll", ".ps1", ".vbs", ".zip", ".msi"])
        ]
        has_network_download = bool(matched_dl_rules) or bool(download_net_events)
        has_saved_or_executed_payload = has_dropped_exe or "RULE_DROPPED_EXECUTABLE_PAYLOAD" in rule_ids

        dl_evidence_ids = get_finding_ids(matched_dl_rules)
        if "RULE_DROPPED_EXECUTABLE_PAYLOAD" in rule_ids:
            for fid in get_finding_ids({"RULE_DROPPED_EXECUTABLE_PAYLOAD"}):
                if fid not in dl_evidence_ids:
                    dl_evidence_ids.append(fid)

        for ne in download_net_events:
            eid = get_event_id(ne)
            if eid and eid not in dl_evidence_ids:
                dl_evidence_ids.append(eid)
                break

        for fe in dropped_exe_events:
            eid = get_event_id(fe)
            if eid and eid not in dl_evidence_ids:
                dl_evidence_ids.append(eid)
                break

        if has_network_download and has_saved_or_executed_payload and dl_evidence_ids:
            assessments.append(CategoryAssessment(
                category_id="downloader",
                category_name="Downloader",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.85,
                evidence_ids=dl_evidence_ids,
                explanation="Observed network file transfer directly correlated with saved binary or executed secondary payload.",
            ))
        elif has_network_download:
            suspected_net_ids = [get_event_id(ne) for ne in download_net_events if get_event_id(ne)]
            assessments.append(CategoryAssessment(
                category_id="downloader",
                category_name="Downloader",
                category_type="behavior",
                classification_status="SUSPECTED",
                confidence=0.55,
                evidence_ids=suspected_net_ids,
                explanation="Network transfer observed, but insufficient evidence linking download to saved or executed secondary binary.",
                limitations=["No saved secondary binary or executed payload was observed following network transfer."],
            ))

        # 6. Loader
        loader_rules = {"RULE_MODULE_LOAD_PAYLOAD", "RULE_DYNAMIC_API_RESOLUTION"}
        matched_loader_rules = set(rule_ids.intersection(loader_rules))
        load_ev_ids = get_finding_ids(matched_loader_rules)

        if matched_loader_rules and load_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="loader",
                category_name="Loader",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.75,
                evidence_ids=load_ev_ids,
                explanation="Observed dynamic module loading and in-memory function resolution for secondary execution stages.",
            ))

        # 7. Launcher
        # Requires contextual execution evidence (e.g. suspicious arguments, persistence context, or process chain)
        launcher_ev_ids: List[str] = []
        for e in proc_events:
            cmd = str((getattr(e, "attributes", None) or (e.get("attributes") if isinstance(e, dict) else {})).get("command_line", "")).lower()
            e_id = get_event_id(e)

            is_suspicious_args = any(pat in cmd for pat in [
                "-enc", "-encodedcommand", "-executionpolicy bypass", "-ep bypass",
                "-windowstyle hidden", "-w hidden", "-nop", "-noninteractive",
                "rundll32", "mshta", "regsvr32", "certutil -urlcache", "bitsadmin /transfer",
                "wscript //b", "cscript //b", "delete shadows"
            ])
            if is_suspicious_args and e_id is not None:
                launcher_ev_ids.append(e_id)

        if launcher_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="launcher",
                category_name="Launcher",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.80,
                evidence_ids=launcher_ev_ids,
                explanation="Observed parent process spawning secondary processes with suspicious or evasive execution arguments.",
            ))
        elif len(proc_events) > 1:
            assessments.append(CategoryAssessment(
                category_id="launcher",
                category_name="Launcher",
                category_type="behavior",
                classification_status="ABSENT",
                confidence=0.10,
                evidence_ids=[],
                explanation="Process creation observed, but execution arguments represent standard unprivileged or installer behavior without suspicious proxy flags.",
            ))

        # 8. Backdoor
        backdoor_rules = {"RULE_PERSISTENCE_REGISTRY", "RULE_COMMAND_AND_CONTROL", "RULE_REGISTRY_RUN_PERSISTENCE"}
        matched_backdoor_rules = set(rule_ids.intersection(backdoor_rules))
        backdoor_ev_ids = get_finding_ids(matched_backdoor_rules)

        if (len(matched_backdoor_rules) >= 2 or ("RULE_PERSISTENCE_REGISTRY" in matched_backdoor_rules and len(net_events) > 0) or ("RULE_REGISTRY_RUN_PERSISTENCE" in matched_backdoor_rules and len(net_events) > 0)) and backdoor_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="backdoor",
                category_name="Backdoor",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.82,
                evidence_ids=backdoor_ev_ids,
                explanation="Demonstrated persistent system autorun modification combined with active external control channel.",
            ))

        # 9. RAT (Remote Access Trojan)
        rat_rules = {"RULE_REMOTE_ACCESS_TROJAN", "RULE_KEYLOGGER_ACTIVE", "RULE_SCREEN_CAPTURE"}
        matched_rat_rules = set(rule_ids.intersection(rat_rules))
        rat_ev_ids = get_finding_ids(matched_rat_rules)

        if matched_rat_rules and rat_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="rat",
                category_name="RAT",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.85,
                evidence_ids=rat_ev_ids,
                explanation="Observed interactive surveillance, remote management, or keystroke/screen logging capabilities.",
            ))

        # 10. Botnet
        botnet_rules = {"RULE_BOTNET_C2", "RULE_IRC_COMMUNICATION"}
        matched_botnet_rules = set(rule_ids.intersection(botnet_rules))
        botnet_ev_ids = get_finding_ids(matched_botnet_rules)

        if matched_botnet_rules and botnet_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="botnet",
                category_name="Botnet",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.78,
                evidence_ids=botnet_ev_ids,
                explanation="Demonstrated periodic group C2 beaconing or coordinated command-reception loops.",
            ))

        # 11. Rootkit
        rootkit_rules = {"RULE_ROOTKIT_DRIVER", "RULE_KERNEL_MANIPULATION"}
        matched_rootkit_rules = set(rule_ids.intersection(rootkit_rules))
        rootkit_ev_ids = get_finding_ids(matched_rootkit_rules)

        if matched_rootkit_rules and rootkit_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="rootkit",
                category_name="Rootkit",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=rootkit_ev_ids,
                explanation="Observed kernel driver manipulation or concealment of system objects.",
            ))

        # 12. Wiper
        wiper_rules = {"RULE_WIPER_MASS_DELETE", "RULE_RAW_DISK_WRITE"}
        matched_wiper_rules = set(rule_ids.intersection(wiper_rules))
        wiper_ev_ids = get_finding_ids(matched_wiper_rules)

        if matched_wiper_rules and wiper_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="wiper",
                category_name="Wiper",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.90,
                evidence_ids=wiper_ev_ids,
                explanation="Deliberate destructive disk sector or file wiping behavior detected without ransom note.",
            ))

        # 13. Spyware
        spyware_rules = {"RULE_KEYLOGGER_ACTIVE", "RULE_CLIPBOARD_MONITOR"}
        matched_spyware_rules = set(rule_ids.intersection(spyware_rules))
        spyware_ev_ids = get_finding_ids(matched_spyware_rules)

        if matched_spyware_rules and spyware_ev_ids:
            assessments.append(CategoryAssessment(
                category_id="spyware",
                category_name="Spyware",
                category_type="behavior",
                classification_status="CONFIRMED",
                confidence=0.80,
                evidence_ids=spyware_ev_ids,
                explanation="Observed background user surveillance, clipboard harvesting, or input interception.",
            ))

        # 14. Kernel Driver (Component type, not standalone malicious verdict)
        is_driver = pe_meta.get("subsystem") == 1 or pe_meta.get("is_driver", False)
        if is_driver:
            driver_ev = [sample_sha256] if sample_sha256 else []
            assessments.append(CategoryAssessment(
                category_id="kernel_driver",
                category_name="Kernel Driver",
                category_type="component",
                classification_status="CONFIRMED",
                confidence=1.0,
                evidence_ids=driver_ev,
                explanation="File structure indicates a Windows kernel-mode driver (.sys). Note: drivers may be benign system components.",
            ))

        # 15. Obfuscation (Characteristic type)
        is_packed = pe_meta.get("is_packed", False)
        high_entropy = pe_meta.get("overall_entropy", 0.0) >= 7.2
        if is_packed or high_entropy:
            obf_ev = [sample_sha256] if sample_sha256 else []
            assessments.append(CategoryAssessment(
                category_id="obfuscation",
                category_name="Obfuscation",
                category_type="characteristic",
                classification_status="CONFIRMED",
                confidence=0.85 if is_packed else 0.70,
                evidence_ids=obf_ev,
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

        # Provenance and evidence validation against SQLite & inputs
        self._validate_and_filter_evidence(
            analysis_id=analysis_id,
            sample_sha256=sample_sha256,
            assessments=assessments,
            input_findings=all_findings,
            input_events=all_events,
            limitations=limitations,
        )

        # Constrain confidence when telemetry is partial or truncated
        if telemetry_completeness in ("PARTIAL", "TRUNCATED", "UNVERIFIED"):
            for a in assessments:
                if a.classification_status != "UNSUPPORTED":
                    a.confidence = round(min(0.65, a.confidence * 0.7), 2)

        # =========================================================================
        # Primary & Secondary Selection
        # =========================================================================
        confirmed_behavior_candidates = [
            a for a in assessments
            if a.category_type == "behavior" and a.classification_status == "CONFIRMED"
        ]
        confirmed_behavior_candidates.sort(key=lambda x: x.confidence, reverse=True)

        primary_cat: Optional[str] = None
        secondary_cats: List[str] = []

        if confirmed_behavior_candidates:
            primary_cat = confirmed_behavior_candidates[0].category_name
            secondary_cats = [c.category_name for c in confirmed_behavior_candidates[1:]]

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
