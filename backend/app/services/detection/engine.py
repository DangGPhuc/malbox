from typing import List, Tuple, Optional, Dict, Any, Set
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.event import AnalysisEvent
from app.models.finding import BehavioralFinding
from app.services.detection.rules import BEHAVIORAL_RULES, BehavioralRule
from app.schemas.report import RiskAssessment

ENGINE_VERSION = "0.2.2"


def _is_api_call_successful(ev: AnalysisEvent) -> bool:
    attrs = ev.attributes or {}
    if attrs.get("failed") is True:
        return False
    status = attrs.get("status")
    ret = attrs.get("return_value")
    # If explicitly 0 status and 0 return value
    if status == 0 and ret in (0, "0", "0x0", "0x00000000", None, False):
        return False
    # If NTSTATUS indicates error (negative or high bit set)
    if isinstance(status, int) and status < 0:
        return False
    if isinstance(ret, str) and (ret.lower().startswith("0xc") or ret.lower().startswith("0x8")):
        return False
    return True


def _extract_target_pid(ev: AnalysisEvent) -> Optional[int]:
    attrs = ev.attributes or {}
    args = attrs.get("arguments", {})
    # 1. Check explicit target_pid in attributes
    if attrs.get("target_pid") is not None:
        try:
            return int(attrs["target_pid"])
        except (ValueError, TypeError):
            pass
    # 2. Check ProcessHandle or hProcess
    handle = str(args.get("ProcessHandle") or args.get("hProcess") or "").lower()
    if handle in ("-1", "0xffffffff", "current_process"):
        return ev.process_id  # pseudo-handle points to self / local process
    # 3. Check arguments dictionary
    for k in ("target_pid", "process_id", "ProcessId", "dwProcessId"):
        if k in args and args[k] is not None:
            try:
                return int(args[k])
            except (ValueError, TypeError):
                pass
    return None


def _is_executable_memory_protection(ev: AnalysisEvent) -> bool:
    attrs = ev.attributes or {}
    args = attrs.get("arguments", {})
    prot_str = (str(args.get("protect", "")) + " " + str(args.get("flProtect", "")) + " " + str(args.get("NewProtect", ""))).lower()
    exec_tokens = [
        "page_execute", "execute_readwrite", "execute_read", "execute",
        "0x40", "0x20", "0x10", "0x80", "64", "32"
    ]
    if any(tok in prot_str for tok in exec_tokens):
        return True
    return bool(attrs.get("executable_memory"))


class DetectionEngine:
    """
    Deterministic behavioral rule engine that identifies malicious TTPs,
    maps MITRE ATT&CK techniques with contextual thresholds, and derives explainable risk scores.
    Separates verified factual observations from behavioral hypotheses and distinguishes
    telemetry completeness from absence of detection.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_behavior(
        self,
        analysis_id: str,
        telemetry_completeness: str = "COMPLETE",
    ) -> Tuple[List[BehavioralFinding], RiskAssessment]:
        events = self.db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id).all()
        findings: List[BehavioralFinding] = []
        rule_score_contribs: List[dict] = []
        total_score = 0

        # Pre-group events by category for efficient contextual evaluation
        proc_cmds = [(e.id, (e.attributes.get("command_line") or "").lower()) for e in events if e.category == "process"]
        file_writes = [(e.id, (e.target_path or "").lower(), e.attributes or {}, (e.action or "").lower()) for e in events if e.category == "file"]
        reg_writes = [(e.id, (e.target_path or "").lower(), e.attributes or {}) for e in events if e.category == "registry"]
        net_conns = [(e.id, e.attributes or {}) for e in events if e.category == "network"]
        http_reqs = [(e.id, (e.target_path or "").lower(), e.attributes or {}) for e in events if e.category in ["http", "network"]]
        proc_events = [e for e in events if e.category == "process"]

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
            # A single ransom note must NOT be classified as mass encryption without supporting encrypted file evidence.
            elif rule.rule_id == "RULE_MASS_FILE_ENCRYPTION":
                encrypted_files = []
                ransom_notes = []
                for ev_id, path, attrs, action in file_writes:
                    is_enc = attrs.get("is_encrypted_target") or any(ext in path for ext in [".wnry", ".locked", ".crypted", ".crypto"])
                    is_note = attrs.get("is_ransom_note") or any(note in path for note in ["@wanadecryptor@", "readme_to_decrypt", "how_to_decrypt", "decrypt_instructions"])
                    if is_enc:
                        encrypted_files.append(ev_id)
                    if is_note:
                        ransom_notes.append(ev_id)

                # Contextual requirement: either (ransom note AND at least one encrypted file), OR multiple encrypted files (>=2)
                if (ransom_notes and encrypted_files) or len(encrypted_files) >= 2:
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
                for ev_id, path, attrs, action in file_writes:
                    if attrs.get("is_credential_target") or any(target in path for target in ["login data", "key4.db", "logins.json", "web data"]):
                        matched_event_ids.append(ev_id)

            # 6. C2 HTTP Exfiltration (T1071.001) - Contextual requirement: POST with gate, beacon, panel, upload or exfiltration flags
            # A successful HTTP POST must NOT automatically be classified as C2 exfiltration without C2 indicators.
            elif rule.rule_id == "RULE_C2_HTTP_EXFILTRATION":
                for ev_id, url, attrs in http_reqs:
                    method = (attrs.get("method") or "").upper()
                    has_c2_indicator = (
                        any(k in url for k in ["gate", "upload", "beacon", "panel", "exfil", "post.php"])
                        or bool(attrs.get("is_c2_exfiltration"))
                        or bool(attrs.get("is_data_upload"))
                    )
                    if method == "POST" and has_c2_indicator:
                        matched_event_ids.append(ev_id)

            # 7. SMB Lateral Probe (T1046) - Contextual requirement: multiple connection attempts
            elif rule.rule_id == "RULE_LATERAL_SMB_PROBE":
                smb_evs = [ev_id for ev_id, attrs in net_conns if attrs.get("dest_port") == 445]
                # Contextual check: requires multiple targets or attempts
                if len(smb_evs) >= 2:
                    matched_event_ids.extend(smb_evs)
                elif len(smb_evs) == 1 and any("spread" in cmd or "worm" in cmd for _, cmd in proc_cmds):
                    matched_event_ids.extend(smb_evs)

            # 8. Dropped Executable Payload (T1027 / T1105) - Contextual requirement (B2):
            # Strict file write requirement:
            # File access/read must NEVER trigger dropped executable.
            # Arbitrary .bin files without verified PE indicators must NOT trigger.
            # Memory dump payloads are preserved as artifacts and not manufactured file writes.
            elif rule.rule_id == "RULE_DROPPED_EXECUTABLE_PAYLOAD":
                executable_exts = (".exe", ".dll", ".sys", ".scr", ".cpl", ".bat", ".cmd", ".vbs", ".ps1")
                for ev_id, path, attrs, action in file_writes:
                    # Must be an actual write or create action; never access or read
                    if action not in ["write", "create", "modify"]:
                        continue

                    # Non-executable formats are excluded
                    is_benign = any(path.endswith(ext) for ext in [".txt", ".log", ".tmp", ".ini", ".cfg", ".dat", ".json", ".xml", ".html"])
                    if is_benign:
                        continue

                    has_exec_ext = any(path.endswith(ext) for ext in executable_exts)
                    is_verified_pe = bool(attrs.get("is_verified_pe")) or "pe" in str(attrs.get("file_type", "")).lower()
                    is_dropped_bin = bool(attrs.get("is_dropped_binary")) and (has_exec_ext or is_verified_pe)

                    # .bin files without verified PE indicators are rejected
                    if path.endswith(".bin") and not is_verified_pe:
                        continue

                    if has_exec_ext or is_dropped_bin:
                        matched_event_ids.append(ev_id)

            # 9. Process Injection Technique (T1055) - Contextual correlation (B1):
            # Must group by verified source process instance and remote target process identity.
            # Must validate API success, executable memory protection, temporal ordering, and reject PID reuse or local self-calls.
            elif rule.rule_id == "RULE_PROCESS_INJECTION_TECHNIQUE":
                alloc_apis = {"virtualalloc", "virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory"}
                protect_apis = {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory", "zwprotectvirtualmemory"}
                write_apis = {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"}
                thread_apis = {"createremotethread", "ntcreatethreadex", "zwcreatethreadex", "rtlcreateuserthread"}

                events_by_source: Dict[int, List[AnalysisEvent]] = {}
                for ev in proc_events:
                    src_pid = ev.process_id
                    if src_pid is None:
                        continue
                    events_by_source.setdefault(src_pid, []).append(ev)

                for src_pid, s_events in events_by_source.items():
                    by_target: Dict[int, List[AnalysisEvent]] = {}
                    for ev in s_events:
                        act = (ev.action or "").lower()
                        attrs = ev.attributes or {}

                        # Extract verified target process identity
                        tgt_pid = _extract_target_pid(ev)
                        if tgt_pid is None:
                            if bool(attrs.get("cross_process")) and attrs.get("target_pid") is not None:
                                try:
                                    tgt_pid = int(attrs["target_pid"])
                                except (ValueError, TypeError):
                                    tgt_pid = None

                        if tgt_pid is None:
                            continue  # Do not invent missing target PID

                        # Exclude self / local memory operations (local allocation is standard multi-threading)
                        if tgt_pid == src_pid:
                            continue

                        # Must be a successful API call
                        if not _is_api_call_successful(ev):
                            continue

                        by_target.setdefault(tgt_pid, []).append(ev)

                    # For each target PID, evaluate the temporal and API sequence
                    for tgt_pid, t_events in by_target.items():
                        alloc_evs = []
                        write_evs = []
                        thread_evs = []

                        for ev in t_events:
                            act = (ev.action or "").lower()
                            attrs = ev.attributes or {}

                            if act in alloc_apis or act in protect_apis:
                                if _is_executable_memory_protection(ev):
                                    alloc_evs.append(ev)
                            elif act in write_apis or bool(attrs.get("cross_process_write")):
                                write_evs.append(ev)
                            elif act in thread_apis or bool(attrs.get("remote_thread")):
                                thread_evs.append(ev)

                        # Sequence requirement:
                        # (Remote Thread AND (Alloc OR Write)) OR (Remote Alloc AND Remote Write)
                        # All targeting the same remote process!
                        matched_seq = []
                        if thread_evs and (alloc_evs or write_evs):
                            for th in thread_evs:
                                th_time = th.timestamp
                                for mem in (alloc_evs + write_evs):
                                    mem_time = mem.timestamp
                                    if th_time is not None and mem_time is not None:
                                        delta_sec = (th_time - mem_time).total_seconds()
                                        if delta_sec < -0.001:  # Out of order: thread before alloc
                                            continue
                                        if delta_sec > 60.0:  # Distant events (> 60s apart, likely unrelated or PID reuse)
                                            continue
                                    matched_seq.extend([th.id, mem.id])
                        elif alloc_evs and write_evs:
                            for al in alloc_evs:
                                al_time = al.timestamp
                                for wr in write_evs:
                                    wr_time = wr.timestamp
                                    if al_time is not None and wr_time is not None:
                                        delta_sec = abs((wr_time - al_time).total_seconds())
                                        if delta_sec > 60.0:
                                            continue
                                    matched_seq.extend([al.id, wr.id])

                        if matched_seq:
                            matched_event_ids.extend(matched_seq)

                matched_event_ids = list(set(matched_event_ids))

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
                    "contributing_event_ids": matched_event_ids,
                    "explanation": rule.explanation,
                    "limitations": rule.limitations,
                    "mitre_attack_id": rule.mitre_attack_id,
                    "mitre_tactic": rule.mitre_tactic,
                    "engine_version": ENGINE_VERSION,
                })

        # Bounded explainable score 0-100
        clamped_score = min(100, total_score)
        if clamped_score >= 80:
            level = "Malicious"
        elif clamped_score >= 50:
            level = "Suspicious"
        elif clamped_score >= 20:
            level = "Low"
        elif telemetry_completeness in ("INCOMPLETE", "UNVERIFIED"):
            # Do not provide a false "Clean" conclusion when telemetry was missing or analyzer crashed (A6/B3)
            level = "Analysis Incomplete — Inconclusive"
        elif telemetry_completeness == "PARTIAL":
            level = "No Suspicious Behavior Observed (Partial Telemetry)"
        else:
            # Absence of evidence is not evidence of absence
            level = "No Suspicious Behavior Observed"

        # Persist findings to database
        self.db.add_all(findings)
        self.db.commit()

        # Confidence is calibrated by telemetry completeness
        if telemetry_completeness == "UNVERIFIED":
            confidence = 0.20
        elif telemetry_completeness == "INCOMPLETE":
            confidence = 0.35
        elif telemetry_completeness == "PARTIAL":
            confidence = 0.60
        else:
            confidence = 0.95 if findings else 0.80

        assessment = RiskAssessment(
            score=clamped_score,
            level=level,
            rule_breakdown=rule_score_contribs,
            confidence=confidence,
        )

        return findings, assessment
