"""Evidence-backed MITRE ATT&CK mapping generator using structured MalBox artifacts.

Rules enforced:
- Every mapping cites concrete structured evidence sources and artifact references.
- Distinguishes static_capability_indicator, observed_event, correlated_observation,
  and unverified_hypothesis.
- Never promotes single-indicator matches (one API, string, rule, or event) to confirmed.
- Never produces an arbitrary global risk score.
"""

from __future__ import annotations

import re
from typing import Any

ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _extract_capa_attack_entries(capa_doc: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for cap in capa_doc.get("capabilities", []) or []:
        if not isinstance(cap, dict):
            continue
        cap_name = str(cap.get("name") or "")
        for att in cap.get("attack", []) or []:
            att_str = (
                f"{att.get('technique', '')} {att.get('subtechnique', '')} {att.get('id', '')}".strip()
                if isinstance(att, dict)
                else str(att)
            )
            m = ATTACK_ID_RE.search(att_str)
            if not m:
                continue
            tid = m.group(1)
            tname = att_str.replace(f"[{tid}]", "").replace(tid, "").strip(" :-[]") or cap_name
            tactic = att.get("tactic") if isinstance(att, dict) else None
            items.append(
                {
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic": tactic,
                    "evidence_source": "capa",
                    "evidence_reference": f"static/capa.json -> capability '{cap_name}'",
                    "observation_type": "static_capability_indicator",
                    "confidence": "low",
                    "verification_level": "static_indicator_only",
                    "explanation": f"capa matched rule '{cap_name}' associated with ATT&CK metadata '{att_str}'.",
                    "limitations": "Static capa match shows code pattern structure only; runtime execution is not proven by static scan alone.",
                }
            )
    return items


def build_attack_mapping(
    pe_doc: dict[str, Any],
    floss_doc: dict[str, Any],
    capa_doc: dict[str, Any],
    yara_doc: dict[str, Any],
    die_doc: dict[str, Any],
    proc_doc: dict[str, Any],
    proc_events_doc: dict[str, Any],
    net_doc: dict[str, Any],
    dns_doc: dict[str, Any],
    fs_doc: dict[str, Any],
    reg_doc: dict[str, Any],
    sysmon_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build deterministic, evidence-backed ATT&CK mappings without speculative risk scoring."""
    raw_observations: list[dict[str, Any]] = []

    # 1. Static capability indicators from capa metadata
    raw_observations.extend(_extract_capa_attack_entries(capa_doc))

    # 2. Static packer / high-entropy obfuscation indicators (T1027)
    high_entropy_secs = [
        sec.get("name")
        for sec in (pe_doc.get("sections") or [])
        if isinstance(sec, dict) and float(sec.get("entropy", 0.0)) >= 7.2
    ]
    die_packers = [
        d.get("name")
        for d in (die_doc.get("detections") or [])
        if isinstance(d, dict) and str(d.get("type") or "").lower() in ("packer", "protector", "crypter")
    ]
    if high_entropy_secs or die_packers:
        refs = []
        if high_entropy_secs:
            refs.append(f"static/pe_info.json -> high-entropy sections ({', '.join(str(s) for s in high_entropy_secs[:5])})")
        if die_packers:
            refs.append(f"static/die.json -> packer/protector signatures ({', '.join(str(p) for p in die_packers[:5])})")
        raw_observations.append(
            {
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "evidence_source": "pefile / detect_it_easy",
                "evidence_reference": "; ".join(refs),
                "observation_type": "static_capability_indicator",
                "confidence": "low",
                "verification_level": "static_indicator_only",
                "explanation": "High section entropy (>= 7.2) or DIE packer/protector indicator suggests possible compression or packing.",
                "limitations": "Encrypted resources, legitimate installers, or packed benign software also exhibit high entropy.",
            }
        )

    # 3. Static YARA rules + API string hypotheses (never marked confirmed)
    for m in yara_doc.get("matches", []) or []:
        if not isinstance(m, dict):
            continue
        rname = str(m.get("rule") or "")
        if "Injection" in rname:
            raw_observations.append(
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "evidence_source": "yara",
                    "evidence_reference": f"static/yara.json -> rule '{rname}'",
                    "observation_type": "unverified_hypothesis",
                    "confidence": "unverified",
                    "verification_level": "static_string_pattern_only",
                    "explanation": f"Local YARA rule '{rname}' matched injection-associated API string references.",
                    "limitations": "Presence of memory-manipulation API strings in binary does not prove execution or malicious injection.",
                }
            )
        elif "Persistence" in rname:
            raw_observations.append(
                {
                    "technique_id": "T1547.001",
                    "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                    "tactic": "Persistence",
                    "evidence_source": "yara",
                    "evidence_reference": f"static/yara.json -> rule '{rname}'",
                    "observation_type": "unverified_hypothesis",
                    "confidence": "unverified",
                    "verification_level": "static_string_pattern_only",
                    "explanation": f"Local YARA rule '{rname}' matched autorun/service string references.",
                    "limitations": "Static persistence string references require dynamic registry or startup verification.",
                }
            )
        elif "Network" in rname:
            raw_observations.append(
                {
                    "technique_id": "T1071.001",
                    "technique_name": "Application Layer Protocol: Web Protocols",
                    "tactic": "Command and Control",
                    "evidence_source": "yara",
                    "evidence_reference": f"static/yara.json -> rule '{rname}'",
                    "observation_type": "unverified_hypothesis",
                    "confidence": "unverified",
                    "verification_level": "static_string_pattern_only",
                    "explanation": f"Local YARA rule '{rname}' matched WinINet/WinHTTP API string references.",
                    "limitations": "HTTP/WinINet API strings alone are common in benign updaters and tools.",
                }
            )

    # 4. Observed dynamic events (strictly from sample-attributed telemetry!)
    pers_hits = reg_doc.get("persistence_indicators") or []
    if pers_hits:
        sample_hit = pers_hits[0]
        raw_observations.append(
            {
                "technique_id": "T1547.001",
                "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "evidence_source": "registry_monitor",
                "evidence_reference": f"dynamic/registry/changes.json -> {len(pers_hits)} persistence-related key op(s), e.g. '{sample_hit.get('target_object')}'",
                "observation_type": "observed_event",
                "confidence": "medium",
                "verification_level": "dynamic_single_source_observation",
                "explanation": "Tracked sample process wrote/modified a Windows autorun/persistence registry key during observation.",
                "limitations": "Registry key changes can also occur in legitimate installers; inspect TargetObject value manually.",
            }
        )

    proc_list = proc_doc.get("processes") or []
    cmd_children = [
        p for p in proc_list
        if isinstance(p, dict) and str(p.get("name") or "").lower() in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
    ]
    if cmd_children:
        names = sorted({str(p.get("name")) for p in cmd_children})
        raw_observations.append(
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "evidence_source": "process_monitor",
                "evidence_reference": f"dynamic/process/processes.json -> tracked interpreter process(es): {', '.join(names)}",
                "observation_type": "observed_event",
                "confidence": "medium",
                "verification_level": "dynamic_single_source_observation",
                "explanation": f"Tracked sample process tree included script/command interpreter process(es): {', '.join(names)}.",
                "limitations": "Legitimate installers and administrative utilities may invoke cmd/PowerShell interpreters.",
            }
        )

    sample_net = [
        c for c in (net_doc.get("connections") or [])
        if isinstance(c, dict) and c.get("classification") == "sample_related_traffic"
    ]
    sample_dns = [
        q for q in (dns_doc.get("queries") or [])
        if isinstance(q, dict) and q.get("classification") == "sample_related_traffic"
    ]
    if sample_net or sample_dns:
        raw_observations.append(
            {
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "evidence_source": "network_monitor",
                "evidence_reference": f"dynamic/network/connections.json ({len(sample_net)} sample connection(s)) / dns.json ({len(sample_dns)} sample DNS query(s))",
                "observation_type": "observed_event",
                "confidence": "medium",
                "verification_level": "dynamic_single_source_observation",
                "explanation": "Tracked sample PID initiated outbound connection or DNS query inside the isolated lab network.",
                "limitations": "Socket/DNS activity does not specify payload intent; external hosts cannot respond in isolated Net 2.",
            }
        )

    sysmon_eid8 = [ev for ev in sysmon_events if ev.get("event_id") == 8]
    if sysmon_eid8:
        raw_observations.append(
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion",
                "evidence_source": "eventlog_monitor",
                "evidence_reference": f"dynamic/eventlogs/events_summary.json -> {len(sysmon_eid8)} Sysmon EID 8 event(s)",
                "observation_type": "observed_event",
                "confidence": "medium",
                "verification_level": "dynamic_sysmon_observation",
                "explanation": "Sysmon Event ID 8 (CreateRemoteThread) occurred during the analysis window.",
                "limitations": "Verify SourceImage/SourceProcessId in Sysmon logs to confirm relation to tracked sample PID.",
            }
        )

    dropped_exes = [
        d for d in (fs_doc.get("dropped_artifact_metadata") or [])
        if isinstance(d, dict) and d.get("is_executable_extension")
    ]
    if dropped_exes:
        raw_observations.append(
            {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "evidence_source": "filesystem_monitor",
                "evidence_reference": f"dynamic/filesystem/changes.json -> {len(dropped_exes)} dropped executable artifact metadata entry(s)",
                "observation_type": "observed_event",
                "confidence": "low",
                "verification_level": "dynamic_single_source_observation",
                "explanation": "Executable file creation observed in sample workspace or tracked file events (metadata recorded only).",
                "limitations": "Self-extracting installers also write executable payloads locally; transfer over network is not implied by local file drop alone.",
            }
        )

    # 5. Aggregate per technique_id & mark correlated_observation ONLY when both static + dynamic agree
    by_tech: dict[str, dict[str, Any]] = {}
    for obs in raw_observations:
        tid = obs["technique_id"]
        if tid not in by_tech:
            by_tech[tid] = {
                "technique_id": tid,
                "technique_name": obs["technique_name"],
                "tactic": obs.get("tactic"),
                "evidence_sources": [obs["evidence_source"]],
                "evidence_references": [obs["evidence_reference"]],
                "observation_types": [obs["observation_type"]],
                "observation_type": obs["observation_type"],
                "confidence": obs["confidence"],
                "verification_level": obs["verification_level"],
                "explanation": obs["explanation"],
                "limitations": obs["limitations"],
            }
        else:
            agg = by_tech[tid]
            if obs["evidence_source"] not in agg["evidence_sources"]:
                agg["evidence_sources"].append(obs["evidence_source"])
            if obs["evidence_reference"] not in agg["evidence_references"]:
                agg["evidence_references"].append(obs["evidence_reference"])
            if obs["observation_type"] not in agg["observation_types"]:
                agg["observation_types"].append(obs["observation_type"])
            if obs["explanation"] not in agg["explanation"]:
                agg["explanation"] += " | " + obs["explanation"]

    final_mappings: list[dict[str, Any]] = []
    for tid in sorted(by_tech.keys()):
        agg = by_tech[tid]
        types = set(agg["observation_types"])
        has_static = bool(types & {"static_capability_indicator", "unverified_hypothesis"})
        has_dynamic = "observed_event" in types
        if has_static and has_dynamic:
            agg["observation_type"] = "correlated_observation"
            agg["confidence"] = "medium"
            agg["verification_level"] = "corroborated_static_and_dynamic"
        elif has_dynamic:
            agg["observation_type"] = "observed_event"
        elif "static_capability_indicator" in types:
            agg["observation_type"] = "static_capability_indicator"
            agg["confidence"] = "low"
        else:
            agg["observation_type"] = "unverified_hypothesis"
            agg["confidence"] = "unverified"
        final_mappings.append(agg)

    counts_by_obs_type = {
        "correlated_observation": sum(1 for m in final_mappings if m["observation_type"] == "correlated_observation"),
        "observed_event": sum(1 for m in final_mappings if m["observation_type"] == "observed_event"),
        "static_capability_indicator": sum(1 for m in final_mappings if m["observation_type"] == "static_capability_indicator"),
        "unverified_hypothesis": sum(1 for m in final_mappings if m["observation_type"] == "unverified_hypothesis"),
    }

    return {
        "schema_version": "1.0",
        "methodology": (
            "Conservative evidence-backed ATT&CK mapping aggregating structured capa, YARA, PE/DIE, "
            "and sample-attributed dynamic telemetry without automated maliciousness verdicts or risk scores."
        ),
        "technique_count": len(final_mappings),
        "counts_by_observation_type": counts_by_obs_type,
        "mappings": final_mappings,
        "limitations": [
            "Single-source static indicators or YARA matches never establish confirmed runtime execution.",
            "Manual analyst review of cited artifacts is required before drawing attribution or intent conclusions.",
        ],
    }
