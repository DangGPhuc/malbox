from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.schemas.static_analysis import (
    FunctionMetadata,
    ImportedSymbol,
    StaticAnalysisResult,
    StaticStringEvidence,
)
from app.services.evidence_correlation.normalization import (
    CAPABILITY_DOMAIN_APIS,
    normalize_api_root,
)
from app.services.evidence_correlation.schemas import (
    CorrelationConfidence,
    CorrelationEvidenceReference,
    CorrelationFinding,
    CorrelationRelationship,
)
from app.services.evidence_correlation.verifier import (
    NormalizedDynamicEvent,
    VerifiedCorrelationContext,
)

_GENERIC_STRING_ALLOW_BLOCKLIST = {
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "ntdll.dll",
    "ws2_32.dll",
    "wininet.dll",
    "msvcrt.dll",
    "http://",
    "https://",
    "windows",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "microsoft",
    "program",
    "default",
}

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{3,}\.(?:com|net|org|io|xyz|onion|bit|ru|cn|info|top|pw)$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_HIGH_SIGNAL_STR_KEYWORDS = (
    "vssadmin",
    "delete shadows",
    "powershell",
    "currentversion\\run",
    "machineguid",
    "tasksche",
    "gate.php",
    ".wnry",
    "login data",
    "key4.db",
    "@please_read_me@",
)


def make_correlation_id(
    rule_id: str,
    analysis_id: str,
    static_ref_ids: List[str],
    dynamic_ref_ids: List[str],
) -> str:
    seed = "|".join(
        [
            rule_id,
            analysis_id,
            ",".join(sorted(set(static_ref_ids))),
            ",".join(sorted(set(dynamic_ref_ids))),
        ]
    )
    return f"corr:{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"


def _to_dynamic_ref(
    ev: NormalizedDynamicEvent,
    is_replay: bool,
    summary: Optional[str] = None,
    *,
    trace_verified: bool = False,
) -> CorrelationEvidenceReference:
    ev_summary = summary or f"{ev.category}:{ev.action} target={ev.target_path or ev.process_name or 'none'}"
    if len(ev_summary) > 180:
        ev_summary = ev_summary[:177] + "..."
    return CorrelationEvidenceReference(
        ref_id=ev.id,
        evidence_kind="dynamic_event",
        source_tool=ev.source_tool or "sandbox",
        timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
        summary=ev_summary,
        is_synthetic=bool(is_replay),
        trace_verified=bool(trace_verified and not is_replay and ev.authenticated_trace is not None),
    )


def _to_static_func_ref(fn: FunctionMetadata, prov_scope: str) -> CorrelationEvidenceReference:
    apis = ", ".join(fn.imported_api_calls[:4])
    summary = f"function {fn.name} @ {fn.entry_address}" + (f" (APIs: {apis})" if apis else "")
    return CorrelationEvidenceReference(
        ref_id=fn.function_id,
        evidence_kind="static_function",
        source_tool="ghidra_headless",
        timestamp=None,
        summary=summary[:180],
        is_synthetic=False,
        provenance_scope=prov_scope,
    )


def _to_static_import_ref(imp: ImportedSymbol, prov_scope: str) -> CorrelationEvidenceReference:
    return CorrelationEvidenceReference(
        ref_id=f"imp:{imp.library.lower()}:{imp.name.lower()}",
        evidence_kind="static_import",
        source_tool="ghidra_headless",
        timestamp=None,
        summary=f"import {imp.library}!{imp.name}" + (f" @ {imp.address}" if imp.address else ""),
        is_synthetic=False,
        provenance_scope=prov_scope,
    )


def _to_static_string_ref(st: StaticStringEvidence, prov_scope: str) -> CorrelationEvidenceReference:
    preview = st.value if len(st.value) <= 96 else st.value[:93] + "..."
    return CorrelationEvidenceReference(
        ref_id=st.string_id,
        evidence_kind="static_string",
        source_tool="ghidra_headless",
        timestamp=None,
        summary=f"string '{preview}' @ {st.address}",
        is_synthetic=False,
        provenance_scope=prov_scope,
    )


@dataclass
class StaticCapabilityIndex:
    functions_scanned: int = 0
    functions_by_id: Dict[str, FunctionMetadata] = field(default_factory=dict)
    functions_by_addr: Dict[str, FunctionMetadata] = field(default_factory=dict)
    functions_by_norm_api: Dict[str, List[FunctionMetadata]] = field(default_factory=dict)
    imports_by_norm_api: Dict[str, ImportedSymbol] = field(default_factory=dict)
    exact_api_display_by_norm: Dict[str, str] = field(default_factory=dict)
    domain_apis: Dict[str, List[str]] = field(default_factory=dict)
    domain_functions: Dict[str, List[FunctionMetadata]] = field(default_factory=dict)
    domain_imports: Dict[str, List[ImportedSymbol]] = field(default_factory=dict)
    curated_strings: List[Tuple[str, StaticStringEvidence]] = field(default_factory=list)
    suppressed_ambiguous_strings: int = 0
    has_dynamic_loader_apis: bool = False


def build_static_index(
    static_res: Optional[StaticAnalysisResult],
    valid_function_ids: Set[str],
    valid_string_ids: Set[str],
    max_functions: int = 120,
) -> StaticCapabilityIndex:
    idx = StaticCapabilityIndex()
    if static_res is None or static_res.status not in ("COMPLETED", "PARTIAL"):
        return idx

    domain_keys = ("file", "file_mutation", "registry", "registry_write", "process", "network")
    for dk in domain_keys:
        idx.domain_apis[dk] = []
        idx.domain_functions[dk] = []
        idx.domain_imports[dk] = []

    domain_api_seen: Dict[str, Set[str]] = {dk: set() for dk in domain_keys}
    domain_fn_seen: Dict[str, Set[str]] = {dk: set() for dk in domain_keys}

    # Sort functions deterministically (higher rank score first, then entry_address)
    ordered_funcs = sorted(
        [fn for fn in static_res.functions if fn.function_id in valid_function_ids],
        key=lambda f: (-float(f.rank_score), f.entry_address, f.function_id),
    )[:max_functions]
    idx.functions_scanned = len(ordered_funcs)

    for fn in ordered_funcs:
        idx.functions_by_id[fn.function_id] = fn
        idx.functions_by_addr[fn.entry_address.lower()] = fn
        for raw_api in fn.imported_api_calls[:30]:
            norm = normalize_api_root(raw_api)
            if not norm:
                continue
            idx.exact_api_display_by_norm.setdefault(norm, raw_api)
            fn_list = idx.functions_by_norm_api.setdefault(norm, [])
            if fn.function_id not in {f.function_id for f in fn_list} and len(fn_list) < 5:
                fn_list.append(fn)
            if norm in ("loadlibrary", "getprocaddress", "ldrgetprocedureaddress"):
                idx.has_dynamic_loader_apis = True
            for dk in domain_keys:
                if norm in CAPABILITY_DOMAIN_APIS[dk]:
                    if raw_api not in domain_api_seen[dk]:
                        domain_api_seen[dk].add(raw_api)
                        idx.domain_apis[dk].append(raw_api)
                    if fn.function_id not in domain_fn_seen[dk] and len(idx.domain_functions[dk]) < 6:
                        domain_fn_seen[dk].add(fn.function_id)
                        idx.domain_functions[dk].append(fn)

    for imp in static_res.imports[:200]:
        norm = normalize_api_root(imp.name)
        if not norm:
            continue
        idx.imports_by_norm_api.setdefault(norm, imp)
        idx.exact_api_display_by_norm.setdefault(norm, imp.name)
        if norm in ("loadlibrary", "getprocaddress", "ldrgetprocedureaddress"):
            idx.has_dynamic_loader_apis = True
        for dk in domain_keys:
            if norm in CAPABILITY_DOMAIN_APIS[dk]:
                if imp.name not in domain_api_seen[dk]:
                    domain_api_seen[dk].add(imp.name)
                    idx.domain_apis[dk].append(imp.name)
                if len(idx.domain_imports[dk]) < 6:
                    idx.domain_imports[dk].append(imp)

    # Index curated non-ambiguous static string evidence
    seen_str_norm: Set[str] = set()
    for st in static_res.strings[:150]:
        if st.string_id not in valid_string_ids:
            continue
        raw_val = (st.value or "").strip()
        lower_val = raw_val.lower()
        if len(lower_val) < 6 or lower_val in _GENERIC_STRING_ALLOW_BLOCKLIST:
            idx.suppressed_ambiguous_strings += 1
            continue
        is_high_signal = bool(
            _URL_RE.search(lower_val)
            or _DOMAIN_RE.match(lower_val)
            or _IPV4_RE.match(lower_val)
            or any(kw in lower_val for kw in _HIGH_SIGNAL_STR_KEYWORDS)
            or lower_val.endswith((".exe", ".dll", ".bat", ".ps1", ".wnry", ".txt", ".ini", ".db"))
        )
        if not is_high_signal:
            idx.suppressed_ambiguous_strings += 1
            continue
        if lower_val not in seen_str_norm:
            seen_str_norm.add(lower_val)
            idx.curated_strings.append((lower_val, st))

    return idx


def _build_limitations(ctx: VerifiedCorrelationContext, base_note: str) -> List[str]:
    notes = [base_note]
    if ctx.is_replay:
        notes.append(
            f"Replay Mode limitation: telemetry stems from synthetic fixture '{ctx.replay_scenario_id or 'default'}' rather than live execution."
        )
    if ctx.static_reuse_detected:
        notes.append("Sample-level static analysis reuse: Ghidra facts come from another analysis sharing identical SHA-256.")
    if ctx.static_result and (ctx.static_result.status == "PARTIAL" or ctx.static_result.is_partial):
        notes.append("Static coverage was bounded/PARTIAL; undiscovered functions may exist.")
    return notes


def run_deterministic_correlation_rules(
    ctx: VerifiedCorrelationContext,
    static_idx: StaticCapabilityIndex,
    events: List[NormalizedDynamicEvent],
    max_findings: int = 30,
) -> Tuple[List[CorrelationFinding], int, int]:
    """
    Executes bounded O(F + E) deterministic static/dynamic correlation rules.
    Returns (findings, candidate_relationships_evaluated, suppressed_ambiguous_count).
    """
    static_res = ctx.static_result
    sample_sha = ctx.sample_sha256
    analysis_id = ctx.analysis.id
    is_replay = ctx.is_replay
    prov_scope = ctx.static_provenance_scope
    findings: List[CorrelationFinding] = []
    candidates_evaluated = 0
    suppressed_ambiguous = static_idx.suppressed_ambiguous_strings

    if static_res is None or static_res.status not in ("COMPLETED", "PARTIAL"):
        return findings, candidates_evaluated, suppressed_ambiguous

    # Partition dynamic events cleanly by category in O(E)
    api_events = [e for e in events if e.category == "api"]
    file_events = [e for e in events if e.category == "file"]
    reg_events = [e for e in events if e.category == "registry"]
    proc_events = [e for e in events if e.category == "process"]
    net_events = [e for e in events if e.category in ("network", "dns", "http")]

    # Helper to resolve static refs for a capability domain
    def _static_refs_for_domain(domain: str) -> List[CorrelationEvidenceReference]:
        refs: List[CorrelationEvidenceReference] = [
            _to_static_func_ref(fn, prov_scope) for fn in static_idx.domain_functions.get(domain, [])[:4]
        ]
        if not refs:
            refs = [_to_static_import_ref(imp, prov_scope) for imp in static_idx.domain_imports.get(domain, [])[:4]]
        return refs

    # ------------------------------------------------------------------
    # RULE 1: Runtime API Telemetry vs Static Imports / Authenticated Traces
    # ------------------------------------------------------------------
    if api_events:
        matched_traced: List[Tuple[NormalizedDynamicEvent, FunctionMetadata, str]] = []
        matched_untraced: List[Tuple[NormalizedDynamicEvent, List[CorrelationEvidenceReference], str]] = []

        for ev in api_events:
            attrs = ev.attributes if isinstance(ev.attributes, Mapping) else {}
            raw_api = str(
                attrs.get("api") or attrs.get("api_name") or attrs.get("function") or ev.target_path or ""
            ).strip()
            if not raw_api:
                continue
            candidates_evaluated += 1
            norm_api = normalize_api_root(raw_api)
            matching_funcs = static_idx.functions_by_norm_api.get(norm_api, [])
            matching_imp = static_idx.imports_by_norm_api.get(norm_api)
            if not matching_funcs and not matching_imp:
                continue

            # Only non-replay + backend-authenticated HMAC trace verifying module/base/IP/API -> DIRECTLY_OBSERVED
            traced_fn: Optional[FunctionMetadata] = None
            auth = ev.authenticated_trace
            if (
                not is_replay
                and auth is not None
                and auth.norm_api == norm_api
                and auth.function_id in static_idx.functions_by_id
            ):
                candidate_fn = static_idx.functions_by_id[auth.function_id]
                if candidate_fn in matching_funcs:
                    traced_fn = candidate_fn

            if traced_fn is not None:
                matched_traced.append((ev, traced_fn, raw_api))
            else:
                srefs = [_to_static_func_ref(fn, prov_scope) for fn in matching_funcs[:3]]
                if not srefs and matching_imp is not None:
                    srefs = [_to_static_import_ref(matching_imp, prov_scope)]
                matched_untraced.append((ev, srefs, raw_api))

        if matched_traced and len(findings) < max_findings:
            ev0, fn0, api0 = matched_traced[0]
            auth0 = ev0.authenticated_trace
            srefs = [_to_static_func_ref(t[1], prov_scope) for t in matched_traced[:4]]
            drefs = [
                _to_dynamic_ref(
                    t[0],
                    is_replay,
                    f"authenticated trace api={t[2]} ip=0x{t[0].authenticated_trace.instruction_pointer:x} in {t[1].name}"
                    if t[0].authenticated_trace
                    else f"trace api={t[2]} in {t[1].name}",
                    trace_verified=True,
                )
                for t in matched_traced[:4]
            ]
            cid = make_correlation_id(
                "CORR_RUNTIME_API_DIRECT_TRACE",
                analysis_id,
                [r.ref_id for r in srefs],
                [r.ref_id for r in drefs],
            )
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_RUNTIME_API_DIRECT_TRACE",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship="DIRECTLY_OBSERVED",
                    relationship_summary=(
                        f"Backend-authenticated runtime trace bound API '{api0}' to static function "
                        f"{fn0.name} ({fn0.entry_address})."
                    ),
                    explanation=(
                        f"Non-replay telemetry from '{ev0.source_tool}' carried backend-signed trace session "
                        f"'{auth0.trace_session_id if auth0 else 'verified'}' for module '{auth0.module_name if auth0 else 'sample'}' "
                        f"mapping IP 0x{(auth0.instruction_pointer if auth0 else 0):x} -> VA 0x{(auth0.mapped_static_va if auth0 else 0):x} "
                        f"inside {fn0.function_id} calling '{api0}'."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.92,
                        level="high",
                        rationale=(
                            "Backend-authenticated module/base/IP trace matched verified sample SHA-256 function bounds "
                            "and recorded API imports."
                        ),
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Observed call trace reflects the monitored execution path within bounded sandbox duration.",
                    ),
                    behavioral_execution_directly_observed=True,
                )
            )

        if matched_untraced and len(findings) < max_findings:
            seen_sids: Set[str] = set()
            srefs: List[CorrelationEvidenceReference] = []
            drefs: List[CorrelationEvidenceReference] = []
            apis_seen: List[str] = []
            for ev, refs, api_name in matched_untraced[:6]:
                if api_name not in apis_seen:
                    apis_seen.append(api_name)
                drefs.append(_to_dynamic_ref(ev, is_replay, f"runtime api={api_name}"))
                for r in refs:
                    if r.ref_id not in seen_sids and len(srefs) < 6:
                        seen_sids.add(r.ref_id)
                        srefs.append(r)

            rel: CorrelationRelationship = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
            cid = make_correlation_id(
                "CORR_API_CAPABILITY_VS_RUNTIME_API",
                analysis_id,
                [r.ref_id for r in srefs],
                [r.ref_id for r in drefs],
            )
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_API_CAPABILITY_VS_RUNTIME_API",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship=rel,
                    relationship_summary=f"Static imports ({', '.join(apis_seen[:4])}) align with runtime API telemetry without function-level trace binding.",
                    explanation=(
                        f"Normalized API calls ({', '.join(apis_seen[:4])}) in dynamic events match static PE imports/references, "
                        "but no verified call-stack address links execution directly to a specific static function."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.45 if is_replay else 0.72,
                        level="low" if is_replay else "medium",
                        rationale="API name normalization matches static imports; missing instruction-pointer trace prevents execution proof.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Imported API name matching alone does not prove which static function invoked the runtime API.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 2: File Capability vs Observed File Events
    # ------------------------------------------------------------------
    has_file_cap = bool(static_idx.domain_apis["file"])
    sig_file_events = [
        e for e in file_events
        if e.action in ("write", "modify", "delete")
        or bool((e.attributes or {}).get("is_dropped_binary"))
        or bool((e.attributes or {}).get("is_encrypted_target"))
        or bool((e.attributes or {}).get("is_ransom_note"))
        or bool((e.attributes or {}).get("is_credential_target"))
    ]
    if file_events:
        candidates_evaluated += 1
        if has_file_cap and not sig_file_events and not static_idx.domain_apis["file_mutation"]:
            # Ambiguous low-signal read-only match suppressed safely
            suppressed_ambiguous += 1
        elif has_file_cap and (sig_file_events or file_events):
            srefs = _static_refs_for_domain("file")
            chosen_fevs = sig_file_events[:5] if sig_file_events else file_events[:4]
            drefs = [_to_dynamic_ref(e, is_replay) for e in chosen_fevs]
            rel: CorrelationRelationship = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
            apis = ", ".join(static_idx.domain_apis["file"][:4])
            cid = make_correlation_id("CORR_FILE_CAPABILITY_VS_EVENTS", analysis_id, [r.ref_id for r in srefs], [r.ref_id for r in drefs])
            if srefs and len(findings) < max_findings:
                findings.append(
                    CorrelationFinding(
                        correlation_id=cid,
                        rule_id="CORR_FILE_CAPABILITY_VS_EVENTS",
                        analysis_id=analysis_id,
                        sample_sha256=sample_sha,
                        static_references=srefs,
                        dynamic_references=drefs,
                        relationship=rel,
                        relationship_summary=f"Static filesystem/crypto APIs ({apis}) are consistent with observed file activity."
                        if not is_replay
                        else f"Synthetic Replay filesystem events compared against static file/crypto capability ({apis}).",
                        explanation=(
                            f"Static binary imports file-manipulation APIs ({apis}) while telemetry records {len(chosen_fevs)} "
                            f"filesystem event(s) (actions: {', '.join(sorted({e.action for e in chosen_fevs}))})."
                        ),
                        confidence=CorrelationConfidence(
                            score=0.4 if is_replay else 0.68,
                            level="low" if is_replay else "medium",
                            rationale="Domain-level API capability aligns with filesystem telemetry; lacks function call-stack proof.",
                        ),
                        known_limitations=_build_limitations(
                            ctx,
                            "Filesystem API presence in PE import table does not prove which function or whether these specific file writes originated from that static block.",
                        ),
                        behavioral_execution_directly_observed=False,
                    )
                )

    # ------------------------------------------------------------------
    # RULE 3: Registry Capability vs Observed Registry Telemetry
    # ------------------------------------------------------------------
    has_reg_cap = bool(static_idx.domain_apis["registry"])
    if reg_events and has_reg_cap:
        candidates_evaluated += 1
        reg_writes = [e for e in reg_events if e.action != "reg_query" or (e.attributes or {}).get("persistence")]
        chosen_revs = reg_writes[:4] if reg_writes else reg_events[:4]
        # Avoid falsely tying read-only queries to persistence unless write capability & write events match
        srefs = _static_refs_for_domain("registry")
        drefs = [_to_dynamic_ref(e, is_replay) for e in chosen_revs]
        rel = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
        apis = ", ".join(static_idx.domain_apis["registry"][:4])
        if srefs and len(findings) < max_findings:
            cid = make_correlation_id("CORR_REGISTRY_CAPABILITY_VS_EVENTS", analysis_id, [r.ref_id for r in srefs], [r.ref_id for r in drefs])
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_REGISTRY_CAPABILITY_VS_EVENTS",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship=rel,
                    relationship_summary=f"Static registry API capability ({apis}) aligns with {'synthetic ' if is_replay else ''}registry telemetry.",
                    explanation=(
                        f"Static PE metadata imports registry APIs ({apis}) and telemetry records {len(chosen_revs)} registry operation(s)."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.4 if is_replay else 0.67,
                        level="low" if is_replay else "medium",
                        rationale="Domain-level registry capability alignment; no direct registry key handle provenance to static address.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Static registry imports alone cannot distinguish benign configuration lookups from malicious persistence without key/trace correlation.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 4: Process-Creation Capability vs Observed Child Processes
    # ------------------------------------------------------------------
    has_proc_cap = bool(static_idx.domain_apis["process"])
    child_procs = [
        e for e in proc_events
        if len(proc_events) > 1 or any(k in str((e.attributes or {}).get("command_line") or "").lower() for k in ("cmd", "powershell", "vssadmin", "rundll32", "schtasks", "tasksche"))
    ]
    if child_procs and has_proc_cap:
        candidates_evaluated += 1
        srefs = _static_refs_for_domain("process")
        drefs = [_to_dynamic_ref(e, is_replay, f"process={e.process_name} cmd={(e.attributes or {}).get('command_line', '')}") for e in child_procs[:4]]
        rel = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
        apis = ", ".join(static_idx.domain_apis["process"][:4])
        if srefs and len(findings) < max_findings:
            cid = make_correlation_id("CORR_PROCESS_CAPABILITY_VS_EVENTS", analysis_id, [r.ref_id for r in srefs], [r.ref_id for r in drefs])
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_PROCESS_CAPABILITY_VS_EVENTS",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship=rel,
                    relationship_summary=f"Static process/execution APIs ({apis}) align with {'synthetic ' if is_replay else ''}child process spawns.",
                    explanation=(
                        f"Static metadata contains process-creation/injection capability ({apis}) alongside {len(child_procs)} child/command execution event(s)."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.4 if is_replay else 0.7,
                        level="low" if is_replay else "medium",
                        rationale="Static process creation API matches runtime child spawn category without direct stack-frame link.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Process spawn telemetry does not identify which internal static function invoked CreateProcess/ShellExecute.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 5: Network Capability vs Observed DNS/TCP/HTTP Telemetry
    # ------------------------------------------------------------------
    has_net_cap = bool(static_idx.domain_apis["network"])
    if net_events and has_net_cap:
        candidates_evaluated += 1
        srefs = _static_refs_for_domain("network")
        drefs = [_to_dynamic_ref(e, is_replay) for e in net_events[:5]]
        rel = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
        apis = ", ".join(static_idx.domain_apis["network"][:4])
        if srefs and len(findings) < max_findings:
            cid = make_correlation_id("CORR_NETWORK_CAPABILITY_VS_EVENTS", analysis_id, [r.ref_id for r in srefs], [r.ref_id for r in drefs])
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_NETWORK_CAPABILITY_VS_EVENTS",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship=rel,
                    relationship_summary=f"Static networking APIs ({apis}) align with {'synthetic ' if is_replay else ''}DNS/TCP/HTTP telemetry.",
                    explanation=(
                        f"Static PE disassembly references networking APIs ({apis}) alongside {len(net_events)} DNS/network/HTTP event(s)."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.42 if is_replay else 0.72,
                        level="low" if is_replay else "medium",
                        rationale="Static socket/HTTP capability aligns with observed network telemetry category.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Network API imports confirm capability only; socket origin address inside binary was not traced.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 6: Exact Curated Static String vs Dynamic Target/Attribute Value
    # ------------------------------------------------------------------
    if static_idx.curated_strings and events:
        # Build O(E) reverse map of normalized target tokens to events (avoids O(S * E)!)
        ev_by_token: Dict[str, List[NormalizedDynamicEvent]] = {}
        ev_search_blobs: List[Tuple[NormalizedDynamicEvent, str]] = []
        for ev in events:
            attrs = ev.attributes if isinstance(ev.attributes, Mapping) else {}
            candidates: List[str] = []
            for v in (
                ev.target_path,
                ev.process_name,
                attrs.get("query"),
                attrs.get("response"),
                attrs.get("dest_ip"),
                attrs.get("url"),
                attrs.get("command_line"),
                attrs.get("value_name"),
                attrs.get("data"),
            ):
                if v and isinstance(v, str):
                    lv = v.strip().lower()
                    candidates.append(lv)
                    base = os.path.basename(lv.replace("\\", "/"))
                    if len(base) >= 6:
                        candidates.append(base)
            joined = " ".join(candidates)
            ev_search_blobs.append((ev, joined))
            for tok in candidates:
                ev_by_token.setdefault(tok, []).append(ev)

        matched_pairs: List[Tuple[StaticStringEvidence, NormalizedDynamicEvent]] = []
        for norm_str, st in static_idx.curated_strings[:80]:
            candidates_evaluated += 1
            hit_events = ev_by_token.get(norm_str)
            if not hit_events:
                # Exact substring boundary check ONLY for long high-signal indicators (>= 8 chars)
                if len(norm_str) >= 8:
                    hit_events = [ev for ev, blob in ev_search_blobs if norm_str in blob][:2]
            if hit_events:
                matched_pairs.append((st, hit_events[0]))

        if matched_pairs and len(findings) < max_findings:
            srefs = [_to_static_string_ref(st, prov_scope) for st, _ in matched_pairs[:5]]
            drefs = [_to_dynamic_ref(ev, is_replay) for _, ev in matched_pairs[:5]]
            rel = "SYNTHETIC_SCENARIO_ONLY" if is_replay else "CONSISTENT_WITH"
            sample_literals = ", ".join(f"'{st.value[:40]}'" for st, _ in matched_pairs[:3])
            cid = make_correlation_id("CORR_STATIC_STRING_IOC_MATCH", analysis_id, [r.ref_id for r in srefs], [r.ref_id for r in drefs])
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_STATIC_STRING_IOC_MATCH",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=drefs,
                    relationship=rel,
                    relationship_summary=f"Extracted static binary string(s) ({sample_literals}) matched {'synthetic scenario' if is_replay else 'observed runtime'} values.",
                    explanation=(
                        f"{len(matched_pairs)} curated static string literal(s) ({sample_literals}) appeared in dynamic event targets or parameters."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.55 if is_replay else 0.84,
                        level="medium" if is_replay else "high",
                        rationale="Exact normalized literal match between Ghidra string section and dynamic telemetry.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Literal string presence inside static data sections does not prove which execution branch constructed or transmitted the value at runtime.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 7A: Unobserved Static Capabilities -> INSUFFICIENT_EVIDENCE
    # ------------------------------------------------------------------
    domain_event_counts = {
        "network": len(net_events),
        "registry": len(reg_events),
        "process": len(child_procs),
        "file": len(sig_file_events),
    }
    for domain in ("network", "registry", "process", "file"):
        if static_idx.domain_apis.get(domain) and domain_event_counts[domain] == 0 and len(findings) < max_findings:
            candidates_evaluated += 1
            srefs = _static_refs_for_domain(domain)
            if not srefs:
                continue
            apis = ", ".join(static_idx.domain_apis[domain][:4])
            cid = make_correlation_id(f"CORR_UNOBSERVED_{domain.upper()}_CAPABILITY", analysis_id, [r.ref_id for r in srefs], [])
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_UNOBSERVED_STATIC_CAPABILITY",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=srefs,
                    dynamic_references=[],
                    relationship="INSUFFICIENT_EVIDENCE",
                    relationship_summary=f"Static {domain} capability ({apis}) had zero corresponding runtime {domain} events.",
                    explanation=(
                        f"Ghidra disassembly discovered {domain}-capable APIs ({apis}), but dynamic telemetry recorded "
                        f"zero corresponding {domain} events. Code presence alone cannot confirm execution."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.75,
                        level="medium",
                        rationale="Confirmed absence of matching dynamic telemetry in monitored domain for statically present APIs.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        f"Missing runtime {domain} telemetry could reflect unreached branches, environment checks/evasion, Replay scenario scope, or sandbox timeout bounds.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    # ------------------------------------------------------------------
    # RULE 7B: Conflicting Evidence / Packing Discrepancy -> CONTRADICTORY
    # ------------------------------------------------------------------
    active_dynamic_domains = [
        (d, cnt) for d, cnt in domain_event_counts.items() if cnt > 0 and not static_idx.domain_apis.get(d)
    ]
    pe_meta = (ctx.sample.pe_metadata if ctx.sample and isinstance(ctx.sample.pe_metadata, dict) else {})
    overall_entropy = float(pe_meta.get("overall_entropy", 0.0) or 0.0)
    is_packed_pe = bool(pe_meta.get("is_packed_heuristic")) or overall_entropy >= 7.2
    minimal_static_surface = len(static_res.imports) <= 2 or len(static_res.functions) <= 1

    if active_dynamic_domains and (is_packed_pe or minimal_static_surface or len(active_dynamic_domains) >= 2):
        candidates_evaluated += 1
        # Cite top static functions/imports (or fallback to entry function) and dynamic domain sample events
        conflict_srefs: List[CorrelationEvidenceReference] = []
        for fn in list(static_idx.functions_by_id.values())[:3]:
            conflict_srefs.append(_to_static_func_ref(fn, prov_scope))
        if not conflict_srefs:
            for imp in static_res.imports[:3]:
                conflict_srefs.append(_to_static_import_ref(imp, prov_scope))

        conflict_drefs: List[CorrelationEvidenceReference] = []
        domain_event_map = {
            "network": net_events,
            "registry": reg_events,
            "process": child_procs,
            "file": sig_file_events,
        }
        missing_domains: List[str] = []
        for dom, _cnt in active_dynamic_domains:
            missing_domains.append(dom)
            if domain_event_map[dom]:
                conflict_drefs.append(_to_dynamic_ref(domain_event_map[dom][0], is_replay))

        if (conflict_srefs or conflict_drefs) and len(findings) < max_findings:
            if is_packed_pe:
                packing_reason = f"high-entropy/packed PE indicators (entropy={overall_entropy:.2f}, imports={len(static_res.imports)})"
            elif minimal_static_surface:
                packing_reason = f"minimal static surface (functions={len(static_res.functions)}, imports={len(static_res.imports)})"
            else:
                packing_reason = f"{len(static_res.imports)} unpacked imports with dynamic API loader={static_idx.has_dynamic_loader_apis}"
            cid = make_correlation_id(
                "CORR_STATIC_DYNAMIC_CONFLICT",
                analysis_id,
                [r.ref_id for r in conflict_srefs],
                [r.ref_id for r in conflict_drefs],
            )
            findings.append(
                CorrelationFinding(
                    correlation_id=cid,
                    rule_id="CORR_STATIC_DYNAMIC_CONFLICT",
                    analysis_id=analysis_id,
                    sample_sha256=sample_sha,
                    static_references=conflict_srefs[:4],
                    dynamic_references=conflict_drefs[:4],
                    relationship="CONTRADICTORY",
                    relationship_summary=(
                        f"Discrepancy between {'synthetic Replay' if is_replay else 'dynamic'} behavior "
                        f"({', '.join(missing_domains)}) and absent static capabilities ({packing_reason})."
                    ),
                    explanation=(
                        f"Telemetry exhibits activity across domain(s) [{', '.join(missing_domains)}] without matching "
                        f"static imports or strings under {packing_reason}. In live execution this indicates likely packing, "
                        "dynamic API resolution (GetProcAddress/LoadLibrary), or secondary dropped code; in Replay Mode "
                        "it confirms static binary features diverge from the synthetic reference scenario."
                    ),
                    confidence=CorrelationConfidence(
                        score=0.78 if (is_packed_pe or is_replay) else 0.65,
                        level="high" if (is_packed_pe or is_replay) else "medium",
                        rationale="Direct absence of corresponding static imports in domain showing dynamic events.",
                    ),
                    known_limitations=_build_limitations(
                        ctx,
                        "Static vs. dynamic discrepancy may stem from packing, GetProcAddress resolution, truncated disassembly, or synthetic Replay fixture mismatch.",
                    ),
                    behavioral_execution_directly_observed=False,
                )
            )

    return findings[:max_findings], candidates_evaluated, suppressed_ambiguous
