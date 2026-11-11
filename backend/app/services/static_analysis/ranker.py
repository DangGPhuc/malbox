from __future__ import annotations

import re
from typing import Dict, List, Tuple

from app.schemas.static_analysis import (
    FunctionAnalysisFinding,
    FunctionCallRelationship,
    FunctionMetadata,
    StaticStringEvidence,
)


# Weighted explainable static API signals (never treated as standalone proof of malware)
_API_CATEGORY_WEIGHTS: Dict[str, Tuple[str, float]] = {
    # Memory allocation & injection primitives
    "virtualalloc": ("Memory allocation/injection API", 4.0),
    "virtualallocex": ("Remote memory allocation API", 5.5),
    "virtualprotect": ("Memory protection modification API", 4.0),
    "writeprocessmemory": ("Cross-process memory write API", 6.0),
    "createremotethread": ("Remote thread creation API", 6.5),
    "ntunmapviewofsection": ("Section unmapping API", 5.5),
    "queueuserapc": ("APC injection API", 5.0),
    # Execution & process launch
    "createprocess": ("Process creation API", 3.5),
    "shellexecute": ("Shell execution API", 4.0),
    "winexec": ("Legacy process launch API", 4.0),
    # Persistence & configuration
    "regsetvalue": ("Registry value write API", 3.5),
    "createservice": ("Windows service creation API", 4.5),
    "startservice": ("Windows service control API", 3.5),
    # Crypto & credential access
    "cryptencrypt": ("Cryptography API (CryptEncrypt)", 4.0),
    "bcryptencrypt": ("Cryptography API (BCryptEncrypt)", 4.0),
    "cryptunprotectdata": ("DPAPI data decryption API", 5.0),
    # Anti-analysis & dynamic resolution
    "isdebuggerpresent": ("Debugger detection check", 4.5),
    "checkremotedebuggerpresent": ("Remote debugger check", 4.5),
    "getprocaddress": ("Dynamic symbol resolution API", 2.5),
    "loadlibrary": ("Dynamic module load API", 2.0),
    # Network egress / transfer
    "internetopen": ("WinINet session API", 3.5),
    "internetconnect": ("WinINet connection API", 4.0),
    "urldownloadtofile": ("File download API", 5.5),
    "winhttpopen": ("WinHTTP client API", 3.5),
    "wsaconnect": ("Winsock connect API", 4.0),
    "send": ("Socket transmit API", 2.5),
    "recv": ("Socket receive API", 2.0),
}

_HIGH_SIGNAL_STRING_PATTERNS: List[Tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"https?://", re.IGNORECASE), "Embedded HTTP(S) URL string", 4.0),
    (re.compile(r"vssadmin|delete\s+shadows|wbadmin|bcdedit", re.IGNORECASE), "Recovery inhibition command token", 5.5),
    (re.compile(r"CurrentVersion\\Run|RunOnce", re.IGNORECASE), "Registry autostart path string", 4.5),
    (re.compile(r"powershell|cmd\.exe|-enc\b", re.IGNORECASE), "Command interpreter string", 3.5),
    (re.compile(r"Login\s+Data|AppData\\Local|Cookies", re.IGNORECASE), "Browser/profile artifact string", 4.0),
    (re.compile(r"@WanaDecryptor|README|HOW_TO_DECRYPT|onion", re.IGNORECASE), "Extortion/Tor-related text token", 5.0),
]


def _normalize_api_token(name: str) -> str:
    short = (name or "").split("::")[-1].split("!")[-1].strip()
    # Strip trailing A / W / Ex suffixes cautiously only for table lookup fallback
    lower = short.lower()
    if lower in _API_CATEGORY_WEIGHTS:
        return lower
    for suffix in ("exa", "exw", "ex", "a", "w"):
        if lower.endswith(suffix) and lower[: -len(suffix)] in _API_CATEGORY_WEIGHTS:
            return lower[: -len(suffix)]
    return lower


def rank_functions(
    functions: List[FunctionMetadata],
    call_graph: List[FunctionCallRelationship],
    strings: List[StaticStringEvidence],
    max_findings: int = 15,
) -> Tuple[List[FunctionMetadata], List[FunctionAnalysisFinding]]:
    """
    Deterministically scores and ranks discovered functions for optional selective decompilation.
    Uses additive, inspectable heuristics (API imports, high-signal strings, xref/call centrality,
    and structural complexity). Never flags a function as malicious solely for importing Windows APIs.
    """
    calls_by_fn: Dict[str, List[str]] = {}
    for rel in call_graph:
        if rel.is_external_import and rel.caller_function_id and rel.callee_name:
            calls_by_fn.setdefault(rel.caller_function_id, []).append(rel.callee_name)

    strings_by_fn: Dict[str, List[str]] = {}
    for st in strings:
        for fid in st.referencing_function_ids:
            strings_by_fn.setdefault(fid, []).append(st.value)

    scored_functions: List[FunctionMetadata] = []
    findings: List[FunctionAnalysisFinding] = []

    for fn in functions:
        score = 0.0
        reasons: List[str] = []

        merged_apis = list(dict.fromkeys([*fn.imported_api_calls, *calls_by_fn.get(fn.function_id, [])]))
        matched_apis: List[str] = []
        seen_api_cats = set()
        for api_name in merged_apis:
            norm = _normalize_api_token(api_name)
            if norm in _API_CATEGORY_WEIGHTS and norm not in seen_api_cats:
                seen_api_cats.add(norm)
                label, weight = _API_CATEGORY_WEIGHTS[norm]
                score += weight
                matched_apis.append(api_name)
                reasons.append(f"+{weight:.1f}: references '{api_name}' ({label})")

        merged_strings = list(dict.fromkeys([*fn.string_refs, *strings_by_fn.get(fn.function_id, [])]))
        matched_strings: List[str] = []
        seen_str_labels = set()
        for s_val in merged_strings:
            for pat, label, weight in _HIGH_SIGNAL_STRING_PATTERNS:
                if pat.search(s_val) and label not in seen_str_labels:
                    seen_str_labels.add(label)
                    score += weight
                    matched_strings.append(s_val[:120])
                    reasons.append(f"+{weight:.1f}: string signal ({label})")

        # Call graph & xref centrality (bounded so standard CRT helpers stay reasonable)
        fan_out = len(set(fn.called_function_ids))
        xref_score = min(4.0, fn.xref_in_count * 0.4 + fan_out * 0.5)
        if xref_score >= 1.0:
            score += xref_score
            reasons.append(
                f"+{xref_score:.1f}: call/xref connectivity (in={fn.xref_in_count}, out={fan_out})"
            )

        # Structural complexity signal (tiny thunks penalized)
        if fn.is_thunk or fn.is_external:
            score *= 0.25
            if reasons:
                reasons.append("x0.25: thunk/external stub de-prioritized for deep decompilation")
        else:
            if (fn.basic_block_count or 0) >= 8 or fn.size_bytes >= 256:
                score += 1.5
                reasons.append(
                    f"+1.5: non-trivial control flow (size={fn.size_bytes}B, blocks={fn.basic_block_count or 0})"
                )

        rounded_score = round(score, 2)
        updated_fn = fn.model_copy(
            update={
                "imported_api_calls": merged_apis[:40],
                "string_refs": merged_strings[:30],
                "rank_score": rounded_score,
                "rank_reasons": reasons[:10],
            }
        )
        scored_functions.append(updated_fn)

        if rounded_score > 0.0 and reasons and not (fn.is_thunk or fn.is_external):
            findings.append(
                FunctionAnalysisFinding(
                    function_id=updated_fn.function_id,
                    entry_address=updated_fn.entry_address,
                    name=updated_fn.name,
                    score=rounded_score,
                    reasons=updated_fn.rank_reasons,
                    imported_apis=matched_apis[:20],
                    string_signals=matched_strings[:10],
                )
            )

    # Sort descending by score, then address ascending for strict determinism
    scored_functions.sort(key=lambda item: (-item.rank_score, item.entry_address, item.function_id))
    findings.sort(key=lambda item: (-item.score, item.entry_address, item.function_id))
    return scored_functions, findings[: max(0, max_findings)]

