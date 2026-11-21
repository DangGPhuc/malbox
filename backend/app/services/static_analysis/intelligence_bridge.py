from __future__ import annotations

from typing import List, Optional, Tuple

from app.core.security import sanitize_untrusted_input_for_ai
from app.schemas.intelligence import StaticAnalysisPlaceholder
from app.schemas.static_analysis import StaticAnalysisResult


def build_static_bundle_contract(
    static_result: Optional[StaticAnalysisResult],
) -> Tuple[StaticAnalysisPlaceholder, List[str], List[str]]:
    """
    Translates an optional verified StaticAnalysisResult into the Intelligence Engine's
    versioned StaticAnalysisPlaceholder contract without inventing symbols or transmitting
    decompiled pseudocode automatically to external AI providers.

    Returns:
      - StaticAnalysisPlaceholder
      - verified static evidence IDs (only populated when verified functions exist)
      - explicit static analysis limitation messages
    """
    if static_result is None:
        return (
            StaticAnalysisPlaceholder(
                status="not_available",
                notes=(
                    "Static disassembly/decompilation (Ghidra Headless) was not executed; "
                    "no static function symbols or CFG internals are available."
                ),
            ),
            [],
            [],
        )

    status = static_result.status
    if status in ("FAILED", "TIMED_OUT", "UNAVAILABLE", "SKIPPED"):
        mapped_status = (
            "timed_out"
            if status == "TIMED_OUT"
            else "failed"
            if status == "FAILED"
            else "not_available"
        )
        err_summary = sanitize_untrusted_input_for_ai(
            "; ".join(static_result.errors or [f"Static analysis status: {status}"]),
            max_chars=300,
        )
        return (
            StaticAnalysisPlaceholder(
                status=mapped_status,
                notes=f"Ghidra headless static analysis did not complete ({status}): {err_summary}",
                analysis_id=static_result.provenance.analysis_id,
                sample_sha256=static_result.provenance.sample_sha256,
                ghidra_version=static_result.provenance.ghidra_version,
                errors=[err_summary] if err_summary else [],
            ),
            [],
            [
                f"Static analysis status is '{status}'; verified function symbols and internals are incomplete or unavailable."
            ],
        )

    if status in ("PENDING", "QUEUED", "RUNNING"):
        return (
            StaticAnalysisPlaceholder(
                status="not_available",
                notes=f"Ghidra headless static analysis is currently {status}; results are not yet finalized.",
                analysis_id=static_result.provenance.analysis_id,
                sample_sha256=static_result.provenance.sample_sha256,
            ),
            [],
            [f"Static analysis is in progress ({status}); function symbols omitted until completion."],
        )

    # Verified COMPLETED or PARTIAL Ghidra facts exist
    mapped_ok_status = "partial" if (status == "PARTIAL" or static_result.is_partial) else "available"
    safe_funcs = []
    valid_static_ids: List[str] = []

    for fn in static_result.functions[:80]:
        safe_funcs.append(
            {
                "function_id": fn.function_id,
                "entry_address": fn.entry_address,
                "name": sanitize_untrusted_input_for_ai(fn.name, max_chars=96),
                "size_bytes": fn.size_bytes,
                "basic_block_count": fn.basic_block_count,
                "is_thunk": fn.is_thunk,
                "is_external": fn.is_external,
                "is_executed": False,
                "imported_api_calls": [
                    sanitize_untrusted_input_for_ai(api, max_chars=64)
                    for api in fn.imported_api_calls[:15]
                ],
                "rank_score": fn.rank_score,
            }
        )
        valid_static_ids.append(fn.function_id)

    prog_meta = None
    if static_result.program_metadata is not None:
        pm = static_result.program_metadata
        prog_meta = {
            "executable_format": pm.executable_format,
            "architecture": pm.architecture,
            "address_size": pm.address_size,
            "total_functions_discovered": pm.total_functions_discovered,
            "total_imports": pm.total_imports,
            "total_exports": pm.total_exports,
        }

    decompiled_present = len(static_result.decompiled_functions) > 0
    limitations: List[str] = []
    if mapped_ok_status == "partial":
        limitations.append(
            "Ghidra static analysis produced PARTIAL results (truncated function caps or per-function decompiler limits reached)."
        )
    if decompiled_present:
        limitations.append(
            "Recovered pseudocode is stored locally on the backend and omitted from VerifiedEvidenceBundle to prevent automatic transmission to external AI providers."
        )

    note = (
        f"Verified Ghidra {static_result.provenance.ghidra_version or ''} static metadata "
        f"({mapped_ok_status}): {len(safe_funcs)} function(s) indexed (binary_executed=False)."
    )

    placeholder = StaticAnalysisPlaceholder(
        status=mapped_ok_status,
        tool="ghidra_headless",
        notes=note,
        analysis_id=static_result.provenance.analysis_id,
        sample_sha256=static_result.provenance.sample_sha256,
        ghidra_version=static_result.provenance.ghidra_version,
        program_metadata=prog_meta,
        functions=safe_funcs,
        ranked_function_count=len(static_result.ranked_findings),
        decompiled_count=len(static_result.decompiled_functions),
        decompiled_omitted_for_external_ai=decompiled_present,
        truncation=static_result.truncation.model_dump(mode="json"),
        errors=[sanitize_untrusted_input_for_ai(e, max_chars=200) for e in static_result.errors[:5]],
    )
    return placeholder, valid_static_ids, limitations

