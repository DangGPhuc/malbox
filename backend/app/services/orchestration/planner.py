from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.ai.llm_client import get_llm_provider
from app.models.analysis import Analysis
from app.models.audit import OrchestrationRecord
from app.schemas.orchestration import AnalysisPlan, ActionValidationResult
from app.services.orchestration.policy import PolicyValidator

class AnalysisPlanner:
    """
    Coordinates AI preflight dynamic analysis planning with strict policy validation.
    """

    def __init__(self, db: Session):
        self.db = db
        self.llm = get_llm_provider()

    def create_and_validate_plan(self, analysis: Analysis) -> Tuple[AnalysisPlan, ActionValidationResult]:
        sample = analysis.sample
        sample_meta = sample.pe_metadata or {}
        sample_meta["file_name"] = sample.file_name
        sample_meta["file_size"] = sample.file_size

        # 1. AI proposes plan
        proposed_raw = self.llm.generate_plan(sample_meta)

        # 2. Rule-based Policy Engine validates plan
        validation = PolicyValidator.validate_analysis_plan(proposed_raw)

        # 3. Determine final executable plan
        if validation.status == "REJECTED":
            # Safe fall back
            final_plan_dict = {
                "profile": "standard",
                "execution_timeout_seconds": 60,
                "requested_artifacts": ["pcap", "screenshots"],
                "telemetry_focus": ["process", "file", "network"],
                "rationale": f"Policy rejected proposed action ({validation.reason}). Enforcing safe fallback baseline.",
                "confidence": 0.5,
                "limitations": ["Fallback policy enforced due to validation rejection."],
            }
        elif validation.status == "MODIFIED" and validation.modified_parameters:
            final_plan_dict = {**proposed_raw, **validation.modified_parameters}
        else:
            final_plan_dict = proposed_raw

        final_plan = AnalysisPlan(**final_plan_dict)

        # 4. Apply approved parameters to the analysis entity
        analysis.profile = final_plan.profile
        analysis.timeout_seconds = final_plan.execution_timeout_seconds

        # 5. Persist complete audit trail
        audit_record = OrchestrationRecord(
            analysis_id=analysis.id,
            stage="preflight_planning",
            proposed_action=proposed_raw,
            supporting_evidence={
                "overall_entropy": sample_meta.get("overall_entropy", 0.0),
                "is_packed": sample_meta.get("is_packed_heuristic", False),
                "number_of_sections": sample_meta.get("number_of_sections", 0),
            },
            validation_result=validation.status,
            validation_notes=validation.reason,
            final_action=final_plan.model_dump(),
            execution_outcome=f"Enforced profile '{final_plan.profile}' ({final_plan.execution_timeout_seconds}s)",
        )
        self.db.add(audit_record)
        self.db.commit()

        return final_plan, validation

