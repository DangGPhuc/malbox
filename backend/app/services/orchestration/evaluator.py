from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.ai.llm_client import get_llm_provider
from app.models.analysis import Analysis
from app.models.audit import OrchestrationRecord
from app.schemas.orchestration import FollowUpRecommendation, ActionValidationResult
from app.services.orchestration.policy import PolicyValidator

class ObservationEvaluator:
    """
    Evaluates observed runtime telemetry for execution gaps, evasion detection,
    and follow-up dynamic analysis pass recommendations.
    """

    def __init__(self, db: Session):
        self.db = db
        self.llm = get_llm_provider()

    def evaluate_observations(
        self,
        analysis: Analysis,
        telemetry_summary: Dict[str, Any]
    ) -> Tuple[FollowUpRecommendation, ActionValidationResult]:
        sample_meta = analysis.sample.pe_metadata or {}

        # 1. AI evaluates telemetry
        proposed_raw = self.llm.evaluate_observations(sample_meta, telemetry_summary)

        # 2. Rule-based Policy Engine validates follow-up
        validation = PolicyValidator.validate_follow_up_action(proposed_raw)

        if validation.status == "REJECTED":
            final_rec_dict = {
                "needs_second_pass": False,
                "recommended_profile": None,
                "telemetry_gaps_identified": ["Policy rejected AI follow-up recommendation."],
                "prioritized_events": [],
                "rationale": f"Policy rejection: {validation.reason}",
                "confidence": 0.5,
                "stop_recommendation": True,
                "stop_reason": validation.reason,
            }
        else:
            final_rec_dict = proposed_raw

        recommendation = FollowUpRecommendation(**final_rec_dict)

        # 3. Log to audit trail
        audit_record = OrchestrationRecord(
            analysis_id=analysis.id,
            stage="observation_evaluation",
            proposed_action=proposed_raw,
            supporting_evidence=telemetry_summary,
            validation_result=validation.status,
            validation_notes=validation.reason,
            final_action=recommendation.model_dump(),
            execution_outcome=(
                f"Second pass recommended ({recommendation.recommended_profile})"
                if recommendation.needs_second_pass else "Telemetry deemed sufficient"
            ),
        )
        self.db.add(audit_record)
        self.db.commit()

        return recommendation, validation

