from typing import Dict, Any, List, Set
from app.schemas.orchestration import ActionValidationResult

ALLOWED_PROFILES: Set[str] = {
    "standard",
    "ransomware_focus",
    "infostealer_focus",
    "evasion_focus",
    "dropper_focus",
    "network_focus",
}
ALLOWED_ARTIFACTS: Set[str] = {
    "pcap",
    "screenshots",
    "memory_strings",
    "dropped_files",
    "network_traffic",
}
ALLOWED_SUBSYSTEMS: Set[str] = {
    "process",
    "file",
    "filesystem",
    "registry",
    "network",
    "memory",
}
ALLOWED_PLAN_KEYS: Set[str] = {
    "profile",
    "execution_timeout_seconds",
    "requested_artifacts",
    "telemetry_focus",
    "rationale",
    "confidence",
    "limitations",
}
ALLOWED_FOLLOW_UP_KEYS: Set[str] = {
    "needs_second_pass",
    "recommended_profile",
    "telemetry_gaps_identified",
    "prioritized_events",
    "rationale",
    "confidence",
    "stop_recommendation",
    "stop_reason",
}
MIN_TIMEOUT_SECONDS: int = 30
MAX_TIMEOUT_SECONDS: int = 300

class PolicyValidator:
    """
    Deterministic rule-based policy engine.
    Acts as the final, immutable authority over all AI-proposed actions.
    Enforces positive allowlists, bounds resource constraints, and prevents command injection.
    """

    @staticmethod
    def validate_analysis_plan(proposed_plan: Dict[str, Any]) -> ActionValidationResult:
        # 1. Positive schema key allowlist validation (rejects any host commands, shell executions, or unknown keys)
        disallowed_keys = set(proposed_plan.keys()) - ALLOWED_PLAN_KEYS
        if disallowed_keys:
            return ActionValidationResult(
                action_type="configure_analysis_plan",
                is_allowed=False,
                status="REJECTED",
                reason=f"Security Policy Violation: Unauthorized keys detected outside positive schema allowlist: {sorted(list(disallowed_keys))}",
            )

        # 2. Positive Profile Allowlist
        profile = proposed_plan.get("profile", "standard")
        if profile not in ALLOWED_PROFILES:
            return ActionValidationResult(
                action_type="configure_analysis_plan",
                is_allowed=False,
                status="REJECTED",
                reason=f"Profile '{profile}' is not in the approved sandbox profile allowlist: {sorted(list(ALLOWED_PROFILES))}",
            )

        # 3. Validate & Clamp Duration Bounds
        raw_timeout = proposed_plan.get("execution_timeout_seconds", 60)
        modified_params = {}
        modified = False

        if not isinstance(raw_timeout, int) or raw_timeout > MAX_TIMEOUT_SECONDS or raw_timeout < MIN_TIMEOUT_SECONDS:
            try:
                clamped_timeout = max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, int(raw_timeout or 60)))
            except (ValueError, TypeError):
                clamped_timeout = 60
            modified_params["execution_timeout_seconds"] = clamped_timeout
            modified = True
        else:
            clamped_timeout = raw_timeout

        # 4. Filter Requested Artifacts against Positive Allowlist
        requested_artifacts = proposed_plan.get("requested_artifacts", [])
        approved_artifacts = [a for a in requested_artifacts if a in ALLOWED_ARTIFACTS]
        if len(approved_artifacts) != len(requested_artifacts):
            modified_params["requested_artifacts"] = approved_artifacts
            modified = True

        # 5. Filter Telemetry Focus against Positive Allowlist
        telemetry_focus = proposed_plan.get("telemetry_focus", [])
        approved_subsystems = [s for s in telemetry_focus if s in ALLOWED_SUBSYSTEMS]
        if len(approved_subsystems) != len(telemetry_focus):
            modified_params["telemetry_focus"] = approved_subsystems
            modified = True

        if modified:
            return ActionValidationResult(
                action_type="configure_analysis_plan",
                is_allowed=True,
                status="MODIFIED",
                reason=f"Parameters modified to adhere to security bounds: timeout={clamped_timeout}s, artifacts={approved_artifacts}",
                modified_parameters=modified_params,
            )

        return ActionValidationResult(
            action_type="configure_analysis_plan",
            is_allowed=True,
            status="ALLOWED",
            reason="All proposed analysis plan parameters validated against security allowlist.",
            modified_parameters=None,
        )

    @staticmethod
    def validate_follow_up_action(proposed_action: Dict[str, Any]) -> ActionValidationResult:
        # Positive schema key allowlist
        disallowed_keys = set(proposed_action.keys()) - ALLOWED_FOLLOW_UP_KEYS
        if disallowed_keys:
            return ActionValidationResult(
                action_type="follow_up_recommendation",
                is_allowed=False,
                status="REJECTED",
                reason=f"Security Policy Violation: Unauthorized follow-up keys outside allowlist: {sorted(list(disallowed_keys))}",
            )

        rec_profile = proposed_action.get("recommended_profile")
        if rec_profile and rec_profile not in ALLOWED_PROFILES:
            return ActionValidationResult(
                action_type="follow_up_recommendation",
                is_allowed=False,
                status="REJECTED",
                reason=f"Recommended follow-up profile '{rec_profile}' is not approved.",
            )

        return ActionValidationResult(
            action_type="follow_up_recommendation",
            is_allowed=True,
            status="ALLOWED",
            reason="Follow-up decision is policy-compliant.",
        )

