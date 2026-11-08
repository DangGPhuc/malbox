from typing import Dict, Any, List
from app.schemas.orchestration import ActionValidationResult

ALLOWED_PROFILES = {"standard", "ransomware_focus", "infostealer_focus", "evasion_focus"}
ALLOWED_ARTIFACTS = {"pcap", "screenshots", "memory_strings", "dropped_files", "network_traffic"}
ALLOWED_SUBSYSTEMS = {"process", "file", "registry", "network"}
MIN_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 300

class PolicyValidator:
    """
    Deterministic rule-based policy engine.
    Acts as the final, immutable authority over all AI-proposed actions.
    Enforces allowlists, bounds resource constraints, and prevents command injection.
    """

    @staticmethod
    def validate_analysis_plan(proposed_plan: Dict[str, Any]) -> ActionValidationResult:
        # 1. Check for unauthorized privileged parameters (host commands, shell access)
        forbidden_keys = {"host_command", "shell_exec", "run_command", "powershell_raw", "sudo"}
        found_forbidden = forbidden_keys.intersection(proposed_plan.keys())
        if found_forbidden:
            return ActionValidationResult(
                action_type="configure_analysis_plan",
                is_allowed=False,
                status="REJECTED",
                reason=f"Security Policy Violation: Unauthorized privileged keys detected: {list(found_forbidden)}",
            )

        # 2. Validate Profile
        profile = proposed_plan.get("profile", "standard")
        if profile not in ALLOWED_PROFILES:
            return ActionValidationResult(
                action_type="configure_analysis_plan",
                is_allowed=False,
                status="REJECTED",
                reason=f"Profile '{profile}' is not in the approved sandbox profile allowlist: {list(ALLOWED_PROFILES)}",
            )

        # 3. Validate & Clamp Duration Bounds
        raw_timeout = proposed_plan.get("execution_timeout_seconds", 60)
        modified_params = {}
        modified = False

        if not isinstance(raw_timeout, int) or raw_timeout > MAX_TIMEOUT_SECONDS or raw_timeout < MIN_TIMEOUT_SECONDS:
            clamped_timeout = max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, int(raw_timeout or 60)))
            modified_params["execution_timeout_seconds"] = clamped_timeout
            modified = True
        else:
            clamped_timeout = raw_timeout

        # 4. Filter Requested Artifacts against Allowlist
        requested_artifacts = proposed_plan.get("requested_artifacts", [])
        approved_artifacts = [a for a in requested_artifacts if a in ALLOWED_ARTIFACTS]
        if len(approved_artifacts) != len(requested_artifacts):
            modified_params["requested_artifacts"] = approved_artifacts
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
