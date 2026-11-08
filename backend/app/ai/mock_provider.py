from typing import Dict, Any, List
from app.ai.provider import LLMProvider
from app.core.security import sanitize_untrusted_input_for_ai

class MockLLMProvider(LLMProvider):
    """
    High-fidelity offline AI provider. Generates structured, deterministic,
    evidence-grounded analysis plans and summaries without external API keys.
    """

    def generate_plan(self, sample_metadata: Dict[str, Any]) -> Dict[str, Any]:
        entropy = sample_metadata.get("overall_entropy", 0.0)
        is_packed = sample_metadata.get("is_packed_heuristic", False)
        sections = sample_metadata.get("sections", [])
        imports = sample_metadata.get("imports", [])
        filename = sanitize_untrusted_input_for_ai(sample_metadata.get("file_name", "sample.exe"))

        # Inspect imported APIs
        all_funcs = []
        for imp in imports:
            all_funcs.extend([f.lower() for f in imp.get("functions", [])])

        is_ransom_suspect = (
            "wannacry" in filename.lower()
            or any("crypt" in f for f in all_funcs)
            or entropy > 7.1
        )
        is_stealer_suspect = (
            "stealer" in filename.lower()
            or "invoice" in filename.lower()
            or any("internet" in f or "http" in f for f in all_funcs)
        )

        if is_ransom_suspect:
            profile = "ransomware_focus"
            timeout = 90
            telemetry_focus = ["file", "registry", "network"]
            requested_artifacts = ["pcap", "screenshots", "dropped_files"]
            rationale = (
                f"Preflight PE triage identified high overall entropy ({entropy}) and encryption-related API imports. "
                "Recommending ransomware-focused detonation with enhanced filesystem and shadow copy telemetry."
            )
        elif is_stealer_suspect:
            profile = "infostealer_focus"
            timeout = 120
            telemetry_focus = ["process", "network", "file"]
            requested_artifacts = ["pcap", "memory_strings"]
            rationale = (
                "Observed network API imports and suspicious loader characteristics. "
                "Recommending infostealer profile to monitor browser vault reads and HTTP C2 exfiltration."
            )
        else:
            profile = "standard"
            timeout = 60
            telemetry_focus = ["process", "file", "registry", "network"]
            requested_artifacts = ["pcap", "screenshots"]
            rationale = "Standard dynamic execution profile selected for general behavioral baseline."

        return {
            "profile": profile,
            "execution_timeout_seconds": timeout,
            "requested_artifacts": requested_artifacts,
            "telemetry_focus": telemetry_focus,
            "rationale": rationale,
            "confidence": 0.88,
            "limitations": [
                "Analysis duration is bounded to mitigate denial-of-service risks.",
                "Evasion techniques targeting specific hardware dates or human interactions may remain undetected.",
            ],
        }

    def evaluate_observations(
        self,
        sample_metadata: Dict[str, Any],
        telemetry_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        proc_count = telemetry_summary.get("total_processes", 0)
        findings_count = telemetry_summary.get("findings_count", 0)
        net_events = telemetry_summary.get("network_events_count", 0)

        gaps = []
        if net_events == 0:
            gaps.append("Zero outbound network telemetry observed; possible sandbox detection or local-only payload.")
        if proc_count <= 1:
            gaps.append("No secondary child processes spawned; possible anti-analysis evasion or immediate termination.")

        needs_second_pass = len(gaps) > 0 and findings_count > 0

        return {
            "needs_second_pass": needs_second_pass,
            "recommended_profile": "evasion_focus" if needs_second_pass else None,
            "telemetry_gaps_identified": gaps,
            "prioritized_events": ["process_spawn", "file_encryption_burst", "registry_persistence"],
            "rationale": (
                "Observation evaluation indicates malicious activity was captured, but evasion defenses may have limited C2 activity."
                if needs_second_pass else
                "Sufficient dynamic telemetry collected to confirm threat profile."
            ),
            "confidence": 0.90,
            "stop_recommendation": False,
            "stop_reason": None,
        }

    def generate_executive_summary(
        self,
        sample_metadata: Dict[str, Any],
        findings_summary: Dict[str, Any],
        timeline: list
    ) -> str:
        filename = sample_metadata.get("file_name", "Target Sample")
        threat_score = findings_summary.get("score", 0)
        threat_level = findings_summary.get("level", "Clean")
        finding_titles = findings_summary.get("finding_titles", [])

        summary = (
            f"AI Forensic Assessment: Sample '{filename}' was evaluated under isolated dynamic monitoring. "
            f"The sample exhibited confirmed {threat_level.upper()} behavior with an explainable threat rating of {threat_score}/100. "
            f"Key behavioral observations include: {', '.join(finding_titles) or 'no malicious indicators'}. "
            "All findings are supported by verifiable execution events, reconstructed process ancestry, and filesystem telemetry."
        )
        return summary

