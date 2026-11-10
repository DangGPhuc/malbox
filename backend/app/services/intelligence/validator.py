import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pydantic import ValidationError

from app.schemas.intelligence import (
    AIProposedIntelligence,
    AIProviderMetadata,
    AnalyticalClaim,
    IOCInterpretation,
    IntelligenceReport,
    TimelineInterpretation,
    ValidationSummary,
    VerifiedEvidenceBundle,
)


_STATIC_FABRICATION_PATTERNS = [
    re.compile(r"\b(?:FUN|LAB|DAT)_[0-9a-fA-F]{4,}\b"),
    re.compile(r"\bsub_[0-9a-fA-F]{4,}\b"),
    re.compile(
        r"\b(?:ghidra|ida\s*pro|radare2)\s+(?:decompilation|disassembly|reveals|shows|confirmed)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bdecompiled\s+function\b", re.IGNORECASE),
    re.compile(r"\bdisassembly\s+at\s+0x[0-9a-fA-F]{4,}\b", re.IGNORECASE),
]

_REPLAY_FALSE_EXECUTION_PATTERNS = [
    re.compile(r"\buploaded\s+(?:sample|binary|file|executable)\s+(?:actually\s+)?executed\b", re.IGNORECASE),
    re.compile(r"\buploaded\s+(?:sample|binary|file)\s+spawned\b", re.IGNORECASE),
    re.compile(r"\blive\s+detonation\s+of\s+the\s+uploaded\b", re.IGNORECASE),
    re.compile(r"\bno\s+replay\s+fixture\b", re.IGNORECASE),
]

_INJECTION_ARTIFACT_PATTERNS = [
    re.compile(r"<\|[^|>]+?\|>"),
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"<\s*script\b", re.IGNORECASE),
]


class EvidenceValidator:
    """
    Validates proposed AI intelligence output against strict Pydantic schemas,
    evidence-ID grounding, Replay/Live provenance invariants, and deterministic authority.
    """

    def validate_and_finalize(
        self,
        raw_output: Any,
        bundle: VerifiedEvidenceBundle,
        provider_meta: AIProviderMetadata,
        fallback_fn: Callable[[VerifiedEvidenceBundle], AIProposedIntelligence],
    ) -> IntelligenceReport:
        warnings: List[str] = []
        fallback_applied = False
        effective_provider_meta = provider_meta.model_copy()

        parsed_obj, parse_error = self._parse_and_check_authority(
            raw_output=raw_output,
            bundle=bundle,
            provider_meta=effective_provider_meta,
        )

        if parse_error is not None:
            warnings.append(f"AI output rejected ({parse_error}); applied deterministic grounded fallback.")
            fallback_applied = True
            proposed = fallback_fn(bundle)
            effective_provider_meta.fallback_used = True
            if effective_provider_meta.provider != "mock":
                effective_provider_meta.provider = "mock_fallback"
                effective_provider_meta.mode = "mock_fallback"
            effective_provider_meta.fallback_reason = parse_error[:200]
        else:
            assert parsed_obj is not None
            proposed = parsed_obj

        valid_ids: Set[str] = set(bundle.valid_evidence_ids)
        removed_invalid_ids: List[str] = []

        # Validate & filter technical claims
        validated_claims: List[AnalyticalClaim] = []
        verified_count = 0
        unverified_count = 0
        rejected_count = 0

        for claim in proposed.technical_claims:
            v_ids: List[str] = []
            inv_ids: List[str] = []
            for eid in claim.supporting_evidence_ids:
                if eid in valid_ids:
                    if eid not in v_ids:
                        v_ids.append(eid)
                else:
                    inv_ids.append(eid)
                    if eid not in removed_invalid_ids:
                        removed_invalid_ids.append(eid)

            status = "VERIFIED"
            notes_parts: List[str] = []
            caveats = list(claim.caveats)

            if inv_ids:
                warnings.append(
                    f"Claim '{claim.claim_id}' cited nonexistent evidence ID(s): {', '.join(inv_ids)}"
                )
                notes_parts.append(f"Removed invalid evidence ID(s): {', '.join(inv_ids)}.")

            if self._contains_static_fabrication(claim.claim_text, bundle):
                status = "REJECTED"
                notes_parts.append(
                    "References unverified static disassembly/function symbols while static analysis is unavailable."
                )
                warnings.append(
                    f"Claim '{claim.claim_id}' rejected for static analysis fabrication."
                )
            elif self._contains_injection_artifact(claim.claim_text):
                status = "REJECTED"
                notes_parts.append("Blocked suspected prompt-injection or script artifact in claim text.")
                warnings.append(f"Claim '{claim.claim_id}' rejected for prompt-injection artifact.")
            elif bundle.provenance.is_replay and self._claims_false_live_execution(claim.claim_text):
                status = "UNVERIFIED"
                notes_parts.append(
                    "Replay Mode provenance mismatch: phrasing suggested uploaded binary executed live."
                )
                caveats.append(
                    f"Replay Mode caveat: telemetry originates from synthetic scenario '{bundle.provenance.replay_scenario_id}'."
                )
                warnings.append(f"Claim '{claim.claim_id}' downgraded due to Replay provenance wording.")
            elif inv_ids and not v_ids:
                status = "REJECTED"
                notes_parts.append("All cited supporting evidence IDs were nonexistent in the verified bundle.")
            elif claim.classification in ("FACT", "INFERENCE") and not v_ids:
                status = "UNVERIFIED"
                notes_parts.append(
                    f"{claim.classification} claim lacks supporting_evidence_ids from verified bundle."
                )
                warnings.append(
                    f"Claim '{claim.claim_id}' ({claim.classification}) marked UNVERIFIED due to missing evidence citations."
                )
            elif inv_ids and claim.classification in ("FACT", "INFERENCE"):
                status = "UNVERIFIED"
                notes_parts.append(
                    "Partial invalid citation detected; remaining cited evidence IDs require review."
                )

            if claim.classification == "HYPOTHESIS" and not caveats:
                caveats.append("Hypothesis requires additional corroborating telemetry or static inspection.")

            if status == "VERIFIED":
                verified_count += 1
            elif status == "UNVERIFIED":
                unverified_count += 1
            else:
                rejected_count += 1

            validated_claims.append(
                AnalyticalClaim(
                    claim_id=claim.claim_id,
                    classification=claim.classification,
                    claim_text=self._scrub_text(claim.claim_text),
                    supporting_evidence_ids=v_ids,
                    confidence=claim.confidence,
                    caveats=[self._scrub_text(c) for c in caveats],
                    validation_status=status,
                    validation_notes=" ".join(notes_parts) if notes_parts else None,
                )
            )

        # Validate timeline interpretations
        validated_timeline: List[TimelineInterpretation] = []
        for entry in proposed.timeline_interpretations:
            t_valid = [eid for eid in entry.supporting_evidence_ids if eid in valid_ids]
            t_invalid = [eid for eid in entry.supporting_evidence_ids if eid not in valid_ids]
            for eid in t_invalid:
                if eid not in removed_invalid_ids:
                    removed_invalid_ids.append(eid)
            if t_invalid:
                warnings.append(
                    f"Timeline phase '{entry.phase}' removed invalid evidence ID(s): {', '.join(t_invalid)}"
                )
            validated_timeline.append(
                TimelineInterpretation(
                    phase=self._scrub_text(entry.phase),
                    summary=self._scrub_text(entry.summary),
                    supporting_evidence_ids=t_valid,
                )
            )

        # Validate IOC interpretations against actual bundle IOCs/telemetry
        known_ioc_tokens = self._collect_known_ioc_tokens(bundle)
        validated_iocs: List[IOCInterpretation] = []
        for item in proposed.ioc_interpretations:
            norm_val = item.ioc_value.strip()
            if norm_val.lower() not in known_ioc_tokens:
                warnings.append(
                    f"Dropped ungrounded IOC interpretation '{norm_val}' not present in verified bundle."
                )
                continue
            i_valid = [eid for eid in item.supporting_evidence_ids if eid in valid_ids]
            i_invalid = [eid for eid in item.supporting_evidence_ids if eid not in valid_ids]
            for eid in i_invalid:
                if eid not in removed_invalid_ids:
                    removed_invalid_ids.append(eid)
            validated_iocs.append(
                IOCInterpretation(
                    ioc_value=self._scrub_text(norm_val),
                    ioc_type=self._scrub_text(item.ioc_type),
                    role_or_context=self._scrub_text(item.role_or_context),
                    confidence=item.confidence,
                    supporting_evidence_ids=i_valid,
                )
            )

        # Enforce Replay provenance & clean text in narratives
        exec_assess = self._scrub_text(proposed.executive_assessment)
        narrative = self._scrub_text(proposed.behavioral_narrative)
        if bundle.provenance.is_replay:
            if self._claims_false_live_execution(exec_assess) or "replay" not in exec_assess.lower():
                warnings.append(
                    "Adjusted executive_assessment to preserve Replay synthetic provenance."
                )
                exec_assess = (
                    f"[Synthetic Replay Scenario '{bundle.provenance.replay_scenario_id or 'default'}' — "
                    "uploaded binary was not executed] "
                    + exec_assess
                )
            if self._claims_false_live_execution(narrative):
                warnings.append(
                    "Prepended Replay provenance disclaimer to behavioral_narrative."
                )
                narrative = (
                    f"[Replay Provenance Note: telemetry reflects synthetic scenario "
                    f"'{bundle.provenance.replay_scenario_id or 'default'}'] "
                    + narrative
                )

        if self._contains_static_fabrication(exec_assess, bundle) or self._contains_static_fabrication(narrative, bundle):
            warnings.append(
                "Detected unverified static disassembly references in narrative while static analysis is unavailable; replacing with grounded fallback narrative."
            )
            fallback_applied = True
            fb = fallback_fn(bundle)
            exec_assess = fb.executive_assessment
            narrative = fb.behavioral_narrative
            validated_claims = [
                AnalyticalClaim(
                    claim_id=c.claim_id,
                    classification=c.classification,
                    claim_text=c.claim_text,
                    supporting_evidence_ids=[eid for eid in c.supporting_evidence_ids if eid in valid_ids],
                    confidence=c.confidence,
                    caveats=list(c.caveats),
                    validation_status="VERIFIED",
                    validation_notes="Replaced by grounded fallback after narrative static-fabrication rejection.",
                )
                for c in fb.technical_claims
            ]
            verified_count = len(validated_claims)
            unverified_count = 0
            rejected_count = 0
            effective_provider_meta.fallback_used = True
            if effective_provider_meta.provider != "mock":
                effective_provider_meta.provider = "mock_fallback"
                effective_provider_meta.mode = "mock_fallback"
            effective_provider_meta.fallback_reason = "Static fabrication in AI narrative"

        limitations = list(proposed.limitations)
        for known_lim in bundle.known_limitations:
            if known_lim not in limitations:
                limitations.append(known_lim)

        if effective_provider_meta.fallback_used and not fallback_applied:
            fallback_applied = True
            if effective_provider_meta.fallback_reason:
                warnings.append(
                    f"Provider fallback active ({effective_provider_meta.fallback_reason})."
                )

        overall_passed = (
            not fallback_applied
            and rejected_count == 0
            and unverified_count == 0
            and not removed_invalid_ids
        )

        validation_summary = ValidationSummary(
            passed=overall_passed,
            total_claims=len(validated_claims),
            verified_claims=verified_count,
            unverified_claims=unverified_count,
            rejected_claims=rejected_count,
            removed_invalid_evidence_ids=removed_invalid_ids,
            warnings=warnings,
            fallback_applied=fallback_applied,
        )

        return IntelligenceReport(
            schema_version="2.0",
            analysis_id=bundle.analysis_id,
            is_replay=bundle.provenance.is_replay,
            replay_scenario_id=bundle.provenance.replay_scenario_id,
            provenance_summary=bundle.provenance.provenance_statement,
            deterministic_risk_score=bundle.deterministic_risk_score,
            deterministic_risk_level=bundle.deterministic_risk_level,
            executive_assessment=exec_assess,
            behavioral_narrative=narrative,
            timeline_interpretations=validated_timeline,
            technical_claims=validated_claims,
            ioc_interpretations=validated_iocs,
            confidence_assessment=proposed.confidence_assessment,
            contradictions_or_gaps=proposed.contradictions_or_gaps,
            limitations=[self._scrub_text(l) for l in limitations],
            recommended_follow_up_actions=proposed.recommended_follow_up_actions,
            evidence_truncation=bundle.truncation,
            provider_metadata=effective_provider_meta,
            validation_summary=validation_summary,
        )

    def _parse_and_check_authority(
        self,
        raw_output: Any,
        bundle: VerifiedEvidenceBundle,
        provider_meta: AIProviderMetadata,
    ) -> Tuple[Optional[AIProposedIntelligence], Optional[str]]:
        if isinstance(raw_output, AIProposedIntelligence):
            return raw_output, None

        data: Any = raw_output
        if isinstance(raw_output, str):
            text = raw_output.strip()
            if text.startswith("```"):
                text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
                text = re.sub(r"\s*```$", "", text)
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                return None, f"Invalid JSON output: {exc}"

        if not isinstance(data, dict):
            return None, f"Expected JSON object for AI intelligence, got {type(data).__name__}"

        working = dict(data)

        # Reject conflicting authoritative scores, provenance, or source metadata
        score_candidates = [
            working.pop("deterministic_risk_score", None),
            working.pop("risk_score", None),
        ]
        for candidate in score_candidates:
            if candidate is not None and candidate != bundle.deterministic_risk_score:
                return (
                    None,
                    f"Authority conflict: proposed risk_score={candidate} differs from deterministic_risk_score={bundle.deterministic_risk_score}",
                )

        level_candidates = [
            working.pop("deterministic_risk_level", None),
            working.pop("risk_level", None),
        ]
        for level_cand in level_candidates:
            if level_cand is not None and str(level_cand).lower() != bundle.deterministic_risk_level.lower():
                return (
                    None,
                    f"Authority conflict: proposed risk_level='{level_cand}' differs from deterministic_risk_level='{bundle.deterministic_risk_level}'",
                )

        if "is_replay" in working:
            proposed_replay = working.pop("is_replay")
            if bool(proposed_replay) != bundle.provenance.is_replay:
                return (
                    None,
                    f"Provenance conflict: proposed is_replay={proposed_replay} differs from verified is_replay={bundle.provenance.is_replay}",
                )

        if "backend_type" in working:
            proposed_backend = working.pop("backend_type")
            if proposed_backend is not None and str(proposed_backend) != bundle.provenance.backend_type:
                return (
                    None,
                    f"Provenance conflict: proposed backend_type='{proposed_backend}' differs from verified '{bundle.provenance.backend_type}'",
                )

        if "replay_scenario_id" in working:
            proposed_scn = working.pop("replay_scenario_id")
            if proposed_scn is not None and proposed_scn != bundle.provenance.replay_scenario_id:
                return (
                    None,
                    f"Provenance conflict: proposed replay_scenario_id='{proposed_scn}' differs from verified '{bundle.provenance.replay_scenario_id}'",
                )

        if "provider_metadata" in working:
            pm = working.pop("provider_metadata")
            if isinstance(pm, dict) and pm.get("provider") not in (None, provider_meta.provider):
                return (
                    None,
                    f"Metadata conflict: proposed provider='{pm.get('provider')}' differs from verified '{provider_meta.provider}'",
                )

        # Strip benign matching envelope metadata if caller echoed them cleanly
        for benign_key in ("schema_version", "analysis_id", "provenance_summary"):
            if benign_key in working:
                if benign_key == "analysis_id" and working[benign_key] != bundle.analysis_id:
                    return None, f"Analysis ID mismatch: '{working[benign_key]}' != '{bundle.analysis_id}'"
                working.pop(benign_key, None)

        try:
            validated = AIProposedIntelligence.model_validate(working)
            return validated, None
        except ValidationError as exc:
            return None, f"Schema validation error: {exc.errors()[0].get('msg', str(exc)) if exc.errors() else str(exc)}"

    @staticmethod
    def _contains_static_fabrication(text: str, bundle: VerifiedEvidenceBundle) -> bool:
        if bundle.static_analysis.status == "available":
            return False
        return any(pat.search(text) for pat in _STATIC_FABRICATION_PATTERNS)

    @staticmethod
    def _claims_false_live_execution(text: str) -> bool:
        return any(pat.search(text) for pat in _REPLAY_FALSE_EXECUTION_PATTERNS)

    @staticmethod
    def _contains_injection_artifact(text: str) -> bool:
        return any(pat.search(text) for pat in _INJECTION_ARTIFACT_PATTERNS)

    @staticmethod
    def _scrub_text(text: str) -> str:
        cleaned = re.sub(r"<\|[^|>]+?\|>", "[filtered]", text)
        return cleaned.strip()

    @staticmethod
    def _collect_known_ioc_tokens(bundle: VerifiedEvidenceBundle) -> Set[str]:
        tokens: Set[str] = set()
        for d in bundle.iocs.domains:
            tokens.add(d.strip().lower())
        for ip in bundle.iocs.ips:
            tokens.add(ip.strip().lower())
        for url in bundle.iocs.urls:
            tokens.add(url.strip().lower())
        for rk in bundle.iocs.registry_keys:
            tokens.add(rk.strip().lower())
        for df in bundle.iocs.dropped_files:
            if isinstance(df, dict):
                for key in ("path", "name", "sha256"):
                    if df.get(key):
                        tokens.add(str(df[key]).strip().lower())
            elif isinstance(df, str):
                tokens.add(df.strip().lower())
        tokens.add(bundle.sample_identity.sha256.lower())
        tokens.add(bundle.sample_identity.file_name.lower())
        for rel in bundle.network_relationships:
            if rel.destination:
                tokens.add(rel.destination.strip().lower())
        return tokens
