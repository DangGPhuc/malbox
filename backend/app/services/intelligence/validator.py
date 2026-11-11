import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pydantic import ValidationError

from app.core.security import redact_sensitive_text
from app.schemas.intelligence import (
    AIProposedIntelligence,
    AIProviderMetadata,
    AnalyticalClaim,
    ArtifactEvidence,
    ClaimSupportCategory,
    DeterministicFindingEvidence,
    IOCInterpretation,
    IntelligenceReport,
    NormalizedEventEvidence,
    ProposedClaim,
    SampleIdentityEvidence,
    TimelineEntryEvidence,
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

_HYPOTHESIS_OVERCONFIDENT_PATTERNS = [
    re.compile(r"\b(?:confirmed\s+fact|definitively\s+proves|verified\s+observation|undoubtedly|100%\s+certain)\b", re.IGNORECASE),
]

_SPECULATIVE_FACT_TERMS = re.compile(
    r"\b(?:nation-state|apt\d+|lazarus|conti|zero-day|kernel\s+rootkit|idt\s+hooking|"
    r"probably|likely|presumably|possibly|may\s+be\s+trying)\b",
    re.IGNORECASE,
)

_RE_EXE = re.compile(r"\b[a-zA-Z0-9_.-]+\.(?:exe|dll|bat|ps1|vbs|cmd|scr|msi)\b", re.IGNORECASE)
_RE_RULE = re.compile(r"\bRULE_[A-Z0-9_]+\b")
_RE_MITRE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_URL = re.compile(r"https?://[^\s'\",;)\]]+", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]{2,}\.)+(?:com|net|org|io|onion|xyz|ru|cn|bit|info|biz|top|pw|cc|su|tk|de|uk)\b",
    re.IGNORECASE,
)
_RE_PID = re.compile(r"\bpid\s*[:=#]?\s*(\d{2,7})\b", re.IGNORECASE)
_RE_PORT = re.compile(r"\bport\s*[:=#]?\s*(\d{1,5})\b", re.IGNORECASE)
_RE_SHA256 = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)

_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "into", "were", "was",
    "have", "has", "been", "are", "only", "not", "all", "such", "under", "during",
    "scenario", "replay", "synthetic", "telemetry", "observed", "evidence",
    "bundle", "event", "record", "valid", "observation", "analysis", "system",
    "sample", "triggered", "deterministic", "rule", "critical", "high", "medium",
    "low", "activity", "behavior", "behavioral", "indicated", "metadata", "recorded",
}


class _EvidenceLookup:
    """Indexes verified bundle records so validator can verify claim semantics per cited ID."""

    def __init__(self, bundle: VerifiedEvidenceBundle) -> None:
        self.bundle = bundle
        self.events: Dict[str, NormalizedEventEvidence] = {e.event_id: e for e in bundle.events}
        self.timeline: Dict[str, TimelineEntryEvidence] = {
            t.event_id: t for t in bundle.timeline if t.event_id
        }
        self.findings: Dict[str, DeterministicFindingEvidence] = {}
        for f in bundle.findings:
            self.findings[f.finding_id] = f
            self.findings[f"finding:{f.finding_id}"] = f
            self.findings[f.rule_id] = f
            self.findings[f"rule:{f.rule_id}"] = f
        self.artifacts: Dict[str, ArtifactEvidence] = {a.evidence_id: a for a in bundle.artifacts}
        self.sample: SampleIdentityEvidence = bundle.sample_identity
        self.static_functions: Dict[str, Dict[str, Any]] = {}
        if bundle.static_analysis.status in ("available", "partial"):
            for fn in bundle.static_analysis.functions:
                if isinstance(fn, dict) and fn.get("function_id"):
                    self.static_functions[str(fn["function_id"])] = fn

    def resolve_ids(
        self, eids: List[str]
    ) -> Tuple[List[str], str, Set[str], Set[str]]:
        """
        Returns:
          - source_labels: structured provenance labels e.g. ['event:process:spawn', 'finding:RULE_...']
          - combined_text_lower: concatenated serialized text of ONLY cited records
          - categories: normalized behavioral categories covered by cited records
          - cited_types: subset of {'sample', 'artifact', 'finding', 'event'}
        """
        source_labels: List[str] = []
        blobs: List[str] = []
        categories: Set[str] = set()
        cited_types: Set[str] = set()

        for eid in eids:
            if eid == self.sample.evidence_id:
                cited_types.add("sample")
                source_labels.append("sample:identity")
                blobs.append(self.sample.model_dump_json())
                categories.add("sample_triage")
                continue

            if eid in self.artifacts:
                art = self.artifacts[eid]
                cited_types.add("artifact")
                source_labels.append(f"artifact:{art.artifact_type}")
                blobs.append(art.model_dump_json())
                categories.add("artifact")
                if art.source_event_id and art.source_event_id in self.events:
                    ev = self.events[art.source_event_id]
                    blobs.append(ev.model_dump_json())
                continue

            if eid in self.findings:
                f = self.findings[eid]
                cited_types.add("finding")
                source_labels.append(f"finding:{f.rule_id}")
                blobs.append(f.model_dump_json())
                categories.add("finding")
                if f.mitre_tactic:
                    categories.add(f.mitre_tactic.lower())
                for seid in f.supporting_event_ids:
                    if seid in self.events:
                        sev = self.events[seid]
                        blobs.append(sev.model_dump_json())
                        categories.add(sev.category)
                continue

            if eid in self.events:
                ev = self.events[eid]
                cited_types.add("event")
                source_labels.append(f"event:{ev.category}:{ev.action}")
                blobs.append(ev.model_dump_json())
                categories.add(ev.category)
                if eid in self.timeline:
                    blobs.append(self.timeline[eid].model_dump_json())
                continue

            if eid in self.timeline:
                tl = self.timeline[eid]
                cited_types.add("event")
                source_labels.append(f"timeline:{tl.category}:{tl.action}")
                blobs.append(tl.model_dump_json())
                categories.add(tl.category)
                continue

            if eid in self.static_functions:
                sfn = self.static_functions[eid]
                cited_types.add("static")
                source_labels.append(f"static:{sfn.get('name', eid)}")
                blobs.append(json.dumps(sfn))
                categories.add("static_analysis")

        return list(dict.fromkeys(source_labels)), " ".join(blobs).lower(), categories, cited_types


class EvidenceValidator:
    """
    Validates proposed AI intelligence output against strict Pydantic schemas,
    evidence-ID existence, evidence-source semantic grounding, Replay/Live provenance
    invariants, and deterministic risk-score authority.
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
            safe_err = redact_sensitive_text(parse_error, max_chars=200)
            warnings.append(f"AI output rejected ({safe_err}); applied deterministic grounded fallback.")
            fallback_applied = True
            proposed = fallback_fn(bundle)
            effective_provider_meta.fallback_used = True
            if effective_provider_meta.provider != "mock":
                effective_provider_meta.provider = "mock_fallback"
                effective_provider_meta.mode = "mock_fallback"
            effective_provider_meta.fallback_reason = safe_err
        else:
            assert parsed_obj is not None
            proposed = parsed_obj

        valid_ids: Set[str] = set(bundle.valid_evidence_ids)
        lookup = _EvidenceLookup(bundle)
        removed_invalid_ids: List[str] = []

        validated_claims: List[AnalyticalClaim] = []
        for claim in proposed.technical_claims:
            validated_claim, inv_ids, claim_warnings = self._validate_claim(
                claim=claim,
                valid_ids=valid_ids,
                lookup=lookup,
                bundle=bundle,
            )
            for eid in inv_ids:
                if eid not in removed_invalid_ids:
                    removed_invalid_ids.append(eid)
            warnings.extend(claim_warnings)
            validated_claims.append(validated_claim)

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

        if (
            self._contains_static_fabrication(exec_assess, bundle)
            or self._contains_static_fabrication(narrative, bundle)
            or self._contains_injection_artifact(exec_assess)
            or self._contains_injection_artifact(narrative)
        ):
            warnings.append(
                "Detected unverified static disassembly or injection content in narrative; replacing with grounded fallback narrative."
            )
            fallback_applied = True
            fb = fallback_fn(bundle)
            exec_assess = fb.executive_assessment
            narrative = fb.behavioral_narrative
            validated_claims = [
                self._validate_claim(c, valid_ids, lookup, bundle)[0]
                for c in fb.technical_claims
            ]
            effective_provider_meta.fallback_used = True
            if effective_provider_meta.provider != "mock":
                effective_provider_meta.provider = "mock_fallback"
                effective_provider_meta.mode = "mock_fallback"
            effective_provider_meta.fallback_reason = "Invalid narrative content replaced by fallback"

        limitations = list(proposed.limitations)
        for known_lim in bundle.known_limitations:
            if known_lim not in limitations:
                limitations.append(known_lim)

        if effective_provider_meta.fallback_used and not fallback_applied:
            fallback_applied = True
            if effective_provider_meta.fallback_reason:
                effective_provider_meta.fallback_reason = redact_sensitive_text(
                    effective_provider_meta.fallback_reason, max_chars=200
                )
                warnings.append(
                    f"Provider fallback active ({effective_provider_meta.fallback_reason})."
                )

        verified_count = sum(1 for c in validated_claims if c.validation_status == "VERIFIED")
        unverified_count = sum(1 for c in validated_claims if c.validation_status == "UNVERIFIED")
        rejected_count = sum(1 for c in validated_claims if c.validation_status == "REJECTED")
        review_required = sum(1 for c in validated_claims if c.requires_human_review)
        det_facts = sum(1 for c in validated_claims if c.support_category == "DETERMINISTIC_FACT")
        inferences = sum(1 for c in validated_claims if c.support_category == "ANALYST_INFERENCE")
        hypotheses = sum(1 for c in validated_claims if c.support_category == "UNCERTAIN_HYPOTHESIS")
        unsupported_facts = sum(
            1
            for c in validated_claims
            if c.classification == "FACT" and c.validation_status != "VERIFIED"
        )

        overall_passed = (
            not fallback_applied
            and rejected_count == 0
            and unsupported_facts == 0
            and not removed_invalid_ids
        )

        validation_summary = ValidationSummary(
            passed=overall_passed,
            total_claims=len(validated_claims),
            verified_claims=verified_count,
            unverified_claims=unverified_count,
            rejected_claims=rejected_count,
            review_required_claims=review_required,
            deterministic_facts=det_facts,
            analyst_inferences=inferences,
            uncertain_hypotheses=hypotheses,
            removed_invalid_evidence_ids=removed_invalid_ids,
            warnings=[redact_sensitive_text(w, max_chars=260) for w in warnings],
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

    def _validate_claim(
        self,
        claim: ProposedClaim,
        valid_ids: Set[str],
        lookup: _EvidenceLookup,
        bundle: VerifiedEvidenceBundle,
    ) -> Tuple[AnalyticalClaim, List[str], List[str]]:
        v_ids: List[str] = []
        inv_ids: List[str] = []
        warnings: List[str] = []

        for eid in claim.supporting_evidence_ids:
            if eid in valid_ids:
                if eid not in v_ids:
                    v_ids.append(eid)
            else:
                inv_ids.append(eid)

        source_labels, cited_blob, cited_cats, cited_types = lookup.resolve_ids(v_ids)
        caveats = list(claim.caveats)
        notes_parts: List[str] = []

        if inv_ids:
            warnings.append(
                f"Claim '{claim.claim_id}' cited nonexistent evidence ID(s): {', '.join(inv_ids)}"
            )
            notes_parts.append(f"Removed invalid evidence ID(s): {', '.join(inv_ids)}.")

        status = "UNVERIFIED"
        support_cat: ClaimSupportCategory = "CONSERVATIVE_UNVERIFIED"
        requires_review = True

        # Hard rejection checks first
        if self._contains_static_fabrication(claim.claim_text, bundle):
            status = "REJECTED"
            support_cat = "UNSUPPORTED_OR_FABRICATED"
            notes_parts.append(
                "References unverified static disassembly/function symbols while static analysis is unavailable."
            )
            warnings.append(f"Claim '{claim.claim_id}' rejected for static analysis fabrication.")
        elif self._contains_injection_artifact(claim.claim_text):
            status = "REJECTED"
            support_cat = "UNSUPPORTED_OR_FABRICATED"
            notes_parts.append("Blocked suspected prompt-injection or script artifact in claim text.")
            warnings.append(f"Claim '{claim.claim_id}' rejected for prompt-injection artifact.")
        elif inv_ids and not v_ids:
            status = "REJECTED"
            support_cat = "UNSUPPORTED_OR_FABRICATED"
            notes_parts.append("All cited supporting evidence IDs were nonexistent in the verified bundle.")
        elif bundle.provenance.is_replay and self._claims_false_live_execution(claim.claim_text):
            status = "REJECTED" if claim.classification == "FACT" else "UNVERIFIED"
            support_cat = "UNSUPPORTED_OR_FABRICATED" if claim.classification == "FACT" else "UNCERTAIN_HYPOTHESIS"
            notes_parts.append(
                "Replay Mode provenance contradiction: claimed uploaded binary executed live."
            )
            caveats.append(
                f"Replay Mode caveat: telemetry originates from synthetic scenario '{bundle.provenance.replay_scenario_id}'."
            )
            warnings.append(f"Claim '{claim.claim_id}' flagged for Replay provenance contradiction.")
        elif v_ids and (contradiction_reason := self._detect_semantic_contradiction(claim.claim_text, cited_blob, cited_cats, cited_types)):
            status = "REJECTED"
            support_cat = "UNSUPPORTED_OR_FABRICATED"
            notes_parts.append(f"Semantic contradiction against cited evidence: {contradiction_reason}")
            warnings.append(
                f"Claim '{claim.claim_id}' rejected: cites existing ID(s) but contradicts cited record ({contradiction_reason})."
            )
        elif claim.classification == "HYPOTHESIS":
            # Hypotheses MUST retain explicit uncertainty and are NEVER labeled VERIFIED confirmed observations
            status = "UNVERIFIED"
            support_cat = "UNCERTAIN_HYPOTHESIS"
            requires_review = True
            if any(pat.search(claim.claim_text) for pat in _HYPOTHESIS_OVERCONFIDENT_PATTERNS):
                caveats.append(
                    "Overconfident language neutralized: hypothesis remains an unconfirmed analytical possibility."
                )
                notes_parts.append(
                    "Hypothesis certainty wording flagged; hypotheses cannot be marked as verified observations."
                )
                warnings.append(f"Hypothesis '{claim.claim_id}' contained certainty wording.")
            if not any("hypothesis" in c.lower() or "uncertain" in c.lower() or "cannot" in c.lower() or "requires" in c.lower() for c in caveats):
                caveats.append("Hypothesis requires additional corroborating telemetry or static inspection.")
            if not notes_parts:
                notes_parts.append("Retained as unconfirmed hypothesis with explicit uncertainty caveats.")
        elif not v_ids:
            status = "UNVERIFIED"
            support_cat = "UNSUPPORTED_OR_FABRICATED"
            notes_parts.append(
                f"{claim.classification} claim lacks supporting_evidence_ids from verified bundle."
            )
            warnings.append(
                f"Claim '{claim.claim_id}' ({claim.classification}) marked UNVERIFIED due to missing evidence citations."
            )
        elif inv_ids:
            status = "UNVERIFIED"
            support_cat = (
                "ANALYST_INFERENCE" if claim.classification == "INFERENCE" else "CONSERVATIVE_UNVERIFIED"
            )
            notes_parts.append(
                "Partial invalid citation detected; remaining cited evidence IDs require human review."
            )
        elif claim.classification == "INFERENCE":
            # Inferences connect records diagnostically and always require human review rather than auto-VERIFIED
            status = "UNVERIFIED"
            support_cat = "ANALYST_INFERENCE"
            requires_review = True
            notes_parts.append(
                "Supported by cited records without contradiction; classified as analyst inference requiring human review."
            )
        else:
            # FACT with all cited IDs valid & zero contradiction: require deterministic programmatic support
            supported, support_detail = self._is_fact_programmatically_supported(
                claim_text=claim.claim_text,
                v_ids=v_ids,
                lookup=lookup,
                cited_blob=cited_blob,
            )
            if supported:
                status = "VERIFIED"
                support_cat = "DETERMINISTIC_FACT"
                requires_review = False
            else:
                status = "UNVERIFIED"
                support_cat = "CONSERVATIVE_UNVERIFIED"
                requires_review = True
                notes_parts.append(
                    f"Citation ID exists, but programmatic verification could not confirm claim semantics ({support_detail}); requires human review."
                )
                warnings.append(
                    f"Claim '{claim.claim_id}' conservatively marked UNVERIFIED ({support_detail})."
                )

        return (
            AnalyticalClaim(
                claim_id=claim.claim_id,
                classification=claim.classification,
                claim_text=self._scrub_text(claim.claim_text),
                supporting_evidence_ids=v_ids,
                confidence=claim.confidence,
                caveats=[self._scrub_text(c) for c in caveats],
                validation_status=status,
                support_category=support_cat,
                requires_human_review=requires_review,
                evidence_sources=source_labels,
                validation_notes=" ".join(notes_parts) if notes_parts else None,
            ),
            inv_ids,
            warnings,
        )

    @staticmethod
    def _detect_semantic_contradiction(
        claim_text: str,
        cited_blob_lower: str,
        cited_cats: Set[str],
        cited_types: Set[str],
    ) -> Optional[str]:
        if not cited_blob_lower:
            return None

        text_lower = claim_text.lower()

        # 1. Explicit identifier attribution checks against ONLY the cited records
        for exe in _RE_EXE.findall(claim_text):
            if exe.lower() not in cited_blob_lower:
                return f"cited records do not mention executable '{exe}'"

        for rule_id in _RE_RULE.findall(claim_text):
            if rule_id.lower() not in cited_blob_lower:
                return f"cited records do not contain rule '{rule_id}'"

        for mitre_id in _RE_MITRE.findall(claim_text):
            if mitre_id.lower() not in cited_blob_lower:
                return f"cited records do not map to MITRE '{mitre_id}'"

        for ip in _RE_IPV4.findall(claim_text):
            if ip.lower() not in cited_blob_lower:
                return f"cited records do not contain IP '{ip}'"

        for url in _RE_URL.findall(claim_text):
            if url.lower() not in cited_blob_lower:
                return f"cited records do not contain URL '{url}'"

        for dom in _RE_DOMAIN.findall(claim_text):
            if dom.lower() not in cited_blob_lower:
                return f"cited records do not reference domain '{dom}'"

        for pid in _RE_PID.findall(claim_text):
            if f'"process_id":{pid}' not in cited_blob_lower and f"pid: {pid}" not in cited_blob_lower and pid not in cited_blob_lower:
                return f"cited records do not contain PID {pid}"

        for port in _RE_PORT.findall(claim_text):
            if port not in cited_blob_lower:
                return f"cited records do not reference port {port}"

        for sha in _RE_SHA256.findall(claim_text):
            if sha.lower() not in cited_blob_lower:
                return f"cited records do not match SHA-256 '{sha[:12]}...'"

        # 2. Behavioral domain vs evidence-source type mismatch checks
        has_network_source = bool(cited_cats & {"network", "dns", "http", "finding"})
        has_file_or_proc = bool(cited_cats & {"file", "process", "finding"})
        has_reg_source = bool(cited_cats & {"registry", "persistence", "finding"})

        if any(k in text_lower for k in ("shadow copy", "vssadmin", "mass file encryption", "encrypted user file")) and not (
            has_file_or_proc and any(k in cited_blob_lower for k in ("shadow", "vssadmin", "encrypt", "ransom", "t1490", "t1486"))
        ):
            return "claims ransomware/encryption activity absent from cited record(s)"

        if any(k in text_lower for k in ("registry persistence", "run key", "hklm", "hkcu")) and not (
            has_reg_source and any(k in cited_blob_lower for k in ("registry", "run", "hklm", "hkcu", "t1547", "persistence"))
        ):
            return "claims registry persistence absent from cited record(s)"

        if any(k in text_lower for k in ("http post", "exfiltrat", "c2 server", "resolved domain")) and not has_network_source:
            return "claims network/DNS/HTTP behavior while cited records contain no network evidence"

        if "sample" in cited_types and cited_types == {"sample"}:
            if any(k in text_lower for k in ("spawned process", "contacted c2", "encrypted files", "exfiltrated")):
                return "claims dynamic execution behavior while citing only static sample metadata"

        if cited_types == {"static"}:
            if any(k in text_lower for k in ("dynamically executed", "executed at runtime", "spawned process", "contacted c2")):
                return "claims dynamic execution behavior while citing only static disassembly metadata"

        return None

    @staticmethod
    def _is_fact_programmatically_supported(
        claim_text: str,
        v_ids: List[str],
        lookup: _EvidenceLookup,
        cited_blob: str,
    ) -> Tuple[bool, str]:
        if _SPECULATIVE_FACT_TERMS.search(claim_text):
            return False, "contains speculative or attribution language unsuited for FACT"

        claim_tokens = {
            t.lower()
            for t in re.findall(r"[A-Za-z0-9_.-]{3,}", claim_text)
            if t.lower() not in _STOPWORDS
        }

        matched_records = 0
        for eid in v_ids:
            if eid == lookup.sample.evidence_id:
                s = lookup.sample
                has_id = s.sha256[:12].lower() in claim_text.lower() or s.file_name.lower() in claim_text.lower()
                has_attr = str(s.file_size) in claim_text or "pe" in claim_text.lower() or s.sha256[:16].lower() in claim_text.lower()
                if has_id and has_attr:
                    matched_records += 1
            elif eid in lookup.artifacts:
                art = lookup.artifacts[eid]
                if art.name.lower() in claim_text.lower():
                    if not art.is_synthetic or "synthetic" in claim_text.lower() or "placeholder" in claim_text.lower() or "mock" in claim_text.lower():
                        matched_records += 1
            elif eid in lookup.findings:
                f = lookup.findings[eid]
                f_words = {
                    w.lower()
                    for w in re.findall(r"[A-Za-z0-9_]{4,}", f"{f.title} {f.description}")
                    if w.lower() not in _STOPWORDS
                }
                overlap = claim_tokens & f_words
                if f.rule_id.lower() in claim_text.lower() or (f.mitre_attack_id and f.mitre_attack_id.lower() in claim_text.lower()) or len(overlap) >= 2:
                    matched_records += 1
            elif eid in lookup.events:
                ev = lookup.events[eid]
                entity_candidates = [
                    ev.process_name or "",
                    ev.target_path or "",
                    Path(ev.target_path).name if ev.target_path else "",
                    str(ev.process_id) if ev.process_id is not None else "",
                ]
                for key in ("dest_ip", "destination_ip", "domain", "host", "url"):
                    val = (ev.attributes or {}).get(key)
                    if val:
                        entity_candidates.append(str(val))
                has_entity = any(
                    cand and len(cand) >= 2 and cand.lower() in claim_text.lower()
                    for cand in entity_candidates
                )
                attr_words = {
                    w.lower()
                    for w in re.findall(r"[A-Za-z0-9_.-]{3,}", json.dumps(ev.attributes or {}))
                    if w.lower() not in _STOPWORDS
                }
                attr_words.add(ev.action.lower())
                attr_words.add(ev.category.lower())
                action_overlap = claim_tokens & attr_words
                if has_entity and len(action_overlap) >= 1:
                    matched_records += 1
            elif eid in lookup.static_functions:
                sfn = lookup.static_functions[eid]
                fn_name = str(sfn.get("name") or "")
                fn_addr = str(sfn.get("entry_address") or "")
                has_fn = (fn_name and fn_name.lower() in claim_text.lower()) or (
                    fn_addr and fn_addr.lower() in claim_text.lower()
                )
                apis = [str(a).lower() for a in (sfn.get("imported_api_calls") or [])]
                has_attr = (
                    any(a in claim_text.lower() for a in apis)
                    or str(sfn.get("size_bytes", "")) in claim_text
                    or "static" in claim_text.lower()
                )
                if has_fn and has_attr:
                    matched_records += 1

        if matched_records >= 1:
            return True, "programmatically grounded"
        return False, "insufficient deterministic field match in cited record(s)"

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
        if bundle.static_analysis.status not in ("available", "partial") or not bundle.static_analysis.functions:
            return any(pat.search(text) for pat in _STATIC_FABRICATION_PATTERNS)

        known_names = {
            str(fn.get("name", "")).lower()
            for fn in bundle.static_analysis.functions
            if isinstance(fn, dict) and fn.get("name")
        }
        for sym_match in re.finditer(r"\b(?:FUN|LAB|DAT)_[0-9a-fA-F]{4,}\b|\bsub_[0-9a-fA-F]{4,}\b", text):
            if sym_match.group(0).lower() not in known_names:
                return True
        return False

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
