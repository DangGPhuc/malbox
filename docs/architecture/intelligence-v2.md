# MALBOX-AI v0.2 — Evidence-Grounded AI Intelligence Architecture (`intelligence-v2`)

## 1. Design Principles

Phase 2A and Phase 2B.1 replace ungrounded reporting with a deterministic, access-controlled, auditable malware intelligence pipeline:

1. **Deterministic Detection Authority**: `DetectionEngine` remains the exclusive authority for `risk_score` (`0-100`), `risk_level`, `BehavioralFinding` matches, and MITRE ATT&CK technique mappings. AI layers cannot modify deterministic scores or fabricate findings.
2. **Database-Bounded & Hard-Capped Evidence Bundles**: `EvidenceBundleBuilder` uses SQL-level bounded retrieval (`COUNT`, batched primary-key `IN` queries, tier `LIMIT`, capped `yield_per`) rather than unbounded `.all()` scans, prioritizes finding-linked events, sanitizes untrusted strings, and strictly enforces `max_bundle_bytes` (raising `BundleSizeLimitError` if required metadata cannot fit).
3. **Provenance Integrity (Replay vs. Live)**: Replay Mode runs explicitly distinguish static triage of the uploaded sample from synthetic telemetry derived from a registered replay fixture (`is_replay=True`, `replay_scenario_id`). Mock placeholder artifacts (stub `.pcap`, 1x1 `.png`, mock text files) are labeled `is_synthetic=True`.
4. **Offline-First & Hardened Opt-In External Providers**:
   - `AI_REPORTING_MODE` defaults to `"opt_in"`, keeping uploads, Replay Mode, and `GET` report endpoints strictly offline using deterministic `MockLLMProvider` intelligence.
   - External enrichment (`"llm"` direct `/chat/completions` or `"opencode"` isolated CLI adapter) requires BOTH dedicated reporting authorization (`X-Reporting-Token` matching `MALBOX_REPORTING_AUTH_TOKEN`, never reusing CAPE `OPERATOR_TOKEN`) AND explicit server/request operator consent (`MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true` + `external_transmission_consent=true`).
5. **Conservative Semantic Validation**: `EvidenceValidator` verifies citation existence, cited source type, entity/category consistency against cited records, programmatic `FACT` grounding, human-review flags on `INFERENCE` claims, mandatory uncertainty on `HYPOTHESIS` claims, and static disassembly guardrails (`StaticAnalysisPlaceholder`, `status="not_available"`).

---

## 2. Architecture & Data Flow

```text
Normalized DB Telemetry (Sample, Analysis, AnalysisEvent, BehavioralFinding)
   │
   ▼
EvidenceBundleBuilder (backend/app/services/intelligence/bundle_builder.py)
   ├─ Bounded SQL retrieval (count, batched finding IDs, tier LIMIT, capped yield_per)
   ├─ Multi-stage size budget enforcement + hard BundleSizeLimitError guard
   ├─ Sanitizes untrusted telemetry strings via sanitize_untrusted_input_for_ai()
   ├─ Builds valid_evidence_ids allowlist + TruncationMetadata + StaticAnalysisPlaceholder
   ▼
VerifiedEvidenceBundle (backend/app/schemas/intelligence.py)
   │
   ├─── opt_in / deterministic ──────▶ MockLLMProvider.generate_intelligence_report()
   ├─── mode="llm" (consented) ──────▶ RealLLMProvider.generate_intelligence_report() (single bounded HTTP POST)
   └─── mode="opencode" (consented) ─▶ OpenCodeReportProvider.generate_intelligence_report() (isolated temp dir)
                                          │
                                          ▼
                               EvidenceValidator.validate_and_finalize()
                                  ├─ Strict schema (extra="forbid") + score/provenance/provider conflict guard
                                  ├─ Citation existence & semantic entity/category consistency per cited record
                                  ├─ FACT -> VERIFIED (deterministic match) / UNVERIFIED / REJECTED
                                  ├─ INFERENCE -> UNVERIFIED (ANALYST_INFERENCE, requires_human_review=True) or REJECTED
                                  ├─ HYPOTHESIS -> UNVERIFIED (UNCERTAIN_HYPOTHESIS + caveats, never VERIFIED) or REJECTED
                                  └─ Rejects static disassembly fabrication & prompt-injection artifacts
   ▼
IntelligenceReport (schema_version="2.0") ──▶ FullReportSchema.intelligence_report & HTML Export
```

---

## 3. Hardened Enrichment Endpoint (`POST /api/v1/analyses/{analysis_id}/report/intelligence`)

- **Authorization**: Dedicated header `X-Reporting-Token` checked via constant-time `hmac.compare_digest` against `MALBOX_REPORTING_AUTH_TOKEN`. Fails closed (`403`) if unconfigured and `401` if invalid/missing or if `X-Operator-Token` is substituted.
- **Consent Gate**: External providers (`llm`, `opencode`) fail closed (`403`) unless both `MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true` and `external_transmission_consent=true`.
- **Resource & Concurrency Protection** ([`enrichment_guard.py`](file:///home/kali/Documents/malbox/backend/app/services/intelligence/enrichment_guard.py)):
  - Sliding-window rate limit (`REPORTING_RATE_LIMIT_REQUESTS` / `REPORTING_RATE_LIMIT_WINDOW_SECONDS` -> `429` with `Retry-After`).
  - Global concurrent cap (`REPORTING_MAX_CONCURRENT_JOBS` -> `429`).
  - Per-analysis mutual exclusion (`409`) and optimistic digest stale-write check before commit (`409`).
- **Preservation on Failure & Redaction**: Wall-clock timeout (`REPORTING_ENRICHMENT_TIMEOUT_SECONDS`), external fallback failures, or provider exceptions roll back cleanly without overwriting the last known-good persisted `AnalysisReport`, and `redact_sensitive_text()` strips tokens, auth headers, keys, and local paths before returning errors.
