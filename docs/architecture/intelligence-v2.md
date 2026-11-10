# MALBOX-AI v0.2 — Evidence-Grounded AI Intelligence Architecture (`intelligence-v2`)

## 1. Design Principles

Phase 2A and Phase 2B.1 replace ungrounded reporting with a deterministic, access-controlled, auditable malware intelligence pipeline:

1. **Deterministic Detection Authority**: `DetectionEngine` remains the exclusive authority for `risk_score` (`0-100`), `risk_level`, `BehavioralFinding` matches, and MITRE ATT&CK technique mappings. AI layers cannot modify deterministic scores or fabricate findings.
2. **Database-Bounded & Hard-Capped Evidence Bundles**: `EvidenceBundleBuilder` uses SQL-level bounded retrieval (`COUNT`, batched primary-key `IN` queries, tier `LIMIT`, capped `yield_per`) rather than unbounded `.all()` scans, prioritizes finding-linked events, sanitizes untrusted strings, and strictly enforces `max_bundle_bytes` (raising `BundleSizeLimitError` if required metadata cannot fit).
3. **Provenance Integrity (Replay vs. Live)**: Replay Mode runs explicitly distinguish static triage of the uploaded sample from synthetic telemetry derived from a registered replay fixture (`is_replay=True`, `replay_scenario_id`). Mock placeholder artifacts (stub `.pcap`, 1x1 `.png`, mock text files) are labeled `is_synthetic=True`.
4. **Offline-First & Hardened Opt-In External Providers**:
   - `AI_REPORTING_MODE` defaults to `"opt_in"`, keeping uploads, Replay Mode, and `GET` report endpoints strictly offline using deterministic `MockLLMProvider` intelligence.
   - External enrichment (`"llm"` direct `/chat/completions` or `"opencode"` Bubblewrap-isolated CLI adapter) requires BOTH dedicated reporting authorization (`X-Reporting-Token` matching `MALBOX_REPORTING_AUTH_TOKEN`, never reusing CAPE `OPERATOR_TOKEN`) AND explicit server/request operator consent (`MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true` + `external_transmission_consent=true`).
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
   ├─── mode="llm" (consented) ──────▶ RealLLMProvider.generate_intelligence_report() (cancellable httpx timeout)
   └─── mode="opencode" (consented) ─▶ OpenCodeReportProvider.generate_intelligence_report() (bwrap + cancel_event)
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
- **Consent & Sandbox Preflight**:
  - External providers (`llm`, `opencode`) fail closed (`403`) unless both `MALBOX_REPORTING_EXTERNAL_AI_CONSENT=true` and `external_transmission_consent=true`.
  - When `provider_mode="opencode"` is requested, the endpoint validates `OPENCODE_ENABLED`, `check_os_sandbox_support()`, and (when network egress is requested) `parse_approved_provider_target()` before dispatching work.
- **Shared Bounded Executor, True Concurrency Accounting & Cancellation** ([`enrichment_guard.py`](../../backend/app/services/intelligence/enrichment_guard.py)):
  - Reuses a single shared bounded `ThreadPoolExecutor` (`max_workers=REPORTING_MAX_CONCURRENT_JOBS`) rather than spawning an executor per request.
  - Sliding-window rate limit (`REPORTING_RATE_LIMIT_REQUESTS` / `REPORTING_RATE_LIMIT_WINDOW_SECONDS` -> `429` with `Retry-After`).
  - Concurrency slots (`_active_count`) and per-analysis locks (`_active_analyses`) are held until the worker callable actually exits its `finally` block — **never** released early on HTTP timeout, preventing parallel bypasses during wind-down.
  - On `REPORTING_ENRICHMENT_TIMEOUT_SECONDS`, `cancel_event.set()` propagates into `OpenCodeReportProvider` (immediate `os.killpg`) and `RealLLMProvider` (clamped `httpx.Timeout` + pre/post response cancel fence), blocking any stale post-timeout database writes (`cancel_event.is_set()` check + optimistic report digest verification -> `409`).
  - **Worker Process Scope**: Limits, locks, and the coordinator's thread pool operate in-process; under single-worker Uvicorn (`--workers 1`, default VM/local setup) they enforce global caps, whereas multi-worker deployments (`workers > 1`) enforce caps per worker process.
- **Preservation on Failure & Redaction**: Wall-clock timeout, external fallback failure, or provider exception rolls back cleanly without overwriting the last known-good persisted `AnalysisReport`, and `redact_sensitive_text()` strips tokens, auth headers, keys, and local paths before returning errors.

---

## 4. Phase 2B.2 Frontend Intelligence UI & Exports

- **Modular Dark-Mode Reporting UI** ([`ReportPage.tsx`](../../frontend/src/pages/ReportPage.tsx), [`IntelligenceReport/`](../../frontend/src/components/IntelligenceReport/index.ts)): Renders strict TypeScript contracts ([`types/index.ts`](../../frontend/src/types/index.ts)) separating deterministic scoring from AI analytical confidence, labeling synthetic Replay telemetry (`SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED`) and mock placeholder artifacts, differentiating `FACT` / `INFERENCE` / `HYPOTHESIS` claims (`VERIFIED` / `UNVERIFIED` / `REJECTED`), resolving clicked evidence IDs via [`EvidenceExplorer.tsx`](../../frontend/src/components/IntelligenceReport/EvidenceExplorer.tsx), and gating external enrichment behind in-memory `X-Reporting-Token` submission and explicit opt-in consent (`AIProviderStatus`).
- **Print-Friendly Standalone HTML & JSON Exports**: [`export_html.py`](../../backend/app/services/reporting/export_html.py) enforces strict CSP + `html.escape` rendering, `@media print` stylesheets for browser PDF saving, complete AI provider metadata, claim validation statuses, truncation indicators, gaps, and limitations. See [INTELLIGENCE_REPORT_UI.md](../ai/INTELLIGENCE_REPORT_UI.md) for full UI component contracts and verification notes.
