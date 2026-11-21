# MALBOX-AI v0.2 — Phase 4B Correlation Explorer UI & Report Integration

This document covers the architecture, safety guarantees, TypeScript contracts, cross-evidence deep linking, bounded visualization, and report export behavior of the **Phase 4B Correlation Explorer** workspace.

---

## 1. Security, Provenance & Execution Guardrails

1. **Read-Only on Page Load**: [`CorrelationPage.tsx`](../../frontend/src/pages/CorrelationPage.tsx) and [`ReportPage.tsx`](../../frontend/src/pages/ReportPage.tsx) call only read-only `GET /api/v1/analyses/{analysis_id}/correlation` on mount. Neither page ever auto-triggers `POST /correlation`, Ghidra Headless, CAPE Live Execution, or external OpenCode/LLM enrichment.
2. **Ephemeral Authorization Token Handling**: [`CorrelationTriggerBar.tsx`](../../frontend/src/components/Correlation/CorrelationTriggerBar.tsx) stores `X-Reporting-Token` strictly in transient React `useState` memory (never written to `localStorage`, `sessionStorage`, URL hashes, or console output). Duplicate submissions while in flight are blocked by state and ref locks, and prior usable correlation results are preserved on HTTP `401`/`403`/`404`/`409`/`429`/`500` errors.
3. **Trace Key Isolation (`MALBOX_TRACE_AUTH_KEY`)**: Runtime execution proof (`DIRECTLY_OBSERVED`) requires a dedicated, high-entropy `MALBOX_TRACE_AUTH_KEY` (empty/disabled by default; weak/default/dev keys and `MALBOX_SECRET_KEY` sharing are rejected by both [`verifier.py`](../../backend/app/services/evidence_correlation/verifier.py) and `./malbox doctor`). HMAC verification proves trace signer authenticity rather than OS sensor infallibility. Replay Mode permanently blocks `DIRECTLY_OBSERVED` (`SYNTHETIC SCENARIO ONLY — UPLOADED BINARY NOT EXECUTED`).
4. **Risk Score & Confidence Separation**: Correlation confidence scores reflect static-to-dynamic linkage evidence only and are explicitly decoupled from deterministic behavioral `risk_score` and AI report `confidence_assessment`.
5. **XSS & Bounded DOM Safety**: Every untrusted telemetry, API, warning, and correlation field is rendered via React JSX text nodes (zero `dangerouslySetInnerHTML`) on the frontend and escaped via `_esc()` with CSP meta headers on [`export_html.py`](../../backend/app/services/reporting/export_html.py).

---

## 2. Strict TypeScript Contracts

Strict zero-`any` interfaces live in [`frontend/src/types/index.ts`](../../frontend/src/types/index.ts):
- Core models: `CorrelationResult`, `CorrelationStatus`, `CorrelationFinding`, `CorrelationRelationship`, `CorrelationEvidenceReference`, `CorrelationConfidence`, `CorrelationProvenance`, `CorrelationLimitations`, `CorrelationTruncation`, `CorrelationSummary`, `CorrelationBundleSection`, `CorrelationBundleFinding`.
- Essential Phase 4A.1 / Gate 0 integrity fields surfaced explicitly: `source_fingerprint`, `is_stale`, `trace_verification_mode`, `is_replay`, `static_reuse_detected`, `behavioral_execution_directly_observed`, and reference-level `trace_verified`.
- API client methods in [`frontend/src/api/client.ts`](../../frontend/src/api/client.ts): `api.getCorrelation(analysisId, signal?)`, `api.triggerCorrelation(analysisId, reportingToken, force)`, and `CorrelationApiError` (preserving HTTP status & `Retry-After`).

---

## 3. Component Architecture

Located in [`frontend/src/components/Correlation/`](../../frontend/src/components/Correlation/index.ts) and lazy-loaded via [`App.tsx`](../../frontend/src/App.tsx):

| Component / Module | Responsibility |
| :--- | :--- |
| [`CorrelationPage.tsx`](../../frontend/src/pages/CorrelationPage.tsx) | Orchestrates read-only GET lifecycle, sequence/epoch request fencing, deep-link validation, bounded paginated `/events` lookup, and section tabs. |
| [`CorrelationTriggerBar.tsx`](../../frontend/src/components/Correlation/CorrelationTriggerBar.tsx) | Transient `X-Reporting-Token` input, explicit `force` toggle, busy indicator without fake `%` progress, and HTTP error mapping. |
| [`CorrelationStatusBar.tsx`](../../frontend/src/components/Correlation/CorrelationStatusBar.tsx) | Displays `COMPLETED`/`PARTIAL`/`INSUFFICIENT_EVIDENCE`/`UNSUPPORTED`/`FAILED`/`NOT YET COMPUTED`, trace auth state, `is_stale` drift alert, Replay synthetic banner, and static reuse notice. |
| [`CorrelationOverview.tsx`](../../frontend/src/components/Correlation/CorrelationOverview.tsx) | Renders KPI counts across all five relationships plus bounded event/function/byte coverage metrics. |
| [`CorrelationFindingsTable.tsx`](../../frontend/src/components/Correlation/CorrelationFindingsTable.tsx) | Search/filter matrix (query, relationship, rule ID, min confidence), distinct visual badges per classification, static/dynamic evidence chips, and Replay banners. |
| [`CorrelationEvidenceInspector.tsx`](../../frontend/src/components/Correlation/CorrelationEvidenceInspector.tsx) | Resolves selected correlation findings against verified `/events` telemetry records or static disassembly summaries, or displays honest unavailability notices when truncated/omitted. |
| [`CorrelationRelationshipView.tsx`](../../frontend/src/components/Correlation/CorrelationRelationshipView.tsx) | Lazy-loads `cytoscape` (`import('cytoscape')`) in browsers cleanly (bounded `<= 36` nodes, `<= 48` edges, real `CorrelationFinding` edges only, plus omitted counters and accessible textual adjacency list fallback). |
| [`CorrelationConfidencePanel.tsx`](../../frontend/src/components/Correlation/CorrelationConfidencePanel.tsx), [`CorrelationProvenancePanel.tsx`](../../frontend/src/components/Correlation/CorrelationProvenancePanel.tsx), [`CorrelationLimitationsPanel.tsx`](../../frontend/src/components/Correlation/CorrelationLimitationsPanel.tsx) | Displays confidence separation guardrails, SHA-256 / `source_fingerprint` provenance metadata, and recorded limitations/truncation/warnings/errors. |

---

## 4. Cross-Evidence Navigation & Intelligence Report Exports

- **Static Function Jump**: Clicking any `func:<sha16>:<addr>` chip inside `CorrelationFindingsTable`, `CorrelationEvidenceInspector`, `CorrelationRelationshipView`, or `CorrelationSummarySection` navigates to [`StaticAnalysisPage.tsx`](../../frontend/src/pages/StaticAnalysisPage.tsx) with validated `initialFunctionId` selected (or raises `navWarning` cleanly if omitted by static bounds).
- **Dynamic Event Lookup**: Clicking a dynamic event reference invokes bounded paginated `GET /api/v1/analyses/{id}/events` (up to 5 pages of 200 per click, cached per analysis) and renders raw source attributes without mutation.
- **Report Integration & Exports**: [`CorrelationSummarySection.tsx`](../../frontend/src/components/IntelligenceReport/CorrelationSummarySection.tsx) embeds `"Static / Dynamic Correlation Assessment"` in [`ReportPage.tsx`](../../frontend/src/pages/ReportPage.tsx) with deep links to [`CorrelationPage.tsx`](../../frontend/src/pages/CorrelationPage.tsx). JSON downloads ([`ReportExportToolbar.tsx`](../../frontend/src/components/IntelligenceReport/ReportExportToolbar.tsx)), standalone HTML exports (`/api/v1/analyses/{id}/report/html`), and Print/PDF outputs preserve relationship labels, confidence, reference IDs, Replay provenance, `is_stale`, `trace_verification_mode`, limitations, and legacy backward compatibility.

