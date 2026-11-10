# MALBOX-AI — Intelligence Report UI Redesign (Phase 2B.2)

## 1. Overview

Phase 2B.2 delivers a modular, evidence-grounded dark-mode reporting experience in [`frontend/src/pages/ReportPage.tsx`](../../frontend/src/pages/ReportPage.tsx) backed by strictly typed contracts in [`frontend/src/types/index.ts`](../../frontend/src/types/index.ts) and component modules under [`frontend/src/components/IntelligenceReport/`](../../frontend/src/components/IntelligenceReport/index.ts).

Core design goals:
- Maintain strict authority separation between deterministic detection verdicts (`risk_score`, `risk_level`, rule breakdowns, MITRE mappings) and AI-generated interpretation (`overall_confidence`, `behavioral_narrative`, analytical claims).
- Keep all uncertainty, validation rejections, truncation windows, contradictions, and Replay vs. Live provenance visible at all times.
- Guarantee zero automatic external AI requests on report viewing (`GET`), ephemeral-only in-memory handling for `X-Reporting-Token`, and safe React text escaping (zero `dangerouslySetInnerHTML`).

---

## 2. Architecture & Component Modules

| Component | Path | Responsibility |
| :--- | :--- | :--- |
| **Report Header** | `frontend/src/components/IntelligenceReport/IntelligenceReportHeader.tsx` | Sample filename, hashes, analysis ID, Replay/Live provenance pill, separated Deterministic Risk Verdict vs. AI Analytical Confidence vs. Provider/Fallback badges, and quick navigation to Workspace / Behavior Graph. |
| **Replay Provenance Banner** | `frontend/src/components/IntelligenceReport/ReplayProvenanceBanner.tsx` | Prominently renders `SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED`, scenario ID, provenance disclaimer, and synthetic artifact notice for Replay runs. |
| **Export Toolbar** | `frontend/src/components/IntelligenceReport/ReportExportToolbar.tsx` | JSON export preserving Replay provenance & Phase 2B intelligence metadata, Standalone HTML link, and browser `window.print()` PDF-friendly print button. |
| **Executive Assessment** | `frontend/src/components/IntelligenceReport/ExecutiveAssessment.tsx` | AI-synthesized assessment paired cleanly with deterministic rule scoring breakdown and static PE triage metadata. |
| **Provider Status & Enrichment** | `frontend/src/components/IntelligenceReport/AIProviderStatus.tsx` | Displays active mode/provider/model/tokens/fallback status and provides explicit user-controlled `POST /api/v1/analyses/{id}/report/intelligence` trigger with ephemeral token state, explicit external consent checkbox, 401/403/409/429/503/504/502 error handling, retry, and automatic report re-fetch. |
| **Evidence-Linked Claims** | `frontend/src/components/IntelligenceReport/EvidenceLinkedClaim.tsx` | Visually differentiates `FACT`, `INFERENCE`, and `HYPOTHESIS` entries and `VERIFIED`, `UNVERIFIED`, and `REJECTED` validation statuses, caveats, human-review flags, and clickable evidence references. |
| **Attack Story Timeline** | `frontend/src/components/IntelligenceReport/AttackStoryTimeline.tsx` | Expand/collapse chronological phase interpretations matched to actual backend `execution_timeline` rows and related findings, plus link to Behavior Graph (never embeds heavy graph rendering inline). |
| **Analyst Narrative & Findings** | `frontend/src/components/IntelligenceReport/AnalystNarrative.tsx` | Interpreted narrative paired with authoritative findings table, MITRE ATT&CK matrix cards, and clickable evidence chips. |
| **IOCs & Artifacts** | `frontend/src/components/IntelligenceReport/IOCIntelligenceTable.tsx` | Contextual IOC interpretations paired with deterministic IOCs and captured artifacts explicitly labeled `SYNTHETIC PLACEHOLDER` in Replay runs. |
| **Confidence & Validation Panels** | `frontend/src/components/IntelligenceReport/ConfidencePanel.tsx`, `ValidationSummaryPanel.tsx`, `InvestigationRecommendations.tsx` | Truncation indicators (`events_included / total_events_available`), contradictions/gaps, stripped invalid evidence IDs, validator warnings, prioritized follow-up actions, and explicit Phase 3 Ghidra placeholder status. |
| **Evidence Record Inspector** | `frontend/src/components/IntelligenceReport/EvidenceExplorer.tsx` | Keyboard-accessible (`Escape` to close) inspector resolving `sample:<sha256>`, `finding:<id>`/`rule:<id>`, `artifact:<name>`, and lazily queried `GET /events` records without fabricating missing/truncated data. |

---

## 3. Security, Privacy & Performance Guarantees

1. **Zero Secret Persistence**: `X-Reporting-Token` lives only in ephemeral component state during the session; never stored in `localStorage`, `sessionStorage`, URLs, or telemetry logs.
2. **Consent & Default-Offline Policy**: `AIProviderStatus` requires explicit user selection and checks `external_transmission_consent` before enabling `llm` or `opencode` submission. OpenCode remains disabled by default on the server.
3. **Prior Report Preservation**: Any HTTP 401, 403, 409, 429, 502, 503, or 504 enrichment error preserves the currently displayed report cleanly and renders a structured error alert with retry.
4. **Bundle Optimization & Dependency Hygiene**: Lazy-loading `BehaviorGraphPage` via `React.lazy` in [`frontend/src/App.tsx`](../../frontend/src/App.tsx) isolates Cytoscape (~452 kB gzip 144 kB) from initial Report/Dashboard loads (~271 kB gzip 75 kB). Upgraded Vite to `^6.4.6` alongside Vitest `^4.1.12` (verified `0 vulnerabilities` via `npm audit`).
5. **Print & Standalone HTML Exports**: Both [`frontend/src/index.css`](../../frontend/src/index.css) and [`backend/app/services/reporting/export_html.py`](../../backend/app/services/reporting/export_html.py) include light-theme `@media print` stylesheets, long hash/IOC wrapping (`.mono-wrap`), strict CSP headers, and complete HTML entity escaping (`html.escape`).

---

## 4. Known Runtime & CI Notes

- Standard `ubuntu-latest` GitHub Actions runners do not include `bwrap` or the `opencode` CLI; therefore, real Bubblewrap + OpenCode integration (`test_real_bwrap_sandbox_and_real_opencode_cli_integration`) was skipped in CI and requires independent Kali host runtime execution (passing locally on Kali with `bwrap` and `opencode v2.1.4`).
- Automated frontend tests use Vitest + React Testing Library (`jsdom`) against realistic WannaCry and RedLine UI fixtures in [`frontend/src/test/fixtures/intelligenceFixtures.ts`](../../frontend/src/test/fixtures/intelligenceFixtures.ts) rather than heavy headless browser automation in CI.

