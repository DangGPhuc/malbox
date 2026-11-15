# Malbox-AI — UX Redesign & Workspace Modernization Report

**Document Reference:** `docs/ui/UX_REDESIGN_REPORT.md`  
**Phase:** Phase C Final System Acceptance  
**Reference Document:** `DESIGN.md`  
**Version:** v0.2.2  

---

## 1. Executive Summary

In response to field audit feedback detailing visual fatigue, dense tables, and low contrast during extended forensic analysis sessions, Malbox-AI was systematically redesigned using the **Notion-Inspired Design System** (`DESIGN.md`).

The previous monolithic dark cyberpunk aesthetic (`#070a12`, `#0b1120`) has been replaced by a tactile, warm-light paper notebook canvas (`#f6f5f4`) with crisp white card surfaces (`#ffffff`), 1px hairline borders (`rgba(0, 0, 0, 0.08)`), 12px corners, and single-chromatic blue commitments (`#0075de`).

For analysts working in dark environments, a zero-flicker light/dark mode switch is accessible in the global navigation bar and persisted across user sessions. Zero external network requests are made for fonts.

---

## 2. Page-by-Page Transformation

### 2.1 Application Shell (`Navbar.tsx` & `App.tsx`)
- **Old:** Crowded single horizontal header bar with limited navigation context.
- **New:** Full application shell featuring:
  - Collapsible desktop sidebar (250px to 68px) with global and active analysis navigation groups.
  - Off-canvas mobile drawer with smooth blur backdrop overlay.
  - Compact sticky top header (58px) with responsive hamburger menu, breadcrumbs, persistent active case pill with quick exit, live health indicator, and accessible theme toggle.
  - Full browser Back/Forward navigation support with bidirectional hash synchronization.

### 2.2 Dashboard (`DashboardPage.tsx`)
- **Old:** Ad-hoc score thresholds, arbitrary malicious classification for 65-point scores, conflated clean counts.
- **New:** Canonical backend risk classifications:
  - Malicious: $\ge 80$.
  - Suspicious: $50–79$.
  - Low Risk: $20–49$.
  - Clean: $< 20$ (Complete telemetry).
  - Incomplete / Needs Review: Partitioned into its own bucket.
  - Total distribution bar is strictly mutually exclusive totaling 100%.
  - Replay vs Live split displayed explicitly.
  - System readiness strip driven by live `api.getHealth()` probe.

### 2.3 Sample Submission Wizard (`SubmitPage.tsx`)
- **Old:** Single-column upload box with ambiguous backend options.
- **New:** Guided 5-Step Wizard:
  1. *Step 1:* File upload or Instant Safe Synthetic Replay Demos (WannaCry / RedLine).
  2. *Step 2:* Quarantined Preflight Triage (file size, SHA-256, Shannon entropy, packed heuristic).
  3. *Step 3:* Execution backend selection (Safe Replay Sandbox vs Live CAPE v2) with live mode readiness checks.
  4. *Step 4:* Profile & Operator Token Gate (mandatory 32+ char token required only for live mode).
  5. *Step 5:* Execution Safety & Confinement Review with explicit analyst authorization.
  - Auto-resets authorization state and operator token when switching backends or samples.

### 2.4 Analysis Workspace (`WorkspacePage.tsx`)
- **Old:** Race conditions when switching between analyses; late responses overwrote active view.
- **New:** Generation-fenced async request pipeline (`generationRef`) eliminating stale data overwrites; immediate state reset on ID switch; non-overlapping polling; unified `AnalysisHeader` showing sample metadata, lifecycle, completeness, risk verdict, and AI confidence.

### 2.5 Behavior Graph (`BehaviorGraphPage.tsx`)
- **Old:** Broken canvas rendering with unparsed CSS variables (`var(--text-main)`).
- **New:** Resolves concrete theme colors (`#111111` in light mode, `#f3f4f6` in dark mode); generation fencing against ID switching; unified `AnalysisHeader`.

### 2.6 Static Function Explorer & Correlation Explorer
- Concrete theme color resolution for Cytoscape call graph and relationship views.
- Read-only pseudocode viewer with strict XSS escaping.

---

## 3. Real Browser Visual Verification (C7)

Visual verification was conducted using headless Chromium (`Chromium 150.0.7871.181`) against real Replay and database analysis records across 3 responsive viewports and both light and dark themes.

All 20 verified screenshots are archived in `docs/screenshots/`:

| Screen | Desktop Light (1440×900) | Desktop Dark (1440×900) | Laptop Light (1024×768) | Mobile Light (390×844) |
|:---|:---:|:---:|:---:|:---:|
| **Dashboard** | `01_dashboard_desktop_light.png` | `01_dashboard_desktop_dark.png` | `01_dashboard_laptop_light.png` | `01_dashboard_mobile_light.png` |
| **Submit Workflow** | `02_submit_desktop_light.png` | `02_submit_desktop_dark.png` | — | `02_submit_mobile_light.png` |
| **Analysis Workspace** | `03_workspace_desktop_light.png` | `03_workspace_desktop_dark.png` | `03_workspace_laptop_light.png` | `03_workspace_mobile_light.png` |
| **Behavior Graph** | `04_behavior_graph_desktop_light.png` | `04_behavior_graph_desktop_dark.png` | — | — |
| **Static Function Explorer** | `05_static_explorer_desktop_light.png` | `05_static_explorer_desktop_dark.png` | — | — |
| **Correlation Explorer** | `06_correlation_explorer_desktop_light.png` | `06_correlation_explorer_desktop_dark.png` | — | — |
| **Intelligence Report** | `07_intelligence_report_desktop_light.png` | `07_intelligence_report_desktop_dark.png` | `07_intelligence_report_laptop_light.png` | — |

---

## 4. Verification & Compliance

- **TypeScript Compilation:** Zero errors (`npm run typecheck`).
- **Vitest Test Suite:** 46 passed across 5 test suites (`npm test`).
- **Backend Test Suite:** 159 passed, 1 skipped (`pytest backend/tests/`).
- **Production Bundle:** Clean build via Vite (`npm run build`).
- **Dependency Audit:** 0 vulnerabilities (`npm audit`).
