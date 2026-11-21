# Malbox-AI — UX Redesign & Workspace Modernization Report

**Document Reference:** `docs/ui/UX_REDESIGN_REPORT.md`  
**Phase:** Live-First Pivot & Notion UX Finalization  
**Reference Document:** `DESIGN.md`  
**Version:** v0.2.2  

---

## 1. Executive Summary

In response to product direction to make Malbox a real suspicious-file analysis platform (comparable in purpose to VirusTotal and Hybrid Analysis), Malbox-AI was systematically redesigned using the **Notion-Inspired Design System** (`DESIGN.md`).

Synthetic malware simulation and replay demos have been completely eliminated from the production user experience. The workflow is now a clean single-action intake:
$$\text{UPLOAD SUSPICIOUS FILE} \longrightarrow \text{AUTOMATIC DUAL-TRACK ANALYSIS} \longrightarrow \text{EVIDENCE-GROUNDED REPORT}$$

The user interface features a warm tactile paper notebook canvas (`#f6f5f4`) with crisp white card surfaces (`#ffffff`), 1px hairline borders (`rgba(0, 0, 0, 0.08)`), 12px corners, and single-chromatic blue commitments (`#0075de`).

For analysts working in low-light environments, a zero-flicker light/dark mode switch is accessible in the global navigation bar and persisted across user sessions.

---

## 2. Page-by-Page Transformation

### 2.1 Application Shell (`Navbar.tsx` & `App.tsx`)
- Collapsible desktop sidebar (250px to 68px) with global and active analysis navigation groups.
- Off-canvas mobile drawer with smooth blur backdrop overlay.
- Compact sticky top header (58px) with responsive hamburger menu, breadcrumbs, persistent active case pill with quick exit, live CAPE readiness indicator, and accessible theme toggle.
- Full browser Back/Forward navigation support with bidirectional hash synchronization.

### 2.2 Dashboard (`DashboardPage.tsx`)
- Displays real live analyses, strictly excluding historical replay cases from active threat metrics (`maliciousCount`, `suspiciousCount`, `lowCount`, `cleanCount`).
- Historical replay records in the database are distinctly labeled with a `Synthetic Replay` badge.
- Infrastructure readiness strip:
  * CAPE Sandbox (Ready vs Standby)
  * Ghidra Decompiler (Available)
  * Detection Engine (Active 17-Category Taxonomy)
  * Telemetry Contract (v0.2.2 Quality Gates)
- Canonical backend risk classifications:
  * Malicious: $\ge 80$.
  * Suspicious: $50–79$.
  * Low Risk: $20–49$.
  * Clean: $< 20$ (Complete telemetry).
  * Incomplete / Needs Review: Partitioned into its own bucket.

### 2.3 Single-Action File Submission (`SubmitPage.tsx`)
- **Old:** 5-step wizard with scenario dropdowns, WannaCry/RedLine quick demo buttons, and confusing backend selectors.
- **New:** Single-purpose, real-world file submission experience:
  1. *Header:* "Analyze a suspicious file".
  2. *Intake Area:* Drag-and-drop zone with visual drag-over feedback + "Browse File" button (PE32/PE32+ formats, 32MB max).
  3. *File Preview:* Quarantined metadata preview (File name, size, SHA-256 in mono, PE validity, Shannon entropy, heuristic packing).
  4. *Capabilities Card:* Automated 4-stage pipeline visualization (Ghidra static extraction, CAPE isolated sandbox detonation, multi-engine correlation, 17-category classification).
  5. *Infrastructure Readiness Badge:* Dynamic CAPE sandbox status.
  6. *Analyst Safety Gate:* Operator token password input (persisted in localStorage) + explicit authorization checkbox.
  7. *CTA Button:* Single prominent "Analyze File" button executing automated analysis.

### 2.4 Analysis Workspace (`WorkspacePage.tsx`)
- Generation-fenced async request pipeline (`generationRef`) eliminating stale data overwrites on quick navigation.
- Non-overlapping polling with graceful terminal state detection.
- Unified `AnalysisHeader` showing sample metadata, lifecycle status, completeness contract, risk verdict, and AI confidence.

### 2.5 Malware Classification Section (`MalwareClassificationSection.tsx` & `ReportPage.tsx`)
- Renders deterministic 17-category malware taxonomy findings.
- Primary category highlight (e.g. `ransomware`, `infostealer`, `wiper`).
- Secondary categories tags for multi-label threats.
- Classification status badges (`CONFIRMED`, `SUSPECTED`, `UNSUPPORTED`).
- Direct deep-links to supporting evidence IDs (`ev-*`), Ghidra static functions, dynamic events, and dropped artifacts.

### 2.6 Behavior Graph & Correlation Explorer
- Dynamic Cytoscape process execution trees with concrete theme color resolution.
- Multi-engine correlation explorer with HMAC-signed trace key verification and graph truncation limits.

---

## 3. Real Browser Visual Verification

Visual verification was conducted using headless Chromium (`/usr/bin/chromium`) against real analysis records across desktop (1440×900), laptop (1024×768), and mobile (390×844) viewports in both light and dark themes.

All verified screenshots are archived in `docs/ui/screenshots/` and `docs/screenshots/`:

| Screen | Desktop Light (1440×900) | Desktop Dark (1440×900) | Laptop Light (1024×768) | Mobile Light (390×844) |
|:---|:---:|:---:|:---:|:---:|
| **Dashboard** | `01_dashboard_desktop_light.png` | `01_dashboard_desktop_dark.png` | `01_dashboard_laptop_light.png` | `01_dashboard_mobile_light.png` |
| **Submit Page** | `02_submit_desktop_light.png` | `02_submit_desktop_dark.png` | `02_submit_laptop_light.png` | `02_submit_mobile_light.png` |
| **Analysis Workspace** | `03_workspace_desktop_light.png` | `03_workspace_desktop_dark.png` | `03_workspace_laptop_light.png` | `03_workspace_mobile_light.png` |
| **Behavior Graph** | `04_behavior_graph_desktop_light.png` | `04_behavior_graph_desktop_dark.png` | — | — |
| **Static Function Explorer** | `05_static_explorer_desktop_light.png` | `05_static_explorer_desktop_dark.png` | — | — |
| **Correlation Explorer** | `06_correlation_explorer_desktop_light.png` | `06_correlation_explorer_desktop_dark.png` | — | — |
| **Intelligence Report** | `07_intelligence_report_desktop_light.png` | `07_intelligence_report_desktop_dark.png` | `07_intelligence_report_laptop_light.png` | — |
| **Malware Classification** | `08_malware_classification_desktop_light.png` | `08_malware_classification_desktop_dark.png` | — | — |

---

## 4. Test Verification & Code Quality

- **TypeScript Typecheck:** 0 errors (`npm run typecheck`).
- **Frontend Test Suite:** 47 passed across 5 test files (`npm test -- --run`).
- **Backend Test Suite:** 171 passed, 1 skipped (`pytest backend/tests/ -v`).
- **Doctor CLI Verification:** 13 passed (`pytest backend/tests/test_doctor_cli.py -v`).
- **Production Build:** Clean Vite bundle build (`npm run build`).
- **npm audit:** 0 vulnerabilities.
