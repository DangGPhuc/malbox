# Malbox-AI — Notion-Inspired Forensic Design System

**Document Reference:** `docs/ui/DESIGN_SYSTEM.md`  
**Applies to:** Frontend Workspace, Application Shell, Intelligence Reports, and Navigation Components  
**Specification Source:** `DESIGN.md` (Notion Warm Paper Notebook Reference)  
**Version:** v0.2.2  

---

## 1. Design Philosophy

Malbox-AI transitions from a high-fatigue dark cyberpunk aesthetic to a warm, editorial, evidence-first forensic notebook. The system mimics a high-quality paper notebook under natural light:
- **Warm Canvas:** `#f6f5f4` (`--color-paper-warmth`) off-white surface that reduces ocular strain during lengthy forensic investigations.
- **Pure White Cards:** `#ffffff` (`--color-pure-white`) floating on the warm canvas with 1px hairline borders (`rgba(0, 0, 0, 0.08)`) and 12px corners — zero heavy drop shadows.
- **Chromatic Economy:** Notion Blue (`#0075de`) anchors the single primary conversion/action commitment. Secondary actions defer to Sky Tint (`#e6f3fe`) or ghost styles.
- **Typographic Hierarchy via Alpha:** Headings and body text leverage `#111111` / `#000000` with calibrated opacity and warm graphite (`#615d59`) and stone (`#757575`) tones.
- **Zero External Dependencies:** Built with zero Google Fonts network requests; uses high-performance system font stacks (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`).

---

## 2. Token Specification

### 2.1 Color Palette

| Token | Light Theme Value | Dark Theme Value | Forensic Role |
|:---|:---|:---|:---|
| `--color-paper-warmth` | `#f6f5f4` | `#0f141d` | Main page canvas background |
| `--color-pure-white` | `#ffffff` | `#171f2c` | Content card surfaces, elevated panels |
| `--color-notion-blue` | `#0075de` | `#38bdf8` | Primary CTA button, active navigation indicator |
| `--color-sky-tint` | `#e6f3fe` | `rgba(56, 189, 248, 0.12)` | Ghost CTA fill, replay provenance highlight |
| `--color-charcoal` | `#111111` | `#f3f4f6` | Headings, emphasized text |
| `--color-graphite` | `#615d59` | `#cbd5e1` | Body copy, explanatory paragraphs |
| `--color-stone` | `#757575` | `#94a3b8` | Muted labels, metadata timestamps |
| `--color-marigold` | `#ffb110` | `#f59e0b` | Suspicious indicator, highlight pills |
| `--color-coral` | `#f64932` | `#ef4444` | High severity, warning highlights |
| `--color-vermillion` | `#e32d14` | `#dc2626` | Malicious verdict, critical alerts |
| `--color-hairline` | `rgba(0,0,0,0.08)` | `rgba(255,255,255,0.09)` | Standard card and table borders |

### 2.2 Border Radii

- **Cards & Elevated Panels:** `12px`
- **Buttons & Interactive Controls:** `8px`
- **Status Pills & Category Badges:** `9999px`
- **Inline Code & Chips:** `6px`

---

## 3. Application Shell Architecture (C2)

The application shell provides unified desktop and mobile navigation:

1. **Collapsible Sidebar:**
   - Width: `250px` (expanded) to `68px` (collapsed).
   - Global group: `Dashboard`, `Analyses / Cases`, `Submit Sample`.
   - Active analysis group (when investigation active): `Workspace`, `Behavior / Timeline`, `Behavior Graph`, `Static Analysis`, `Correlation Explorer`, `Analysis Report`.
   - Responsive off-canvas drawer on mobile (`< 900px`) with blurred backdrop overlay.
2. **Compact Top Header:**
   - Height: `58px`.
   - Hamburger sidebar toggle for desktop/mobile.
   - Breadcrumbs navigation (`Malbox / Cases / [ID] / [Tab]`).
   - Persistent active case pill with single-click exit.
   - Live backend health indicator (`Replay Safe`, `Live: Active / Isolated`).
   - Accessible theme toggle (`Sun` / `Moon` icon).
3. **Deep Linking & Hash Synchronization:**
   - Synchronizes URL hash (`#workspace/[ID]`, `#graph/[ID]`, `#static/[ID]`, `#correlation/[ID]`, `#report/[ID]`).
   - Fully supports browser Back and Forward navigation via `hashchange` event listeners.

---

## 4. Theme Support & Accessibility

- **Default Theme:** Light theme (`data-theme="light"`).
- **Dark Theme Toggle:** Accessible via top navigation bar (`Sun` / `Moon` icon), persisted in `localStorage('malbox_theme')` with optional query parameter override (`?theme=dark`).
- **Canvas Color Resolution:** Cytoscape.js HTML5 canvas rendering in `BehaviorGraphPage`, `StaticCallGraphPanel`, and `CorrelationRelationshipView` resolves concrete theme colors (`#111111` vs `#f3f4f6`) to prevent broken rendering of CSS variables.
- **Motion Reduction:** Fully honors `@media (prefers-reduced-motion: reduce)` by clamping transition durations to `0.01ms`.
- **High-Fidelity PDF Export:** Includes dedicated `@media print` rules enforcing pure white background, desaturated typography, and avoiding awkward page breaks across forensic tables.
