# Malbox-AI — Notion-Inspired Forensic Design System

**Document Reference:** `docs/ui/DESIGN_SYSTEM.md`  
**Applies to:** Frontend Workspace, Intelligence Reports, and Navigation Components  
**Specification Source:** `DESIGN.md` (Notion Warm Paper Notebook Reference)

---

## 1. Design Philosophy

Malbox-AI transitions from a high-fatigue dark cyberpunk aesthetic to a warm, editorial, evidence-first forensic notebook. The system mimics a high-quality paper notebook under natural light:
- **Warm Canvas:** `#f6f5f4` (`--color-paper-warmth`) off-white surface that reduces ocular strain during lengthy forensic investigations.
- **Pure White Cards:** `#ffffff` (`--color-pure-white`) floating on the warm canvas with 1px hairline borders (`rgba(0, 0, 0, 0.08)`) and 12px corners — zero heavy drop shadows.
- **Chromatic Economy:** Notion Blue (`#0075de`) anchors the single primary conversion/action commitment. Secondary actions defer to Sky Tint (`#e6f3fe`) or ghost styles.
- **Typographic Hierarchy via Alpha:** Headings and body text leverage `#111111` / `#000000` with calibrated opacity and warm graphite (`#615d59`) and stone (`#757575`) tones.

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

## 3. Core Component Library

### 3.1 Primary CTA Button (`.btn-primary` / `.btn-notion-primary`)
- Fill: `#0075de`
- Text: `#ffffff`
- Typography: 14px, weight 500
- Radius: 8px
- Padding: 6px 15px

### 3.2 Ghost Secondary Button (`.btn-secondary` / `.btn-notion-ghost`)
- Fill: `#e6f3fe` (Sky Tint)
- Text: `#0075de`
- Border: `1px solid rgba(0, 117, 222, 0.15)`
- Radius: 8px

### 3.3 Signature Hero Highlight Pill (`.hero-pill` / `.hero-pill-blue`)
- Applied inline inside headlines to emphasize forensic keywords (`Provenance`, `Executable`, `Correlation`).
- Border Radius: `9999px`
- Padding: `2px 14px`

### 3.4 Telemetry Quality Pills (`.pill-tag`)
- `badge-clean` / `badge-complete`: `#15803d` text on `rgba(21, 128, 61, 0.1)`
- `badge-incomplete` / `badge-warning`: `#c2410c` text on `rgba(232, 157, 1, 0.12)`
- `badge-malicious`: `#b91c1c` text on `rgba(246, 73, 50, 0.12)`

---

## 4. Theme Support & Accessibility

- **Default Theme:** Light theme (`data-theme="light"`).
- **Dark Theme Toggle:** Accessible via top navigation bar (`Sun` / `Moon` icon), persisted in `localStorage('malbox_theme')`.
- **Motion Reduction:** Fully honors `@media (prefers-reduced-motion: reduce)` by clamping transition durations to `0.01ms`.
- **High-Fidelity PDF Export:** Includes dedicated `@media print` rules enforcing pure white background, desaturated typography, and avoiding awkward page breaks across forensic tables.
