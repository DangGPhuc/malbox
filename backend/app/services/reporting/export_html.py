import html
from typing import Any, Dict, List


def _esc(value: Any, default: str = "") -> str:
    if value is None or value == "":
        return html.escape(default)
    return html.escape(str(value))


def generate_html_report(report_data: Dict[str, Any]) -> str:
    """
    Renders and exports a secure, standalone, print-friendly HTML intelligence report with
    strict CSP meta headers, complete HTML escaping of untrusted fields, Phase 2A/2B
    evidence-grounded intelligence preservation, and prominent replay provenance indicators.
    """
    analysis_id = _esc(report_data.get("analysis_id"), "N/A")
    generated_at = _esc(report_data.get("generated_at"), "")
    summary = _esc(report_data.get("executive_summary"), "")
    backend_type = str(report_data.get("backend_type") or "replay")
    is_replay = bool(report_data.get("is_replay", backend_type == "replay"))
    replay_scenario = _esc(report_data.get("replay_scenario_id") or "default_fixture")
    disclaimer = _esc(report_data.get("provenance_disclaimer"), "")

    meta = report_data.get("sample_metadata") or {}
    risk = report_data.get("risk_assessment") or {}
    score = int(risk.get("score", 0))
    raw_level = str(risk.get("level") or "No Suspicious Behavior Observed")
    level = _esc(raw_level)
    findings: List[Dict[str, Any]] = report_data.get("findings") or []
    mitre: List[Dict[str, Any]] = report_data.get("mitre_attack_mappings") or []
    iocs: Dict[str, Any] = report_data.get("extracted_iocs") or {}
    timeline: List[Dict[str, Any]] = report_data.get("execution_timeline") or []
    limitations: Dict[str, Any] = report_data.get("confidence_and_limitations") or {}
    follow_up: Dict[str, Any] = report_data.get("recommended_follow_up") or {}
    artifacts: List[Dict[str, Any]] = report_data.get("artifacts") or []
    intel = report_data.get("intelligence_report")

    level_colors = {
        "Malicious": "#ef4444",
        "Suspicious": "#f97316",
        "Low": "#eab308",
        "Clean": "#22c55e",
        "No Suspicious Behavior Observed": "#3b82f6",
    }
    badge_color = level_colors.get(raw_level, "#3b82f6")

    if is_replay:
        provenance_banner = f"""
        <section class="banner banner-replay" aria-label="Replay Provenance Notice">
            <div class="banner-top">
                <span class="pill pill-replay">REPLAY SIMULATION</span>
                <strong>SYNTHETIC REPLAY — UPLOADED BINARY NOT EXECUTED</strong>
                <span class="mono tag-scenario">Scenario: {replay_scenario}</span>
            </div>
            <p class="banner-sub">
                {disclaimer or 'This report was generated using verified offline behavioral telemetry fixtures. Uploaded sample bytes underwent static triage only and were NOT executed.'}
            </p>
        </section>
        """
    else:
        provenance_banner = """
        <section class="banner banner-live" aria-label="Live Sandbox Provenance">
            <div class="banner-top">
                <span class="pill pill-live">LIVE DETONATION</span>
                <strong>Isolated Hypervisor Sandbox Execution</strong>
            </div>
            <p class="banner-sub">
                Telemetry reflects live execution inside the configured isolated sandbox environment.
            </p>
        </section>
        """

    intel_section = ""
    if isinstance(intel, dict):
        pm = intel.get("provider_metadata") or {}
        vs = intel.get("validation_summary") or {}
        conf = intel.get("confidence_assessment") or {}
        trunc = intel.get("evidence_truncation") or {}
        claims = intel.get("technical_claims") or []
        timeline_interp = intel.get("timeline_interpretations") or []
        ioc_interps = intel.get("ioc_interpretations") or []
        gaps = intel.get("contradictions_or_gaps") or []
        intel_limits = intel.get("limitations") or []
        actions = intel.get("recommended_follow_up_actions") or []

        intel_exec = _esc(intel.get("executive_assessment"), summary)
        intel_narrative = _esc(intel.get("behavioral_narrative"), "")
        intel_provenance = _esc(intel.get("provenance_summary"), "")

        intel_mode = _esc(pm.get("mode"), "deterministic_mock")
        intel_provider = _esc(pm.get("provider"), "mock")
        intel_model = _esc(pm.get("model"), "n/a")
        intel_tokens = int(pm.get("tokens_used") or 0)
        intel_fallback_used = bool(pm.get("fallback_used", False))
        intel_fallback_reason = _esc(pm.get("fallback_reason"), "")
        intel_rules_ver = _esc(pm.get("rules_version"), "2.0")
        intel_gen_at = _esc(pm.get("generated_at"), "")

        conf_val = conf.get("overall_confidence")
        conf_pct = f"{round(float(conf_val) * 100)}%" if isinstance(conf_val, (int, float)) else _esc(conf_val, "n/a")
        conf_comp = _esc(conf.get("evidence_completeness"), "n/a")
        conf_rationale = _esc(conf.get("rationale"), "")

        vs_passed = "Yes" if vs.get("passed", True) else "No"
        vs_total = int(vs.get("total_claims") or 0)
        vs_ver = int(vs.get("verified_claims") or 0)
        vs_unver = int(vs.get("unverified_claims") or 0)
        vs_rej = int(vs.get("rejected_claims") or 0)
        vs_rev = int(vs.get("review_required_claims") or 0)
        removed_ids = ", ".join(_esc(x) for x in (vs.get("removed_invalid_evidence_ids") or [])) or "None"
        val_warnings = "".join(f"<li>{_esc(w)}</li>" for w in (vs.get("warnings") or []))

        fallback_html = (
            f"<span class='pill pill-warn'>FALLBACK USED</span>"
            + (f" <span class='muted'>Reason: {intel_fallback_reason}</span>" if intel_fallback_reason else "")
            if intel_fallback_used
            else "<span class='pill pill-ok'>NO FALLBACK</span>"
        )

        claims_rows = ""
        for c in claims:
            c_id = _esc(c.get("claim_id"), "claim")
            c_type = _esc(c.get("classification"), "HYPOTHESIS")
            c_status = _esc(c.get("validation_status"), "UNVERIFIED")
            c_cat = _esc(c.get("support_category"), "CONSERVATIVE_UNVERIFIED")
            c_text = _esc(c.get("claim_text"), "")
            c_conf = c.get("confidence")
            c_conf_str = f"{round(float(c_conf) * 100)}%" if isinstance(c_conf, (int, float)) else "n/a"
            c_review = bool(c.get("requires_human_review", False))
            c_notes = _esc(c.get("validation_notes"), "")
            c_caveats = ", ".join(_esc(x) for x in (c.get("caveats") or []))
            c_ids = ", ".join(_esc(i) for i in (c.get("supporting_evidence_ids") or [])) or "none"

            claims_rows += f"""
            <li class="claim-item claim-{c_status.lower()}">
                <div class="claim-head">
                    <strong>{c_id}</strong>
                    <span class="pill pill-type">{c_type}</span>
                    <span class="pill pill-status-{c_status.lower()}">{c_status}</span>
                    <span class="pill pill-neutral">{c_cat}</span>
                    <span class="muted">Confidence: {c_conf_str}</span>
                    {"<span class='pill pill-warn'>HUMAN REVIEW REQUIRED</span>" if c_review else ""}
                </div>
                <div class="claim-body">{c_text}</div>
                <div class="claim-meta">
                    <span>Evidence IDs: <code class="mono-wrap">{c_ids}</code></span>
                    {f"<div>Caveats: {c_caveats}</div>" if c_caveats else ""}
                    {f"<div>Validation Note: {c_notes}</div>" if c_notes else ""}
                </div>
            </li>"""

        timeline_interp_rows = ""
        for t in timeline_interp:
            t_phase = _esc(t.get("phase"), "Phase")
            t_sum = _esc(t.get("summary"), "")
            t_ids = ", ".join(_esc(i) for i in (t.get("supporting_evidence_ids") or [])) or "none"
            timeline_interp_rows += f"""
            <li class="timeline-entry">
                <div><strong>{t_phase}</strong></div>
                <div>{t_sum}</div>
                <div class="claim-meta">Evidence IDs: <code class="mono-wrap">{t_ids}</code></div>
            </li>"""

        ioc_interp_rows = ""
        for item in ioc_interps:
            iv = _esc(item.get("ioc_value"), "")
            it = _esc(item.get("ioc_type"), "")
            ir = _esc(item.get("role_or_context"), "")
            ic = item.get("confidence")
            ic_str = f"{round(float(ic) * 100)}%" if isinstance(ic, (int, float)) else "n/a"
            ie = ", ".join(_esc(x) for x in (item.get("supporting_evidence_ids") or [])) or "none"
            ioc_interp_rows += f"""
            <tr>
                <td class="mono-wrap">{iv}</td>
                <td>{it}</td>
                <td>{ir}</td>
                <td>{ic_str}</td>
                <td class="mono-wrap">{ie}</td>
            </tr>"""

        gaps_html = "".join(
            f"<li><strong>{_esc(g.get('gap_type'))}:</strong> {_esc(g.get('description'))} "
            f"<span class='muted'>(Impact: {_esc(g.get('impact'))})</span></li>"
            for g in gaps
        )
        limits_html = "".join(f"<li>{_esc(lim)}</li>" for lim in intel_limits)
        actions_html = "".join(
            f"<li><span class='pill pill-neutral'>{_esc(a.get('priority')).upper()}</span> "
            f"<strong>{_esc(a.get('action'))}</strong> — {_esc(a.get('rationale'))} "
            + ("<span class='pill pill-warn'>MANUAL APPROVAL</span>" if a.get("requires_manual_approval") else "")
            + "</li>"
            for a in actions
        )

        trunc_flag = "Truncated" if trunc.get("truncated") else "Complete within budget"
        trunc_events_inc = int(trunc.get("events_included") or 0)
        trunc_events_tot = int(trunc.get("total_events_available") or 0)
        trunc_events_om = int(trunc.get("events_omitted") or 0)

        intel_section = f"""
        <section class="card">
            <h2>AI Intelligence Assessment (v2.0)</h2>
            <div class="meta-bar">
                <span><strong>Provenance:</strong> {intel_provenance}</span><br>
                <span>Mode: <strong>{intel_mode}</strong> | Provider: <strong>{intel_provider}</strong> (<span class="mono-wrap">{intel_model}</span>) | Tokens: <strong>{intel_tokens}</strong> | Rules: <strong>{intel_rules_ver}</strong> | Generated: {intel_gen_at}</span><br>
                <span>{fallback_html}</span>
            </div>
            <div class="split-metrics">
                <div class="metric-box">
                    <div class="metric-label">Deterministic Risk Verdict</div>
                    <div class="metric-value">{score}/100 ({level})</div>
                </div>
                <div class="metric-box">
                    <div class="metric-label">AI Analytical Confidence (Non-Authoritative)</div>
                    <div class="metric-value">{conf_pct} ({conf_comp} completeness)</div>
                    <div class="muted">{conf_rationale}</div>
                </div>
            </div>
            <h3>AI Executive Assessment</h3>
            <p class="prose">{intel_exec}</p>
            <h3>Interpreted Behavioral Narrative</h3>
            <p class="prose">{intel_narrative}</p>

            <h3>Validation Summary &amp; Claim Matrix</h3>
            <div class="meta-bar">
                Validation Passed: <strong>{vs_passed}</strong> | Total: <strong>{vs_total}</strong> |
                Verified: <strong>{vs_ver}</strong> | Unverified: <strong>{vs_unver}</strong> |
                Rejected: <strong>{vs_rej}</strong> | Review Required: <strong>{vs_rev}</strong><br>
                Removed Invalid Evidence IDs: <code class="mono-wrap">{removed_ids}</code>
                {f"<ul>{val_warnings}</ul>" if val_warnings else ""}
            </div>
            <ul class="claims-list">{claims_rows or '<li class="muted">No structured analytical claims recorded.</li>'}</ul>

            {f"<h3>Attack Story Timeline Interpretations</h3><ul class='timeline-list'>{timeline_interp_rows}</ul>" if timeline_interp_rows else ""}

            {f'''<h3>Contextual IOC Interpretations</h3>
            <table>
                <thead><tr><th>IOC Value</th><th>Type</th><th>Context</th><th>Confidence</th><th>Evidence IDs</th></tr></thead>
                <tbody>{ioc_interp_rows}</tbody>
            </table>''' if ioc_interp_rows else ""}

            <div class="grid">
                <div>
                    <h3>Evidence Completeness & Gaps</h3>
                    <p class="muted">Bundle Status: <strong>{trunc_flag}</strong> ({trunc_events_inc}/{trunc_events_tot} events included, {trunc_events_om} omitted)</p>
                    <ul>{gaps_html or "<li class='muted'>None reported</li>"}</ul>
                    <ul>{limits_html}</ul>
                </div>
                <div>
                    <h3>Recommended Follow-Up Actions</h3>
                    <ul>{actions_html or "<li class='muted'>None specified</li>"}</ul>
                </div>
            </div>
        </section>"""

    findings_rows = ""
    for f in findings:
        sev = _esc(f.get("severity"), "Low")
        title = _esc(f.get("title"), "")
        desc = _esc(f.get("description"), "")
        m_id = _esc(f.get("mitre_attack_id"), "N/A")
        ev_ids = ", ".join(_esc(eid) for eid in (f.get("supporting_event_ids") or [])) or "None"
        findings_rows += f"""
        <tr>
            <td><span class="pill pill-neutral">{sev}</span></td>
            <td><strong>{title}</strong></td>
            <td>{desc}</td>
            <td class="mono-wrap">{m_id}</td>
            <td class="mono-wrap">{ev_ids}</td>
        </tr>
        """

    mitre_badges = ""
    for m in mitre:
        t_id = _esc(m.get("technique_id"), "")
        t_name = _esc(m.get("technique_name"), "")
        tactic = _esc(m.get("tactic"), "Unknown")
        m_desc = _esc(m.get("description"), "")
        t_evs = ", ".join(_esc(e) for e in (m.get("supporting_event_ids") or [])) or "None"
        mitre_badges += f"""
        <div class="mitre-card">
            <div class="mitre-head">
                <strong>{t_id}: {t_name}</strong>
                <span class="muted">Tactic: {tactic}</span>
            </div>
            <p>{m_desc}</p>
            <div class="claim-meta">Supporting Events: <code class="mono-wrap">{t_evs}</code></div>
        </div>
        """

    timeline_items = ""
    for t in timeline[:25]:
        ts = _esc(t.get("timestamp"), "No timestamp")
        t_sum = _esc(t.get("summary"), "")
        t_id = _esc(t.get("event_id"), "")
        timeline_items += f"""
        <li class="timeline-entry">
            <span class="mono-wrap muted">{ts}</span>
            {f" <code class='mono-wrap'>[{t_id}]</code>" if t_id else ""}
            <div>{t_sum}</div>
        </li>
        """

    artifacts_html = ""
    for a in artifacts:
        a_name = _esc(a.get("name") or a.get("file_name"), "unnamed")
        a_type = _esc(a.get("type"), "unknown")
        a_syn = bool(a.get("is_synthetic", is_replay))
        a_note = _esc(a.get("provenance_note"), "")
        artifacts_html += (
            f"<li><strong>{a_name}</strong> ({a_type}) "
            + ("<span class='pill pill-warn'>SYNTHETIC PLACEHOLDER</span>" if a_syn else "<span class='pill pill-ok'>LIVE ARTIFACT</span>")
            + (f" — <span class='muted'>{a_note}</span>" if a_note else "")
            + "</li>"
        )

    safe_file_name = _esc(meta.get("file_name"), "N/A")
    safe_file_size = _esc(meta.get("file_size"), "0")
    safe_sha256 = _esc(meta.get("sha256"), "N/A")
    pe_meta = meta.get("pe_metadata") or {}
    safe_entropy = _esc(pe_meta.get("overall_entropy"), "N/A")
    safe_subsystem = _esc(pe_meta.get("subsystem"), "N/A")

    safe_domains = ", ".join(_esc(d) for d in (iocs.get("domains") or [])) or "None"
    safe_ips = ", ".join(_esc(i) for i in (iocs.get("ips") or [])) or "None"
    safe_urls = ", ".join(_esc(u) for u in (iocs.get("urls") or [])) or "None"
    safe_reg = ", ".join(_esc(r) for r in (iocs.get("registry_keys") or [])) or "None"
    safe_dropped_count = len(iocs.get("dropped_files") or [])

    safe_evasion_risk = _esc(limitations.get("sandbox_evasion_risk"), "None")
    safe_confinement = _esc(limitations.get("network_confinement"), "Isolated")
    recs_list = "".join(f"<li>{_esc(r)}</li>" for r in (follow_up.get("recommendations") or []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:;">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>malbox-ai Analysis Report — {analysis_id}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            background-color: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 1.75rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 1.25rem; margin-bottom: 1.5rem; }}
        .logo {{ font-size: 1.45rem; font-weight: 700; color: #38bdf8; letter-spacing: -0.5px; }}
        .card {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 1.35rem; margin-bottom: 1.25rem; break-inside: avoid; }}
        .score-pill {{ background: {badge_color}; color: #ffffff; padding: 0.35rem 0.9rem; border-radius: 9999px; font-weight: 700; font-size: 0.9rem; display: inline-block; }}
        h2 {{ color: #38bdf8; font-size: 1.15rem; margin-top: 0; border-bottom: 1px solid #1e293b; padding-bottom: 0.45rem; }}
        h3 {{ color: #e2e8f0; font-size: 1rem; margin: 1.1rem 0 0.5rem 0; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }}
        th, td {{ padding: 0.6rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
        th {{ background: #1e293b; color: #94a3b8; font-weight: 600; }}
        .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }}
        .mono-wrap {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.82rem; overflow-wrap: anywhere; word-break: break-word; }}
        .muted {{ color: #94a3b8; font-size: 0.85rem; }}
        .prose {{ color: #e2e8f0; font-size: 0.95rem; margin: 0.35rem 0 0.8rem 0; }}
        .banner {{ padding: 14px 18px; border-radius: 6px; margin-bottom: 1.25rem; }}
        .banner-replay {{ background: #1e1b4b; border: 1px solid #6366f1; border-left: 6px solid #818cf8; color: #e0e7ff; }}
        .banner-live {{ background: #14532d; border: 1px solid #22c55e; border-left: 6px solid #4ade80; color: #bbf7d0; }}
        .banner-top {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }}
        .banner-sub {{ margin: 6px 0 0 0; font-size: 0.85rem; }}
        .tag-scenario {{ background: rgba(15, 23, 42, 0.7); padding: 2px 6px; border-radius: 4px; }}
        .pill {{ display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }}
        .pill-replay {{ background: #4f46e5; color: #ffffff; }}
        .pill-live {{ background: #16a34a; color: #ffffff; }}
        .pill-type {{ background: #1e3a8a; color: #bfdbfe; }}
        .pill-status-verified {{ background: #166534; color: #dcfce7; }}
        .pill-status-unverified {{ background: #92400e; color: #fef3c7; }}
        .pill-status-rejected {{ background: #991b1b; color: #fee2e2; }}
        .pill-warn {{ background: #92400e; color: #fef3c7; }}
        .pill-ok {{ background: #166534; color: #dcfce7; }}
        .pill-neutral {{ background: #334155; color: #e2e8f0; }}
        .meta-bar {{ background: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.9rem; font-size: 0.85rem; }}
        .split-metrics {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.75rem; margin-bottom: 1rem; }}
        .metric-box {{ background: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem; }}
        .metric-label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; font-weight: 700; }}
        .metric-value {{ font-size: 1.05rem; font-weight: 700; color: #f8fafc; margin-top: 2px; }}
        .claims-list, .timeline-list {{ list-style: none; padding-left: 0; margin: 0; }}
        .claim-item {{ background: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.65rem; break-inside: avoid; }}
        .claim-rejected {{ border-left: 4px solid #ef4444; }}
        .claim-unverified {{ border-left: 4px solid #f59e0b; }}
        .claim-verified {{ border-left: 4px solid #22c55e; }}
        .claim-head {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; margin-bottom: 0.4rem; }}
        .claim-body {{ color: #f1f5f9; font-size: 0.92rem; }}
        .claim-meta {{ color: #94a3b8; font-size: 0.8rem; margin-top: 0.35rem; }}
        .timeline-entry {{ margin-bottom: 0.65rem; padding-left: 0.75rem; border-left: 2px solid #475569; break-inside: avoid; }}
        .mitre-card {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 0.75rem; margin-bottom: 0.6rem; border-radius: 4px; break-inside: avoid; }}
        .mitre-head {{ display: flex; justify-content: space-between; gap: 0.5rem; margin-bottom: 0.25rem; }}

        @media (max-width: 780px) {{
            body {{ padding: 1rem; }}
            .grid, .split-metrics {{ grid-template-columns: 1fr; }}
        }}

        @page {{ margin: 1.4cm; }}
        @media print {{
            body {{ background-color: #ffffff; color: #0f172a; padding: 0; font-size: 11pt; }}
            .card, .meta-bar, .metric-box, .claim-item, .mitre-card {{ background: #ffffff !important; border: 1px solid #cbd5e1 !important; color: #0f172a !important; }}
            .banner-replay {{ background: #eef2ff !important; border: 1px solid #4f46e5 !important; color: #1e1b4b !important; }}
            .banner-live {{ background: #ecfdf5 !important; border: 1px solid #16a34a !important; color: #14532d !important; }}
            .logo, h2, h3, strong {{ color: #0f172a !important; }}
            .muted, .claim-meta {{ color: #475569 !important; }}
            .prose, .claim-body {{ color: #0f172a !important; }}
            th {{ background: #f1f5f9 !important; color: #0f172a !important; }}
            .pill, .score-pill {{ border: 1px solid #475569 !important; color: #0f172a !important; background: #f8fafc !important; }}
        }}
    </style>
</head>
<body>
    <main class="container">
        <header class="header">
            <div>
                <div class="logo">malbox-ai // Forensic Intelligence Report</div>
                <div class="muted">Task ID: <span class="mono-wrap">{analysis_id}</span> | Generated: {generated_at}</div>
            </div>
            <div>
                <span class="score-pill">Deterministic Risk: {level} ({score}/100)</span>
            </div>
        </header>

        {provenance_banner}

        <section class="card">
            <h2>Executive Summary</h2>
            <p class="prose">{summary}</p>
        </section>

        <div class="grid">
            <section class="card">
                <h2>Sample Metadata</h2>
                <table>
                    <tr><td class="muted">File Name</td><td class="mono-wrap">{safe_file_name}</td></tr>
                    <tr><td class="muted">File Size</td><td class="mono-wrap">{safe_file_size} bytes</td></tr>
                    <tr><td class="muted">SHA-256</td><td class="mono-wrap">{safe_sha256}</td></tr>
                    <tr><td class="muted">Entropy</td><td class="mono-wrap">{safe_entropy}</td></tr>
                    <tr><td class="muted">Subsystem</td><td class="mono-wrap">{safe_subsystem}</td></tr>
                </table>
            </section>
            <section class="card">
                <h2>Extracted Indicators of Compromise (IOCs)</h2>
                <div style="font-size: 0.9rem;">
                    <div><strong>Domains:</strong> <span class="mono-wrap">{safe_domains}</span></div>
                    <div><strong>IPs:</strong> <span class="mono-wrap">{safe_ips}</span></div>
                    <div><strong>URLs:</strong> <span class="mono-wrap">{safe_urls}</span></div>
                    <div><strong>Registry Keys:</strong> <span class="mono-wrap">{safe_reg}</span></div>
                    <div><strong>Dropped Files:</strong> <span class="mono-wrap">{safe_dropped_count} item(s)</span></div>
                </div>
            </section>
        </div>

        <section class="card">
            <h2>Deterministic Behavioral Findings ({len(findings)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Finding Title</th>
                        <th>Description</th>
                        <th>MITRE ATT&amp;CK</th>
                        <th>Supporting Events</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows or '<tr><td colspan="5" class="muted">No deterministic rules triggered.</td></tr>'}
                </tbody>
            </table>
        </section>

        <section class="card">
            <h2>MITRE ATT&amp;CK Matrix Mapping ({len(mitre)})</h2>
            {mitre_badges or '<p class="muted">No MITRE ATT&CK techniques mapped.</p>'}
        </section>

        <section class="card">
            <h2>Execution Telemetry Timeline</h2>
            <ul class="timeline-list">
                {timeline_items or '<li class="muted">No execution timeline entries recorded.</li>'}
            </ul>
        </section>

        <section class="card">
            <h2>Artifacts &amp; Provenance Inventory ({len(artifacts)})</h2>
            <ul>
                {artifacts_html or '<li class="muted">No artifacts recorded.</li>'}
            </ul>
        </section>

        {intel_section}

        <div class="grid">
            <section class="card">
                <h2>Baseline Confidence &amp; Sandbox Limitations</h2>
                <p class="prose">{safe_evasion_risk}</p>
                <div class="muted">Confinement: {safe_confinement}</div>
            </section>
            <section class="card">
                <h2>Baseline Follow-Up Recommendations</h2>
                <ul>
                    {recs_list or '<li class="muted">None recorded.</li>'}
                </ul>
            </section>
        </div>
    </main>
</body>
</html>"""
