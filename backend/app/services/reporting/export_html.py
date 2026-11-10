import html
import json
from typing import Dict, Any

def generate_html_report(report_data: Dict[str, Any]) -> str:
    """
    Renders and exports a secure, standalone HTML intelligence report with
    strict CSP meta headers, complete HTML escaping of untrusted fields, and
    prominent replay data provenance indicators.
    """
    analysis_id = html.escape(str(report_data.get("analysis_id", "N/A")))
    generated_at = html.escape(str(report_data.get("generated_at", "")))
    summary = html.escape(str(report_data.get("executive_summary", "")))
    backend_type = report_data.get("backend_type", "replay")
    is_replay = report_data.get("is_replay", backend_type == "replay")
    replay_scenario = html.escape(str(report_data.get("replay_scenario_id") or "default_fixture"))
    disclaimer = html.escape(str(report_data.get("provenance_disclaimer") or ""))

    meta = report_data.get("sample_metadata", {})
    risk = report_data.get("risk_assessment", {})
    score = int(risk.get("score", 0))
    level = html.escape(str(risk.get("level", "No Suspicious Behavior Observed")))
    findings = report_data.get("findings", [])
    mitre = report_data.get("mitre_attack_mappings", [])
    iocs = report_data.get("extracted_iocs", {})
    timeline = report_data.get("execution_timeline", [])
    limitations = report_data.get("confidence_and_limitations", {})
    follow_up = report_data.get("recommended_follow_up", {})
    intel = report_data.get("intelligence_report")
    intel_section = ""
    if isinstance(intel, dict):
        pm = intel.get("provider_metadata") or {}
        vs = intel.get("validation_summary") or {}
        conf = intel.get("confidence_assessment") or {}
        claims_rows = ""
        for c in intel.get("technical_claims") or []:
            c_type = html.escape(str(c.get("classification", "HYPOTHESIS")))
            c_status = html.escape(str(c.get("validation_status", "VERIFIED")))
            c_text = html.escape(str(c.get("claim_text", "")))
            c_ids = html.escape(", ".join(str(i) for i in (c.get("supporting_evidence_ids") or []))) or "none"
            c_id = html.escape(str(c.get("claim_id", "")))
            claims_rows += (
                f"<li style='margin-bottom:0.6rem;'>"
                f"<strong>{c_id}</strong> "
                f"<span class='badge' style='background:#334155;margin-right:4px;'>{c_type}</span>"
                f"<span class='badge' style='background:#1e3a8a;margin-right:6px;'>{c_status}</span>"
                f"{c_text}"
                f"<div style='color:#94a3b8;font-size:0.8rem;'>Evidence IDs: <code>{c_ids}</code></div>"
                f"</li>"
            )
        intel_narrative = html.escape(str(intel.get("behavioral_narrative", "")))
        intel_mode = html.escape(str(pm.get("mode", "deterministic_mock")))
        intel_provider = html.escape(str(pm.get("provider", "mock")))
        intel_model = html.escape(str(pm.get("model", "n/a")))
        intel_conf = html.escape(str(conf.get("overall_confidence", "n/a")))
        intel_comp = html.escape(str(conf.get("evidence_completeness", "n/a")))
        intel_passed = html.escape(str(vs.get("passed", True)))
        intel_section = f"""
            <div class="card">
                <h2>AI Intelligence Assessment (v2.0)</h2>
                <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.75rem;">
                    Mode: <strong>{intel_mode}</strong> | Provider: <strong>{intel_provider}</strong> ({intel_model}) |
                    Confidence: <strong>{intel_conf}</strong> ({intel_comp}) | Validation Passed: <strong>{intel_passed}</strong>
                </p>
                <p style="color:#e2e8f0;font-size:0.95rem;margin-bottom:1rem;">{intel_narrative}</p>
                <ul style="color:#cbd5e1;font-size:0.9rem;padding-left:1.2rem;">{claims_rows}</ul>
            </div>"""

    level_colors = {
        "Malicious": "#ef4444",
        "Suspicious": "#f97316",
        "Low": "#eab308",
        "Clean": "#22c55e",
        "No Suspicious Behavior Observed": "#3b82f6",
    }
    badge_color = level_colors.get(level, "#3b82f6")

    # Replay Provenance Banner
    if is_replay:
        provenance_banner = f"""
        <div style="background: #1e1b4b; border: 1px solid #6366f1; border-left: 6px solid #818cf8; padding: 14px 18px; border-radius: 6px; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="background: #4f46e5; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px;">REPLAY SIMULATION</span>
                <span style="font-weight: 600; color: #e0e7ff; font-size: 0.95rem;">Synthetic Behavioral Telemetry (Scenario: {replay_scenario})</span>
            </div>
            <p style="margin: 6px 0 0 0; color: #a5b4fc; font-size: 0.85rem;">
                {disclaimer or 'This report was generated using verified offline behavioral telemetry fixtures. No live malware was detonated during this run.'}
            </p>
        </div>
        """
    else:
        provenance_banner = f"""
        <div style="background: #14532d; border: 1px solid #22c55e; border-left: 6px solid #4ade80; padding: 14px 18px; border-radius: 6px; margin-bottom: 1.5rem;">
            <span style="background: #16a34a; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700;">LIVE DETONATION</span>
            <span style="font-weight: 600; color: #bbf7d0; font-size: 0.95rem; margin-left: 8px;">Isolated Hypervisor Sandbox Execution</span>
        </div>
        """

    findings_rows = ""
    for f in findings:
        sev = html.escape(str(f.get("severity", "Low")))
        title = html.escape(str(f.get("title", "")))
        desc = html.escape(str(f.get("description", "")))
        m_id = html.escape(str(f.get("mitre_attack_id") or "N/A"))
        findings_rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #334155;"><span style="background: #334155; padding: 2px 8px; border-radius: 4px; font-weight: bold;">{sev}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-weight: 600;">{title}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{desc}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-family: monospace; color: #38bdf8;">{m_id}</td>
        </tr>
        """

    mitre_badges = ""
    for m in mitre:
        t_id = html.escape(str(m.get("technique_id", "")))
        t_name = html.escape(str(m.get("technique_name", "")))
        tactic = html.escape(str(m.get("tactic", "Unknown")))
        m_desc = html.escape(str(m.get("description", "")))
        mitre_badges += f"""
        <div style="background: #1e293b; border-left: 4px solid #38bdf8; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; font-weight: bold;">
                <span style="color: #38bdf8;">{t_id}: {t_name}</span>
                <span style="color: #94a3b8; font-size: 0.85rem;">Tactic: {tactic}</span>
            </div>
            <p style="margin: 4px 0 0 0; color: #cbd5e1; font-size: 0.9rem;">{m_desc}</p>
        </div>
        """

    timeline_items = ""
    for t in timeline[:25]:
        ts = html.escape(str(t.get("timestamp", "")))
        t_sum = html.escape(str(t.get("summary", "")))
        timeline_items += f"""
        <li style="margin-bottom: 8px; padding-left: 10px; border-left: 2px solid #475569;">
            <span style="font-family: monospace; font-size: 0.8rem; color: #94a3b8;">{ts}</span>
            <div style="font-weight: 500; color: #f1f5f9;">{t_sum}</div>
        </li>
        """

    safe_file_name = html.escape(str(meta.get("file_name", "N/A")))
    safe_file_size = html.escape(str(meta.get("file_size", 0)))
    safe_sha256 = html.escape(str(meta.get("sha256", "N/A")))
    pe_meta = meta.get("pe_metadata", {}) or {}
    safe_entropy = html.escape(str(pe_meta.get("overall_entropy", "N/A")))
    safe_subsystem = html.escape(str(pe_meta.get("subsystem", "N/A")))

    safe_domains = html.escape(", ".join(iocs.get("domains", [])) or "None")
    safe_ips = html.escape(", ".join(iocs.get("ips", [])) or "None")
    safe_reg = html.escape(", ".join(iocs.get("registry_keys", [])) or "None")
    safe_dropped_count = len(iocs.get("dropped_files", []))

    safe_evasion_risk = html.escape(str(limitations.get("sandbox_evasion_risk", "None")))
    safe_confinement = html.escape(str(limitations.get("network_confinement", "Isolated")))

    recs_list = "".join([f"<li>{html.escape(str(r))}</li>" for r in follow_up.get("recommendations", [])])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:;">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>malbox-ai Analysis Report — {analysis_id}</title>
    <style>
        body {{
            background-color: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; margin-bottom: 1.5rem; }}
        .logo {{ font-size: 1.5rem; font-weight: 700; color: #38bdf8; letter-spacing: -0.5px; }}
        .card {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .score-pill {{ background: {badge_color}; color: #ffffff; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: 700; font-size: 0.9rem; }}
        h2 {{ color: #38bdf8; font-size: 1.25rem; margin-top: 0; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
        th {{ background: #1e293b; color: #94a3b8; padding: 10px; font-weight: 600; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.85rem; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo">malbox-ai // Forensic Intelligence</div>
                <div style="color: #64748b; font-size: 0.85rem; margin-top: 4px;">Task ID: {analysis_id} | Generated: {generated_at}</div>
            </div>
            <div>
                <span class="score-pill">Risk: {level} ({score}/100)</span>
            </div>
        </div>

        {provenance_banner}

        <div class="card">
            <h2>Executive Summary</h2>
            <p style="font-size: 1.05rem; color: #e2e8f0; margin-bottom: 0;">{summary}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Sample Metadata</h2>
                <table>
                    <tr><td style="color: #94a3b8;">File Name</td><td class="mono">{safe_file_name}</td></tr>
                    <tr><td style="color: #94a3b8;">File Size</td><td class="mono">{safe_file_size} bytes</td></tr>
                    <tr><td style="color: #94a3b8;">SHA-256</td><td class="mono">{safe_sha256}</td></tr>
                    <tr><td style="color: #94a3b8;">Entropy</td><td class="mono">{safe_entropy}</td></tr>
                    <tr><td style="color: #94a3b8;">Subsystem</td><td class="mono">{safe_subsystem}</td></tr>
                </table>
            </div>
            <div class="card">
                <h2>Extracted Indicators of Compromise (IOCs)</h2>
                <div style="font-size: 0.9rem;">
                    <strong>Contacted Domains:</strong> <span class="mono">{safe_domains}</span><br>
                    <strong>Contacted IPs:</strong> <span class="mono">{safe_ips}</span><br>
                    <strong>Registry Persistence:</strong> <span class="mono">{safe_reg}</span><br>
                    <strong>Dropped Files:</strong> <span class="mono">{safe_dropped_count} item(s)</span>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Behavioral Findings & Evidence Provenance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Finding Title</th>
                        <th>Description</th>
                        <th>MITRE ATT&CK</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>MITRE ATT&CK Matrix Mapping</h2>
            {mitre_badges}
        </div>

        <div class="card">
            <h2>Execution Timeline</h2>
            <ul style="list-style: none; padding-left: 0;">
                {timeline_items}
            </ul>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Confidence & Limitations</h2>
                <p style="color: #cbd5e1; font-size: 0.9rem;">{safe_evasion_risk}</p>
                <div style="color: #94a3b8; font-size: 0.85rem;">Confinement: {safe_confinement}</div>
            </div>
            {intel_section}
            <div class="card">
                <h2>Recommended Follow-up Actions</h2>
                <ul style="color: #cbd5e1; font-size: 0.9rem; padding-left: 1.2rem;">
                    {recs_list}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
