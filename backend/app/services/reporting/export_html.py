import json
from typing import Dict, Any

def generate_html_report(report_data: Dict[str, Any]) -> str:
    analysis_id = report_data.get("analysis_id", "N/A")
    generated_at = report_data.get("generated_at", "")
    summary = report_data.get("executive_summary", "")
    meta = report_data.get("sample_metadata", {})
    risk = report_data.get("risk_assessment", {})
    score = risk.get("score", 0)
    level = risk.get("level", "Clean")
    findings = report_data.get("findings", [])
    mitre = report_data.get("mitre_attack_mappings", [])
    iocs = report_data.get("extracted_iocs", {})
    timeline = report_data.get("execution_timeline", [])
    limitations = report_data.get("confidence_and_limitations", {})
    follow_up = report_data.get("recommended_follow_up", {})

    level_colors = {
        "Malicious": "#ef4444",
        "Suspicious": "#f97316",
        "Low": "#eab308",
        "Clean": "#22c55e",
    }
    badge_color = level_colors.get(level, "#94a3b8")

    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "Low")
        findings_rows += f"""
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #334155;"><span style="background: #334155; padding: 2px 8px; border-radius: 4px; font-weight: bold;">{sev}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-weight: 600;">{f.get('title', '')}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155;">{f.get('description', '')}</td>
            <td style="padding: 10px; border-bottom: 1px solid #334155; font-family: monospace; color: #38bdf8;">{f.get('mitre_attack_id') or 'N/A'}</td>
        </tr>
        """

    mitre_badges = ""
    for m in mitre:
        mitre_badges += f"""
        <div style="background: #1e293b; border-left: 4px solid #38bdf8; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; font-weight: bold;">
                <span style="color: #38bdf8;">{m.get('technique_id')}: {m.get('technique_name')}</span>
                <span style="color: #94a3b8; font-size: 0.85rem;">Tactic: {m.get('tactic')}</span>
            </div>
            <p style="margin: 4px 0 0 0; color: #cbd5e1; font-size: 0.9rem;">{m.get('description')}</p>
        </div>
        """

    timeline_items = ""
    for t in timeline[:20]:
        timeline_items += f"""
        <li style="margin-bottom: 8px; padding-left: 10px; border-left: 2px solid #475569;">
            <span style="font-family: monospace; font-size: 0.8rem; color: #94a3b8;">{t.get('timestamp')}</span>
            <div style="font-weight: 500; color: #f1f5f9;">{t.get('summary')}</div>
        </li>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
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
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
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
                <span class="score-pill">Risk: {level.upper()} ({score}/100)</span>
            </div>
        </div>

        <div class="card">
            <h2>Executive Summary</h2>
            <p style="font-size: 1.05rem; color: #e2e8f0; margin-bottom: 0;">{summary}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Sample Metadata</h2>
                <table>
                    <tr><td style="color: #94a3b8;">File Name</td><td class="mono">{meta.get('file_name')}</td></tr>
                    <tr><td style="color: #94a3b8;">File Size</td><td class="mono">{meta.get('file_size')} bytes</td></tr>
                    <tr><td style="color: #94a3b8;">SHA-256</td><td class="mono">{meta.get('sha256')}</td></tr>
                    <tr><td style="color: #94a3b8;">Entropy</td><td class="mono">{meta.get('pe_metadata', {}).get('overall_entropy', 'N/A')}</td></tr>
                    <tr><td style="color: #94a3b8;">Subsystem</td><td class="mono">{meta.get('pe_metadata', {}).get('subsystem', 'N/A')}</td></tr>
                </table>
            </div>
            <div class="card">
                <h2>Extracted Indicators of Compromise (IOCs)</h2>
                <div style="font-size: 0.9rem;">
                    <strong>Contacted Domains:</strong> <span class="mono">{', '.join(iocs.get('domains', [])) or 'None'}</span><br>
                    <strong>Contacted IPs:</strong> <span class="mono">{', '.join(iocs.get('ips', [])) or 'None'}</span><br>
                    <strong>Registry Persistence:</strong> <span class="mono">{', '.join(iocs.get('registry_keys', [])) or 'None'}</span><br>
                    <strong>Dropped Files:</strong> <span class="mono">{len(iocs.get('dropped_files', []))} item(s)</span>
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
                <p style="color: #cbd5e1; font-size: 0.9rem;">{limitations.get('sandbox_evasion_risk', 'None')}</p>
                <div style="color: #94a3b8; font-size: 0.85rem;">Confinement: {limitations.get('network_confinement', 'Isolated')}</div>
            </div>
            <div class="card">
                <h2>Recommended Follow-up Actions</h2>
                <ul style="color: #cbd5e1; font-size: 0.9rem; padding-left: 1.2rem;">
                    {''.join([f'<li>{r}</li>' for r in follow_up.get('recommendations', [])])}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
