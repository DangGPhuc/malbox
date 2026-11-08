from typing import Dict, Any

def generate_html_report(report_data: Dict[str, Any]) -> str:
    """Renders a standalone forensic HTML report from report JSON data."""
    # Will be fully fleshed out with dark theme in Phase 2
    analysis_id = report_data.get("analysis_id", "Unknown")
    summary = report_data.get("executive_summary", "No summary provided.")
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>malbox-ai Analysis Report - {analysis_id}</title>
    <style>
        body {{ background: #0b0f19; color: #f1f5f9; font-family: sans-serif; padding: 2rem; }}
        h1 {{ color: #38bdf8; }}
        .card {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <h1>malbox-ai Forensic Analysis Report</h1>
    <div class="card">
        <h3>Analysis ID: {analysis_id}</h3>
        <p>{summary}</p>
    </div>
</body>
</html>"""
