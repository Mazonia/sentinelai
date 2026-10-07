"""
Automated Security Report Generator
Produces HTML (Cyberpunk Dark), Markdown, and JSON Reports.
"""
import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List


class ReportGenerator:
    """Generates audit-ready reports from scan findings"""

    @staticmethod
    def generate_json(data: Dict[str, Any], filepath: Path) -> Path:
        """Export raw scan results to JSON"""
        filepath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return filepath

    @staticmethod
    def generate_markdown(data: Dict[str, Any], filepath: Path) -> Path:
        """Export findings to Markdown format"""
        target = data.get("target", "Target")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = data.get("findings", [])
        recon = data.get("recon", {})

        md = [
            "# 🛡️ SentinelAI Security Audit Report",
            "",
            f"- **Target**: `{target}`",
            f"- **Scan Date**: `{date_str}`",
            f"- **Total Findings**: `{len(findings)}`",
            "",
            "---",
            "",
            "## 🌐 Reconnaissance Summary",
            f"- **Host**: `{recon.get('hostname', 'N/A')}`",
            f"- **IP Addresses**: `{', '.join(recon.get('ip_addresses', [])) or 'N/A'}`",
            f"- **WAF**: `{recon.get('waf') or 'None detected'}`",
            f"- **Open Ports**: `{', '.join(str(p.get('port')) + '/' + p.get('service', '') for p in recon.get('open_ports', [])) or 'None'}`",
            f"- **Technologies**: `{', '.join(recon.get('technologies', [])) or 'N/A'}`",
            "",
            "---",
            "",
            "## 🚨 Vulnerability Findings",
            ""
        ]

        if not findings:
            md.append("✅ **No vulnerabilities detected during this scan.**")
        else:
            md.append("| Severity | Vulnerability | Parameter / Path | CVSS |")
            md.append("| :--- | :--- | :--- | :--- |")
            for f in findings:
                sev = f.get("severity", "MEDIUM")
                title = f.get("title", f.get("type", "Issue"))
                param = f.get("parameter", "N/A")
                cvss = f.get("cvss_score", "N/A")
                md.append(f"| **{sev}** | {title} | `{param}` | {cvss} |")

            md.append("")
            md.append("### Detailed Remediation Guidance")
            for idx, f in enumerate(findings, 1):
                md.append(f"#### {idx}. {f.get('title', f.get('type'))} ({f.get('severity')})")
                md.append(f"- **URL**: `{f.get('url')}`")
                md.append(f"- **Description**: {f.get('description', 'N/A')}")
                md.append(f"- **Remediation**:\n```\n{f.get('remediation', 'N/A')}\n```")
                md.append("")

        filepath.write_text("\n".join(md), encoding="utf-8")
        return filepath

    @staticmethod
    def generate_html(data: Dict[str, Any], filepath: Path) -> Path:
        """Export findings to stunning Dark Cyberpunk HTML report"""
        target = html.escape(str(data.get("target", "Target")))
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = data.get("findings", [])
        recon = data.get("recon", {})

        crit_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
        high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
        med_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
        low_count = sum(1 for f in findings if str(f.get("severity")).upper() in ["LOW", "INFO"])

        finding_cards = []
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "MEDIUM")).upper()
            color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else ("#eab308" if sev == "MEDIUM" else "#3b82f6"))
            title = html.escape(str(f.get("title", f.get("type", "Issue"))))
            url = html.escape(str(f.get("url", "")))
            param = html.escape(str(f.get("parameter", "N/A")))
            remediation = html.escape(str(f.get("remediation", "Review configuration and sanitize input.")))
            cvss = f.get("cvss_score", "N/A")

            card = f"""
            <div class="card" style="border-left: 5px solid {color}; margin-bottom: 1.2rem; background: #111827; border-radius: 12px; overflow: hidden; border: 1px solid #374151;">
                <div style="padding: 1rem 1.5rem; background: rgba(255,255,255,0.02); border-bottom: 1px solid #374151; display: flex; align-items: center; gap: 1rem;">
                    <span style="background: {color}; color: white; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.8rem; font-weight: 700;">{sev}</span>
                    <span style="font-weight: 600; font-size: 1.1rem; flex-grow: 1;">#{idx} {title}</span>
                    <span style="background: #1e293b; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.85rem; color: #94a3b8;">CVSS {cvss}</span>
                </div>
                <div style="padding: 1.5rem;">
                    <p><b>Target URL:</b> <code style="background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8;">{url}</code></p>
                    <p><b>Parameter / Component:</b> <code style="background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8;">{param}</code></p>
                    <div style="margin-top: 1rem; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); padding: 1rem; border-radius: 8px;">
                        <b style="color: #10b981;">💡 Remediation Advice:</b>
                        <pre style="background: #030712; border: 1px solid #1f2937; padding: 1rem; border-radius: 8px; color: #10b981; font-family: monospace; overflow-x: auto; margin-top: 0.5rem;">{remediation}</pre>
                    </div>
                </div>
            </div>"""
            finding_cards.append(card)

        ports_str = html.escape(", ".join(str(p.get("port")) + "/" + p.get("service", "") for p in recon.get("open_ports", [])) or "None detected")
        tech_str = html.escape(", ".join(recon.get("technologies", [])) or "N/A")
        cards_html = "\n".join(finding_cards) if finding_cards else '<div style="padding: 1.5rem; background: #111827; border-radius: 12px; border: 1px solid #374151;">✨ <b>No vulnerabilities detected on target.</b></div>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI Security Report - {target}</title>
    <style>
        body {{
            background: #0b0f19;
            color: #f3f4f6;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border: 1px solid #4338ca;
            padding: 2.5rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-box {{
            background: #111827;
            border: 1px solid #374151;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
        }}
        .stat-box .num {{
            font-size: 2.4rem;
            font-weight: 800;
            margin: 0.2rem 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0 0 0.5rem 0; font-size: 2.2rem; background: linear-gradient(90deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🛡️ SentinelAI Security Audit Report</h1>
            <p style="color: #9ca3af; margin: 0;">Target: <b>{target}</b> | Scanned on: {date_str}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-box"><span style="color: #ef4444; font-weight: bold;">CRITICAL</span><div class="num" style="color: #ef4444;">{crit_count}</div></div>
            <div class="stat-box"><span style="color: #f97316; font-weight: bold;">HIGH</span><div class="num" style="color: #f97316;">{high_count}</div></div>
            <div class="stat-box"><span style="color: #eab308; font-weight: bold;">MEDIUM</span><div class="num" style="color: #eab308;">{med_count}</div></div>
            <div class="stat-box"><span style="color: #3b82f6; font-weight: bold;">LOW / INFO</span><div class="num" style="color: #3b82f6;">{low_count}</div></div>
        </div>

        <div style="background: #111827; border: 1px solid #374151; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem;">
            <h3 style="margin-top: 0;">🌐 Reconnaissance & Target Metadata</h3>
            <p><b>Host:</b> <code style="background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8;">{recon.get("hostname", "N/A")}</code> | <b>IP:</b> <code style="background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8;">{', '.join(recon.get("ip_addresses", [])) or "N/A"}</code> | <b>WAF:</b> <code style="background: #1e293b; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8;">{recon.get("waf") or "None detected"}</code></p>
            <p><b>Open Ports:</b> {ports_str}</p>
            <p><b>Tech Stack:</b> {tech_str}</p>
        </div>

        <h2>🚨 Findings & Remediations ({len(findings)})</h2>
        {cards_html}
    </div>
</body>
</html>"""
        filepath.write_text(html_content, encoding="utf-8")
        return filepath
