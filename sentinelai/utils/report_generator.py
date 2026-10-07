"""
Automated Security Report Generator
Produces HTML (Cyberpunk Dark), Markdown, and JSON Reports.
"""
import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class ReportGenerator:
    """Generates audit-ready reports from scan findings"""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        self.data = data or {}

    def save_all(self, output_dir: str = "reports") -> Dict[str, str]:
        """Save HTML, Markdown, and JSON reports to output directory"""
        out_p = Path(output_dir)
        out_p.mkdir(parents=True, exist_ok=True)
        target = self.data.get("target", "scan")
        clean_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        html_p = out_p / f"sentinel_{clean_target}.html"
        md_p = out_p / f"sentinel_{clean_target}.md"
        json_p = out_p / f"sentinel_{clean_target}.json"

        self.generate_html(html_p)
        self.generate_markdown(md_p)
        self.generate_json(json_p)

        return {
            "html": str(html_p),
            "markdown": str(md_p),
            "json": str(json_p)
        }

    def generate_json(self_or_data, arg1=None, arg2=None) -> Any:
        """Export raw scan results to JSON (supports instance and static calls)"""
        if isinstance(self_or_data, ReportGenerator):
            data = arg1 if isinstance(arg1, dict) else self_or_data.data
            filepath = arg2 if isinstance(arg1, dict) else arg1
        else:
            data = self_or_data
            filepath = arg1

        content = json.dumps(data, indent=2, default=str)
        if filepath:
            fp = Path(filepath)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            return fp
        return content

    def generate_markdown(self_or_data, arg1=None, arg2=None) -> Any:
        """Export findings to Markdown format (supports instance and static calls)"""
        if isinstance(self_or_data, ReportGenerator):
            data = arg1 if isinstance(arg1, dict) else self_or_data.data
            filepath = arg2 if isinstance(arg1, dict) else arg1
        else:
            data = self_or_data
            filepath = arg1

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

        full_md = "\n".join(md)
        if filepath:
            fp = Path(filepath)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(full_md, encoding="utf-8")
            return fp
        return full_md

    def generate_html(self_or_data, arg1=None, arg2=None) -> Any:
        """Export findings to stunning Dark Cyberpunk HTML report (supports instance and static calls)"""
        if isinstance(self_or_data, ReportGenerator):
            data = arg1 if isinstance(arg1, dict) else self_or_data.data
            filepath = arg2 if isinstance(arg1, dict) else arg1
        else:
            data = self_or_data
            filepath = arg1

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
                    <span style="background: {color}; color: #000; font-weight: 800; font-size: 0.75rem; padding: 0.25rem 0.6rem; border-radius: 9999px;">{sev}</span>
                    <span style="color: #f3f4f6; font-size: 1.1rem; font-weight: 600;">{title}</span>
                    <span style="margin-left: auto; color: #9ca3af; font-size: 0.85rem;">CVSS: <strong style="color: {color};">{cvss}</strong></span>
                </div>
                <div style="padding: 1.2rem 1.5rem; color: #d1d5db; font-size: 0.95rem;">
                    <p style="margin: 0 0 0.5rem 0;"><strong>Vulnerable URL:</strong> <a href="{url}" target="_blank" style="color: #38bdf8; word-break: break-all;">{url}</a></p>
                    <p style="margin: 0 0 0.8rem 0;"><strong>Parameter:</strong> <code>{param}</code></p>
                    <div style="background: #1f2937; padding: 1rem; border-radius: 8px; border: 1px solid #374151; margin-top: 0.8rem;">
                        <span style="color: #10b981; font-weight: 600; display: block; margin-bottom: 0.3rem;">🛡️ Remediation Advice:</span>
                        <pre style="margin: 0; color: #e5e7eb; font-size: 0.85rem; white-space: pre-wrap; font-family: monospace;">{remediation}</pre>
                    </div>
                </div>
            </div>"""
            finding_cards.append(card)

        cards_html = "\n".join(finding_cards) if finding_cards else "<p style='color: #10b981; font-size: 1.2rem;'>No security vulnerabilities detected during this audit.</p>"

        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI Audit Report — {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --surface: #0f172a;
            --border: #1e293b;
            --text: #f8fafc;
            --primary: #38bdf8;
            --cyan-glow: 0 0 20px rgba(56, 189, 248, 0.2);
        }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: 'Outfit', -apple-system, sans-serif;
            margin: 0;
            padding: 2rem 1.5rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9));
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--cyan-glow);
        }}
        .badge {{
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.2rem;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        }}
        code {{
            background: #1e293b;
            color: #38bdf8;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <h1 style="margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 0.6rem;">
                        <span>🛡️</span> SentinelAI Audit Report
                    </h1>
                    <p style="margin: 0.5rem 0 0 0; color: #94a3b8; font-size: 1rem;">
                        Target: <strong style="color: #38bdf8;">{target}</strong> | Generated on {date_str}
                    </p>
                </div>
                <div class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid #38bdf8;">
                    AI-Verified Scan
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card" style="border-top: 3px solid #ef4444;">
                    <div style="color: #94a3b8; font-size: 0.85rem;">CRITICAL</div>
                    <div class="stat-value" style="color: #ef4444;">{crit_count}</div>
                </div>
                <div class="stat-card" style="border-top: 3px solid #f97316;">
                    <div style="color: #94a3b8; font-size: 0.85rem;">HIGH</div>
                    <div class="stat-value" style="color: #f97316;">{high_count}</div>
                </div>
                <div class="stat-card" style="border-top: 3px solid #eab308;">
                    <div style="color: #94a3b8; font-size: 0.85rem;">MEDIUM</div>
                    <div class="stat-value" style="color: #eab308;">{med_count}</div>
                </div>
                <div class="stat-card" style="border-top: 3px solid #3b82f6;">
                    <div style="color: #94a3b8; font-size: 0.85rem;">LOW / INFO</div>
                    <div class="stat-value" style="color: #3b82f6;">{low_count}</div>
                </div>
            </div>
        </div>

        <div style="margin-bottom: 2rem; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 1.5rem;">
            <h2 style="margin: 0 0 1rem 0; font-size: 1.3rem; color: #f8fafc;">🌐 Reconnaissance & Fingerprint Intelligence</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; font-size: 0.95rem;">
                <div><span style="color: #94a3b8;">Hostname:</span> <code>{recon.get('hostname', 'N/A')}</code></div>
                <div><span style="color: #94a3b8;">IPs:</span> <code>{', '.join(recon.get('ip_addresses', [])) or 'N/A'}</code></div>
                <div><span style="color: #94a3b8;">WAF:</span> <code>{recon.get('waf') or 'None detected'}</code></div>
                <div><span style="color: #94a3b8;">Open Ports:</span> <code>{', '.join(str(p.get('port')) for p in recon.get('open_ports', [])) or 'None'}</code></div>
            </div>
        </div>

        <div>
            <h2 style="font-size: 1.4rem; margin-bottom: 1.2rem; color: #f8fafc;">🚨 Discovered Vulnerabilities & Remediation</h2>
            {cards_html}
        </div>
    </div>
</body>
</html>"""

        if filepath:
            fp = Path(filepath)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(full_html, encoding="utf-8")
            return fp
        return full_html
