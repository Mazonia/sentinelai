"""
SentinelAI Command-Line Interface Entry Point
Supports both direct subcommands and rich interactive dashboard mode.
"""
import sys
import asyncio
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from sentinelai.cli.menu import InteractiveDashboard
from sentinelai.core.standalone_scanner import StandaloneScanner
from sentinelai.modules.recon_detector import ReconDetector
from sentinelai.utils.report_generator import ReportGenerator


def print_help():
    print("""
SentinelAI - AI-Powered Offensive Security & Vulnerability Arsenal

Usage:
    python -m sentinelai.cli.main                     Launch interactive terminal dashboard
    python -m sentinelai.cli.main scan <target_url>   Run full automated vulnerability scan
    python -m sentinelai.cli.main recon <domain>      Perform OSINT & Reconnaissance on domain
    python -m sentinelai.cli.main tools               Open the curated security tools arsenal
    python -m sentinelai.cli.main --help              Show this help message
""")


def main():
    if len(sys.argv) == 1:
        # Launch Interactive Dashboard
        InteractiveDashboard.main_menu()
        return

    cmd = sys.argv[1].lower().strip()

    if cmd in ("--help", "-h", "help"):
        print_help()
    elif cmd == "scan":
        if len(sys.argv) < 3:
            print("Usage: python -m sentinelai.cli.main scan <target_url>")
            sys.exit(1)
        target = sys.argv[2]
        print(f"[*] Starting SentinelAI scan on: {target}")
        scanner = StandaloneScanner()
        results = asyncio.run(scanner.run_full_scan(target, enable_ai=True))
        InteractiveDashboard.display_scan_results(results)

        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        html_p = ReportGenerator.generate_html(results, reports_dir / f"sentinel_{safe_target}.html")
        md_p = ReportGenerator.generate_markdown(results, reports_dir / f"sentinel_{safe_target}.md")
        print(f"[+] Audit HTML report saved: {html_p.resolve()}")
        print(f"[+] Audit Markdown report saved: {md_p.resolve()}")
    elif cmd == "recon":
        if len(sys.argv) < 3:
            print("Usage: python -m sentinelai.cli.main recon <domain>")
            sys.exit(1)
        target = sys.argv[2]
        print(f"[*] Starting OSINT & Reconnaissance on: {target}")
        recon = ReconDetector()
        res = asyncio.run(recon.scan_domain(target))
        print(f"[+] Hostname: {res['hostname']}")
        print(f"[+] IP Addresses: {', '.join(res['ip_addresses'])}")
        print(f"[+] WAF: {res['waf']}")
        print(f"[+] Open Ports: {res['open_ports']}")
        print(f"[+] Subdomains ({len(res['subdomains'])}): {res['subdomains'][:10]}")
    elif cmd in ("tools", "arsenal"):
        InteractiveDashboard.run_arsenal_flow()
    else:
        print(f"Unknown command '{cmd}'. Use --help for options.")
        sys.exit(1)


if __name__ == "__main__":
    main()
