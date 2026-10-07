"""
SentinelAI Command-Line Interface Entry Point
Supports both direct subcommands and rich interactive dashboard mode.
"""
import sys
import asyncio
from pathlib import Path

# Fix Windows console UTF-8 output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from sentinelai.cli.menu import InteractiveDashboard
from sentinelai.core.standalone_scanner import StandaloneScanner
from sentinelai.core.http_client import AsyncHTTPClient
from sentinelai.modules.recon_detector import ReconDetector
from sentinelai.modules.dir_fuzzer import DirFuzzer
from sentinelai.utils.report_generator import ReportGenerator


def print_help():
    print("""
🛡️ SentinelAI - AI-Powered Offensive Security & Vulnerability Arsenal

Usage:
    sentinelai                     Launch interactive numbered terminal console (Recommended)
    sentinelai scan <target_url>   Run full automated vulnerability scan on target
    sentinelai copilot             Launch interactive AI Security Copilot terminal chat
    sentinelai recon <domain>      Perform OSINT & Reconnaissance on domain
    sentinelai fuzz <target_url>   Fuzz sensitive files & hidden paths on target
    sentinelai tools               Open the curated security tools arsenal
    sentinelai reports             Browse and open generated security audit reports
    sentinelai api                 Start local FastAPI backend at http://127.0.0.1:8000
    sentinelai --help              Show this help message
""")


def main():
    if len(sys.argv) == 1:
        InteractiveDashboard.main_menu()
        return

    cmd = sys.argv[1].lower().strip()

    if cmd in ("--help", "-h", "help"):
        print_help()
    elif cmd in ("copilot", "ai", "chat"):
        InteractiveDashboard.run_copilot_flow()
    elif cmd == "scan":
        if len(sys.argv) < 3:
            InteractiveDashboard.run_full_scan_flow()
            return
        target = sys.argv[2]
        InteractiveDashboard.session_target = target
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
            InteractiveDashboard.run_recon_flow()
            return
        target = sys.argv[2]
        InteractiveDashboard.session_target = target
        print(f"[*] Starting OSINT & Reconnaissance on: {target}")
        recon = ReconDetector()
        res = asyncio.run(recon.scan_domain(target))
        print(f"[+] Hostname: {res['hostname']}")
        print(f"[+] IP Addresses: {', '.join(res['ip_addresses'])}")
        print(f"[+] WAF: {res['waf']}")
        print(f"[+] Open Ports: {res['open_ports']}")
        print(f"[+] Subdomains ({len(res['subdomains'])}): {res['subdomains'][:10]}")
    elif cmd == "fuzz":
        if len(sys.argv) < 3:
            InteractiveDashboard.run_fuzzer_flow()
            return
        target = sys.argv[2]
        InteractiveDashboard.session_target = target
        print(f"[*] Starting Fast Path Fuzzing on: {target}")
        async def _run_fuzz():
            client = AsyncHTTPClient(timeout=10, max_concurrent=25)
            fuzzer = DirFuzzer(client, concurrency=25)
            res = await fuzzer.scan([target])
            await client.close()
            return res
        findings = asyncio.run(_run_fuzz())
        print(f"[+] Discovered {len(findings)} sensitive or active endpoints:")
        for f in findings:
            print(f"    [{f['severity']}] {f['parameter']} -> {f['evidence']}")
    elif cmd in ("tools", "arsenal"):
        InteractiveDashboard.run_arsenal_flow()
    elif cmd in ("reports", "report"):
        InteractiveDashboard.run_reports_flow()
    elif cmd in ("api", "server"):
        InteractiveDashboard.run_server_flow()
    else:
        print(f"Unknown command '{cmd}'. Launching interactive menu...")
        InteractiveDashboard.main_menu()


if __name__ == "__main__":
    main()
