"""
Interactive Rich Terminal Dashboard & High-Efficiency Arsenal for SentinelAI
Designed for zero-typing navigation: users simply enter numbers (1, 2, 3...)
to execute complete workflows, targeted audits, and external tools with
persistent target memory, 1-click auto-installation, and live execution logging.
"""
import asyncio
import os
import sys
import webbrowser
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ..modules.arsenal import ToolArsenal, ARSENAL_CATEGORIES
from ..modules.recon_detector import ReconDetector
from ..modules.dir_fuzzer import DirFuzzer
from ..core.standalone_scanner import StandaloneScanner
from ..core.http_client import AsyncHTTPClient
from ..utils.report_generator import ReportGenerator
from ..modules.injection_detector import InjectionDetector
from ..modules.xss_detector import XSSDetector
from ..modules.cors_ssrf_detector import CORSSSRFDetector
from ..modules.traversal_detector import PathTraversalDetector
from ..modules.config_detector import ConfigDetector

console = Console(force_terminal=True, highlight=False)

BANNER = """[bold cyan]
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝[/bold cyan]
      [bold red]⚡ AI-POWERED OFFENSIVE SECURITY & PENETRATION TESTING ARSENAL ⚡[/bold red]
"""


class InteractiveDashboard:
    """Main interactive terminal application with persistent session memory"""

    session_target: Optional[str] = None
    last_report_files: Dict[str, str] = {}

    @classmethod
    def display_banner(cls):
        console.clear()
        console.print(BANNER)
        target_display = f"[bold green]{cls.session_target}[/bold green]" if cls.session_target else "[dim]Not Set[/dim]"
        console.print(Panel.fit(
            f"[bold white]Active Target:[/bold white] {target_display}  "
            f"[dim]|[/dim]  [cyan]Tip: Enter single-digit numbers ([bold yellow]1-9[/bold yellow]) or shorthand commands ([bold]scan[/bold], [bold]recon[/bold], [bold]fuzz[/bold], [bold]tools[/bold])[/cyan]",
            border_style="cyan"
        ))

    @classmethod
    def get_target_input(cls, prompt_msg: str = "Enter Target URL / Domain") -> Optional[str]:
        """Prompt user for target with memory fallback so user can just hit Enter"""
        default_val = cls.session_target or "https://example.com"
        choice = Prompt.ask(f"\n[bold cyan]{prompt_msg}[/bold cyan]", default=default_val).strip()
        if not choice or choice == "0":
            return None
        if not choice.startswith("http://") and not choice.startswith("https://") and not choice.startswith("127."):
            if "." in choice:
                choice = f"https://{choice}"
        cls.session_target = choice
        return choice

    @classmethod
    def main_menu(cls):
        """Root interactive numbered menu loop"""
        while True:
            cls.display_banner()
            table = Table(title="[bold yellow]SENTINELAI INTERACTIVE CONSOLE[/bold yellow]", border_style="blue", show_header=True)
            table.add_column("#", style="bold green", width=4)
            table.add_column("Security Module / Workflow", style="bold white", width=36)
            table.add_column("Description / Capability", style="dim")

            table.add_row("1", "⚡ Multi-Task Assessment Workflows", "1-Click chained presets (Perimeter, Content, API, Full)")
            table.add_row("2", "🎯 Full Deep Vulnerability Scan", "Crawl, OWASP audit suite, AI analysis & report generation")
            table.add_row("3", "🔍 Reconnaissance & OSINT Engine", "DNS, certificate subdomains, 22-port scanner, WAF identification")
            table.add_row("4", "📂 Fast Sensitive File Fuzzer", "Multi-threaded discovery of .env, .git, backups, SQL & APIs")
            table.add_row("5", "🧪 Targeted Vulnerability Tester", "Directly audit SQLi, XSS, CORS, SSRF, LFI, and Security Headers")
            table.add_row("6", "🧰 Security Tools Arsenal", "26+ Tools across 10 Categories with 1-Click Auto-Install & Logs")
            table.add_row("7", "📄 View & Open Audit Reports", "Browse, read, and 1-click open Cyberpunk HTML reports in browser")
            table.add_row("8", "🌐 Start SentinelAI REST API Server", "Launch FastAPI backend on localhost:8000 + Swagger UI docs")
            table.add_row("9", "🎯 Set / Change Active Target", f"Configure session memory target [{cls.session_target or 'None'}]")
            table.add_row("0", "🚪 Exit SentinelAI", "Quit framework")

            console.print(table)
            choice = Prompt.ask("\n[bold cyan]Select an option [0-9][/bold cyan]", default="1").strip().lower()

            if choice in ("1", "workflow", "workflows"):
                cls.run_workflows_flow()
            elif choice in ("2", "scan"):
                cls.run_full_scan_flow()
            elif choice in ("3", "recon"):
                cls.run_recon_flow()
            elif choice in ("4", "fuzz"):
                cls.run_fuzzer_flow()
            elif choice in ("5", "audit", "test"):
                cls.run_targeted_audit_flow()
            elif choice in ("6", "tools", "arsenal"):
                cls.run_arsenal_flow()
            elif choice in ("7", "reports", "report"):
                cls.run_reports_flow()
            elif choice in ("8", "api", "server"):
                cls.run_server_flow()
            elif choice in ("9", "target"):
                cls.set_target_flow()
            elif choice in ("0", "exit", "quit", "q"):
                console.print("\n[bold green]Stay safe! Exiting SentinelAI...[/bold green]\n")
                sys.exit(0)
            else:
                console.print("[red]Invalid selection! Enter a number between 0 and 9.[/red]")
                Prompt.ask("Press Enter to continue")

    @classmethod
    def set_target_flow(cls):
        """Configure session target"""
        console.print(Panel("[bold cyan]Session Target Manager[/bold cyan]\nSet a base target URL or domain to reuse across all menus."))
        new_target = cls.get_target_input("Enter New Target URL or Domain")
        if new_target:
            console.print(f"[bold green]✔ Target updated to:[/bold green] {cls.session_target}")
        Prompt.ask("\nPress Enter to return to main menu")

    @classmethod
    def run_workflows_flow(cls):
        """1-Click Chained Multi-Task Security Workflows"""
        while True:
            cls.display_banner()
            console.print("[bold yellow]⚡ MULTI-TASK AUTOMATED WORKFLOWS (Chained 1-Click Tasks)[/bold yellow]\n")
            console.print("[1] 🌐 Perimeter & Infrastructure Recon  - OSINT + DNS + 22 Ports + WAF + Headers (Fast ~10s)")
            console.print("[2] 📂 Content & Sensitive File Discovery - Crawl + 50 Paths + Configs + Backups + LFI (~25s)")
            console.print("[3] 🔌 API & Endpoint Attack Surface     - Swagger/OpenAPI + GraphQL + CORS + SSRF Vectors (~20s)")
            console.print("[4] 🛡️ Complete Full-Scope Assessment     - Recon -> Crawl -> Full 9-Module Audit -> AI Patches")
            console.print("[0] 🔙 Back to Main Menu\n")

            wf_choice = Prompt.ask("Select workflow [0-4]", default="1")
            if wf_choice == "0":
                break

            target = cls.get_target_input("Target URL for Workflow Execution")
            if not target:
                continue

            scanner = StandaloneScanner()
            results = {}

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Running automated workflow...", total=100)

                def update_cb(desc: str, pct: int):
                    progress.update(task, description=f"[cyan]{desc}[/cyan]", completed=pct)

                if wf_choice == "1":
                    results = asyncio.run(scanner.run_perimeter_recon(target, progress_cb=update_cb))
                elif wf_choice == "2":
                    results = asyncio.run(scanner.run_content_discovery(target, progress_cb=update_cb))
                elif wf_choice == "3":
                    results = asyncio.run(scanner.run_api_discovery(target, progress_cb=update_cb))
                elif wf_choice == "4":
                    results = asyncio.run(scanner.run_full_scan(target, enable_ai=True, progress_cb=update_cb))

            cls.display_scan_results(results)

            # Auto-save report
            out_dir = Path("reports")
            out_dir.mkdir(exist_ok=True)
            safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
            html_p = ReportGenerator.generate_html(results, out_dir / f"sentinel_{safe_target}.html")
            md_p = ReportGenerator.generate_markdown(results, out_dir / f"sentinel_{safe_target}.md")
            console.print(f"\n[bold green]✔ Reports generated in ./reports/[/bold green]")

            # Follow-up actions
            while True:
                console.print("\n[bold yellow]Next Action:[/bold yellow]")
                console.print("[1] 🌐 Open HTML Report in Default Browser")
                console.print("[2] 📄 Print Markdown Summary")
                console.print("[0] 🔙 Return to Workflows Menu")

                act = Prompt.ask("Select action", default="1")
                if act == "1":
                    try:
                        webbrowser.open(html_p.resolve().as_uri())
                        console.print("[bold green]✔ Opened report in browser![/bold green]")
                    except Exception as e:
                        console.print(f"[red]Could not open browser: {e}[/red]")
                elif act == "2":
                    console.print(Panel(md_p.read_text(encoding="utf-8"), title="Markdown Report", border_style="cyan"))
                elif act == "0":
                    break

    @classmethod
    def run_full_scan_flow(cls):
        """Guided automated security scan with numbered post-actions"""
        console.print(Panel("[bold yellow]🎯 Full Target Vulnerability Scan & AI Audit[/bold yellow]\n"
                            "Crawls endpoints, runs injection, XSS, SSRF, LFI, and misconfiguration suites."))
        target = cls.get_target_input("Target URL to Scan")
        if not target:
            return

        console.print("\n[bold]Select Scan Intensity:[/bold]")
        console.print("[1] Standard Audit (Medium intensity, optimal speed & depth) [Recommended]")
        console.print("[2] Fast Scan (Top endpoints & error-based checks only)")
        console.print("[3] Deep Audit (High intensity, exhaustive payloads)")
        intensity_choice = Prompt.ask("Select intensity", default="1")

        console.print("\n[bold]AI Correlation & Remediation Guidance:[/bold]")
        console.print("[1] Enabled (AI analyzes findings and generates patches) [Recommended]")
        console.print("[2] Disabled (Heuristic baseline only)")
        ai_choice = Prompt.ask("Select option", default="1")
        enable_ai = (ai_choice != "2")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Initializing SentinelAI Engine...", total=100)

            def update_progress(desc: str, pct: int):
                progress.update(task, description=f"[cyan]{desc}[/cyan]", completed=pct)

            scanner = StandaloneScanner()
            results = asyncio.run(scanner.run_full_scan(target, enable_ai=enable_ai, progress_cb=update_progress))

        cls.display_scan_results(results)

        out_dir = Path("reports")
        out_dir.mkdir(exist_ok=True)
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        html_p = ReportGenerator.generate_html(results, out_dir / f"sentinel_{safe_target}.html")
        md_p = ReportGenerator.generate_markdown(results, out_dir / f"sentinel_{safe_target}.md")
        json_p = ReportGenerator.generate_json(results, out_dir / f"sentinel_{safe_target}.json")

        console.print(f"\n[bold green]✔ Reports generated in ./reports/[/bold green]")

        while True:
            console.print("\n[bold yellow]What would you like to do next?[/bold yellow]")
            console.print("[1] 🌐 Open Cyberpunk HTML Report in Default Browser")
            console.print("[2] 📄 Print Markdown Report Summary in Terminal")
            console.print("[3] 📂 Fuzz Hidden Files on this Target")
            console.print("[4] 🔍 Run Domain Recon on this Target")
            console.print("[5] 🎯 Scan a Different Target")
            console.print("[0] 🔙 Return to Main Menu")

            post_choice = Prompt.ask("Select action", default="1")
            if post_choice == "1":
                try:
                    webbrowser.open(html_p.resolve().as_uri())
                    console.print("[bold green]✔ Opened report in default browser![/bold green]")
                except Exception as e:
                    console.print(f"[red]Could not open browser: {e}[/red]")
            elif post_choice == "2":
                console.print(Panel(md_p.read_text(encoding="utf-8"), title="Markdown Report", border_style="cyan"))
            elif post_choice == "3":
                cls.run_fuzzer_flow()
                break
            elif post_choice == "4":
                cls.run_recon_flow()
                break
            elif post_choice == "5":
                cls.session_target = None
                cls.run_full_scan_flow()
                break
            elif post_choice == "0":
                break

    @classmethod
    def display_scan_results(cls, results: dict):
        console.print("\n[bold green]========== SCAN COMPLETED ==========[/bold green]\n")
        recon = results.get("recon", {})
        if recon:
            console.print(Panel(
                f"[bold]Target:[/bold] {results.get('target')}\n"
                f"[bold]Host IP:[/bold] {', '.join(recon.get('ip_addresses', [])) or 'N/A'}\n"
                f"[bold]WAF Detected:[/bold] {recon.get('waf') or 'None detected'}\n"
                f"[bold]Open Ports:[/bold] {', '.join(str(p['port']) for p in recon.get('open_ports', [])) or 'None'}\n"
                f"[bold]Discovered Subdomains:[/bold] {len(recon.get('subdomains', []))}",
                title="[bold cyan]Reconnaissance Overview[/bold cyan]",
                border_style="blue"
            ))

        findings = results.get("findings", [])
        if not findings:
            console.print("[bold green]✨ No security vulnerabilities detected on target.[/bold green]")
            return

        table = Table(title=f"[bold red]Identified Vulnerabilities ({len(findings)})[/bold red]", border_style="red")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Vulnerability", style="bold white")
        table.add_column("CVSS", width=6)
        table.add_column("Parameter / URL", style="cyan")

        for f in findings:
            sev = str(f.get("severity", "MEDIUM")).upper()
            color = "red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else "cyan")
            table.add_row(
                f"[{color}]{sev}[/{color}]",
                f.get("title", f.get("type")),
                str(f.get("cvss_score", "N/A")),
                str(f.get("parameter", f.get("url", "")))[:40]
            )
        console.print(table)

    @classmethod
    def run_recon_flow(cls):
        """Guided domain reconnaissance with chained actions"""
        console.print(Panel("[bold cyan]🔍 Domain OSINT & Reconnaissance Engine[/bold cyan]\n"
                            "Discovers subdomains, scans open ports, identifies WAFs, and fingerprints technologies."))
        target = cls.get_target_input("Domain or URL to Recon")
        if not target:
            return

        clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        with console.status(f"[bold cyan]Running OSINT & port scans on {clean_domain}...[/bold cyan]"):
            recon = ReconDetector()
            results = asyncio.run(recon.scan_domain(clean_domain))

        table = Table(title=f"[bold cyan]RECONNAISSANCE INTELLIGENCE — {clean_domain}[/bold cyan]", border_style="cyan")
        table.add_column("Attribute", style="bold white", width=20)
        table.add_column("Discovery", style="green")

        table.add_row("Hostname", results["hostname"])
        table.add_row("IP Addresses", ", ".join(results["ip_addresses"]) or "None")
        table.add_row("WAF Firewall", results["waf"] or "None detected")
        table.add_row("Server Banner", results["server_banner"] or "Hidden")
        table.add_row("Technologies", ", ".join(results["technologies"]) or "N/A")
        table.add_row("Open Ports", ", ".join(f"{p['port']}/{p['service']}" for p in results["open_ports"]) or "None")
        table.add_row("Subdomains Found", f"{len(results['subdomains'])} subdomains")

        console.print(table)

        if results["subdomains"]:
            sub_panel = "\n".join(results["subdomains"][:25])
            if len(results["subdomains"]) > 25:
                sub_panel += f"\n...and {len(results['subdomains']) - 25} more"
            console.print(Panel(sub_panel, title="Discovered Subdomains", border_style="blue"))

        while True:
            console.print("\n[bold yellow]Next Action:[/bold yellow]")
            console.print("[1] 🎯 Run Full Vulnerability Scan on this target")
            console.print("[2] 📂 Fuzz Hidden Paths on this target")
            console.print("[3] 🔍 Recon another domain")
            console.print("[0] 🔙 Return to Main Menu")

            ch = Prompt.ask("Select action", default="1")
            if ch == "1":
                cls.run_full_scan_flow()
                break
            elif ch == "2":
                cls.run_fuzzer_flow()
                break
            elif ch == "3":
                cls.session_target = None
                cls.run_recon_flow()
                break
            elif ch == "0":
                break

    @classmethod
    def run_fuzzer_flow(cls):
        """Fast path fuzzer with intensity selection"""
        console.print(Panel("[bold yellow]📂 Fast Directory & Sensitive File Fuzzer[/bold yellow]\n"
                            "Audits high-value paths with automatic wildcard soft-404 detection."))
        target = cls.get_target_input("Base URL to Fuzz")
        if not target:
            return

        console.print("\n[bold]Select Wordlist Depth:[/bold]")
        console.print("[1] Standard (50+ critical paths: .env, .git, backups, SQL dumps, APIs) [Recommended]")
        console.print("[2] Quick (Top 20 high-priority configs & admin panels)")
        w_choice = Prompt.ask("Select option", default="1")
        intensity = "low" if w_choice == "2" else "medium"

        with console.status(f"[bold cyan]Asynchronously probing endpoints on {target}...[/bold cyan]"):
            async def _fuzz():
                client = AsyncHTTPClient(timeout=10, max_concurrent=25)
                fuzzer = DirFuzzer(client, concurrency=25)
                res = await fuzzer.scan([target], intensity=intensity)
                await client.close()
                return res

            findings = asyncio.run(_fuzz())

        if not findings:
            console.print("[bold green]✨ No sensitive or exposed paths discovered (Server properly protected).[/bold green]")
        else:
            table = Table(title=f"[bold green]Discovered Endpoints ({len(findings)})[/bold green]", border_style="green")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Resource Path", style="bold white")
            table.add_column("URL", style="cyan")
            table.add_column("Evidence", style="dim")

            for f in findings:
                table.add_row(f.get("severity"), f.get("parameter"), f.get("url"), f.get("evidence"))
            console.print(table)

        while True:
            console.print("\n[bold yellow]Next Action:[/bold yellow]")
            console.print("[1] 🎯 Run Full Vulnerability Scan on this target")
            console.print("[2] 📂 Fuzz another target")
            console.print("[0] 🔙 Return to Main Menu")

            ch = Prompt.ask("Select action", default="0")
            if ch == "1":
                cls.run_full_scan_flow()
                break
            elif ch == "2":
                cls.session_target = None
                cls.run_fuzzer_flow()
                break
            elif ch == "0":
                break

    @classmethod
    def run_targeted_audit_flow(cls):
        """Targeted single-vulnerability testing suite"""
        console.print(Panel("[bold magenta]🧪 Targeted Vulnerability Audit Suite[/bold magenta]\n"
                            "Test specific vulnerability classes independently."))
        target = cls.get_target_input("Target URL to Audit")
        if not target:
            return

        while True:
            console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
            console.print("[bold yellow]Select Vulnerability to Audit:[/bold yellow]")
            console.print("[1] 💉 SQL Injection (SQLi)")
            console.print("[2] ⚡ Cross-Site Scripting (XSS)")
            console.print("[3] 🔄 CORS Misconfigurations & SSRF Input Vectors")
            console.print("[4] 📁 Path Traversal & Local File Inclusion (LFI)")
            console.print("[5] 🛡️ Missing Security Headers & Information Disclosure")
            console.print("[0] 🔙 Return to Main Menu")

            mod_choice = Prompt.ask("Select module [0-5]", default="1")
            if mod_choice == "0":
                break

            findings = []
            async def _run_single(mod_id: str):
                client = AsyncHTTPClient(timeout=15, max_concurrent=20)
                try:
                    if mod_id == "1":
                        d = InjectionDetector(client)
                        return await d.scan([target])
                    elif mod_id == "2":
                        d = XSSDetector(client)
                        return await d.scan([target])
                    elif mod_id == "3":
                        d = CORSSSRFDetector(client)
                        return await d.scan([target])
                    elif mod_id == "4":
                        d = PathTraversalDetector(client)
                        return await d.scan([target])
                    elif mod_id == "5":
                        d = ConfigDetector(client)
                        return await d.scan([target])
                finally:
                    await client.close()

            with console.status("[bold cyan]Executing targeted security probes...[/bold cyan]"):
                findings = asyncio.run(_run_single(mod_choice))

            if not findings:
                console.print(f"[bold green]✔ Target passed audit: No vulnerabilities detected for this module.[/bold green]")
            else:
                table = Table(title=f"Vulnerability Audit Findings ({len(findings)})", border_style="red")
                table.add_column("Severity", style="bold", width=10)
                table.add_column("Title / Description", style="bold white")
                table.add_column("Parameter / Path", style="cyan")
                for f in findings:
                    table.add_row(f.get("severity", "MEDIUM"), f.get("title", f.get("type")), f.get("parameter", target))
                console.print(table)

            Prompt.ask("\nPress Enter to return to module selection")

    @classmethod
    def run_arsenal_flow(cls):
        """Enhanced tools arsenal launcher with 10 categories, auto-install, and live logging"""
        while True:
            cls.display_banner()
            console.print("[bold yellow]🧰 SECURITY TOOLS ARSENAL (30+ Tools across 10 Categories)[/bold yellow]\n")

            cats = list(ARSENAL_CATEGORIES.keys())
            for idx, cat in enumerate(cats, 1):
                console.print(f"[bold cyan][{idx}][/bold cyan] {cat}")
            console.print("[bold red][0][/bold red] 🔙 Back to Main Menu")

            choice = Prompt.ask("\nSelect a category [0-10]", default="1")
            if choice == "0":
                break

            if choice.isdigit() and 1 <= int(choice) <= len(cats):
                cat_name = cats[int(choice) - 1]
                tools = ARSENAL_CATEGORIES[cat_name]

                while True:
                    console.clear()
                    cls.display_banner()
                    table = Table(title=f"[bold]{cat_name}[/bold]", border_style="magenta")
                    table.add_column("#", width=4)
                    table.add_column("Tool Name", style="bold white")
                    table.add_column("Status", style="bold")
                    table.add_column("Description", style="dim")

                    for t_idx, t in enumerate(tools, 1):
                        is_inst = ToolArsenal.get_tool_status(t["cmd"])
                        st = "[green]Installed[/green]" if is_inst else "[red]Not Found[/red]"
                        table.add_row(str(t_idx), t["name"], st, t["desc"])

                    console.print(table)
                    console.print("[bold red][0][/bold red] 🔙 Back to Categories\n")

                    t_choice = Prompt.ask("Select tool number [0-N]", default="0")
                    if t_choice == "0":
                        break

                    if t_choice.isdigit() and 1 <= int(t_choice) <= len(tools):
                        selected = tools[int(t_choice) - 1]
                        is_installed = ToolArsenal.get_tool_status(selected["cmd"])

                        console.print(Panel(
                            f"[bold]Tool:[/bold] {selected['name']}\n"
                            f"[bold]Description:[/bold] {selected['desc']}\n"
                            f"[bold]Status:[/bold] {'[green]Installed in PATH[/green]' if is_installed else '[red]Not installed[/red]'}\n"
                            f"[bold]Quick Preset:[/bold] [yellow]{selected.get('preset_quick', selected['preset'])}[/yellow]\n"
                            f"[bold]Deep Preset:[/bold] [yellow]{selected.get('preset_deep', selected['preset'])}[/yellow]\n"
                            f"[bold]Install Guide:[/bold] [green]{selected['install']}[/green]",
                            title=f"Tool: {selected['name']}",
                            border_style="cyan"
                        ))

                        if not is_installed:
                            console.print("[bold yellow]Tool Actions:[/bold yellow]")
                            if selected.get("pip_pkg"):
                                console.print("[1] ⚡ 1-Click Auto-Install (pip install into environment)")
                                console.print("[0] 🔙 Back")
                                act = Prompt.ask("Select action", default="1")
                                if act == "1":
                                    success = ToolArsenal.install_tool(selected)
                                    Prompt.ask("\nPress Enter to continue")
                            else:
                                console.print(f"[bold yellow]Install command:[/bold yellow] {selected['install']}")
                                Prompt.ask("\nPress Enter to continue")
                        else:
                            console.print("[bold yellow]Execution Mode:[/bold yellow]")
                            console.print("[1] 🚀 Run Standard Preset")
                            console.print("[2] ⚡ Run Quick Scan Mode")
                            console.print("[3] 🔬 Run Deep / Aggressive Mode")
                            console.print("[4] ✏️ Enter Custom Command Arguments")
                            console.print("[0] 🔙 Cancel")
                            act = Prompt.ask("Select action", default="1")

                            if act in ("1", "2", "3", "4"):
                                target = cls.get_target_input("Target IP/Domain for tool execution")
                                if target:
                                    clean_t = target.replace("https://", "").replace("http://", "").split("/")[0]
                                    mode_map = {"1": "standard", "2": "quick", "3": "deep"}

                                    if act == "4":
                                        custom_args = Prompt.ask("Enter custom arguments", default=f"-u {clean_t}")
                                        ToolArsenal.execute_tool(selected, clean_t, custom_args=custom_args)
                                    else:
                                        ToolArsenal.execute_tool(selected, clean_t, mode=mode_map[act])

                                    Prompt.ask("\nPress Enter to return to tools menu")

    @classmethod
    def run_reports_flow(cls):
        """Interactive reports explorer with 1-click browser view"""
        while True:
            console.clear()
            cls.display_banner()
            console.print("[bold yellow]📄 SECURITY AUDIT REPORTS EXPLORER[/bold yellow]\n")
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            files = sorted(list(reports_dir.glob("*.*")), key=lambda p: p.stat().st_mtime, reverse=True)
            valid_files = [f for f in files if f.suffix in [".html", ".md", ".json"]]

            if not valid_files:
                console.print("[yellow]No audit reports found in ./reports yet. Run a scan first![/yellow]")
                Prompt.ask("\nPress Enter to return to main menu")
                break

            table = Table(title="Generated Security Reports", border_style="green")
            table.add_column("#", width=4)
            table.add_column("Filename", style="bold white")
            table.add_column("Type", style="cyan")
            table.add_column("Size", style="dim")

            for idx, f in enumerate(valid_files, 1):
                ftype = "Cyberpunk HTML Report" if f.suffix == ".html" else ("Markdown Summary" if f.suffix == ".md" else "JSON Data")
                size_str = f"{f.stat().st_size / 1024:.1f} KB"
                table.add_row(str(idx), f.name, ftype, size_str)

            console.print(table)
            console.print("[bold cyan][A][/bold cyan] Open Most Recent HTML Report in Browser")
            console.print("[bold red][0][/bold red] 🔙 Back to Main Menu\n")

            choice = Prompt.ask("Enter report number [1-N] or A/0", default="1").strip()
            if choice == "0":
                break
            elif choice.lower() == "a":
                html_files = [f for f in valid_files if f.suffix == ".html"]
                if html_files:
                    webbrowser.open(html_files[0].resolve().as_uri())
                    console.print(f"[bold green]✔ Opened {html_files[0].name} in browser![/bold green]")
                Prompt.ask("Press Enter to continue")
            elif choice.isdigit() and 1 <= int(choice) <= len(valid_files):
                selected = valid_files[int(choice) - 1]
                if selected.suffix == ".html":
                    webbrowser.open(selected.resolve().as_uri())
                    console.print(f"[bold green]✔ Opened {selected.name} in browser![/bold green]")
                else:
                    console.print(Panel(selected.read_text(encoding="utf-8", errors="replace"), title=selected.name, border_style="cyan"))
                Prompt.ask("Press Enter to continue")

    @classmethod
    def run_server_flow(cls):
        """Launch the REST API server"""
        console.print(Panel("[bold cyan]🌐 SentinelAI REST API & Web Server[/bold cyan]\n"
                            "Starts the FastAPI backend at http://127.0.0.1:8000 with interactive Swagger UI."))
        console.print("[1] 🚀 Start API Server Now")
        console.print("[2] 📖 Open API Documentation in Browser (http://127.0.0.1:8000/docs)")
        console.print("[0] 🔙 Return to Main Menu")

        choice = Prompt.ask("Select option", default="1")
        if choice == "1":
            console.print("[bold green]Starting SentinelAI API on http://127.0.0.1:8000... (Press Ctrl+C to return)[/bold green]\n")
            try:
                import uvicorn
                uvicorn.run("sentinelai.api.main:app", host="127.0.0.1", port=8000, reload=False)
            except KeyboardInterrupt:
                console.print("\n[yellow]API Server stopped.[/yellow]")
            except Exception as e:
                console.print(f"[red]Error starting server: {e}[/red]")
            Prompt.ask("\nPress Enter to return to main menu")
        elif choice == "2":
            webbrowser.open("http://127.0.0.1:8000/docs")
            Prompt.ask("Press Enter to continue")
