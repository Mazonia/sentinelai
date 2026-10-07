"""
Interactive Rich Terminal Dashboard & Arsenal Launcher for SentinelAI
Inspired by hackingtool with modern styling and responsive menus.
"""
import asyncio
import os
import sys
from pathlib import Path

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
    """Main interactive terminal application"""

    @classmethod
    def display_banner(cls):
        console.clear()
        console.print(BANNER)
        console.print(Panel.fit(
            "[bold white]Select an operation below or press [yellow]0[/yellow] to exit.[/bold white]\n"
            "[green]• Standalone Security Scanner[/green]  [blue]• Recon & OSINT Engine[/blue]  [magenta]• Multi-Tool Arsenal[/magenta]",
            border_style="cyan"
        ))

    @classmethod
    def main_menu(cls):
        while True:
            cls.display_banner()
            table = Table(title="[bold yellow]SENTINELAI COMMAND MODULES[/bold yellow]", border_style="blue", show_header=True)
            table.add_column("Key", style="bold green", width=6)
            table.add_column("Category / Feature", style="bold white")
            table.add_column("Description", style="dim")

            table.add_row("1", "🎯 Full Target Vulnerability Scan", "Automated crawl + OWASP Top 10 + AI Remediation")
            table.add_row("2", "🔍 Reconnaissance & OSINT Engine", "Subdomains, port scanner, tech stack & WAF detection")
            table.add_row("3", "📂 Fast Directory & Sensitive File Fuzzer", "Built-in multi-threaded path fuzzer with wildcard 404 filter")
            table.add_row("4", "🌐 Quick Web & Parameter Audit", "Audit URLs for XSS, SQLi, SSRF, LFI, and CORS")
            table.add_row("5", "🧰 Security Tool Arsenal", "Launchpad for Nmap, SQLmap, Nikto, Nuclei, Gobuster, etc.")
            table.add_row("6", "📄 Export & View Last Report", "Generate HTML, Markdown, or JSON audit reports")
            table.add_row("0", "🚪 Exit SentinelAI", "Quit the framework")

            console.print(table)
            choice = Prompt.ask("\n[bold cyan]Select an option[/bold cyan]", default="1")

            if choice == "1":
                cls.run_full_scan_flow()
            elif choice == "2":
                cls.run_recon_flow()
            elif choice == "3":
                cls.run_fuzzer_flow()
            elif choice == "4":
                cls.run_web_audit_flow()
            elif choice == "5":
                cls.run_arsenal_flow()
            elif choice == "6":
                cls.export_report_flow()
            elif choice == "0":
                console.print("\n[bold green]Stay safe! Exiting SentinelAI...[/bold green]\n")
                sys.exit(0)
            else:
                console.print("[red]Invalid selection![/red]")
                Prompt.ask("Press Enter to continue")

    @classmethod
    def run_full_scan_flow(cls):
        target = Prompt.ask("\n[bold cyan]Enter target URL (e.g., https://example.com)[/bold cyan]")
        if not target:
            return

        enable_ai = Confirm.ask("Enable AI False-Positive Reduction & Remediation?", default=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Initializing SentinelAI Scanner...", total=100)

            def update_progress(desc: str, pct: int):
                progress.update(task, description=f"[cyan]{desc}[/cyan]", completed=pct)

            scanner = StandaloneScanner()
            results = asyncio.run(scanner.run_full_scan(target, enable_ai=enable_ai, progress_cb=update_progress))

        cls.display_scan_results(results)

        if Confirm.ask("\nExport audit report (HTML & Markdown)?", default=True):
            out_dir = Path("reports")
            out_dir.mkdir(exist_ok=True)
            safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
            html_p = ReportGenerator.generate_html(results, out_dir / f"sentinel_{safe_target}.html")
            md_p = ReportGenerator.generate_markdown(results, out_dir / f"sentinel_{safe_target}.md")
            console.print(f"[bold green]✔ HTML Report:[/bold green] {html_p.resolve()}")
            console.print(f"[bold green]✔ Markdown Report:[/bold green] {md_p.resolve()}")

        Prompt.ask("\nPress Enter to return to main menu")

    @classmethod
    def display_scan_results(cls, results: dict):
        console.print("\n[bold green]========== SCAN COMPLETED ==========[/bold green]\n")
        recon = results.get("recon", {})
        console.print(Panel(
            f"[bold]Target:[/bold] {results.get('target')}\n"
            f"[bold]Host IP:[/bold] {', '.join(recon.get('ip_addresses', [])) or 'N/A'}\n"
            f"[bold]WAF Detected:[/bold] {recon.get('waf') or 'None'}\n"
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
        table.add_column("Severity", style="bold")
        table.add_column("Vulnerability")
        table.add_column("CVSS")
        table.add_column("Parameter / URL")

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
        target = Prompt.ask("\n[bold cyan]Enter domain or URL to recon (e.g., example.com)[/bold cyan]")
        if not target:
            return

        with console.status("[bold cyan]Querying DNS, Certificate Transparency, WAF & Ports...[/bold cyan]"):
            recon = ReconDetector()
            results = asyncio.run(recon.scan_domain(target))

        table = Table(title="[bold cyan]RECONNAISSANCE RESULTS[/bold cyan]", border_style="cyan")
        table.add_column("Field", style="bold white")
        table.add_column("Data", style="green")

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

        Prompt.ask("\nPress Enter to return to main menu")

    @classmethod
    def run_fuzzer_flow(cls):
        target = Prompt.ask("\n[bold cyan]Enter target URL to fuzz (e.g., https://example.com)[/bold cyan]")
        if not target:
            return

        with console.status("[bold cyan]Asynchronously fuzzing 40+ high-value paths...[/bold cyan]"):
            async def _fuzz():
                client = AsyncHTTPClient(timeout=10, max_concurrent=25)
                fuzzer = DirFuzzer(client, concurrency=25)
                res = await fuzzer.scan([target])
                await client.close()
                return res

            findings = asyncio.run(_fuzz())

        if not findings:
            console.print("[bold yellow]No sensitive or accessible paths found.[/bold yellow]")
        else:
            table = Table(title=f"[bold green]Discovered Endpoints ({len(findings)})[/bold green]", border_style="green")
            table.add_column("Severity", style="bold")
            table.add_column("Resource Path", style="bold white")
            table.add_column("URL", style="cyan")
            table.add_column("Evidence")

            for f in findings:
                table.add_row(f.get("severity"), f.get("parameter"), f.get("url"), f.get("evidence"))
            console.print(table)

        Prompt.ask("\nPress Enter to return to main menu")

    @classmethod
    def run_web_audit_flow(cls):
        cls.run_full_scan_flow()

    @classmethod
    def run_arsenal_flow(cls):
        while True:
            cls.display_banner()
            console.print("[bold yellow]🧰 SECURITY TOOLS ARSENAL (Inspired by hackingtool)[/bold yellow]\n")

            cats = list(ARSENAL_CATEGORIES.keys())
            for idx, cat in enumerate(cats, 1):
                console.print(f"[bold cyan][{idx}][/bold cyan] {cat}")
            console.print("[bold red][0][/bold red] Back to Main Menu")

            choice = Prompt.ask("\nSelect a category", default="1")
            if choice == "0":
                break

            if choice.isdigit() and 1 <= int(choice) <= len(cats):
                cat_name = cats[int(choice) - 1]
                tools = ARSENAL_CATEGORIES[cat_name]

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
                t_choice = Prompt.ask("Select tool number (or 0 to back)", default="0")
                if t_choice == "0":
                    continue

                if t_choice.isdigit() and 1 <= int(t_choice) <= len(tools):
                    selected = tools[int(t_choice) - 1]
                    if not ToolArsenal.get_tool_status(selected["cmd"]):
                        console.print(f"\n[bold red]Tool '{selected['name']}' is not installed in PATH.[/bold red]")
                        console.print(f"[bold yellow]Install via:[/bold yellow] [green]{selected['install']}[/green]\n")
                        Prompt.ask("Press Enter to continue")
                    else:
                        target = Prompt.ask(f"Enter target URL / IP for {selected['name']}")
                        if target:
                            ToolArsenal.execute_tool(selected, target)
                            Prompt.ask("\nTool execution finished. Press Enter to continue")

    @classmethod
    def export_report_flow(cls):
        console.print("[cyan]Reports are stored in the './reports' directory.[/cyan]")
        reports_dir = Path("reports")
        if reports_dir.exists():
            files = list(reports_dir.glob("*"))
            if files:
                table = Table(title="Generated Security Reports", border_style="green")
                table.add_column("Filename", style="bold white")
                table.add_column("Size (Bytes)", style="cyan")
                for f in files:
                    table.add_row(f.name, str(f.stat().st_size))
                console.print(table)
            else:
                console.print("[yellow]No reports generated yet.[/yellow]")
        Prompt.ask("\nPress Enter to return to main menu")
