import argparse
import asyncio
import sys
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load .env file TRƯỚC KHI import bất kỳ module nào
load_dotenv()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Internal Modules
from core.recon.subdomain import SubdomainEnumerator
from core.recon.web_analysis import WebAnalysis
from core.scan.nuclei_runner import NucleiRunner
from core.ai.triage import AITriage
from db.knowledge_graph import KnowledgeGraph
from core.monitor.delta import DeltaDetector
from scheduler import MonitoringScheduler

console = Console()

def check_critical_tools():
    """Check critical tools trước khi chạy."""
    import shutil
    
    critical_tools = {
        "subfinder": "Subdomain enumeration",
        "httpx": "HTTP probing",
        "nuclei": "Vulnerability scanning",
    }
    
    missing = []
    for tool, desc in critical_tools.items():
        if not shutil.which(tool):
            missing.append(f"{tool} ({desc})")
    
    if missing:
        console.print("\n[bold red]⚠️  Critical tools missing:[/bold red]")
        for tool in missing:
            console.print(f"  - {tool}")
        console.print("\n[yellow]Run 'python check_tools.py --fix' to see installation commands.[/yellow]")
        console.print("[dim]Or continue anyway (some features will be disabled)...[/dim]\n")
        
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            console.print("[red]Aborted.[/red]")
            sys.exit(1)

class ReconAutoCLI:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.mode = args.command  # dùng command name làm mode
        self.start_time = datetime.now()

        # Core Intelligence & Engine
        self.db = KnowledgeGraph()
        self.sub_enum = SubdomainEnumerator()
        self.web_analysis = WebAnalysis()
        self.nuclei = NucleiRunner()
        self.ai_triage = AITriage()
        self.detector = DeltaDetector(self.db, self.sub_enum, self.nuclei, None) # AlertManager mock

    def print_banner(self):
        banner = """
        ╔══════════════════════════════════════╗
        ║     RECON-AUTO v1.0 | @yourhandle   ║
        ╚══════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")

    def print_header(self):
        console.print(f"[*] Target     : [bold]{self.target}[/bold]")
        console.print(f"[*] Mode       : [bold]{self.mode.capitalize()}[/bold]")
        console.print(f"[*] Started    : [bold]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/bold]\n")

    # --- STAGE IMPLEMENTATIONS ---

    async def run_recon_pipeline(self):
        """Stage 1 & 2: Subdomain Enum + Alive Check"""
        self.print_banner()
        self.print_header()

        # 1. Subdomain Enum
        console.print("──────────── Stage 1: Subdomain Enum ────────────")
        subdomains = await self.sub_enum.enumerate_subdomains(self.target)
        if not subdomains:
            console.print("[!] No subdomains found. Aborting.")
            return

        # 2. Alive Check
        console.print("──────────── Stage 2: Alive Check ────────────")
        alive_hosts = await self.web_analysis.analyze_hosts(subdomains)
        if not alive_hosts:
            console.print("[!] No alive hosts found. Aborting.")
            return

        console.print(f"\n[✓] Recon complete. {len(alive_hosts)} alive hosts ready for scanning.\n")

    async def run_scan_pipeline(self, from_db=False):
        """Stage 3: Nuclei + AI Triage"""
        self.print_banner()
        self.print_header()

        hosts = []
        if from_db:
            console.print("[→] Fetching hosts from database...")
            # In real implementation: hosts = await self.db.get_alive_hosts(self.target)
            hosts = [{"url": f"https://{self.target}", "technologies": ["nginx"]}] # Mock
        else:
            console.print("[!] Error: Use --from-db to run scan on existing assets.")
            return

        # 3. Nuclei Scan
        console.print("──────────── Stage 3: Vuln Scan ────────────")
        findings = await self.nuclei.run_full_nuclei_pipeline(hosts)

        # 4. AI Triage
        if findings:
            console.print("──────────── Stage 4: AI Triage ────────────")
            console.print(f"[→] Sending {len(findings)} findings to Claude API...")
            enriched = await self.ai_triage.triage_findings(findings, {"domain": self.target, "tech_stack": []})

            # Show Summary Table
            self.print_summary_table(enriched)
        else:
            console.print("[✓] No vulnerabilities discovered.")

    def print_summary_table(self, enriched_findings):
        console.print("\n──────────── Summary ────────────")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim")
        table.add_column("Count", justify="right")

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in enriched_findings:
            sev = f.get('severity', 'low').lower()
            counts[sev] = counts.get(sev, 0) + 1

        for sev, count in counts.items():
            color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "informational": "white"}.get(sev, "white")
            table.add_row(f"[{color}]{sev.capitalize()}[/{color}]", str(count))

        console.print(table)
        duration = datetime.now() - self.start_time
        console.print(f"\n[✓] Total time     : {str(duration).split('.')[0]}")

    # --- SUBCOMMANDS ---

    async def cmd_recon(self):
        check_critical_tools()  # Check tools trước khi chạy
        await self.run_recon_pipeline()

    async def cmd_scan(self):
        check_critical_tools()  # Check tools trước khi chạy
        await self.run_scan_pipeline(from_db=self.args.from_db)

    async def cmd_monitor(self):
        scheduler = MonitoringScheduler(self.detector)
        await scheduler.start()

    async def cmd_show(self):
        """Show subdomains or findings for a target."""
        console.print(f"[bold]Querying data for {self.target}...[/bold]")
        # Mocking query
        if self.args.type == "subdomains":
            console.print(f"Found 12 subdomains for {self.target}...")
        else:
            console.print(f"Found 3 findings for {self.target}...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon-Auto: AI-Powered Bug Bounty Framework")
    subparsers = parser.add_subparsers(dest="command")

    # Command: recon
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance (subdomains + alive check)")
    recon_parser.add_argument("-d", "--target", required=True, help="Target domain")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan (Nuclei)")
    scan_parser.add_argument("-d", "--target", required=True, help="Target domain")
    scan_parser.add_argument("--from-db", action="store_true", help="Use assets already in DB")

    # Command: monitor
    monitor_parser = subparsers.add_parser("monitor", help="Start continuous monitoring daemon")
    monitor_parser.add_argument("-d", "--target", required=True, help="Target domain")

    # Command: show
    show_parser = subparsers.add_parser("show", help="Show assets or findings from DB")
    show_parser.add_argument("-d", "--target", required=True, help="Target domain")
    show_parser.add_argument("--type", choices=['subdomains', 'findings'], required=True, help="Type of data to show")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = ReconAutoCLI(args)

    try:
        if args.command == "recon":
            asyncio.run(cli.cmd_recon())
        elif args.command == "scan":
            asyncio.run(cli.cmd_scan())
        elif args.command == "monitor":
            asyncio.run(cli.cmd_monitor())
        elif args.command == "show":
            asyncio.run(cli.cmd_show())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[!] Fatal Error: {e}")
        import traceback
        traceback.print_exc()
