import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.recon.subdomain import SubdomainEnumerator
from core.recon.web_analysis import WebAnalysis
from core.recon.url_collection import run_url_collection_pipeline
from core.recon.param_discovery import run_param_discovery_pipeline
from core.recon.js_analysis import run_js_analysis_pipeline
from core.scan.nuclei_runner import NucleiRunner
from core.scan.web_vulns import run_web_vuln_pipeline
from core.scan.sqli_scanner import run_sqli_scan_pipeline
from core.scan.takeover_scanner import run_takeover_scan_pipeline
from core.scan.git_exposure import run_git_exposure_pipeline
from core.scan.port_scanner import run_port_scan_pipeline
from core.ai.triage import AITriage
from core.ai.report_gen import ReportGenerator
from core.monitor.delta import DeltaDetector
from db.knowledge_graph import KnowledgeGraph
from scheduler import MonitoringScheduler

console = Console()


# =============================================================================
# Tool Checker
# =============================================================================

def check_critical_tools():
    import shutil
    go_bin = os.path.expanduser("~/go/bin")
    path = go_bin + ":" + os.environ.get("PATH", "")
    missing = []
    for tool in ["subfinder", "nuclei"]:
        if not shutil.which(tool, path=path):
            missing.append(tool)
    if missing:
        console.print(f"\n[bold red]Missing tools: {', '.join(missing)}[/bold red]")
        console.print("[yellow]Run: python check_tools.py --fix[/yellow]\n")


# =============================================================================
# CLI Class
# =============================================================================

class ReconAutoCLI:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.mode = args.command
        self.start_time = datetime.now()
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)

        self.sub_enum = SubdomainEnumerator()
        self.web_analysis = WebAnalysis()
        self.nuclei = NucleiRunner()
        self.ai_triage = AITriage()
        self.db = KnowledgeGraph()

    def _cache(self, name: str) -> str:
        return f"{self.results_dir}/{self.target}_{name}.json"

    def _save(self, name: str, data):
        with open(self._cache(name), "w") as f:
            json.dump(data, f, indent=2)

    def _load(self, name: str):
        path = self._cache(name)
        if os.path.exists(path):
            return json.load(open(path))
        return None

    def print_banner(self):
        console.print(Panel.fit(
            f"[bold cyan]RECON-AUTO v2.0[/bold cyan] | Target: [bold]{self.target}[/bold]\n"
            f"Mode: [bold]{self.mode.upper()}[/bold] | Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan"
        ))

    def print_stage(self, n: int, name: str):
        console.print(f"\n[bold cyan]{'─'*15} Stage {n}: {name} {'─'*15}[/bold cyan]")

    # =========================================================================
    # RECON PIPELINE
    # =========================================================================

    async def cmd_recon(self):
        check_critical_tools()
        self.print_banner()

        # Stage 1: Subdomain Enum
        self.print_stage(1, "Subdomain Enumeration")
        subdomains = await self.sub_enum.enumerate_subdomains(self.target)
        if not subdomains:
            console.print("[!] No subdomains found.")
            return
        self._save("subdomains", subdomains)

        # Stage 2: Alive Check
        self.print_stage(2, "Alive Check")
        alive_hosts = await self.web_analysis.analyze_hosts(subdomains)
        if not alive_hosts:
            console.print("[!] No alive hosts found.")
            return
        self._save("alive", alive_hosts)

        # Stage 3: Subdomain Takeover
        self.print_stage(3, "Subdomain Takeover Check")
        takeover = await run_takeover_scan_pipeline(subdomains, use_subzy=False, use_manual=True)
        vuln_takeovers = takeover.get("manual_results", [])
        if vuln_takeovers:
            console.print(f"[bold red][!] {len(vuln_takeovers)} potential takeovers found![/bold red]")
            for t in vuln_takeovers:
                console.print(f"  - {t.subdomain} → {t.service}")

        # Stage 4: URL Collection
        self.print_stage(4, "URL Collection")
        alive_urls = [h["url"] for h in alive_hosts]
        url_data = await run_url_collection_pipeline(alive_urls, run_active=True, run_passive=True)
        self._save("urls", url_data)

        # Stage 5: JS Analysis
        self.print_stage(5, "JavaScript Analysis")
        js_files = url_data.get("js_files", [])
        if js_files:
            js_data = await run_js_analysis_pipeline(js_files, base_domain=self.target, max_files=30)
            self._save("js_analysis", js_data)
            if js_data.get("all_secrets"):
                console.print(f"[bold red][!] SECRETS found in JS files![/bold red]")
                for stype, vals in js_data["all_secrets"].items():
                    console.print(f"  - {stype}: {len(vals)} found")
        else:
            console.print("[dim]No JS files found[/dim]")

        # Stage 6: .git Exposure
        self.print_stage(6, ".git Exposure Check")
        git_data = await run_git_exposure_pipeline(alive_urls)
        if git_data.get("exposed_results"):
            console.print(f"[bold red][!] {len(git_data['exposed_results'])} exposed .git repos![/bold red]")
            for r in git_data["exposed_results"]:
                console.print(f"  - {r.url}")

        # Summary
        duration = datetime.now() - self.start_time
        console.print(f"\n[bold green]✓ Recon complete in {str(duration).split('.')[0]}[/bold green]")
        console.print(f"  Subdomains : {len(subdomains)}")
        console.print(f"  Alive hosts: {len(alive_hosts)}")
        console.print(f"  URLs found : {len(url_data.get('all_urls', []))}")
        console.print(f"  JS files   : {len(js_files)}")
        console.print(f"\n[→] Next: python main.py scan -d {self.target} --from-db")

    # =========================================================================
    # SCAN PIPELINE
    # =========================================================================

    async def cmd_scan(self):
        check_critical_tools()
        self.print_banner()

        # Load hosts từ recon cache
        alive_hosts = self._load("alive")
        if not alive_hosts:
            console.print(f"[!] No recon data found. Run: python main.py recon -d {self.target}")
            return

        alive_urls = [h["url"] for h in alive_hosts]
        url_data = self._load("urls") or {}
        urls_with_params = url_data.get("urls_with_params", [])

        console.print(f"[✓] Loaded {len(alive_hosts)} hosts, {len(urls_with_params)} URLs with params")

        all_findings = []

        # Stage 1: Nuclei
        self.print_stage(1, "Nuclei Vulnerability Scan")
        nuclei_findings = await self.nuclei.run_full_nuclei_pipeline(alive_hosts)
        all_findings.extend(nuclei_findings)
        console.print(f"[✓] Nuclei: {len(nuclei_findings)} findings")

        # Stage 2: Web Vulns (XSS, CORS, SSRF, CRLF, Open Redirect)
        self.print_stage(2, "Web Vulnerability Scan")
        web_findings = await run_web_vuln_pipeline(
            urls_with_params or alive_urls,
            blind_xss=os.environ.get("INTERACTSH_SERVER", ""),
            skip=[]
        )
        all_findings.extend([f.to_dict() for f in web_findings])
        console.print(f"[✓] Web vulns: {len(web_findings)} findings")

        # Stage 3: SQLi
        self.print_stage(3, "SQL Injection Scan")
        sqli_data = await run_sqli_scan_pipeline(
            urls_with_params or alive_urls,
            use_sqlmap=False,
            use_manual=True
        )
        sqli_findings = sqli_data.get("manual_results", [])
        all_findings.extend([vars(f) for f in sqli_findings])
        console.print(f"[✓] SQLi: {len(sqli_findings)} findings")

        # Stage 4: Port Scan
        self.print_stage(4, "Port Scanning")
        hosts_only = list(set(h.split("//")[-1].split("/")[0] for h in alive_urls))
        port_data = await run_port_scan_pipeline(hosts_only[:20], fast_scan=True, top_ports=100)
        open_ports = sum(len(v) for v in port_data.values())
        console.print(f"[✓] Port scan: {open_ports} open ports found")

        # Stage 5: AI Triage
        self.print_stage(5, "AI Triage")
        if all_findings:
            console.print(f"[→] Triaging {len(all_findings)} findings with Gemini AI...")
            enriched = await self.ai_triage.triage_findings(
                all_findings,
                {"domain": self.target, "company_type": "automotive", "has_pii": True}
            )
            self._save("findings", enriched)
            self._print_summary(enriched)
        else:
            console.print("[✓] No vulnerabilities found.")

        duration = datetime.now() - self.start_time
        console.print(f"\n[bold green]✓ Scan complete in {str(duration).split('.')[0]}[/bold green]")
        console.print(f"[→] View results: python main.py show -d {self.target} --type findings")

    def _print_summary(self, findings):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            sev = f.get("severity", "low").lower()
            counts[sev] = counts.get(sev, 0) + 1
        colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "informational": "white"}
        for sev, count in counts.items():
            if count > 0:
                table.add_row(f"[{colors[sev]}]{sev.upper()}[/{colors[sev]}]", str(count))
        console.print(table)

    # =========================================================================
    # SHOW COMMAND
    # =========================================================================

    async def cmd_show(self):
        if self.args.type == "subdomains":
            data = self._load("subdomains")
            if data:
                console.print(f"[✓] {len(data)} subdomains for {self.target}")
                for s in data[:50]:
                    console.print(f"  {s}")
                if len(data) > 50:
                    console.print(f"  [dim]... and {len(data)-50} more[/dim]")
            else:
                console.print("[!] Run recon first.")

        elif self.args.type == "findings":
            data = self._load("findings")
            if data:
                console.print(f"[✓] {len(data)} findings for {self.target}\n")
                for f in data:
                    sev = f.get("severity", "info").upper()
                    colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
                    color = colors.get(sev, "white")
                    console.print(f"  [{color}][{sev}][/{color}] {f.get('name', 'Unknown')} — {f.get('url', '')}")
            else:
                console.print("[!] Run scan first.")

        elif self.args.type == "urls":
            data = self._load("urls")
            if data:
                all_urls = data.get("all_urls", [])
                params = data.get("urls_with_params", [])
                js = data.get("js_files", [])
                console.print(f"[✓] URLs for {self.target}")
                console.print(f"  Total     : {len(all_urls)}")
                console.print(f"  With params: {len(params)}")
                console.print(f"  JS files  : {len(js)}")
            else:
                console.print("[!] Run recon first.")

    # =========================================================================
    # MONITOR
    # =========================================================================

    async def cmd_monitor(self):
        detector = DeltaDetector(self.db, self.sub_enum, self.nuclei, None)
        scheduler = MonitoringScheduler(detector)
        await scheduler.start()


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon-Auto v2.0 — AI-Powered Bug Bounty Framework")
    subparsers = parser.add_subparsers(dest="command")

    # recon
    p = subparsers.add_parser("recon", help="Full recon: subdomains + alive + URLs + JS + takeover")
    p.add_argument("-d", "--target", required=True)

    # scan
    p = subparsers.add_parser("scan", help="Vuln scan: nuclei + web vulns + SQLi + port scan + AI triage")
    p.add_argument("-d", "--target", required=True)
    p.add_argument("--from-db", action="store_true", default=True)

    # show
    p = subparsers.add_parser("show", help="Show results")
    p.add_argument("-d", "--target", required=True)
    p.add_argument("--type", choices=["subdomains", "findings", "urls"], required=True)

    # monitor
    p = subparsers.add_parser("monitor", help="Continuous monitoring daemon")
    p.add_argument("-d", "--target", required=True)

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
        elif args.command == "show":
            asyncio.run(cli.cmd_show())
        elif args.command == "monitor":
            asyncio.run(cli.cmd_monitor())
    except KeyboardInterrupt:
        console.print("\n[!] Interrupted.")
    except Exception as e:
        console.print(f"\n[bold red][!] Fatal Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
