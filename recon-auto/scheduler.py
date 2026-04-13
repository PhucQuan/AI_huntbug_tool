import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from rich.console import Console
from datetime import datetime

console = Console()

class MonitoringScheduler:
    """
    Orchestrates all background monitoring jobs using APScheduler.
    """
    def __init__(self, detector):
        self.detector = detector
        self.scheduler = AsyncIOScheduler()
        # Ensure target configuration is loaded here

    async def start(self):
        """Initializes and starts the background jobs."""
        console.print("[bold blue]Starting Recon-Auto Monitoring Daemon...[/bold blue]")

        # Job 1: Lightweight Cert Transparency (Every 6 hours)
        self.scheduler.add_job(
            self._job_cert_transparency,
            'interval',
            hours=6
        )

        # Job 2: Daily Full Subdomain Recon (2 AM)
        self.scheduler.add_job(
            self._job_daily_recon,
            'cron',
            hour=2
        )

        # Job 3: Daily JS Endpoint Analysis (3 AM)
        self.scheduler.add_job(
            self._job_js_endpoints,
            'cron',
            hour=3
        )

        # Job 4: Weekly Full Vuln Scan (Sunday 4 AM)
        self.scheduler.add_job(
            self._job_weekly_scan,
            'cron',
            day_of_week='sun',
            hour=4
        )

        self.scheduler.start()
        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            self.scheduler.shutdown()

    # --- Job Wrappers to fetch dynamic targets ---
    async def _job_cert_transparency(self):
        # Fetch targets from config DB
        await self.detector.check_cert_transparency("example.com")

    async def _job_daily_recon(self):
        console.print(f"[*] Dispatching daily recon routine at {datetime.now()}")
        await self.detector.check_new_subdomains("example.com")

    async def _job_js_endpoints(self):
        console.print(f"[*] Dispatching daily JS tracking routine...")
        await self.detector.check_js_endpoints(1, "https://example.com/app.js")

    async def _job_weekly_scan(self):
        console.print(f"[!] Dispatching WEEKLY Full pipeline...")
        # Invoke nuclei and full scanner here
        pass

