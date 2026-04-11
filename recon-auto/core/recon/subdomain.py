import asyncio
import subprocess
import aiosqlite
import dns.asyncresolver
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

# --- Configuration & Fingerprints ---
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": [".github.io"],
    "Heroku": [".herokuapp.com"],
    "Netlify": [".netlify.app"],
    "AWS S3": [".s3.amazonaws.com", ".s3-"],
    "Shopify": [".myshopify.com"],
}

class SubdomainDB:
    """CRUD operations for the subdomains table in SQLite."""

    def __init__(self, db_path: str = "recon_auto.db"):
        self.db_path = db_path

    async def init_db(self):
        """Initializes the database and creates the subdomains table."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            """)
            await db.commit()

    async def add_subdomains(self, subdomains_data: list[dict]):
        """
        Adds multiple subdomains to the database.
        subdomains_data: list of dicts like {'domain': 'sub.example.com', 'source': 'subfinder'}
        """
        async with aiosqlite.connect(self.db_path) as db:
            for data in subdomains_data:
                await db.execute(
                    "INSERT INTO subdomains (domain, source) VALUES (?, ?)",
                    (data['domain'], data['source'])
                )
            await db.commit()

class SubdomainEnumerator:
    """Orchestrates subdomain enumeration and takeover checks."""

    def __init__(self, db_path: str = "recon_auto.db"):
        self.db = SubdomainDB(db_path)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def _run_command(self, cmd: str, tool_name: str) -> list[str]:
        """
        Helper to run a shell command asynchronously with timeout and error handling.
        """
        try:
            # Use asyncio.create_subprocess_shell to run the command
            process = await asyncio.wait_for(
                asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=300  # 5 minutes timeout
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                # Check if it's a "command not found" error (often exit code 127)
                if "not found" in stderr.decode() or process.returncode == 127:
                    console.print(f"[!] {tool_name}: not installed, skipping")
                    return []
                else:
                    console.print(f"[!] {tool_name}: failed with error: {stderr.decode().strip()}")
                    return []

            results = stdout.decode().strip().splitlines()
            return [line.strip() for line in results if line.strip()]

        except asyncio.TimeoutError:
            console.print(f"[!] {tool_name}: timed out after 5 minutes")
            return []
        except Exception as e:
            console.print(f"[!] {tool_name}: unexpected error: {e}")
            return []

    async def run_subfinder(self, domain: str) -> list[str]:
        """Runs subfinder."""
        return await self._run_command(f"subfinder -d {domain} -silent", "subfinder")

    async def run_amass(self, domain: str) -> list[str]:
        """Runs amass."""
        # amass is often slow, using passive mode for speed in this skeleton
        return await self._run_command(f"amass enum -passive -d {domain} -silent", "amass")

    async def run_assetfinder(self, domain: str) -> list[str]:
        """Runs assetfinder."""
        return await self._run_command(f"assetfinder --subs-only {domain}", "assetfinder")

    async def check_takeover(self, subdomain: str) -> dict:
        """
        Checks for basic subdomain takeover by inspecting CNAME records.
        Returns: {'vulnerable': bool, 'service': str}
        """
        try:
            answers = await self.resolver.resolve(subdomain, 'CNAME')
            if not answers:
                return {"vulnerable": False, "service": None}

            # Take the first CNAME record
            cname = str(answers[0].target).lower()

            for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                for fp in fingerprints:
                    if fp in cname:
                        # In a real tool, we would further verify if the service
                        # is actually misconfigured (e.g., returning a 404 with a specific message).
                        # For this skeleton, we flag it if the CNAME matches a known service provider.
                        return {"vulnerable": True, "service": service}

            return {"vulnerable": False, "service": None}

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return {"vulnerable": False, "service": None}
        except Exception as e:
            # console.print(f"[!] Error checking takeover for {subdomain}: {e}")
            return {"vulnerable": False, "service": None}

    async def enumerate_subdomains(self, domain: str) -> list[str]:
        """
        Main entry point: Runs tools in parallel, merges, deduplicates,
        saves to DB, and displays progress.
        """
        await self.db.init_db()

        console.print(f"[bold blue]Starting enumeration for: {domain}[/bold blue]")

        # 1. Run tools in parallel
        # Note: Since we only have 3 tools, asyncio.gather satisfies the "max 3" requirement.
        tasks = [
            self.run_subfinder(domain),
            self.run_amass(domain),
            self.run_assetfinder(domain)
        ]

        # We'll use a custom way to track individual tool results for the Rich output
        # instead of just waiting for gather.

        results_map = {}

        # We create a wrapper to capture results and tool name for reporting
        async def task_wrapper(coro, name):
            res = await coro
            results_map[name] = res
            if res:
                console.print(f"[✓] {name}: {len(res)} subdomains")
            else:
                # The error handling inside _run_command already prints the [!] or [!] message
                pass
            return res

        # Execute tasks
        await asyncio.gather(
            task_wrapper(self.run_subfinder(domain), "subfinder"),
            task_wrapper(self.run_amass(domain), "amass"),
            task_wrapper(self.run_assetfinder(domain), "assetfinder")
        )

        # 2. Merge and deduplicate
        all_subdomains = set()
        subdomains_to_db = []

        for tool_name, sub_list in results_map.items():
            for sub in sub_list:
                if sub not in all_subdomains:
                    all_subdomains.add(sub)
                    subdomains_to_db.append({"domain": sub, "source": tool_name})

        # 3. Save to DB
        if subdomains_to_db:
            await self.db.add_subdomains(subdomains_to_db)

        # 4. Final Report
        console.print(f"[→] Total unique: {len(all_subdomains)} subdomains")

        return list(all_subdomains)

# If testing this file directly
if __name__ == "__main__":
    async def test():
        enum = SubdomainEnumerator()
        await enum.enumerate_subdomains("example.com")

    asyncio.run(test())
