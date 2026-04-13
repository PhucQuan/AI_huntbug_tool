import asyncio
import json
import logging
import os
from datetime import datetime
from rich.console import Console

console = Console()
logger = logging.getLogger("recon_auto.web_analysis")


class WebAnalysis:
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(f"{self.output_dir}/screenshots", exist_ok=True)

    async def run_httpx(self, subdomains: list[str]) -> list[dict]:
        """Runs httpx, reads stdout directly (no -o flag)."""
        os.makedirs(self.output_dir, exist_ok=True)
        input_file = os.path.abspath(f"{self.output_dir}/temp_subdomains.txt")

        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        console.print(f"[->] Running httpx on {len(subdomains)} hosts...")

        try:
            process = await asyncio.create_subprocess_exec(
                "httpx",
                "-l", input_file,
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-threads", "50",
                "-timeout", "10",
                "-no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=600
            )
        except asyncio.TimeoutError:
            console.print("[!] httpx timed out after 10 minutes")
            return []
        except FileNotFoundError:
            console.print("[!] httpx: not installed")
            return []
        except Exception as e:
            logger.error(f"httpx failed: {e}")
            return []

        raw = stdout.decode(errors="ignore")

        alive_hosts = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    continue
                url = data.get("url") or data.get("input") or ""
                if not url:
                    continue
                alive_hosts.append({
                    "url": url,
                    "status_code": data.get("status_code", 0),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                    "checked_at": datetime.now().isoformat(),
                })
            except json.JSONDecodeError:
                continue

        console.print(f"[✓] httpx: {len(alive_hosts)} alive hosts found")
        return alive_hosts

    async def detect_waf(self, url: str) -> str:
        try:
            process = await asyncio.create_subprocess_shell(
                f"wafw00f {url}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
            for line in stdout.decode(errors="ignore").splitlines():
                if "is behind" in line:
                    return line.split("is behind")[1].strip()
        except Exception:
            pass
        return "None"

    async def take_screenshots(self, alive_hosts: list[dict]):
        if not alive_hosts:
            return
        input_file = f"{self.output_dir}/alive_urls.txt"
        with open(input_file, "w") as f:
            f.write("\n".join([h["url"] for h in alive_hosts]))
        try:
            process = await asyncio.create_subprocess_shell(
                f"gowitness file -f {input_file} --screenshot-path {self.output_dir}/screenshots/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=300)
            console.print(f"[✓] Screenshots saved: {self.output_dir}/screenshots/")
        except Exception:
            console.print("[!] gowitness: not installed, skipping screenshots")

    def prioritize_targets(self, hosts: list[dict]) -> list[dict]:
        def score(host):
            pts = 0
            title = (host.get("title") or "").lower()
            tech = " ".join(host.get("technologies") or []).lower()
            if any(k in title for k in ["login", "admin", "dashboard"]):
                pts += 10
            if host.get("status_code") in [200, 401, 403]:
                pts += 5
            if any(k in tech for k in ["wordpress", "php 5", "apache 2"]):
                pts += 8
            return pts
        return sorted(hosts, key=score, reverse=True)

    async def analyze_hosts(self, subdomains: list[str]) -> list[dict]:
        alive_hosts = await self.run_httpx(subdomains)
        alive_hosts = self.prioritize_targets(alive_hosts)
        asyncio.create_task(self.take_screenshots(alive_hosts))
        return alive_hosts
