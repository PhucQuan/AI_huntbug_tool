import asyncio
import json
import logging
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger("recon_auto.web_analysis")

class WebAnalysis:
    """
    Handles alive checking, technology detection, WAF detection,
    and screenshot taking for a list of subdomains.
    """

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(f"{self.output_dir}/screenshots", exist_ok=True)

    async def _run_command(self, cmd: str, tool_name: str) -> str:
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            # httpx cần timeout lớn hơn cho nhiều hosts
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600  # 10 phút
            )
            stderr_text = stderr.decode(errors="ignore")
            if process.returncode != 0 and "not found" in stderr_text:
                console.print(f"[!] {tool_name}: not installed or failed")
                return ""
            return stdout.decode(errors="ignore").strip()
        except asyncio.TimeoutError:
            console.print(f"[!] {tool_name}: timed out")
            return ""
        except Exception as e:
            logger.error(f"{tool_name} execution failed: {e}")
            return ""

    async def run_httpx(self, subdomains: list[str]) -> list[dict]:
        """Runs httpx to check host vitality and technologies."""
        os.makedirs(self.output_dir, exist_ok=True)
        input_file = f"{self.output_dir}/temp_subdomains.txt"
        output_file = f"{self.output_dir}/httpx_results.json"

        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        console.print(f"[→] Running httpx on {len(subdomains)} hosts...")

        # Dùng -o để ghi ra file thay vì đọc stdout (tránh buffer overflow)
        cmd = (
            f"httpx -l {input_file} "
            f"-o {output_file} "
            f"-json -status-code -title -tech-detect "
            f"-threads 50 -timeout 10 -no-color -silent"
        )

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=600)
        except asyncio.TimeoutError:
            console.print("[!] httpx timed out after 10 minutes")
        except Exception as e:
            logger.error(f"httpx execution failed: {e}")

        # Đọc từ output file
        alive_hosts = []
        if not os.path.exists(output_file):
            console.print("[!] httpx output file not found")
            return []

        with open(output_file, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url") or data.get("input") or ""
                    if not url:
                        continue
                    alive_hosts.append({
                        "url": url,
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "checked_at": datetime.now().isoformat()
                    })
                except json.JSONDecodeError:
                    continue

        console.print(f"[✓] httpx: {len(alive_hosts)} alive hosts found")

        # Optional json dump for debugging
        with open(output_file, "w") as f:
            json.dump(alive_hosts, f, indent=4)
            
        return alive_hosts

    async def detect_waf(self, url: str) -> str:
        """Runs wafw00f to detect WAF footprint."""
        # This is a bit slow so only invoke occasionally or asynchronously per host
        cmd = f"wafw00f {url}"
        stdout = await self._run_command(cmd, "wafw00f")
        # Parsing real output of wafw00f can be tricky, simplified example:
        for line in stdout.splitlines():
            if "is behind" in line:
                return line.split("is behind")[1].strip()
        return "None"

    async def take_screenshots(self, alive_hosts: list[dict]):
        """Runs gowitness to capture screenshots of alive URLs."""
        if not alive_hosts: return
        input_file = f"{self.output_dir}/alive_urls.txt"
        with open(input_file, "w") as f:
            f.write("\n".join([h['url'] for h in alive_hosts]))
            
        console.print(f"[→] Taking screenshots of {len(alive_hosts)} alive hosts...")
        cmd = f"gowitness file -f {input_file} --screenshot-path {self.output_dir}/screenshots/"
        await self._run_command(cmd, "gowitness")
        console.print(f"[✓] Screenshots saved: {self.output_dir}/screenshots/")
        
        # Generate Gallery
        await self.generate_html_gallery(alive_hosts)

    async def generate_html_gallery(self, alive_hosts: list[dict]):
        date_str = datetime.now().strftime("%Y%m%d")
        gallery_path = f"{self.output_dir}/gallery_{date_str}.html"
        
        html_content = "<html><head><title>Recon Screenshots</title>"
        html_content += "<style>body{font-family: sans-serif;} .grid{display: flex; flex-wrap: wrap;} .card{border: 1px solid #ccc; margin: 10px; padding: 10px; text-align: center; width: 320px;} img{max-width: 100%; border: 1px solid #eee;}</style>"
        html_content += "</head><body><h1>Recon Screenshots</h1><div class='grid'>"
        
        for host in alive_hosts:
            url = host['url']
            # gowitness usually saves as proto-domain-port.png or similar, assuming mapping for brevity:
            # We'll link to actual URL
            html_content += f"<div class='card'><h3><a href='{url}' target='_blank'>{url}</a></h3>"
            html_content += f"<p>Status: {host['status_code']} | Title: {host['title']}</p></div>"
            
        html_content += "</div></body></html>"
        with open(gallery_path, "w") as f:
            f.write(html_content)
        console.print(f"[✓] Gallery: {gallery_path}")

    def prioritize_targets(self, hosts: list[dict]) -> list[dict]:
        """Sorts assets by priority (login pages, admin panels, old stacks)."""
        def score(host):
            pts = 0
            title = host['title'].lower()
            tech = " ".join(host['technologies']).lower()
            if "login" in title or "admin" in title or "dashboard" in title:
                pts += 10
            if host['status_code'] in [200, 401, 403]:
                pts += 5
            if "wordpress" in tech or "php 5" in tech or "apache 2" in tech:
                pts += 8 # Older tech stacks score higher priority
            return pts

        return sorted(hosts, key=score, reverse=True)

    async def analyze_hosts(self, subdomains: list[str]) -> list[dict]:
        """Orchestrates HTTPX alive checking and enrichment."""
        alive_hosts = await self.run_httpx(subdomains)
        
        # WAF detect for top hosts only to save time (example: just checking)
        # for h in alive_hosts[:10]:
        #     h['waf'] = await self.detect_waf(h['url'])
        
        # Prioritization
        alive_hosts = self.prioritize_targets(alive_hosts)
        
        # Taking screenshots concurrently
        asyncio.create_task(self.take_screenshots(alive_hosts))
        
        return alive_hosts
