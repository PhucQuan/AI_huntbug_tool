import asyncio
import json
import logging
import os
import shutil
from datetime import datetime
from rich.console import Console

console = Console()
logger = logging.getLogger("recon_auto.web_analysis")

# Thêm Go bin vào PATH để tìm được httpx, subfinder, etc.
_GO_BIN = os.path.expanduser("~/go/bin")
_ENV = os.environ.copy()
if _GO_BIN not in _ENV.get("PATH", ""):
    _ENV["PATH"] = _GO_BIN + ":" + _ENV.get("PATH", "")


def _find_bin(name: str) -> str:
    """Ưu tiên ~/go/bin để tránh nhầm với Python package binaries trong venv."""
    direct = os.path.join(_GO_BIN, name)
    if os.path.isfile(direct):
        return direct
    return shutil.which(name, path=_ENV["PATH"]) or name


class WebAnalysis:
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(f"{self.output_dir}/screenshots", exist_ok=True)

    async def run_httpx(self, subdomains: list[str]) -> list[dict]:
        """Runs httpx, reads stdout directly."""
        os.makedirs(self.output_dir, exist_ok=True)
        input_file = os.path.abspath(f"{self.output_dir}/temp_subdomains.txt")

        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        console.print(f"[->] Running httpx on {len(subdomains)} hosts...")

        httpx_bin = _find_bin("httpx")
        # Fallback to known path nếu shutil.which không tìm được
        if not os.path.exists(httpx_bin):
            httpx_bin = os.path.expanduser("~/go/bin/httpx")

        cmd = (
            f"{httpx_bin} -l {input_file} "
            f"-json -status-code -title -tech-detect "
            f"-threads 50 -timeout 10 -no-color"
        )

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_ENV,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=600)
        except asyncio.TimeoutError:
            console.print("[!] httpx timed out after 10 minutes")
            return []
        except Exception as e:
            logger.error(f"httpx failed: {e}")
            return []

        raw = stdout.decode(errors="ignore")
        console.print(f"[->] httpx raw output: {len(raw)} bytes")

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
                env=_ENV,
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
            gowitness_bin = _find_bin("gowitness")
            process = await asyncio.create_subprocess_exec(
                gowitness_bin, "file",
                "-f", input_file,
                "--screenshot-path", f"{self.output_dir}/screenshots/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_ENV,
            )
            await asyncio.wait_for(process.communicate(), timeout=300)
            console.print(f"[✓] Screenshots saved")
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
        if alive_hosts:
            asyncio.create_task(self.take_screenshots(alive_hosts))
        return alive_hosts
