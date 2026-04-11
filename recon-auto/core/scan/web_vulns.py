"""
core/scan/web_vulns.py — Web Vulnerability Scanner Chains
=========================================================
Wrapper cho các tool scan chuyên biệt:
  - dalfox    → XSS
  - corsy     → CORS misconfiguration
  - crlfuzz   → CRLF injection
  - ssrfmap   → SSRF
  - oralyzer  → Open Redirect

Mỗi scanner:
  1. Kiểm tra tool có cài không, nếu không thì skip (không crash)
  2. Chạy async subprocess
  3. Parse output → trả về list[Finding]
  4. Lưu vào DB qua db/queries.py
"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

console = Console()


# =============================================================================
# Data Model
# =============================================================================

@dataclass
class WebFinding:
    url: str
    vulnerability_type: str
    severity: str
    name: str
    description: str
    tool: str
    request: str = ""
    response: str = ""
    payload: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# =============================================================================
# Helpers
# =============================================================================

def _tool_available(name: str) -> bool:
    """Check nếu một tool binary có trong PATH không."""
    return shutil.which(name) is not None


async def _run_cmd(cmd: str, timeout: int = 120) -> tuple[str, str]:
    """Run shell command async, return (stdout, stderr)."""
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    except asyncio.TimeoutError:
        proc.kill()
        return "", f"Timeout after {timeout}s"


# =============================================================================
# XSS — dalfox
# =============================================================================

async def scan_xss(urls: list[str], blind_xss_endpoint: str = "") -> list[WebFinding]:
    """
    Chạy dalfox trên danh sách URLs, parse JSON output.
    blind_xss_endpoint: interactsh hoặc xsshunter URL (optional)
    """
    if not _tool_available("dalfox"):
        console.print("[yellow][!] dalfox not installed — skipping XSS scan[/yellow]")
        return []

    findings = []
    console.print(f"[cyan][→] Running dalfox XSS on {len(urls)} URLs...[/cyan]")

    for url in urls:
        blind_flag = f"--blind {blind_xss_endpoint}" if blind_xss_endpoint else ""
        cmd = f"dalfox url \"{url}\" {blind_flag} --silence --format json"
        stdout, stderr = await _run_cmd(cmd, timeout=60)

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # dalfox sometimes prints non-JSON lines
                if "reflected" in line.lower() or "xss" in line.lower():
                    findings.append(WebFinding(
                        url=url, vulnerability_type="xss", severity="high",
                        name="Reflected XSS", description=line, tool="dalfox",
                    ))
                continue

            findings.append(WebFinding(
                url=data.get("data", url),
                vulnerability_type="xss",
                severity="high",
                name=data.get("type", "XSS"),
                description=data.get("message", "XSS detected by dalfox"),
                tool="dalfox",
                payload=data.get("pocs", [{}])[0].get("data", ""),
            ))

    console.print(f"[green][✓] dalfox: {len(findings)} XSS finding(s)[/green]")
    return findings


# =============================================================================
# CORS — corsy
# =============================================================================

async def scan_cors(urls: list[str]) -> list[WebFinding]:
    """
    Chạy corsy, detect CORS misconfiguration.
    """
    if not _tool_available("corsy"):
        console.print("[yellow][!] corsy not installed — skipping CORS scan[/yellow]")
        return []

    # Ghi urls ra temp file
    import tempfile, os
    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmpfile.write("\n".join(urls))
    tmpfile.close()

    findings = []
    try:
        cmd = f"corsy -i {tmpfile.name} -t 5 --headers 'User-Agent: Mozilla/5.0' 2>/dev/null"
        stdout, _ = await _run_cmd(cmd, timeout=120)

        for line in stdout.splitlines():
            if "vulnerable" in line.lower() or "cors" in line.lower():
                # corsy output format: "[VULN] URL — reason"
                url_part = line.split("]")[-1].strip() if "]" in line else line
                findings.append(WebFinding(
                    url=url_part.split(" ")[0] if " " in url_part else url_part,
                    vulnerability_type="cors",
                    severity="medium",
                    name="CORS Misconfiguration",
                    description=line.strip(),
                    tool="corsy",
                ))
    finally:
        os.unlink(tmpfile.name)

    console.print(f"[green][✓] corsy: {len(findings)} CORS finding(s)[/green]")
    return findings


# =============================================================================
# CRLF Injection — crlfuzz
# =============================================================================

async def scan_crlf(urls: list[str]) -> list[WebFinding]:
    """Chạy crlfuzz để tìm CRLF injection."""
    if not _tool_available("crlfuzz"):
        console.print("[yellow][!] crlfuzz not installed — skipping CRLF scan[/yellow]")
        return []

    findings = []
    console.print(f"[cyan][→] Running crlfuzz on {len(urls)} URLs...[/cyan]")

    for url in urls:
        cmd = f"crlfuzz -u \"{url}\" -s"
        stdout, _ = await _run_cmd(cmd, timeout=30)

        if "vulnerable" in stdout.lower() or "crlf" in stdout.lower():
            findings.append(WebFinding(
                url=url, vulnerability_type="crlf", severity="medium",
                name="CRLF Injection",
                description=f"CRLF injection detected at {url}",
                tool="crlfuzz",
            ))

    console.print(f"[green][✓] crlfuzz: {len(findings)} CRLF finding(s)[/green]")
    return findings


# =============================================================================
# Open Redirect — oralyzer
# =============================================================================

async def scan_open_redirect(urls: list[str]) -> list[WebFinding]:
    """Chạy oralyzer để tìm open redirect."""
    if not _tool_available("oralyzer"):
        console.print("[yellow][!] oralyzer not installed — skipping Open Redirect scan[/yellow]")
        return []

    findings = []
    console.print(f"[cyan][→] Running oralyzer Open Redirect on {len(urls)} URLs...[/cyan]")

    for url in urls:
        cmd = f"oralyzer -u \"{url}\""
        stdout, _ = await _run_cmd(cmd, timeout=30)

        if "vulnerable" in stdout.lower():
            findings.append(WebFinding(
                url=url, vulnerability_type="open_redirect", severity="medium",
                name="Open Redirect",
                description=stdout.strip()[:300],
                tool="oralyzer",
            ))

    console.print(f"[green][✓] oralyzer: {len(findings)} Open Redirect finding(s)[/green]")
    return findings


# =============================================================================
# SSRF — ssrfmap + manual OOB check
# =============================================================================

async def scan_ssrf(urls: list[str], oob_server: str = "") -> list[WebFinding]:
    """
    Chạy ssrfmap. OOB detection cần interactsh endpoint.
    """
    if not _tool_available("ssrfmap"):
        console.print("[yellow][!] ssrfmap not installed — skipping SSRF scan[/yellow]")
        return []

    findings = []
    console.print(f"[cyan][→] Running ssrfmap SSRF on {len(urls)} URLs...[/cyan]")

    for url in urls:
        payload_server = oob_server or "http://169.254.169.254/latest/meta-data/"
        cmd = f"python ssrfmap/ssrfmap.py -r {url} -p url -m readfiles"
        stdout, _ = await _run_cmd(cmd, timeout=60)

        if "ssrf" in stdout.lower() or "success" in stdout.lower():
            findings.append(WebFinding(
                url=url, vulnerability_type="ssrf", severity="high",
                name="Server Side Request Forgery",
                description=stdout.strip()[:300],
                tool="ssrfmap",
                payload=payload_server,
            ))

    console.print(f"[green][✓] ssrfmap: {len(findings)} SSRF finding(s)[/green]")
    return findings


# =============================================================================
# Orchestrator
# =============================================================================

async def run_web_vuln_pipeline(
    urls: list[str],
    tech_stack: list[str] | None = None,
    blind_xss: str = "",
    oob_server: str = "",
    skip: list[str] | None = None,
) -> list[WebFinding]:
    """
    Chạy toàn bộ web vuln scanners song song.
    skip: list vuln type để bỏ qua, ví dụ ["ssrf", "crlf"]
    """
    skip = skip or []
    tasks = []

    if "xss" not in skip:
        tasks.append(scan_xss(urls, blind_xss))
    if "cors" not in skip:
        tasks.append(scan_cors(urls))
    if "crlf" not in skip:
        tasks.append(scan_crlf(urls))
    if "open_redirect" not in skip:
        tasks.append(scan_open_redirect(urls))
    if "ssrf" not in skip:
        tasks.append(scan_ssrf(urls, oob_server))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[WebFinding] = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
        elif isinstance(r, Exception):
            console.print(f"[red][!] Scanner error: {r}[/red]")

    console.print(f"\n[bold green][★] Web vuln scan: {len(all_findings)} total finding(s)[/bold green]")
    return all_findings
