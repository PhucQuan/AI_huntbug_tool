"""
core/scan/takeover_scanner.py — Subdomain Takeover Detection
=============================================================
Detect subdomain takeover vulnerabilities bằng:
  - subzy — automated takeover checker
  - Manual CNAME + fingerprint checking
"""

import asyncio
import dns.asyncresolver
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Dict

import httpx
from rich.console import Console

console = Console()


@dataclass
class TakeoverResult:
    subdomain: str
    cname: str
    service: str
    vulnerable: bool
    fingerprint: str
    tool: str


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_cmd(cmd: str, timeout: int = 300) -> tuple[str, str]:
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
# Takeover Fingerprints
# =============================================================================

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": [".github.io"],
        "response": ["There isn't a GitHub Pages site here", "404 - File not found"],
    },
    "Heroku": {
        "cname": [".herokuapp.com", ".herokussl.com"],
        "response": ["No such app", "There's nothing here"],
    },
    "Netlify": {
        "cname": [".netlify.app", ".netlify.com"],
        "response": ["Not Found - Request ID"],
    },
    "AWS S3": {
        "cname": [".s3.amazonaws.com", ".s3-", ".s3."],
        "response": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "Shopify": {
        "cname": [".myshopify.com"],
        "response": ["Sorry, this shop is currently unavailable"],
    },
    "Tumblr": {
        "cname": [".tumblr.com"],
        "response": ["Whatever you were looking for doesn't currently exist"],
    },
    "WordPress.com": {
        "cname": [".wordpress.com"],
        "response": ["Do you want to register"],
    },
    "Ghost": {
        "cname": [".ghost.io"],
        "response": ["The thing you were looking for is no longer here"],
    },
    "Pantheon": {
        "cname": [".pantheonsite.io"],
        "response": ["404 error unknown site"],
    },
    "Zendesk": {
        "cname": [".zendesk.com"],
        "response": ["Help Center Closed"],
    },
    "Bitbucket": {
        "cname": [".bitbucket.io"],
        "response": ["Repository not found"],
    },
    "Azure": {
        "cname": [".azurewebsites.net", ".cloudapp.azure.com"],
        "response": ["404 Web Site not found"],
    },
}


# =============================================================================
# subzy — Automated Takeover Checker
# =============================================================================

async def run_subzy(subdomains: List[str]) -> List[TakeoverResult]:
    """
    Chạy subzy để check subdomain takeover.
    Install: go install github.com/PentestPad/subzy@latest
    """
    if not _tool_available("subzy"):
        console.print("[yellow][!] subzy not installed — skipping[/yellow]")
        return []
    
    tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_input.write("\n".join(subdomains))
    tmp_input.close()
    
    try:
        cmd = f"subzy run --targets {tmp_input.name} --concurrency 50 --hide_fails --verify_ssl"
        console.print(f"[cyan][→] Running subzy on {len(subdomains)} subdomains...[/cyan]")
        
        stdout, stderr = await _run_cmd(cmd, timeout=300)
        
        # Parse subzy output
        results = []
        for line in stdout.splitlines():
            if "vulnerable" in line.lower() or "[vuln]" in line.lower():
                # Format: [VULN] subdomain.example.com [Service]
                match = line.split()
                if len(match) >= 2:
                    subdomain = match[1]
                    service = match[2] if len(match) > 2 else "unknown"
                    
                    results.append(TakeoverResult(
                        subdomain=subdomain,
                        cname="",
                        service=service,
                        vulnerable=True,
                        fingerprint=line,
                        tool="subzy",
                    ))
        
        console.print(f"[green][✓] subzy: {len(results)} vulnerable subdomains found[/green]")
        return results
        
    finally:
        os.unlink(tmp_input.name)


# =============================================================================
# Manual Takeover Detection
# =============================================================================

async def check_takeover_manual(subdomain: str) -> TakeoverResult:
    """
    Check subdomain takeover thủ công:
    1. Resolve CNAME
    2. Check fingerprint
    3. HTTP request để verify
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    try:
        # 1. Resolve CNAME
        answers = await resolver.resolve(subdomain, 'CNAME')
        if not answers:
            return None
        
        cname = str(answers[0].target).lower()
        
        # 2. Check CNAME fingerprint
        matched_service = None
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            for fp in fingerprints["cname"]:
                if fp in cname:
                    matched_service = service
                    break
            if matched_service:
                break
        
        if not matched_service:
            return None
        
        # 3. HTTP request để verify response fingerprint
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            try:
                resp = await client.get(f"https://{subdomain}")
                body = resp.text
                
                # Check response fingerprints
                for response_fp in TAKEOVER_FINGERPRINTS[matched_service]["response"]:
                    if response_fp.lower() in body.lower():
                        return TakeoverResult(
                            subdomain=subdomain,
                            cname=cname,
                            service=matched_service,
                            vulnerable=True,
                            fingerprint=response_fp,
                            tool="manual",
                        )
            except Exception:
                pass
        
        return None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception as e:
        return None


async def run_manual_takeover_bulk(subdomains: List[str]) -> List[TakeoverResult]:
    """Chạy manual takeover check trên nhiều subdomains."""
    console.print(f"[cyan][→] Running manual takeover checks on {len(subdomains)} subdomains...[/cyan]")
    
    tasks = [check_takeover_manual(sub) for sub in subdomains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    vulnerable = []
    for result in results:
        if isinstance(result, TakeoverResult) and result.vulnerable:
            vulnerable.append(result)
    
    console.print(f"[green][✓] Manual takeover: {len(vulnerable)} vulnerabilities found[/green]")
    return vulnerable


# =============================================================================
# Orchestrator
# =============================================================================

async def run_takeover_scan_pipeline(
    subdomains: List[str],
    use_subzy: bool = True,
    use_manual: bool = True,
) -> Dict[str, List[TakeoverResult]]:
    """
    Chạy subdomain takeover detection pipeline.
    """
    console.print(f"[cyan][→] Starting subdomain takeover scan on {len(subdomains)} subdomains...[/cyan]")
    
    results = {
        "subzy_results": [],
        "manual_results": [],
    }
    
    # 1. subzy (fast)
    if use_subzy:
        results["subzy_results"] = await run_subzy(subdomains)
    
    # 2. Manual checking
    if use_manual:
        results["manual_results"] = await run_manual_takeover_bulk(subdomains)
    
    total_vulns = len(results["subzy_results"]) + len(results["manual_results"])
    console.print(f"\n[bold red][★] Takeover Scan Summary: {total_vulns} vulnerable subdomains found[/bold red]")
    
    return results
